#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Audit coverage's prototype suite (F6), Gate 0's exit
# (docs/FOX_F6_Audit_Design.md, section 18): pgAudit in default mode, the log
# hook that keeps values out of the server log, and the line that says how
# each audited transaction ended and whom it was for.
#
# Self-contained, and touches no install: it builds the engine image under a tag
# of its own, runs throwaway Postgres containers from it with audit on, and
# removes them at the end. Logs go to a tmpfs in each container, so a full one
# can be made on purpose. The shared stack in the test VM is never stopped,
# started or written to.
#
#   make integration-f6
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2

REPO="$(cd "$(dirname "$0")/.." && pwd)"
C=fox-f6-proto
# On disk, not in /tmp: the measured forensic round writes about 3.6 GB of
# audit log a minute, and /tmp in the test VM is a 2 GB tmpfs. Filled, the log
# stopped the round, which then said nothing at all (found 10 Nov 2026).
WORK="$(mktemp -d -p /var/tmp)"
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }

# -v with every removal: the official image declares a data volume, so each
# container gets an anonymous one, which a plain rm leaves behind. Left, the
# benchmark's filled the test VM's disk.
gone() { sudo docker rm -fv "$1" >/dev/null 2>&1; }
cleanup() { for c in fox-f6-proto fox-f6-proto-off fox-f6-proto-full fox-f6-proto-bench; do gone "$c"; done; sudo rm -rf "$WORK"; }
trap cleanup EXIT

# Synthetic values, made to pass their checks (Verhoeff for Aadhaar, Luhn for
# cards) as a real one would, and to be found if they leak anywhere. None is
# anyone's.
AADHAAR1=739146258013
AADHAAR2=847261930525
AADHAAR3=562904817363
CARD1=4532015112830366
CARD2=5274981203716484
PAN=BQRPK4821M
EMAIL=ravi.kumar.f6@example.in
PHONE=9845012345
VALUES_RE="$AADHAAR1|$AADHAAR2|$AADHAAR3|$CARD1|$CARD2|$PAN|$EMAIL|$PHONE"

# Start-time settings on the command line, the policy in ALTER SYSTEM, as the
# design splits them (section 15), so a mode change is a reload.
START=(-c shared_preload_libraries=pgaudit,bb_identity -c logging_collector=on
       -c log_destination=jsonlog -c log_directory=/auditlog -c log_filename=pg.log
       -c log_rotation_age=0 -c log_rotation_size=0)
POLICY="ALTER SYSTEM SET pgaudit.log = 'ddl, role';
        ALTER SYSTEM SET pgaudit.role = 'bb_audit';
        ALTER SYSTEM SET pgaudit.log_statement = off;
        ALTER SYSTEM SET pgaudit.log_parameter = off;
        ALTER SYSTEM SET pgaudit.log_relation = on;
        ALTER SYSTEM SET pgaudit.log_catalog = off;
        ALTER SYSTEM SET log_min_error_statement = panic;
        ALTER SYSTEM SET log_parameter_max_length = 0;
        ALTER SYSTEM SET log_parameter_max_length_on_error = 0;"

# start <container> <image> <log> [postgres args…]: a throwaway server. <log>
# is a tmpfs size (1m, 256m), so a full log can be made on purpose, or a
# directory on disk, as the benchmark uses: a log in memory flatters the cost.
start() {
  local name="$1" img="$2" log="$3" mount; shift 3
  gone "$name"
  case "$log" in
    /*) sudo mkdir -p "$log"; sudo chmod 1777 "$log"; mount=(-v "$log:/auditlog") ;;
    *) mount=(--tmpfs "/auditlog:size=$log,mode=1777") ;;
  esac
  sudo docker run -d --name "$name" -e POSTGRES_USER=dbadmin -e POSTGRES_PASSWORD=f6proto -e POSTGRES_DB=appdb \
    "${mount[@]}" "$img" postgres "$@" >/dev/null
  for _ in $(seq 90); do
    [ "$(sudo docker exec "$name" psql -X -tA -U dbadmin -d appdb -c 'SELECT 1' 2>/dev/null)" = "1" ] && return 0
    sleep 1
  done
  return 1
}

# su: a statement as the superuser. as: a script (stdin) as a role, over the
# container's socket, where the official image trusts local connections.
su() { sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c "$1" 2>&1; }
# sus: a script (stdin) as the superuser, one statement at a time, which ALTER
# SYSTEM needs: it cannot run inside the one transaction -c makes of several.
sus() { sudo docker exec -i "$C" psql -X -q -tA -U dbadmin -d appdb 2>&1; }
as() { sudo docker exec -i "$C" psql -X -q -tA -U "$1" -d appdb 2>&1; }

# The server log, as JSON lines. mark: how many lines so far. since <mark>: the
# lines after it, once the logging collector has written them.
log_all() { sudo docker exec "$C" sh -c 'cat /auditlog/*.json 2>/dev/null'; }
mark() { log_all | wc -l | tr -d ' '; }
since() { sleep 1.2; log_all | tail -n +"$(( $1 + 1 ))"; }
# msgs: each line as "session|vxid|severity|state|message". A line that is not
# whole JSON (the one being written when a full log ran out of space) is
# "torn".
msgs() { python3 -c '
import sys, json
for l in sys.stdin:
    if l.strip():
        try:
            d = json.loads(l)
        except ValueError:
            print("torn"); continue
        print("|".join([d.get("session_id", ""), d.get("vxid", ""), d["error_severity"], d.get("state_code", ""), d["message"]]))'; }
# fields: every key any line has, beyond the ones each always has.
audit_lines() { msgs | grep -F '|AUDIT: OBJECT,' ; }

digest() { sed -n '/PostgresBaseDigests/,/^}/p' "$REPO/internal/branch/images.go" | grep "\"$1\"" | sed 's/.*"\(sha256:[0-9a-f]*\)".*/\1/'; }

echo "### building the engine image, which has pgAudit and the hook, under its own tag"
build_ok=1
for m in 18 16; do
  if ! sudo docker build -q -t "fox-f6-proto:$m" --build-arg PG_MAJOR="$m" --build-arg PG_DIGEST="$(digest $m)" \
       "$REPO/docker/postgres" >/dev/null 2>"$WORK/build-$m.log"; then
    build_ok=0; tail -20 "$WORK/build-$m.log"
  fi
done
assert_eq "the image builds with pgAudit for Postgres 18 and 16" "$build_ok" "1"
assert_eq "…pinned to the versions the Dockerfile names" \
  "$(sudo docker run --rm fox-f6-proto:18 dpkg-query -W -f '${Version}' postgresql-18-pgaudit)|$(sudo docker run --rm fox-f6-proto:16 dpkg-query -W -f '${Version}' postgresql-16-pgaudit)" \
  "18.0-3.pgdg12+1|16.1-2.pgdg12+1"

# ---------------------------------------------------------------------------
# The suite proper, once per major.
# ---------------------------------------------------------------------------
on_major() {
  local m="$1" IMG="fox-f6-proto:$1"
  echo
  echo "################ PostgreSQL $m ################"
  echo "### a throwaway server with audit on, the Blackbox and application identity"
  start "$C" "$IMG" 256m "${START[@]}" || { bad "the server starts with pgAudit and bb_identity preloaded ($m)"; return; }
  echo "$POLICY SELECT pg_reload_conf();" | sus >/dev/null
  assert_eq "both libraries are loaded, and the policy is default mode" \
    "$(su "SHOW shared_preload_libraries")|$(su "SHOW pgaudit.log_statement")|$(su "SHOW pgaudit.log_parameter")|$(su "SHOW pgaudit.role")" \
    "pgaudit,bb_identity|off|off|bb_audit"
  local installed=1
  for f in internal/ledger/ledger.sql internal/ledger/ledger_ext.sql internal/ledger/provenance.sql \
           internal/ledger/datachanges.sql internal/ledger/tracking.sql internal/ledger/identity.sql; do
    sudo docker exec -i "$C" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 < "$REPO/$f" >/dev/null 2>>"$WORK/install-$m.log" || { installed=0; echo "  (installing $f failed)"; }
  done
  assert_eq "the Blackbox and application identity install with audit on" "$installed" "1"

  local K1; K1="$(mint keygen "$WORK" "k1-$m")"
  su "INSERT INTO bb_f1.install VALUES (1, 'fox-test', 'main');
      CREATE ROLE shop_app LOGIN IN ROLE db_client;
      CREATE ROLE alice LOGIN IN ROLE db_client;
      CREATE ROLE carol LOGIN IN ROLE db_client;
      INSERT INTO bb.app_issuers (issuer, kid, db_role, public_key) VALUES ('shop', 'k1', 'shop_app', decode('$K1', 'hex'));
      CREATE ROLE bb_audit NOLOGIN;
      CREATE ROLE bb_audit_read NOLOGIN;
      CREATE TABLE customers (id int PRIMARY KEY, email text UNIQUE NOT NULL, aadhaar text, pan text CHECK (pan ~ '^[A-Z]{5}[0-9]{4}[A-Z]\$'), phone text);
      CREATE TABLE cards (id int PRIMARY KEY, customer int REFERENCES customers (id), number text);
      CREATE TABLE notes (id int, body text);
      GRANT ALL ON customers, cards, notes TO db_client;
      GRANT INSERT, UPDATE, DELETE ON customers TO bb_audit;
      GRANT SELECT, INSERT, UPDATE, DELETE ON cards TO bb_audit;
      GRANT SELECT, INSERT, UPDATE, DELETE ON customers, cards TO bb_audit_read;
      ALTER ROLE carol SET pgaudit.role = 'bb_audit_read';" >/dev/null

  echo "### what default mode logs"
  local M; M="$(mark)"
  as alice >/dev/null <<SQL
INSERT INTO customers VALUES (1, '$EMAIL', '$AADHAAR1', '$PAN', '$PHONE');
INSERT INTO notes VALUES (1, 'a note about $AADHAAR1');
SELECT * FROM customers;
SQL
  local L; L="$(since "$M" | msgs)"
  assert_eq "a write to a marked table is logged, by class, command and table, and nothing it held" \
    "$(echo "$L" | grep -c 'AUDIT: OBJECT,[0-9]*,1,WRITE,INSERT,TABLE,public.customers,<not logged>,<not logged>$')" "1"
  assert_eq "…a write to an unmarked table is not" "$(echo "$L" | grep -c 'public.notes')" "0"
  assert_eq "…nor a read of a table marked for writes only" "$(echo "$L" | grep -c 'READ,SELECT,TABLE,public.customers')" "0"
  M="$(mark)"
  echo "INSERT INTO cards VALUES (1, 1, '$CARD1'); SELECT number FROM cards;" | as alice >/dev/null
  echo "SELECT email FROM customers;" | as carol >/dev/null
  L="$(since "$M" | msgs)"
  assert_eq "a table marked for reads has every read logged" "$(echo "$L" | grep -c 'READ,SELECT,TABLE,public.cards')" "1"
  assert_eq "…and a login given the read-audit role has its reads of marked tables logged" \
    "$(echo "$L" | grep -c 'READ,SELECT,TABLE,public.customers')" "1"
  M="$(mark)"
  # Not DROP TABLE: the Blackbox refuses it by default.
  echo "CREATE TABLE ddl_probe (id int); ALTER TABLE ddl_probe ADD COLUMN x int; CREATE ROLE someone NOLOGIN; DROP ROLE someone;" | sus >/dev/null
  L="$(since "$M" | msgs)"
  assert_eq "schema and role changes are logged, a superuser's too" \
    "$(echo "$L" | grep -oE 'AUDIT: SESSION,[0-9]+,[0-9]+,(DDL|ROLE),(CREATE TABLE|ALTER TABLE|CREATE ROLE|DROP ROLE),' | sed 's/.*,\(DDL\|ROLE\),//' | sort -u | tr '\n' ' ')" \
    "ALTER TABLE, CREATE ROLE, CREATE TABLE, DROP ROLE, "

  echo "### no values in the log: the Gate 0 exit test"
  M="$(mark)"
  local T; T="$(mint token "$WORK/k1-$m.seed")"
  {
    echo "INSERT INTO customers VALUES (2, '$EMAIL', '$AADHAAR2', NULL, NULL);"                   # 23505, detail holds the email
    echo "INSERT INTO customers VALUES ('$AADHAAR3', 'x@example.in', NULL, NULL, NULL);"          # 22P02, message holds the value
    echo "SELECT '$CARD2'::int;"                                                                  # 22003
    echo "INSERT INTO customers VALUES (3, 'y@example.in', NULL, '$PAN-x', NULL);"                # 23514, detail holds the row
    echo "INSERT INTO cards VALUES (2, 99, '$CARD2');"                                            # 23503, detail holds the row
    echo "INSERT INTO customers VALUES (4, NULL, '$AADHAAR3', NULL, NULL);"                       # 23502, detail holds the row
    echo "SELECT '{\"aadhaar\": $AADHAAR3,'::jsonb;"                                              # 22P02, json token
    echo "SELECT 1 / (length('$PHONE') - 10);"                                                    # 22012
    echo "DO \$\$BEGIN RAISE EXCEPTION 'customer % not found', '$AADHAAR1'; END\$\$;"              # P0001
    echo "DO \$\$BEGIN RAISE WARNING 'card %', '$CARD1'; RAISE NOTICE 'pan %', '$PAN'; END\$\$;"
    echo "DO \$\$BEGIN RAISE LOG 'customer % %', '$EMAIL', '$PHONE'; END\$\$;"
    echo "DO \$\$BEGIN RAISE LOG 'AUDIT: OBJECT,1,1,WRITE,INSERT,TABLE,public.customers,$AADHAAR2,<none>'; END\$\$;"
    echo "DO \$\$BEGIN EXECUTE format('INSERT INTO customers VALUES (1, %L, NULL, NULL, NULL)', '$EMAIL'); END\$\$;"  # 23505 with context
    echo "SELECT length(\$1) \\bind '$AADHAAR2' \\g"
    echo "SELECT bb.act_for(\$1) \\bind '$T' \\g"
    echo "COPY customers (id, email, aadhaar) FROM STDIN;"
    printf '5\tz@example.in\t%s\nnot-a-number\t%s\t%s\n\\.\n' "$AADHAAR1" "$EMAIL" "$AADHAAR2"   # 22P02 with COPY context
  } > "$WORK/leaks.sql"
  local CLIENT; CLIENT="$(as shop_app < "$WORK/leaks.sql")"
  L="$(since "$M")"
  assert_eq "none of the values reaches the server log, from the start: every error, warning and raised line is redacted" \
    "$(log_all | grep -cE "$VALUES_RE")" "0"
  assert_eq "…and the application identity token does not either" "$(echo "$L" | grep -cF "$T")" "0"
  assert_eq "…nor the containers' own output" "$(sudo docker logs "$C" 2>&1 | grep -cE "$VALUES_RE")" "0"
  assert_eq "…and no line carries a detail, a context, a hint or a statement" \
    "$(echo "$L" | python3 -c 'import sys,json; print(sum(1 for l in sys.stdin if l.strip() and set(json.loads(l)) & {"detail","context","hint","statement","internal_query"}))')" "0"
  assert_eq "each error is in the log as its SQLSTATE" \
    "$(echo "$L" | msgs | grep -o 'OUTCOME,ERROR,[0-9A-Z]*' | sed 's/OUTCOME,ERROR,//' | sort | uniq -c | awk '{print $2":"$1}' | tr '\n' ' ')" \
    "22003:2 22012:1 22P02:2 23502:1 23503:1 23505:2 23514:1 P0001:1 "
  assert_eq "…the raised warning, notice and log lines as redacted, the forged audit line among them" \
    "$(echo "$L" | msgs | grep -c '|REDACTED,')" "3"
  assert_contains "the client still gets the whole error, value and all" "$CLIENT" "Key (email)=($EMAIL) already exists"
  assert_contains "…and its raised message" "$CLIENT" "customer $AADHAAR1 not found"

  echo "### how each audited transaction ended, and whom it was for"
  M="$(mark)"
  echo "INSERT INTO customers VALUES (10, 'c10@example.in', NULL, NULL, NULL);" | as alice >/dev/null
  L="$(since "$M" | msgs)"
  local A X
  A="$(echo "$L" | grep -F 'public.customers' | head -1)"; X="$(echo "$L" | grep -F 'AUDIT: TXN,' | head -1)"
  assert_eq "a committed write has its audit line, then COMMIT, in the same session and transaction" \
    "$(echo "$X" | cut -d'|' -f1)|$(echo "$X" | sed 's/.*AUDIT: TXN,\([^,]*\),\([A-Z]*\),.*/\1,\2/')" \
    "$(echo "$A" | cut -d'|' -f1)|$(echo "$A" | cut -d'|' -f2),COMMIT"
  M="$(mark)"
  echo "INSERT INTO customers VALUES (10, 'dup@example.in', NULL, NULL, NULL);" | as alice >/dev/null
  echo "BEGIN; INSERT INTO customers VALUES (11, 'c11@example.in', NULL, NULL, NULL); ROLLBACK;" | as alice >/dev/null
  L="$(since "$M" | msgs)"
  assert_eq "a failed write: its audit line, the error's SQLSTATE, then ROLLBACK; and one rolled back on purpose: ROLLBACK" \
    "$(echo "$L" | sed 's/^[^|]*|[^|]*|[^|]*|[^|]*|//' | sed 's/AUDIT: OBJECT.*/OBJECT/; s/AUDIT: TXN,[^,]*,\([A-Z]*\),.*/\1/; s/AUDIT: OUTCOME,ERROR,/E/' | tr '\n' ' ')" \
    "OBJECT E23505 ROLLBACK OBJECT ROLLBACK "
  M="$(mark)"
  echo "BEGIN; INSERT INTO customers VALUES (12, 'c12@example.in', NULL, NULL, NULL); SAVEPOINT s; UPDATE customers SET phone = NULL WHERE id = 12; DELETE FROM customers WHERE id = 12; ROLLBACK TO s; COMMIT;" | as alice >/dev/null
  L="$(since "$M" | msgs)"
  assert_eq "a savepoint rolled back says how many audited statements it undid, and the rest commit" \
    "$(echo "$L" | grep -o 'AUDIT: TXN,[^,]*,[A-Z]*,*[0-9]*' | sed 's/AUDIT: TXN,[^,]*,//' | tr '\n' ' ')" "SUBROLLBACK,2 COMMIT, "
  M="$(mark)"
  echo "SELECT 1; INSERT INTO notes VALUES (2, 'x');" | as alice >/dev/null
  assert_eq "a transaction with no audit line adds no line" "$(since "$M" | msgs | grep -c 'AUDIT: TXN')" "0"

  M="$(mark)"
  as shop_app >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$(mint token "$WORK/k1-$m.seed")' \g
INSERT INTO customers VALUES (20, 'c20@example.in', NULL, NULL, NULL);
COMMIT;
BEGIN;
SET LOCAL bb.claimed_actor = 'bob';
INSERT INTO customers VALUES (21, 'c21@example.in', NULL, NULL, NULL);
COMMIT;
BEGIN;
SET LOCAL bb.app.actor = 'mallory'; SET LOCAL bb.app.issuer = 'shop'; SET LOCAL bb.app.kid = 'k1';
SET LOCAL bb.app.mac = '0000000000000000000000000000000000000000000000000000000000000000';
INSERT INTO customers VALUES (22, 'c22@example.in', NULL, NULL, NULL);
COMMIT;
BEGIN;
SAVEPOINT s;
SELECT bb.act_for(\$1) \bind '$(mint token "$WORK/k1-$m.seed" -sub eve)' \g
ROLLBACK TO s;
INSERT INTO customers VALUES (23, 'c23@example.in', NULL, NULL, NULL);
COMMIT;
SQL
  L="$(since "$M" | msgs)"
  assert_eq "whom for: asserted by the application, claimed, forged settings (none), and an assertion its savepoint undid (none)" \
    "$(echo "$L" | grep -o 'AUDIT: TXN,[^,]*,COMMIT,.*' | sed 's/AUDIT: TXN,[^,]*,COMMIT,//' | tr '\n' ' ')" \
    "asserted,shop,alice claimed,,bob none,, none,, "

  echo "### nobody but a superuser changes what is audited"
  assert_contains "a client cannot turn auditing off for its session" \
    "$(echo "SET pgaudit.log = 'none';" | as alice)" "permission denied"
  assert_contains "…nor give itself another audit role" \
    "$(echo "SET pgaudit.role = 'nobody';" | as alice)" "permission denied"
  assert_contains "…nor change another login's" \
    "$(echo "ALTER ROLE carol SET pgaudit.role = 'bb_audit';" | as alice)" "permission denied"

  echo "### coverage: the ways a marked table can be reached"
  su "CREATE VIEW v_customers AS SELECT * FROM customers;
      CREATE VIEW v_cards AS SELECT * FROM cards;
      CREATE FUNCTION add_customer(i int) RETURNS void LANGUAGE sql SECURITY DEFINER
        AS \$\$ INSERT INTO customers (id, email) VALUES (i, 'f' || i || '@example.in') \$\$;
      CREATE FUNCTION note_trigger() RETURNS trigger LANGUAGE plpgsql
        AS \$\$ BEGIN INSERT INTO customers (id, email) VALUES (NEW.id, 't' || NEW.id || '@example.in'); RETURN NEW; END \$\$;
      CREATE TABLE trig_notes (id int);
      CREATE TRIGGER t AFTER INSERT ON trig_notes FOR EACH ROW EXECUTE FUNCTION note_trigger();
      GRANT ALL ON v_customers, v_cards, trig_notes TO db_client;
      GRANT EXECUTE ON FUNCTION add_customer(int) TO db_client;" >/dev/null
  logged() { local m0; m0="$(mark)"; as alice >/dev/null; since "$m0" | msgs | grep -c "$1"; }
  local matrix
  matrix="view-write:$(echo "INSERT INTO v_customers (id, email) VALUES (30, 'v30@example.in');" | logged 'WRITE,INSERT,TABLE,public.customers')"
  matrix="$matrix view-read:$(echo "SELECT * FROM v_cards;" | logged 'READ,SELECT,TABLE,public.cards')"
  matrix="$matrix definer:$(echo "SELECT add_customer(31);" | logged 'WRITE,INSERT,TABLE,public.customers')"
  matrix="$matrix cte:$(echo "WITH n AS (INSERT INTO customers (id, email) VALUES (32, 'c32@example.in') RETURNING id) SELECT * FROM n;" | logged 'WRITE,INSERT,TABLE,public.customers')"
  matrix="$matrix trigger:$(echo "INSERT INTO trig_notes VALUES (33);" | logged 'WRITE,INSERT,TABLE,public.customers')"
  matrix="$matrix copy:$(printf 'COPY customers (id, email) FROM STDIN;\n34\tcp34@example.in\n\\.\n' | logged 'public.customers')"
  matrix="$matrix truncate:$(echo "BEGIN; TRUNCATE customers; ROLLBACK;" | logged 'TRUNCATE')"
  echo "  coverage: $matrix"
  # Two limits, stated in the design (section 12): pgAudit's object audit does
  # not see the statements inside a SECURITY DEFINER function, whoever owns it,
  # and does not cover TRUNCATE, which the Blackbox refuses by default.
  assert_eq "views, CTEs, triggers and COPY reach the marked table's log; a SECURITY DEFINER function's body and TRUNCATE do not" \
    "$matrix" "view-write:1 view-read:1 definer:0 cte:1 trigger:1 copy:1 truncate:0"

  echo "### forensic mode: statement text, by a reload, values and all"
  echo "ALTER SYSTEM SET pgaudit.log_statement = on; SELECT pg_reload_conf();" | sus >/dev/null
  sleep 1
  M="$(mark)"
  echo "INSERT INTO customers VALUES (40, 'f40@example.in', '$AADHAAR3', NULL, NULL);" | as alice >/dev/null
  echo "INSERT INTO customers VALUES (40, 'f41@example.in', '$AADHAAR1', NULL, NULL);" | as alice >/dev/null
  echo "SELECT count(*) FROM cards WHERE number = \$1 \\bind '$CARD2' \\g" | as alice >/dev/null
  su "ALTER ROLE carol PASSWORD 'not-to-be-logged-f6'" >/dev/null
  L="$(since "$M")"
  assert_eq "forensic mode puts the statement's text in its audit line" \
    "$(echo "$L" | msgs | grep -c "AUDIT: OBJECT,.*INSERT INTO customers VALUES (40, 'f40@example.in', '$AADHAAR3'")" "1"
  assert_eq "…errors stay redacted, so a failed statement's values are only in its own audit line" \
    "$(echo "$L" | msgs | grep "$AADHAAR1" | grep -vc 'AUDIT: OBJECT')" "0"
  assert_eq "…parameters stay out: the read is logged, its bound value is not" \
    "$(echo "$L" | msgs | grep -c 'READ,SELECT,TABLE,public.cards')|$(echo "$L" | grep -c "$CARD2")" "1|0"
  assert_eq "…and a password is redacted" "$(echo "$L" | grep -c 'not-to-be-logged-f6')|$(echo "$L" | grep -c 'PASSWORD <REDACTED>')" "0|1"
  echo "ALTER SYSTEM SET pgaudit.log_statement = off; SELECT pg_reload_conf();" | sus >/dev/null

  gone "$C"
}

( cd "$REPO" && go build -o "$WORK/mint" ./scripts/f1/mint ) || { echo "could not build the mint tool"; exit 1; }
mint() { "$WORK/mint" "$@"; }

# F6_BENCH_ONLY=1 runs the measurements alone, for working on them.
if [ -z "${F6_BENCH_ONLY:-}" ]; then
on_major 18
on_major 16

echo
echo "### loaded on demand, as every install loads it today, the library changes nothing"
start "$C-off" fox-f6-proto:18 64m || bad "a server without the preload starts"
sudo docker exec -i "$C-off" psql -X -q -U dbadmin -d appdb >/dev/null 2>&1 <<SQL
CREATE EXTENSION bb_identity;
SELECT bbid_txn_id();
CREATE TABLE t (email text UNIQUE);
INSERT INTO t VALUES ('$EMAIL');
INSERT INTO t VALUES ('$EMAIL');
SQL
sleep 1
assert_eq "the server log is the server's own, as before: the error and its detail as PostgreSQL wrote them" \
  "$(sudo docker logs "$C-off" 2>&1 | grep -c "Key (email)=($EMAIL) already exists")" "1"
gone "$C-off"

echo "### a full log: writes go on, and the gap is visible"
C=fox-f6-proto-full
start "$C" fox-f6-proto:18 1m "${START[@]}" || bad "a server with a 1 MB log starts"
echo "$POLICY SELECT pg_reload_conf();" | sus >/dev/null
su "CREATE ROLE bb_audit NOLOGIN; CREATE TABLE customers (id int PRIMARY KEY, aadhaar text); GRANT INSERT ON customers TO bb_audit;" >/dev/null
for i in $(seq 1 4000); do echo "INSERT INTO customers VALUES ($i, '$AADHAAR1');"; done > "$WORK/fill.sql"
sudo docker exec -i "$C" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 < "$WORK/fill.sql" >/dev/null 2>"$WORK/fill.err"
fill_rc=$?
assert_eq "4,000 audited writes into a 1 MB log all succeed" "$fill_rc|$(su 'SELECT count(*) FROM customers')" "0|4000"
assert_eq "…the log filled" "$(sudo docker exec "$C" df --output=pcent /auditlog | tail -1 | tr -d ' %')" "100"
# Nothing reports the loss: not the server's own output, not its stderr file.
# So the collector has to find a gap itself (design, section 13).
assert_eq "…and nothing says lines were lost: the gap is silent" \
  "$(sudo docker logs "$C" 2>&1 | grep -c 'could not write')|$(sudo docker exec "$C" sh -c 'cat /auditlog/pg.log 2>/dev/null' | grep -c 'could not write')" "0|0"
assert_eq "…and the server still answers" "$(su 'SELECT 1')" "1"
LOGGED="$(log_all | msgs | grep -c 'AUDIT: OBJECT')"
echo "  audited lines that reached the log: $LOGGED of 4000; lines cut off part-way: $(log_all | msgs | grep -c '^torn$')"
assert_eq "…with no value on its own output either" "$(sudo docker logs "$C" 2>&1 | grep -c "$AADHAAR1")" "0"
sudo docker exec -u postgres "$C" sh -c ': > /auditlog/pg.json'
assert_eq "space freed (the log emptied)" "$(log_all | wc -c | tr -d ' ')" "0"
su "INSERT INTO customers VALUES (5000, 'x')" >/dev/null
sleep 1.2
assert_eq "…the next audited write is logged again" "$(log_all | msgs | grep -c 'AUDIT: OBJECT')" "1"
gone "$C"

fi

echo "### under load, no line is lost"
# PostgreSQL's logging process slows the server rather than drop a line: 16
# clients of pgbench, every statement audited, then the log counted once the
# logging process has caught up. TPC-B is four writes and a read a transaction.
C=fox-f6-proto-bench
logbytes() { sudo sh -c "cat '$WORK'/bench-log/*.json 2>/dev/null | wc -c" | tr -d ' '; }
# settled: the log's size once the logging process has caught up, which after
# a fast run takes seconds, or minutes.
settled() { local a b; b="$(logbytes)"; for _ in $(seq 300); do sleep 1; a="$b"; b="$(logbytes)"; [ "$a" = "$b" ] && break; done; echo "$b"; }
logcount() { sudo sh -c "cat '$WORK'/bench-log/*.json 2>/dev/null" | grep -c "$1"; }
start "$C" fox-f6-proto:18 "$WORK/bench-log" "${START[@]}" || bad "the load server starts"
echo "$POLICY SELECT pg_reload_conf();" | sus >/dev/null
sudo docker exec "$C" pgbench -U dbadmin -i -s 10 -q appdb >/dev/null 2>&1
su "CREATE ROLE bb_audit NOLOGIN;
    GRANT SELECT, INSERT, UPDATE, DELETE ON pgbench_accounts, pgbench_tellers, pgbench_branches, pgbench_history TO bb_audit;" >/dev/null
settled >/dev/null
W0="$(logcount ',WRITE,')"; R0="$(logcount ',READ,')"; T0="$(logcount 'AUDIT: TXN,')"
N="$(sudo docker exec "$C" pgbench -U dbadmin -c 16 -j 4 -T 20 -M prepared appdb 2>/dev/null | sed -n 's/^number of transactions actually processed: \([0-9]*\).*/\1/p')"
settled >/dev/null
echo "  $N transactions"
# One read more than the transactions, in a transaction of its own: before a
# run, pgbench reads pgbench_branches to learn the scale.
assert_eq "every audited write has its line, every read its line, every transaction its line" \
  "$(( $(logcount ',WRITE,') - W0 ))|$(( $(logcount ',READ,') - R0 ))|$(( $(logcount 'AUDIT: TXN,') - T0 ))" "$(( N * 4 ))|$(( N + 1 ))|$(( N + 1 ))"
assert_eq "…and none was cut off" "$(sudo sh -c "cat '$WORK'/bench-log/*.json" | msgs | grep -c '^torn$')" "0"
gone "$C"; sudo rm -rf "$WORK/bench-log"

echo "### measured: pgbench on PostgreSQL 18, 16 clients, three rounds each, medians"
# off: no preload. pgaudit: pgAudit alone in default mode. default: pgAudit
# and bb_identity's hook and transaction line. forensic: default plus statement
# text. In those three every pgbench table is marked for writes, and
# pgbench_accounts for reads: the worst case, every statement audited. partial:
# default mode with one table marked for writes (pgbench_accounts), so one
# statement in five is audited, nearer what marking personal-data tables gives.
# Reads run first, on a fresh database: after the write run, its leftover work
# (dead rows, a checkpoint) made the read numbers say nothing.
#
# 16 clients on the VM's 4 CPUs: the cost is capacity, measured with the CPUs
# full. With 4 clients the runs were bound by round trips, and a busy logging
# process, keeping the virtual CPUs awake, made audited reads look faster than
# unaudited ones.
C=fox-f6-proto-bench
# bench: tps, and the transactions done, as "tps n".
bench() { sudo docker exec "$C" pgbench -U dbadmin "$@" appdb 2>"$WORK/pgbench.err" |
  sed -n -e 's/^number of transactions actually processed: \([0-9]*\).*/n \1/p' -e 's/^tps = \([0-9]*\).*/t \1/p' |
  awk '$1 == "t" {t = $2} $1 == "n" {n = $2} END {print t + 0, n + 0}'; }
median() { tr ' ' '\n' | grep -v '^$' | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
for mode in off pgaudit default partial forensic; do eval "R_tpcb_$mode=''; R_sel_$mode=''"; done
for round in 1 2 3; do
  for mode in off pgaudit default partial forensic; do
    case "$mode" in
      off) args=() ;;
      pgaudit) args=(-c shared_preload_libraries=pgaudit "${START[@]:2}") ;;
      *) args=("${START[@]}") ;;
    esac
    start "$C" fox-f6-proto:18 "$WORK/bench-log" "${args[@]}" || { bad "the $mode server starts"; continue; }
    if [ "$mode" != off ]; then
      extra=""; [ "$mode" = forensic ] && extra="ALTER SYSTEM SET pgaudit.log_statement = on;"
      echo "$POLICY $extra SELECT pg_reload_conf();" | sus >/dev/null
    fi
    sudo docker exec "$C" pgbench -U dbadmin -i -s 10 -q appdb >/dev/null 2>&1
    if [ "$mode" = partial ]; then
      su "CREATE ROLE bb_audit NOLOGIN; GRANT INSERT, UPDATE, DELETE ON pgbench_accounts TO bb_audit;" >/dev/null
    else
      su "CREATE ROLE bb_audit NOLOGIN;
          GRANT SELECT, INSERT, UPDATE, DELETE ON pgbench_accounts, pgbench_tellers, pgbench_branches, pgbench_history TO bb_audit;" >/dev/null
    fi
    sel="$(bench -c 16 -j 4 -T 20 -M prepared -S | cut -d' ' -f1)"
    if [ "$(sudo docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" != true ]; then
      bad "the $mode server stopped during the run"; sudo docker logs "$C" 2>&1 | tail -5; gone "$C"; continue
    fi
    read -r tpcb ntx <<<"$(bench -c 16 -j 4 -T 40 -M prepared)"
    # A round that did not finish is shown, with pgbench's own words, and left
    # out of the medians: twice in some forty runs on the shared VM, a write
    # run gave no result, and never again with its errors shown.
    if [ "${tpcb:-0}" -eq 0 ] || [ "${sel:-0}" -eq 0 ]; then
      echo "  (the $mode run, round $round, did not finish:)"; tail -3 "$WORK/pgbench.err" | sed 's/^/    /'
    else
      eval "R_tpcb_$mode=\"\$R_tpcb_$mode $tpcb\"; R_sel_$mode=\"\$R_sel_$mode $sel\""
    fi
    gone "$C"; sudo rm -rf "$WORK/bench-log"
  done
done
printf '  %-10s %26s %26s\n' "mode" "TPC-B tps (runs)" "select tps (runs)"
done_rounds=yes
for mode in off pgaudit default partial forensic; do
  eval "t=\$R_tpcb_$mode; r=\$R_sel_$mode"
  [ "$(echo $t | wc -w)" -ge 2 ] || done_rounds=no
  eval "M_tpcb_$mode=$(echo $t | median); M_sel_$mode=$(echo $r | median)"
  eval "printf '  %-10s %8s (%s) %8s (%s)\n' $mode \$M_tpcb_$mode \"$(echo $t | tr ' ' /)\" \$M_sel_$mode \"$(echo $r | tr ' ' /)\""
done
assert_eq "every mode finished at least two of its three rounds" "$done_rounds" "yes"
pct() { echo $(( ($1 - $2) * 100 / $1 )); }
echo "  write cost, medians: pgAudit alone $(pct "$M_tpcb_off" "$M_tpcb_pgaudit")%, default mode $(pct "$M_tpcb_off" "$M_tpcb_default")%, one table in five $(pct "$M_tpcb_off" "$M_tpcb_partial")%, forensic $(pct "$M_tpcb_off" "$M_tpcb_forensic")% (budget for default: 5%)"
echo "  read cost, medians:  pgAudit alone $(pct "$M_sel_off" "$M_sel_pgaudit")%, default mode $(pct "$M_sel_off" "$M_sel_default")%, forensic $(pct "$M_sel_off" "$M_sel_forensic")%"

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" -eq 0 ]
