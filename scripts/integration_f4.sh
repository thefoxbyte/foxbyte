#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Erasure's prototype suite (F4), Gate 0's exit
# (docs/FOX_F4_Erasure_Design.md, section 19): placeholders made with
# PostgreSQL's own lexer, and their cost; the Blackbox's entries redacted with
# a seal, the chain and its anchors still verifying and tampering caught; the
# catalog facts a plan rests on; a branch made before an erasure, erased, then
# remade, read afterwards for what is left; and a restore to before the
# erasure, erased again by row keys before anyone can reach it.
#
# Self-contained, and touches no install: it builds the engine image under a tag
# of its own, runs throwaway containers from it, makes a ZFS pool of its own
# from a file, and removes all of it at the end. The shared stack in the test VM
# is never stopped, started or written to.
#
#   make integration-f4
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2

REPO="$(cd "$(dirname "$0")/.." && pwd)"
C=fox-f4-proto
WORK="$(mktemp -d)"
POOL=f4proto
PASS=0
FAIL=0
CONTAINERS="fox-f4-proto fox-f4-proto-main fox-f4-proto-branch fox-f4-proto-src fox-f4-proto-restore"

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }
assert_ne() { if [ "$2" != "$3" ]; then ok "$1"; else bad "$1 (got '$2', want anything else)"; fi; }
note() { echo "  NOTE: $1"; }

gone() { sudo docker rm -fv "$1" >/dev/null 2>&1; }
cleanup() {
  for c in $CONTAINERS; do gone "$c"; done
  sudo zpool destroy -f "$POOL" >/dev/null 2>&1
  case "$WORK" in /tmp/tmp.*) sudo rm -rf -- "$WORK" ;; esac
}
trap cleanup EXIT

# Synthetic values, made to be found if they are left anywhere. None is anyone's.
EMAIL=asha.rao.f4@example.in
PHONE=9845012399
OTHER=ravi.kumar.f4@example.in
VALUES_RE="$EMAIL|$PHONE"

# start <name> <image> [docker options…] [-- server options…]
start() {
  local name="$1" img="$2"; shift 2
  local opts=() args=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do opts+=("$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  args=("$@")
  gone "$name"
  sudo docker run -d --name "$name" -e POSTGRES_USER=dbadmin -e POSTGRES_PASSWORD=f4proto -e POSTGRES_DB=appdb \
    "${opts[@]}" "$img" ${args[@]+"${args[@]}"} >/dev/null
  for _ in $(seq 90); do
    [ "$(sudo docker exec "$name" psql -X -tA -U dbadmin -d appdb -c 'SELECT 1' 2>/dev/null)" = "1" ] && return 0
    sleep 1
  done
  return 1
}
su() { sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c "$1" 2>&1; }
sus() { sudo docker exec -i "$C" psql -X -q -tA -U dbadmin -d appdb -v ON_ERROR_STOP=1 2>&1; }
as() { sudo docker exec "$C" psql -X -q -tA -U "$1" -d appdb -c "$2" 2>&1; }
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

digest() { sed -n '/PostgresBaseDigests/,/^}/p' "$REPO/internal/branch/images.go" | grep "\"$1\"" | sed 's/.*"\(sha256:[0-9a-f]*\)".*/\1/'; }

echo "### building the engine image, with placeholders in bb_identity, under its own tag"
build_ok=1
for m in 18 16; do
  if ! sudo docker build -q -t "fox-f4-proto:$m" --build-arg PG_MAJOR="$m" --build-arg PG_DIGEST="$(digest $m)" \
       "$REPO/docker/postgres" >/dev/null 2>"$WORK/build-$m.log"; then
    build_ok=0; tail -20 "$WORK/build-$m.log"
  fi
done
assert_eq "the image builds for Postgres 18 and 16" "$build_ok" "1"

# The hard cases (design, section 9): quotes inside strings, E'' strings,
# dollar quotes, comments holding quotes and values, quoted identifiers with
# digits, numbers of every shape, parameters already there, several statements.
cat > "$WORK/corpus.sql" <<'SQL'
SELECT bb_f1.bbid_placeholders(q) FROM (VALUES
 (1, $q$UPDATE people SET email = 'a''b@x.com', phone = '98' WHERE id = 42$q$),
 (2, $q$UPDATE t SET note = E'it\'s asha' WHERE x = 1.5e3 AND y = .5 AND z = 0x1F$q$),
 (3, $q$UPDATE t SET d = $$asha@x.com$$, e = $tag$it's $$ here$tag$ WHERE "col2" = 3$q$),
 (4, $q$DELETE FROM "t 1" /* asha's row */ WHERE a = 'x' -- fix asha@x.com
$q$),
 (5, $q$UPDATE t SET a = $1, b = 'v' WHERE c = $2; DELETE FROM t WHERE id = -7$q$),
 (6, $q$UPDATE t SET j = '{"email":"asha@x.com"}'::jsonb, d = date '2020-01-01', b = B'101', x = X'FF', u = U&'d\0061t' WHERE t1.col3 = 2$q$),
 (7, $q$update t set arr = ARRAY['a','b'] where tags @> '{x}' and id in (1,2,3)$q$),
 (8, $q$UPDATE "Weird ""Name""" SET "a'b" = 'v' /* nested /* comment */ 'not a string' */ WHERE c = 'x'$q$),
 (9, $q$UPDATE t SET x = 'line one
line two' WHERE y = 'a'
  'b' AND z = 'c' 'd'$q$),
 (10, $q$DELETE FROM t WHERE id = 1;$q$)
) v(n, q) ORDER BY n;
SQL
# Case 4 ends in a space: the comment and the newline after it became one.
# Case 9: strings on two lines are one constant, as the server joins them; on
# one line they are two tokens (and a syntax error to the server).
cat > "$WORK/corpus.want" <<'TXT'
UPDATE people SET email = $1, phone = $2 WHERE id = $3
UPDATE t SET note = $1 WHERE x = $2 AND y = $3 AND z = $4
UPDATE t SET d = $1, e = $2 WHERE "col2" = $3
DELETE FROM "t 1" WHERE a = $1@
UPDATE t SET a = $1, b = $3 WHERE c = $2; DELETE FROM t WHERE id = -$4
UPDATE t SET j = $1::jsonb, d = date $2, b = $3, x = $4, u = $5 WHERE t1.col3 = $6
update t set arr = ARRAY[$1,$2] where tags @> $3 and id in ($4,$5,$6)
UPDATE "Weird ""Name""" SET "a'b" = $1 WHERE c = $2
UPDATE t SET x = $1 WHERE y = $2 AND z = $3 $4
DELETE FROM t WHERE id = $1;
TXT
sed -i 's/@$/ /' "$WORK/corpus.want"

for m in 18 16; do
  echo
  echo "################ PostgreSQL $m ################"
  C=fox-f4-proto
  start "$C" "fox-f4-proto:$m" || { bad "the PostgreSQL $m server starts"; continue; }
  sus >/dev/null <<'SQL'
CREATE SCHEMA bb_f1;
REVOKE ALL ON SCHEMA bb_f1 FROM PUBLIC;
CREATE EXTENSION bb_identity WITH SCHEMA bb_f1;
SQL

  echo "### placeholders, with the server's own lexer"
  sudo docker exec -i "$C" psql -X -q -tA -U dbadmin -d appdb < "$WORK/corpus.sql" > "$WORK/corpus.got" 2>&1
  if diff -u "$WORK/corpus.want" "$WORK/corpus.got" > "$WORK/corpus.diff"; then
    ok "every literal in the ten hard cases becomes a placeholder, and nothing else changes"
  else
    bad "the hard cases: $(cat "$WORK/corpus.diff")"
  fi
  assert_eq "a comment holding a value is gone with it" \
    "$(su "SELECT position('asha' IN bb_f1.bbid_placeholders(\$q\$DELETE FROM t -- asha@x.com
WHERE a = 1 /* asha */\$q\$))")" "0"
  assert_eq "standard_conforming_strings off: a backslash-escaped quote is read as the server reads it" \
    "$(sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c "SET standard_conforming_strings = off" -c "SELECT bb_f1.bbid_placeholders(\$q\$UPDATE t SET a = 'it\\'s' WHERE b = 1\$q\$)" 2>&1)" \
    'UPDATE t SET a = $1 WHERE b = $2'
  assert_contains "a text the lexer refuses raises its error, as the server would" \
    "$(su "SELECT bb_f1.bbid_placeholders('UPDATE t SET a = ''unterminated')")" "unterminated quoted string"
  assert_eq "NULL in, NULL out (STRICT)" "$(su "SELECT bb_f1.bbid_placeholders(NULL) IS NULL")" "t"
  # Updated from 0.2, as an install that has the masking hash would be.
  su "CREATE DATABASE upd" >/dev/null
  sudo docker exec "$C" psql -X -q -tA -U dbadmin -d upd -c "CREATE EXTENSION bb_identity VERSION '0.2'" >/dev/null 2>&1
  assert_eq "an install at 0.2 updates to 0.3 and has it" \
    "$(sudo docker exec "$C" psql -X -q -tA -U dbadmin -d upd -c "ALTER EXTENSION bb_identity UPDATE" -c "SELECT extversion FROM pg_extension WHERE extname = 'bb_identity'" -c "SELECT bbid_placeholders('DELETE FROM t WHERE a = 1')" 2>&1 | tr '\n' '|')" \
    '0.3|DELETE FROM t WHERE a = $1|'
  T0=$(date +%s%N)
  su "SELECT count(bb_f1.bbid_placeholders('UPDATE public.customers SET email = ''asha.rao@example.in'', phone = ''+91 98450 12345'', updated_at = now() WHERE id = ' || g)) FROM generate_series(1, 100000) g" >/dev/null
  note "PostgreSQL $m: 100,000 placeholder calls on a typical UPDATE: $(ms "$T0") ms"

  echo "### the Blackbox, as the engine installs it, then redaction with a seal"
  inst_ok=1
  for f in ledger.sql ledger_ext.sql provenance.sql datachanges.sql; do
    sudo docker exec -i "$C" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 < "$REPO/internal/ledger/$f" >"$WORK/inst-$f.log" 2>&1 \
      || { inst_ok=0; tail -5 "$WORK/inst-$f.log"; }
  done
  assert_eq "the Blackbox installs" "$inst_ok" "1"
  sus >/dev/null <<SQL
CREATE TABLE public.people (id bigint PRIMARY KEY, email text, phone text, note text);
GRANT ALL ON public.people TO db_client;
INSERT INTO public.people VALUES (1, '$EMAIL', '$PHONE', 'x'), (2, '$OTHER', '9123400000', 'y'), (3, 'c@example.org', '9000000003', 'z');
SQL
  # An agent's changes, which the Blackbox records with their text, values and all.
  as db_agent "UPDATE public.people SET note = 'called' WHERE email = '$EMAIL'" >/dev/null
  as db_agent "UPDATE public.people SET phone = '$PHONE' WHERE id = 1; UPDATE public.people SET note = 'n' WHERE id = 3" >/dev/null
  as db_agent "UPDATE public.people SET note = 'kept' WHERE id = 2 -- not this person" >/dev/null
  as db_agent "DELETE FROM public.people WHERE id = 1 /* $EMAIL asked */" >/dev/null
  # A schema change carrying the value: kept as it is, and flagged.
  su "ALTER TABLE public.people ALTER COLUMN note SET DEFAULT '$EMAIL'" >/dev/null
  DML_WITH="$(su "SELECT count(*) FROM bb.schema_ledger WHERE command_tag IN ('UPDATE','DELETE') AND statement ~ '$VALUES_RE'")"
  assert_eq "the agent's changes are recorded with the person's values in their text" "$([ "$DML_WITH" -ge 3 ] && echo yes || echo "no ($DML_WITH)")" "yes"
  CONTROL_ID="$(su "SELECT id FROM bb.schema_ledger WHERE statement LIKE '%not this person%'")"
  CONTROL_TEXT="$(su "SELECT md5(statement) FROM bb.schema_ledger WHERE id = $CONTROL_ID")"
  MAXID="$(su "SELECT max(id) FROM bb.schema_ledger")"
  ROOT_SQL="SELECT encode(sha256(convert_to(string_agg(row_hash, ',' ORDER BY id), 'UTF8')), 'hex') FROM bb.schema_ledger WHERE id <= $MAXID"
  EXT_SQL="SELECT encode(sha256(convert_to(string_agg(bb._ext_hash(e), ',' ORDER BY ledger_id), 'UTF8')), 'hex') FROM bb.ledger_ext e WHERE ledger_id <= $MAXID"
  ROOT_BEFORE="$(su "$ROOT_SQL")"
  EXT_BEFORE="$(su "$EXT_SQL" 2>&1)"
  sudo docker exec -i "$C" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 < "$REPO/docs/f4/redact.sql" >"$WORK/redact.log" 2>&1 \
    || bad "the redaction prototype installs: $(tail -3 "$WORK/redact.log")"
  assert_eq "before: the chain verifies" "$(su "SELECT count(*) FROM bb.verify_sealed()")" "0"

  OUT="$(su "SELECT redacted || '|' || cardinality(flagged) || '|' || entry FROM bb.erasure_redact('erasure-1', ARRAY['$EMAIL', '$PHONE'])")"
  REDACTED="${OUT%%|*}"; REST="${OUT#*|}"; FLAGGED="${REST%%|*}"; ENTRY="${REST#*|}"
  assert_eq "every data change holding a value is redacted" "$REDACTED" "$DML_WITH"
  assert_eq "the schema change holding one is flagged, not changed" "$FLAGGED" "1"
  assert_eq "no data change's text holds a value now" \
    "$(su "SELECT count(*) FROM bb.schema_ledger WHERE command_tag IN ('UPDATE','DELETE') AND statement ~ '$VALUES_RE'")" "0"
  assert_eq "…nor the comment the agent wrote one in" "$(su "SELECT count(*) FROM bb.schema_ledger WHERE statement LIKE '%asked%'")" "0"
  assert_contains "the schema change keeps its exact text" \
    "$(su "SELECT statement FROM bb.schema_ledger WHERE command_tag = 'ALTER TABLE' ORDER BY id DESC LIMIT 1")" "SET DEFAULT '$EMAIL'"
  assert_eq "an entry that did not hold a value is untouched" "$(su "SELECT md5(statement) FROM bb.schema_ledger WHERE id = $CONTROL_ID")" "$CONTROL_TEXT"
  assert_contains "a redacted entry reads with placeholders" \
    "$(su "SELECT statement FROM bb.schema_ledger WHERE command_tag = 'DELETE' ORDER BY id DESC LIMIT 1")" 'WHERE id = $1'
  assert_eq "every row hash is as it was, so the anchors' roots are unchanged" "$(su "$ROOT_SQL")" "$ROOT_BEFORE"
  assert_eq "…and so is the capture each anchor leaf also covers (ledger_ext)" "$(su "$EXT_SQL" 2>&1)" "$EXT_BEFORE"
  assert_contains "the redaction is itself an entry, chained, holding the seals' digest and no value" \
    "$(su "SELECT command_tag || ': ' || statement FROM bb.schema_ledger WHERE id = $ENTRY")" "ERASURE REDACT: redacted $REDACTED entries; seals sha256:"
  assert_eq "…that entry holds no value" "$(su "SELECT count(*) FROM bb.schema_ledger WHERE id = $ENTRY AND (statement || object_identity) ~ '$VALUES_RE'")" "0"
  assert_eq "after: the chain verifies, redacted entries by their seals" "$(su "SELECT count(*) FROM bb.verify_sealed()")" "0"
  assert_eq "a second request finds nothing left to redact in those entries" \
    "$(su "SELECT redacted FROM bb.erasure_redact('erasure-2', ARRAY['$EMAIL', '$PHONE'])")" "0"
  assert_eq "…and the chain still verifies" "$(su "SELECT count(*) FROM bb.verify_sealed()")" "0"

  echo "### the ledger stays append-only, and tampering after the redaction is caught"
  assert_contains "an UPDATE of an entry outside a redaction is refused" \
    "$(su "UPDATE bb.schema_ledger SET statement = 'x' WHERE id = $CONTROL_ID")" "append-only"
  assert_contains "inside an unlock, a change to anything but the statement is refused" \
    "$(su "BEGIN; INSERT INTO bb.ledger_unlock VALUES ('t'); UPDATE bb.schema_ledger SET actor = 'someone' WHERE id = $CONTROL_ID; ROLLBACK")" "append-only"
  assert_contains "db_client cannot unlock it" \
    "$(as db_client "INSERT INTO bb.ledger_unlock VALUES ('t')")" "permission denied"
  assert_contains "db_client cannot run a redaction" \
    "$(as db_client "SELECT * FROM bb.erasure_redact('x', ARRAY['x'])")" "permission denied"
  RID="$(su "SELECT min(id) FROM bb.ledger_seals")"
  tamper() { su "BEGIN; SET LOCAL session_replication_role = replica; $1; SELECT string_agg(DISTINCT split_part(problem, ':', 1), ',' ORDER BY split_part(problem, ':', 1)) FROM bb.verify_sealed(); ROLLBACK" | grep -v '^$' | tail -1; }
  assert_contains "a redacted entry's text changed afterwards: its seal fails" \
    "$(tamper "UPDATE bb.schema_ledger SET statement = statement || ' -- edited' WHERE id = $RID")" "seal"
  assert_contains "a seal removed: the entry fails its hash, and the digest fails" \
    "$(tamper "DELETE FROM bb.ledger_seals WHERE id = $RID")" "digest,hash"
  assert_contains "the text changed and its seal rewritten to match: the digest fails" \
    "$(tamper "UPDATE bb.schema_ledger SET statement = 'edited' WHERE id = $RID; UPDATE bb.ledger_seals s SET seal = bb._seal(s.orig_row_hash, bb._ledger_hash(l)) FROM bb.schema_ledger l WHERE l.id = s.id AND s.id = $RID")" "digest"
  assert_contains "…and the digest rewritten too: the redaction's own entry fails its hash" \
    "$(tamper "UPDATE bb.schema_ledger SET statement = 'edited' WHERE id = $RID; UPDATE bb.ledger_seals s SET seal = bb._seal(s.orig_row_hash, bb._ledger_hash(l)) FROM bb.schema_ledger l WHERE l.id = s.id AND s.id = $RID; UPDATE bb.schema_ledger SET statement = regexp_replace(statement, 'sha256:.*', 'sha256:' || bb._seals_digest(id)) WHERE id = (SELECT by_entry FROM bb.ledger_seals WHERE id = $RID)")" "hash"
  assert_contains "an entry rewritten with a seal of its own that no redaction wrote: caught" \
    "$(tamper "UPDATE bb.schema_ledger SET statement = 'edited' WHERE id = $CONTROL_ID; INSERT INTO bb.ledger_seals SELECT id, row_hash, bb._seal(row_hash, bb._ledger_hash(l)), 999999 FROM bb.schema_ledger l WHERE id = $CONTROL_ID")" "seal"

  echo "### from now on, placeholders in what the Blackbox records"
  # Every place datachanges.sql records a data change's text: agents' changes,
  # blocked and flagged ones, and TRUNCATE. Not the refusal of a bb_ trigger,
  # which is a schema change and keeps its exact text.
  sed '/, bad, current_query()/!s/current_query()/bb_f1.bbid_placeholders(current_query())/g' \
    "$REPO/internal/ledger/datachanges.sql" > "$WORK/datachanges_ph.sql"
  assert_eq "datachanges.sql records a data change's text in six places" \
    "$(grep -c 'bbid_placeholders(current_query())' "$WORK/datachanges_ph.sql")" "6"
  # The cost, on an agent's single-row updates, each its own statement, with the
  # impact limits lifted so that every one is applied and recorded.
  # Each run starts the same way: the capture installed (which puts the default
  # limits back), then the limits lifted.
  lift() { su "SET session_replication_role = replica; DELETE FROM bb.dml_limits; DELETE FROM bb.dml_budgets; TRUNCATE bb.dml_spent" >/dev/null; }
  install_capture() {
    sudo docker exec -i "$C" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 < "$1" >"$WORK/ph-install.log" 2>&1 \
      || bad "the data-change capture installs from $(basename "$1"): $(tail -3 "$WORK/ph-install.log")"
    lift
  }
  for i in $(seq 1 2000); do echo "UPDATE public.people SET note = 'n$i', email = 'p$i@example.org' WHERE id = 2;"; done > "$WORK/updates.sql"
  run_updates() { local t; t=$(date +%s%N); sudo docker exec -i "$C" psql -X -q -U db_agent -d appdb < "$WORK/updates.sql" >/dev/null 2>&1; ms "$t"; }
  applied() { su "SELECT count(*) FROM bb.schema_ledger WHERE status = 'APPLIED' AND command_tag = 'UPDATE'"; }
  install_capture "$REPO/internal/ledger/datachanges.sql"
  run_updates >/dev/null # warm
  A0="$(applied)"
  BASE_MS="$(run_updates)"
  install_capture "$WORK/datachanges_ph.sql"
  run_updates >/dev/null
  PH_MS="$(run_updates)"
  assert_eq "every timed UPDATE was applied and recorded, none refused" \
    "$(( $(applied) - A0 )) $(su "SELECT count(*) FROM bb.schema_ledger WHERE status = 'BLOCKED'")" "6000 0"
  note "PostgreSQL $m: 2,000 recorded agent UPDATEs: ${BASE_MS} ms as today, ${PH_MS} ms with placeholders"
  as db_agent "UPDATE public.people SET email = '$OTHER', phone = '9123400000' WHERE id = 2" >/dev/null
  assert_eq "an agent's UPDATE is now recorded without its values" \
    "$(su "SELECT statement FROM bb.schema_ledger WHERE command_tag = 'UPDATE' ORDER BY id DESC LIMIT 1")" \
    'UPDATE public.people SET email = $1, phone = $2 WHERE id = $3'
  as db_agent "UPDATE public.people SET email = '$EMAIL'" >/dev/null
  assert_eq "a blocked attempt is recorded without its values too" \
    "$(su "SELECT status || ': ' || statement FROM bb.schema_ledger ORDER BY id DESC LIMIT 1")" \
    'BLOCKED: UPDATE public.people SET email = $1'
  assert_eq "…and the chain still verifies" "$(su "SELECT count(*) FROM bb.verify_sealed()")" "0"
  gone "$C"
done

echo
echo "################ what a plan rests on, PostgreSQL 18 ################"
C=fox-f4-proto
start "$C" fox-f4-proto:18 || bad "the server starts"
sus >/dev/null <<SQL
CREATE TABLE customers (id bigint PRIMARY KEY, email text UNIQUE, phone text NOT NULL, city text NOT NULL DEFAULT 'unknown', name text);
CREATE TABLE orders (id bigint PRIMARY KEY, customer_id bigint REFERENCES customers ON DELETE RESTRICT, ship_phone text, amount numeric);
CREATE TABLE order_notes (id bigint PRIMARY KEY, order_id bigint REFERENCES orders ON DELETE CASCADE, body text);
CREATE TABLE tickets (id bigint PRIMARY KEY, customer_id bigint REFERENCES customers ON DELETE CASCADE, contact text);
CREATE TABLE signups (email text, at timestamptz DEFAULT now());
INSERT INTO customers VALUES (1, '$EMAIL', '$PHONE', 'Pune', 'Asha'), (2, '$OTHER', '9123400000', 'Delhi', 'Ravi');
INSERT INTO orders VALUES (10, 1, '$PHONE', 100), (11, 2, '9123400000', 50);
INSERT INTO order_notes VALUES (100, 10, 'leave at the door');
INSERT INTO tickets VALUES (200, 1, '$EMAIL');
INSERT INTO signups VALUES ('$EMAIL');
SQL
# The tables that refer to customers, at any depth, from the catalog alone.
FK_SQL="WITH RECURSIVE r(rel, depth, deltype) AS (
  SELECT conrelid, 1, confdeltype::text FROM pg_constraint WHERE contype = 'f' AND confrelid = 'customers'::regclass
  UNION SELECT c.conrelid, r.depth + 1, c.confdeltype::text FROM pg_constraint c JOIN r ON c.confrelid = r.rel WHERE c.contype = 'f' AND r.depth < 10)
  SELECT string_agg(rel::regclass || ':' || depth || ':' || deltype, ',' ORDER BY rel::regclass::text) FROM r"
assert_eq "the catalog gives every table referring to the person's, at each depth, with its ON DELETE" \
  "$(su "$FK_SQL")" "order_notes:2:c,orders:1:r,tickets:1:c"
assert_contains "a delete a RESTRICT key refuses is refused before anything else runs" \
  "$(su "BEGIN; DELETE FROM customers WHERE id = 1; ROLLBACK")" "foreign key constraint \"orders_customer_id_fkey\""
assert_contains "clearing a NOT NULL column without a default is refused" \
  "$(su "BEGIN; UPDATE customers SET phone = NULL WHERE id = 1; ROLLBACK")" "violates not-null constraint"
assert_eq "a NOT NULL column with a default clears to its default" \
  "$(su "BEGIN; UPDATE customers SET city = DEFAULT WHERE id = 1 RETURNING city; ROLLBACK" | grep -v '^$' | head -1)" "unknown"
assert_eq "the catalog says which columns are NOT NULL without a default" \
  "$(su "SELECT string_agg(attname, ',' ORDER BY attname) FROM pg_attribute WHERE attrelid = 'customers'::regclass AND attnum > 0 AND attnotnull AND NOT atthasdef AND NOT attisdropped")" "id,phone"
assert_eq "a table with neither a primary key nor a replica identity is known as one" \
  "$(su "SELECT relname FROM pg_class c WHERE relname IN ('customers','orders','order_notes','tickets','signups') AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND (i.indisprimary OR i.indisreplident)) ORDER BY 1")" "signups"
assert_eq "a unique column cleared on two rows: NULLs are distinct, both clear" \
  "$(su "BEGIN; UPDATE customers SET email = NULL; SELECT count(*) FROM customers WHERE email IS NULL; ROLLBACK" | grep -v '^$' | head -1)" "2"
assert_eq "CASCADE from the person's row reaches the rows the catalog listed, and no others" \
  "$(su "BEGIN; DELETE FROM orders WHERE customer_id = 1; DELETE FROM customers WHERE id = 1; SELECT (SELECT count(*) FROM tickets) || ',' || (SELECT count(*) FROM order_notes) || ',' || (SELECT count(*) FROM orders); ROLLBACK" | grep -v '^$' | head -1)" "0,0,1"
gone "$C"

echo
echo "################ a branch made before the erasure, PostgreSQL 18, on ZFS ################"
sudo truncate -s 2G "$WORK/pool.img"
if ! sudo zpool create -f -o ashift=12 -m "$WORK/pool" "$POOL" "$WORK/pool.img" 2>"$WORK/zpool.log"; then
  bad "a pool of the suite's own: $(cat "$WORK/zpool.log")"
else
  sudo zfs create "$POOL/main"; sudo chown 999:999 "$WORK/pool/main"
  PGD=(-e PGDATA=/var/lib/postgresql/data/pg)
  start fox-f4-proto-main fox-f4-proto:18 -v "$WORK/pool/main:/var/lib/postgresql/data" "${PGD[@]}" || bad "main starts on the pool"
  C=fox-f4-proto-main
  sus >/dev/null <<SQL
CREATE TABLE people (id bigint PRIMARY KEY, email text UNIQUE, phone text, note text);
INSERT INTO people SELECT g, 'person' || g || '@example.org', '98' || lpad(g::text, 8, '0'), 'n' FROM generate_series(1, 20000) g;
INSERT INTO people VALUES (900001, '$EMAIL', '$PHONE', 'x');
CREATE INDEX people_phone ON people (phone);
ANALYZE; CHECKPOINT;
SQL
  # As the engine makes a branch: a checkpoint, a snapshot of the parent, a clone.
  sudo zfs snapshot "$POOL/main@for-branch"
  sudo zfs clone "$POOL/main@for-branch" "$POOL/branch"
  start fox-f4-proto-branch fox-f4-proto:18 -v "$WORK/pool/branch:/var/lib/postgresql/data" "${PGD[@]}" || bad "the branch starts on the clone"
  left() { sudo grep -rlaE "$VALUES_RE" "$WORK/pool/$1" 2>/dev/null | wc -l | tr -d ' '; }
  # The plan's steps on one branch: clear the person's columns, vacuum, rewrite,
  # statistics recomputed and their old rows rewritten too, the old WAL gone.
  erase() {
    local c="$1"
    sudo docker exec -i "$c" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL
UPDATE people SET email = NULL, phone = NULL WHERE id = 900001;
SQL
    sudo docker exec "$c" psql -X -q -U dbadmin -d appdb -c "VACUUM (INDEX_CLEANUP ON) people" >/dev/null 2>&1
    echo "$(sudo grep -rlaE "$VALUES_RE" "$WORK/pool/$2/pg/base" 2>/dev/null | wc -l | tr -d ' ')"
    for s in "VACUUM FULL people" "ANALYZE people" "VACUUM FULL pg_statistic" "CHECKPOINT" "ALTER SYSTEM SET wal_recycle = off" "SELECT pg_reload_conf()"; do
      sudo docker exec "$c" psql -X -q -U dbadmin -d appdb -c "$s" >/dev/null 2>&1
    done
    for _ in 1 2 3; do sudo docker exec "$c" psql -X -q -U dbadmin -d appdb -c "SELECT pg_switch_wal()" -c CHECKPOINT >/dev/null 2>&1; done
    sudo docker exec "$c" psql -X -q -U dbadmin -d appdb -c "ALTER SYSTEM RESET wal_recycle" -c "SELECT pg_reload_conf()" >/dev/null 2>&1
  }
  assert_ne "before: main's files hold the person" "$(left main/pg/base)" "0"
  AFTER_VACUUM="$(erase fox-f4-proto-main main)"
  note "main: files under base/ holding a value after the UPDATE and VACUUM (INDEX_CLEANUP ON): $AFTER_VACUUM"
  assert_eq "a live query on main finds nothing" "$(su "SELECT count(*) FROM people WHERE email = '$EMAIL' OR phone = '$PHONE'")" "0"
  assert_eq "after the rewrite, main's whole data directory holds no value, WAL included" "$(left main/pg)" "0"
  assert_ne "the branch, untouched yet, still holds the person" "$(left branch/pg/base)" "0"
  C=fox-f4-proto-branch
  erase fox-f4-proto-branch branch >/dev/null
  assert_eq "the branch erased the same way: its own data directory holds no value" "$(left branch/pg)" "0"
  SNAP_LEFT="$(sudo grep -rlaE "$VALUES_RE" "$WORK/pool/main/.zfs/snapshot/for-branch/pg/base" 2>/dev/null | wc -l | tr -d ' ')"
  assert_ne "but main's snapshot the branch was made from still holds the person" "$SNAP_LEFT" "0"
  assert_contains "…and cannot be destroyed while the branch exists" "$(sudo zfs destroy "$POOL/main@for-branch" 2>&1)" "dependent clones"
  sudo zpool sync "$POOL"
  note "space main's snapshot keeps alive while the branch exists: $(sudo zfs get -Hpo value usedbysnapshots "$POOL/main") bytes"
  # The branch remade: deleted with its snapshot, then made again from the erased parent.
  gone fox-f4-proto-branch
  sudo zfs destroy "$POOL/branch" && sudo zfs destroy "$POOL/main@for-branch"
  sudo docker exec fox-f4-proto-main psql -X -q -U dbadmin -d appdb -c CHECKPOINT >/dev/null 2>&1
  sudo zfs snapshot "$POOL/main@for-branch"
  sudo zfs clone "$POOL/main@for-branch" "$POOL/branch"
  start fox-f4-proto-branch fox-f4-proto:18 -v "$WORK/pool/branch:/var/lib/postgresql/data" "${PGD[@]}" || bad "the remade branch starts"
  assert_eq "the remade branch, its snapshot included, holds no value" \
    "$(left branch/pg)|$(sudo grep -rlaE "$VALUES_RE" "$WORK/pool/main/.zfs/snapshot/for-branch" 2>/dev/null | wc -l | tr -d ' ')" "0|0"
  assert_eq "…and has every other row" "$(sudo docker exec fox-f4-proto-branch psql -X -tA -U dbadmin -d appdb -c 'SELECT count(*) FROM people WHERE email IS NOT NULL')" "20000"
  gone fox-f4-proto-branch; gone fox-f4-proto-main
fi

echo
echo "################ a restore to before the erasure, PostgreSQL 18 ################"
sudo mkdir -p "$WORK/archive" "$WORK/backup" "$WORK/srcdata" "$WORK/restore"
sudo chown 999:999 "$WORK/archive" "$WORK/backup" "$WORK/srcdata" "$WORK/restore"
C=fox-f4-proto-src
start "$C" fox-f4-proto:18 -v "$WORK/srcdata:/var/lib/postgresql/data" -e PGDATA=/var/lib/postgresql/data/pg -v "$WORK/archive:/archive" -v "$WORK/backup:/backup" \
  -- -c archive_mode=on -c "archive_command=cp %p /archive/%f" -c wal_level=replica || bad "the source server starts, archiving"
sus >/dev/null <<SQL
CREATE TABLE people (id bigint PRIMARY KEY, email text, phone text, note text);
INSERT INTO people SELECT g, 'person' || g || '@example.org', '98' || lpad(g::text, 8, '0'), 'n' FROM generate_series(1, 2000) g;
SQL
sudo docker exec -u postgres "$C" pg_basebackup -U dbadmin -D /backup/base -X stream >/dev/null 2>&1 || bad "a base backup is taken"
su "INSERT INTO people VALUES (900001, '$EMAIL', '$PHONE', 'x'), (900002, '$OTHER', '9123400000', 'y')" >/dev/null
sleep 2
BEFORE_ERASURE="$(su "SELECT now()")"
sleep 2
# The erasure, and what the request keeps instead of the values: each row's key.
KEYS="$(su "SELECT string_agg(id::text, ',') FROM people WHERE email = '$EMAIL'")"
su "UPDATE people SET email = NULL, phone = NULL WHERE id IN ($KEYS)" >/dev/null
su "SELECT pg_switch_wal()" >/dev/null; sleep 2
assert_eq "the request kept the row's key, not its values" "$KEYS" "900001"
gone "$C"
# The restore: the base backup, recovered to just before the erasure, reachable
# only through its socket in the container while the erasure is applied again.
sudo cp -a "$WORK/backup/base" "$WORK/restore/pg"
sudo sh -c "touch '$WORK/restore/pg/recovery.signal'; printf \"restore_command = 'cp /archive/%%f %%p'\nrecovery_target_time = '%s'\nrecovery_target_action = 'promote'\n\" '$BEFORE_ERASURE' >> '$WORK/restore/pg/postgresql.auto.conf'"
sudo chown -R 999:999 "$WORK/restore/pg"
C=fox-f4-proto-restore
start "$C" fox-f4-proto:18 -v "$WORK/restore:/var/lib/postgresql/data" -e PGDATA=/var/lib/postgresql/data/pg -v "$WORK/archive:/archive" \
  -- -c "listen_addresses=" || bad "the restored copy starts, with no address to listen on"
for _ in $(seq 60); do [ "$(su "SELECT pg_is_in_recovery()")" = "f" ] && break; sleep 1; done
assert_eq "the restore brought the person back" "$(su "SELECT count(*) FROM people WHERE email = '$EMAIL'")" "1"
assert_contains "while it is erased again, nothing reaches it over the network" \
  "$(sudo docker exec -e PGPASSWORD=f4proto "$C" psql -X -h 127.0.0.1 -U dbadmin -d appdb -c 'SELECT 1' 2>&1)" "Connection refused"
su "UPDATE people SET email = NULL, phone = NULL WHERE id IN ($KEYS)" >/dev/null
for s in "VACUUM FULL people" "CHECKPOINT"; do su "$s" >/dev/null; done
gone "$C"
start "$C" fox-f4-proto:18 -v "$WORK/restore:/var/lib/postgresql/data" -e PGDATA=/var/lib/postgresql/data/pg || bad "the copy opens, listening"
assert_eq "once open, it is reachable" "$(sudo docker exec -e PGPASSWORD=f4proto "$C" psql -X -tA -h 127.0.0.1 -U dbadmin -d appdb -c 'SELECT 1' 2>&1)" "1"
assert_eq "…and the person is not in it, applied again by the row key alone" "$(su "SELECT count(*) FROM people WHERE email = '$EMAIL' OR phone = '$PHONE'")" "0"
assert_eq "…while another person restored with it is still there" "$(su "SELECT count(*) FROM people WHERE email = '$OTHER'")" "1"
assert_eq "…and its table's files hold no value" "$(sudo grep -rlaE "$VALUES_RE" "$WORK/restore/pg/base" 2>/dev/null | wc -l | tr -d ' ')" "0"
note "the archive still holds the person's WAL: $(sudo grep -rlaE "$VALUES_RE" "$WORK/archive" 2>/dev/null | wc -l | tr -d ' ') file(s); it goes only when backups are pruned (design, section 11)"
gone "$C"

echo
echo "==== $PASS passed, $FAIL failed ===="
[ "$FAIL" = 0 ]
