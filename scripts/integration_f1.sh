#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The F1 prototype's suite: Gate 0's exit (docs/FOX_F1_Identity_Design.md,
# section 11). An application actor per transaction, asserted with an Ed25519
# token, checked by the fox_ed25519 extension, guarded by a MAC, and attributed
# on the Blackbox's DDL record.
#
# Self-contained, and touches no install: it builds the engine image WITH_F1=on
# under a tag of its own, runs a throwaway Postgres from it, installs the
# Blackbox and the prototype into that, and removes it at the end. The shared
# stack in the test VM is never stopped, started or written to.
#
# "Every path" (Gateway, console, API, MCP, agent keys) is Gate 1: it needs the
# product wired, which the prototype deliberately is not.
#
#   make integration-f1
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMG=fox-f1-proto:18
IMG16=fox-f1-proto:16
C=fox-f1-proto
WORK="$(mktemp -d)"
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }

cleanup() { sudo docker rm -f "$C" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

# su: a statement as the superuser. as: a script (stdin) as a role, over the
# container's socket, where the official image trusts local connections.
su() { sudo docker exec "$C" psql -X -q -tA -U dbadmin -d appdb -c "$1" 2>&1; }
as() { sudo docker exec -i "$C" psql -X -q -tA -U "$1" -d appdb 2>&1; }

# attr <table>: how the Blackbox's record of creating it was attributed.
attr() { su "SELECT app_state || '|' || coalesce(app_actor, '') || '|' || coalesce(note, '') FROM bb.f1_report WHERE object_identity = 'public.$1' ORDER BY id DESC LIMIT 1"; }

# one <role> <token> <table>: a transaction that asserts with the token, then
# makes a table; prints its attribution.
one() {
  as "$1" >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$2' \g
CREATE TABLE $3 (id int);
COMMIT;
SQL
  attr "$3"
}

digest() { sed -n '/PostgresBaseDigests/,/^}/p' "$REPO/internal/branch/images.go" | grep "\"$1\"" | sed 's/.*"\(sha256:[0-9a-f]*\)".*/\1/'; }

echo "### building the engine image with the extension (WITH_F1=on), under its own tag"
build_ok=1
for m in 18 16; do
  tag="fox-f1-proto:$m"
  if ! sudo docker build -q -t "$tag" --build-arg WITH_F1=on --build-arg PG_MAJOR="$m" --build-arg PG_DIGEST="$(digest $m)" \
       "$REPO/docker/postgres" >/dev/null 2>"$WORK/build-$m.log"; then
    build_ok=0; tail -20 "$WORK/build-$m.log"
  fi
done
assert_eq "the image builds with the extension for Postgres 18 and 16" "$build_ok" "1"
assert_eq "…and without it, by default, the image has no extension" \
  "$(sudo docker run --rm "$(sudo docker build -q --build-arg PG_DIGEST="$(digest 18)" "$REPO/docker/postgres" 2>/dev/null)" \
     sh -c 'ls /usr/lib/postgresql/18/lib/fox_ed25519.so 2>/dev/null | wc -l')" "0"

echo "### a throwaway Postgres, with the Blackbox and the prototype"
sudo docker rm -f "$C" >/dev/null 2>&1
sudo docker run -d --name "$C" -e POSTGRES_USER=dbadmin -e POSTGRES_PASSWORD=f1proto -e POSTGRES_DB=appdb "$IMG" >/dev/null
for _ in $(seq 60); do [ "$(su 'SELECT 1')" = "1" ] && break; sleep 1; done
# The Blackbox as the engine installs it (EnsureLedgerV2's order): the base,
# then the richer capture, provenance, the data guardrails, and row tracking,
# which needs the guardrails' override function. Then the prototype.
installed=1
: >"$WORK/install.log"
for f in internal/ledger/ledger.sql internal/ledger/ledger_ext.sql internal/ledger/provenance.sql \
         internal/ledger/datachanges.sql internal/ledger/tracking.sql scripts/f1/f1_proto.sql; do
  sudo docker exec -i "$C" psql -X -q -U dbadmin -d appdb -v ON_ERROR_STOP=1 < "$REPO/$f" >/dev/null 2>>"$WORK/install.log" || { installed=0; echo "  (installing $f failed)"; }
done
assert_eq "the Blackbox and the prototype install" "$installed" "1"
[ -s "$WORK/install.log" ] && grep -v '^NOTICE' "$WORK/install.log" | head -5

( cd "$REPO" && go build -o "$WORK/mint" ./scripts/f1/mint ) || { echo "could not build the mint tool"; exit 1; }
mint() { "$WORK/mint" "$@"; }
K1="$(mint keygen "$WORK" k1)"; K2="$(mint keygen "$WORK" k2)"; mint keygen "$WORK" evil >/dev/null
KS="$(mint keygen "$WORK" ks)"
tok() { local key="$1"; shift; mint token "$WORK/$key.seed" "$@"; }
su "INSERT INTO bb_f1.install VALUES (1, 'fox-test', 'main');
    CREATE ROLE shop_app LOGIN IN ROLE db_client; CREATE ROLE other_app LOGIN IN ROLE db_client;
    CREATE ROLE strict_app LOGIN IN ROLE db_client;
    INSERT INTO bb.app_issuers (issuer, kid, db_role, public_key) VALUES
      ('shop', 'k1', 'shop_app', decode('$K1', 'hex')), ('shop', 'k2', 'shop_app', decode('$K2', 'hex'));
    INSERT INTO bb.app_issuers (issuer, kid, db_role, public_key, on_invalid) VALUES
      ('strict', 'ks', 'strict_app', decode('$KS', 'hex'), 'refuse');" >/dev/null

echo "### the extension"
assert_eq "it verifies RFC 8032's test vectors, and refuses them altered" \
  "$(su "SELECT bb_f1.fox_ed25519_verify(decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','hex'), ''::bytea,
           decode('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b','hex'))
         || '|' || bb_f1.fox_ed25519_verify(decode('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c','hex'), decode('72','hex'),
           decode('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00','hex'))
         || '|' || bb_f1.fox_ed25519_verify(decode('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c','hex'), decode('73','hex'),
           decode('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00','hex'))")" \
  "true|true|false"
assert_eq "…and 20,000 random inputs of every length are refused without crashing a backend" \
  "$(su "SELECT count(*) FILTER (WHERE bb_f1.fox_ed25519_verify(bb_f1.fox_random_bytes((g % 40) + 12), bb_f1.fox_random_bytes((g % 300) + 1), bb_f1.fox_random_bytes((g % 70) + 1))) FROM generate_series(1, 20000) g")|$(su "SELECT bb_f1.fox_ed25519_verify(''::bytea, ''::bytea, ''::bytea)")|$(su 'SELECT 1')" \
  "0|f|1"
assert_eq "its private functions are not a client's to call" \
  "$(echo "SELECT bb_f1.fox_app_mac('a','shop','k1','');" | as shop_app | grep -c 'permission denied for schema bb_f1')" "1"
# Its own link to OpenSSL, not one borrowed from the postgres binary: built
# with PGXS's MODULES, SHLIB_LINK was ignored and the library had none.
assert_eq "the library links libcrypto itself, on 18 and 16" \
  "$(sudo docker run --rm "$IMG" sh -c 'ldd /usr/lib/postgresql/18/lib/fox_ed25519.so | grep -c libcrypto')|$(sudo docker run --rm "$IMG16" sh -c 'ldd /usr/lib/postgresql/16/lib/fox_ed25519.so | grep -c libcrypto')" "1|1"
assert_eq "the Postgres 16 build verifies too" \
  "$(sudo docker run --rm "$IMG16" sh -c 'ls /usr/lib/postgresql/16/lib/fox_ed25519.so >/dev/null && echo built')" "built"

echo "### signatures"
assert_eq "a valid token asserts the user" "$(one shop_app "$(tok k1)" s_valid)" "asserted by shop|alice|"
assert_eq "one bit of the signature changed is refused" "$(one shop_app "$(tok k1 -flip)" s_flip)" "none||token refused: bad signature"
assert_eq "signed by another key under the same kid is refused" "$(one shop_app "$(tok evil)" s_evil)" "none||token refused: bad signature"
assert_eq "an unknown key id is refused" "$(one shop_app "$(tok k1 -kid k9)" s_kid)" "none||token refused: unknown key"
n=0
for h in '{"alg":"HS256","typ":"JWT","kid":"k1"}' '{"alg":"none","typ":"JWT","kid":"k1"}' '{"alg":"RS256","typ":"JWT","kid":"k1"}' '{"alg":"EdDSA","kid":"k1","jku":"https://x"}' '{"alg":"EdDSA","typ":"JWT"}'; do
  n=$((n + 1))
  assert_eq "a header other than EdDSA with a kid and nothing else is refused: $h" "$(one shop_app "$(tok k1 -header "$h")" "s_hdr$n")" "none||token refused: header"
done
assert_eq "malformed tokens are refused: not three parts, not base64url, too long" \
  "$(one shop_app "abc" s_m1)/$(one shop_app "a.b!.c" s_m2)/$(one shop_app "$(head -c 9000 /dev/zero | tr '\0' a)" s_m3)" \
  "none||token refused: malformed/none||token refused: malformed/none||token refused: malformed"
assert_eq "an empty signature is a bad signature" "$(one shop_app "$(tok k1 -nosig)" s_nosig)" "none||token refused: bad signature"

echo "### binding to the application's own database role"
T="$(tok k1)"
assert_eq "the same token from another application's role is refused" "$(one other_app "$T" b_other)" "none||token refused: wrong session role"
assert_eq "…and from the superuser" "$(one dbadmin "$T" b_super)" "none||token refused: wrong session role"
assert_eq "…while the application's own role may use it more than once, within its life" "$(one shop_app "$T" b_again)" "asserted by shop|alice|"

echo "### claims"
assert_eq "expired" "$(one shop_app "$(tok k1 -iat -600 -exp -120)" c_expired)" "none||token refused: expired"
assert_eq "not yet valid" "$(one shop_app "$(tok k1 -iat 120 -exp 300)" c_future)" "none||token refused: not yet valid"
assert_eq "30 seconds of clock skew either way is allowed" \
  "$(one shop_app "$(tok k1 -iat 25 -exp 280)" c_skew1)/$(one shop_app "$(tok k1 -iat -250 -exp -25)" c_skew2)" \
  "asserted by shop|alice|/asserted by shop|alice|"
assert_eq "a life over the application's limit is refused" "$(one shop_app "$(tok k1 -exp 600)" c_life)" "none||token refused: life too long"
assert_eq "another install's audience is refused" "$(one shop_app "$(tok k1 -aud elsewhere)" c_aud)" "none||token refused: wrong audience"
assert_eq "a branch claim must be this branch" \
  "$(one shop_app "$(tok k1 -branch main)" c_br1)/$(one shop_app "$(tok k1 -branch qa)" c_br2)" \
  "asserted by shop|alice|/none||token refused: wrong branch"
assert_eq "a tenant is recorded beside the user" \
  "$(one shop_app "$(tok k1 -tenant acme)" c_tenant >/dev/null; su "SELECT app_tenant FROM bb.f1_report WHERE object_identity = 'public.c_tenant'")" "acme"

echo "### one application actor per transaction"
assert_contains "a second assertion in a transaction is refused" \
  "$(as shop_app <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
SELECT bb.act_for(\$1) \bind '$(tok k1 -sub bob)' \g
ROLLBACK;
SQL
)" "already acts for alice"
as shop_app >/dev/null <<SQL
BEGIN; SELECT set_config('fox.app.actor', 'mallory', true); CREATE TABLE p_handset (id int); COMMIT;
SQL
assert_eq "an actor set by hand is not an actor" "$(attr p_handset)" "none||an application actor was present and failed its check"
as shop_app >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
SELECT current_setting('fox.app.actor') AS a, current_setting('fox.app.issuer') AS i, current_setting('fox.app.kid') AS k, current_setting('fox.app.mac') AS m \gset
COMMIT;
BEGIN;
SELECT set_config('fox.app.actor', :'a', true), set_config('fox.app.issuer', :'i', true), set_config('fox.app.kid', :'k', true), set_config('fox.app.mac', :'m', true);
CREATE TABLE p_copied (id int);
COMMIT;
SQL
assert_eq "a valid MAC copied from another transaction fails" "$(attr p_copied)" "none||an application actor was present and failed its check"
as shop_app >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
SELECT set_config(n, current_setting(n), false) FROM unnest(ARRAY['fox.app.actor','fox.app.issuer','fox.app.kid','fox.app.tenant','fox.app.mac']) AS n;
COMMIT;
CREATE TABLE p_carried (id int);
SQL
assert_eq "values carried into the next transaction at session level fail" "$(attr p_carried)" "none||an application actor was present and failed its check"
as shop_app >/dev/null <<SQL
SET fox.claimed_actor = 'bob'; CREATE TABLE p_claimed (id int);
SQL
assert_eq "a client's own word is recorded as claimed, never asserted" "$(attr p_claimed)" "claimed|bob|"

echo "### savepoints"
as shop_app >/dev/null <<SQL
BEGIN;
SAVEPOINT s;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
CREATE TABLE sp_gone (id int);
ROLLBACK TO s;
CREATE TABLE sp_after (id int);
COMMIT;
SQL
assert_eq "an assertion rolled back with its savepoint takes its changes with it" \
  "$(su "SELECT count(*) FROM bb.schema_ledger WHERE object_identity = 'public.sp_gone'")|$(attr sp_after)" "0|none||"
as shop_app >/dev/null <<SQL
BEGIN;
SAVEPOINT s;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
CREATE TABLE sp_in (id int);
RELEASE s;
CREATE TABLE sp_out (id int);
COMMIT;
SQL
assert_eq "…and one released stays, for what follows it too" "$(attr sp_in)/$(attr sp_out)" "asserted by shop|alice|/asserted by shop|alice|"
as shop_app >/dev/null <<SQL
BEGIN;
SAVEPOINT a; SAVEPOINT b;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
RELEASE b; ROLLBACK TO a;
SELECT bb.act_for(\$1) \bind '$(tok k1 -sub bob)' \g
CREATE TABLE sp_nested (id int);
COMMIT;
SQL
assert_eq "nested: rolled back past the assertion, another may be made" "$(attr sp_nested)" "asserted by shop|bob|"
assert_eq "no surviving record carries an actor that was not in force when it was written" \
  "$(su "SELECT count(*) FROM bb.f1_report WHERE object_identity LIKE 'public.sp_%' AND app_state LIKE 'asserted%' AND object_identity NOT IN ('public.sp_in','public.sp_out','public.sp_nested')")" "0"

echo "### one connection, many users (a pool)"
as shop_app >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok k1 -sub alice)' \g
CREATE TABLE pool_1 (id int);
COMMIT;
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok k1 -sub bob)' \g
CREATE TABLE pool_2 (id int);
COMMIT;
BEGIN;
CREATE TABLE pool_3 (id int);
COMMIT;
SQL
assert_eq "each transaction is its own user's, and one that forgets to assert is nobody's" \
  "$(attr pool_1)/$(attr pool_2)/$(attr pool_3)" "asserted by shop|alice|/asserted by shop|bob|/none||"

assert_eq "bb.app_actor_label() decides as bb.app_actor() does: asserted, claimed, none, and a forgery" \
  "$(as shop_app <<SQL | tr '\n' '/'
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok k1)' \g
SELECT bb.app_actor_label();
COMMIT;
BEGIN; SET LOCAL fox.claimed_actor = 'bob'; SELECT bb.app_actor_label(); COMMIT;
BEGIN; SELECT '[' || bb.app_actor_label() || ']'; COMMIT;
BEGIN; SELECT set_config('fox.app.actor', 'mallory', true); SELECT '[' || bb.app_actor_label() || ']'; COMMIT;
SQL
)" "alice/asserted:shop:alice/claimed:bob/[]/mallory/[]/"

echo "### keys over their life"
assert_eq "during a rotation both keys are good" \
  "$(one shop_app "$(tok k1 -sub r1)" k_rot1)/$(one shop_app "$(tok k2 -kid k2 -sub r2)" k_rot2)" \
  "asserted by shop|r1|/asserted by shop|r2|"
T1="$(tok k1)"
su "UPDATE bb.app_issuers SET revoked_at = clock_timestamp() WHERE kid = 'k1'" >/dev/null
assert_eq "a revoked key is refused at once, and the other still works" \
  "$(one shop_app "$T1" k_rev1)/$(one shop_app "$(tok k2 -kid k2)" k_rev2)" \
  "none||token refused: revoked key/asserted by shop|alice|"
su "UPDATE bb.app_issuers SET revoked_at = clock_timestamp(), compromised_since = (SELECT at FROM bb.schema_ledger WHERE object_identity = 'public.k_rot2') WHERE kid = 'k2'" >/dev/null
assert_eq "a key reported compromised marks what was asserted under it since, never plain asserted" \
  "$(attr k_rot2)/$(attr k_rot1)" "asserted by shop (key reported compromised)|r2|/asserted by shop|r1|"
assert_contains "an application that chose refuse has a bad token stop the transaction" \
  "$(as strict_app <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$(tok ks -kid ks -iss strict -flip)' \g
CREATE TABLE strict_t (id int);
COMMIT;
SQL
)" "application identity refused: bad signature"
assert_eq "…so nothing it did is recorded" "$(su "SELECT count(*) FROM bb.schema_ledger WHERE object_identity = 'public.strict_t'")" "0"

echo "### the token stays out of the logs"
TL="$(tok ks -kid ks -iss strict)"
CQ="$(as strict_app <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$TL' \g
SELECT current_query();
CREATE TABLE log_t (id int);
COMMIT;
SQL
)"
SIGPART="${TL##*.}"
assert_eq "not in current_query(), so not in the Blackbox's statement text" \
  "$(grep -c -- "$SIGPART" <<<"$CQ")|$(su "SELECT count(*) FROM bb.schema_ledger WHERE statement LIKE '%' || '${SIGPART:0:40}' || '%'")" "0|0"
assert_eq "not in the server log, though a refused token's error is" \
  "$(sudo docker logs "$C" 2>&1 | grep -c -- "${SIGPART:0:40}")|$(sudo docker logs "$C" 2>&1 | grep -c 'application identity refused' | awk '{print ($1>=1)}')" "0|1"

echo "### what it costs"
su "UPDATE bb.app_issuers SET revoked_at = NULL, compromised_since = NULL" >/dev/null
T="$(tok k2 -kid k2 -sub bench)"
printf 'BEGIN;\nSELECT 1;\nCOMMIT;\n' > "$WORK/base.sql"
printf "BEGIN;\nSELECT bb.act_for('%s');\nCOMMIT;\n" "$T" > "$WORK/act.sql"
sudo docker cp "$WORK/base.sql" "$C:/tmp/base.sql" && sudo docker cp "$WORK/act.sql" "$C:/tmp/act.sql"
lat() { sudo docker exec "$C" pgbench -n -U shop_app -d appdb -T 8 -f "$1" 2>/dev/null | sed -n 's/^latency average = \([0-9.]*\) ms/\1/p'; }
B="$(lat /tmp/base.sql)"; A="$(lat /tmp/act.sql)"
echo "  (a transaction: ${B} ms; with an assertion: ${A} ms)"
assert_eq "an assertion costs under 0.5 ms a transaction" "$(awk -v a="$A" -v b="$B" 'BEGIN{print (a != "" && b != "" && a - b < 0.5)}')" "1"
PER="$(as shop_app <<SQL | sed -n 's/^PER \([0-9.]*\)$/\1/p'
BEGIN;
SELECT bb.act_for(\$1) \bind '$T' \g
CREATE TEMP TABLE t0 AS SELECT clock_timestamp() AS t;
-- In the WHERE clause, against g: a function in FROM with nothing of g in it
-- is called once for the whole query, which measured nothing (0.8 µs).
SELECT count(*) FROM generate_series(1, 10000) g WHERE g > 0 AND (bb.app_actor()).state = 'asserted';
SELECT 'PER ' || round((extract(epoch FROM clock_timestamp() - t) * 1000000 / 10000)::numeric, 1) FROM t0;
COMMIT;
SQL
)"
echo "  (bb.app_actor(), what each recorded row pays: ${PER} µs a call)"
assert_eq "checking the actor costs under 5 µs a call, the check remembered across rows" "$(awk -v p="$PER" 'BEGIN{print (p != "" && p < 5)}')" "1"

# The bound the cache exists for (design, sections 11 and 13): a 10,000-row
# UPDATE on a table with FoxByte's row-tracking trigger, against the same
# trigger asking for the application actor on every row, as 5.2's
# last_modified_for will (bb.app_actor_label(), the string that column
# holds). The minimum of nine alternating runs each: noise on the VM only ever
# adds time, and medians moved several percent from run to run while the
# minimums held steady.
su "CREATE TABLE bench_a (id int PRIMARY KEY, v int, created_at timestamptz, updated_at timestamptz, last_modified_by text);
    CREATE TABLE bench_b (LIKE bench_a INCLUDING ALL);
    INSERT INTO bench_a (id, v) SELECT g, 0 FROM generate_series(1, 10000) g;
    INSERT INTO bench_b (id, v) SELECT g, 0 FROM generate_series(1, 10000) g;
    GRANT ALL ON bench_a, bench_b TO shop_app;
    DO \$\$ DECLARE src text; BEGIN
      SELECT prosrc INTO src FROM pg_proc WHERE oid = 'bb.track_row()'::regprocedure;
      EXECUTE format('CREATE FUNCTION public.bench_track_with_actor() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS %L',
                     regexp_replace(src, 'BEGIN', 'BEGIN IF bb.app_actor_label() <> ''asserted:shop:bench'' THEN RAISE EXCEPTION ''not asserted''; END IF;'));
    END \$\$;
    CREATE TRIGGER bench_a_track BEFORE INSERT OR UPDATE ON bench_a FOR EACH ROW EXECUTE FUNCTION bb.track_row('created_at', 'updated_at', 'last_modified_by');
    CREATE TRIGGER bench_b_track BEFORE INSERT OR UPDATE ON bench_b FOR EACH ROW EXECUTE FUNCTION public.bench_track_with_actor('created_at', 'updated_at', 'last_modified_by');" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9; do
  for t in bench_a bench_b; do
    cat <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$T' \g
SELECT clock_timestamp() AS t0 \gset
UPDATE $t SET v = v + 1;
SELECT '$t', extract(epoch FROM clock_timestamp() - :'t0'::timestamptz) * 1000;
COMMIT;
SQL
  done
done > "$WORK/bench.sql"
sudo docker cp "$WORK/bench.sql" "$C:/tmp/bench.sql"
BENCH="$(sudo docker exec "$C" psql -X -q -tA -F ' ' -U shop_app -d appdb -f /tmp/bench.sql 2>&1)"
fastest() { grep "^$1 " <<<"$BENCH" | awk '{print $2}' | sort -n | head -1; }
MA="$(fastest bench_a)"; MB="$(fastest bench_b)"
echo "  (10,000 tracked rows updated: ${MA} ms; asking for the application actor on each row too: ${MB} ms)"
assert_eq "asking for the actor on every row of a 10,000-row tracked update costs under 5%" \
  "$(awk -v a="$MA" -v b="$MB" 'BEGIN{print (a != "" && b != "" && b <= a * 1.05)}')" "1"
# The benchmark's trigger raises on any row not asserted, so nine updates of
# every row is nine checks of every row that all passed.
assert_eq "…and every row of every run was checked and asserted" \
  "$(su "SELECT count(*) FROM bench_b WHERE v = 9")" "10000"

echo
echo "==== ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ]
