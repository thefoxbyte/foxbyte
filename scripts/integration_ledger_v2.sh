#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Blackbox 2.0 integration checks. Run inside the Linux dev VM (ZFS + Docker):
#   make integration-v2
# Section 0 pins behaviour that must NOT change while 2.0 is built alongside it;
# later sections test each phase. Complements scripts/integration_test.sh, which
# must keep passing too. Exits non-zero if any assertion fails.
set -uo pipefail

# Refuses to run anywhere but the throwaway test VM (see scripts/lib/test_guard.sh).
# A guard that can't be found must stop the suite, not let it carry on.
. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
# Names in one place (generated from brand.json by `make brand`).
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

S="${FOX_BIN:-/tmp/fox}"
GATEWAY="postgresql://dbadmin@127.0.0.1:6432"
API="https://localhost:8080"
AGENTS="https://localhost:8088"
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
# pg <container> <sql>  -> tuples-only result, as the superuser over the local socket
pg() { local c="$1"; shift; sudo docker exec "$c" psql -U dbadmin -d appdb -tAc "$*" 2>/dev/null; }
# gw <key> <branch> <sql>  -> psql through the gateway, stderr included
gw() { PGPASSWORD="$1" psql "$GATEWAY/$2" -tAc "$3" 2>&1; }
# main_ready: wait until main really is serving. Deliberately over TCP
# (-h localhost), not the Unix socket: on a container's first start the Postgres
# entrypoint runs initdb against a temporary server that listens on the socket
# only, so a socket probe reports ready while the real cluster does not exist
# yet -- the same trap internal/branch.waitReady documents.
main_ready() {
  local i
  for i in $(seq 1 60); do
    [ "$(sudo docker exec -e PGPASSWORD=foxbyte pg-main psql -h localhost -U dbadmin -d appdb -tAc 'SELECT 1' 2>/dev/null)" = "1" ] && return 0
    sleep 1
  done
  echo "  (main did not become ready)" >&2
  return 1
}

# count_main <sql>: a count from main, waiting for a numeric answer. A restart
# can leave the first query unanswered, and an empty string compared with -gt
# is a shell error, not a failed assertion.
count_main() {
  local i n
  for i in $(seq 1 30); do
    n="$(pg pg-main "$1")"
    case "$n" in '' | *[!0-9]*) sleep 2 ;; *) echo "$n"; return 0 ;; esac
  done
  echo ""
  return 1
}

jget() { python3 -c 'import sys,json; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
jcols() { python3 -c 'import sys,json; print(",".join(json.load(sys.stdin)["columns"]))'; }
# mcp_call <tool> <json-args> [env...]  -> the tool's text result
# The MCP server acts as an API key's account (K6), so every call carries one;
# pass FOX_API_KEY=... in the env arguments to use a different key.
mcp_call() {
  local tool="$1" args="$2"; shift 2
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}" \
    | env FOX_API_KEY="$KEY" "$@" "$S" mcp 2>/dev/null \
    | python3 -c 'import sys,json
for line in sys.stdin:
    m=json.loads(line)
    if m.get("id")==2: print(m["result"]["content"][0]["text"])'
}

echo "### setup"
$S stop >/dev/null 2>&1; sleep 1
$S start >/dev/null 2>&1; sleep 5; main_ready
USER_EMAIL="v2test@foxbyte.dev"
printf 'password123\n' | $S user create "$USER_EMAIL" >/dev/null 2>&1 || true
KEY="$($S apikey create "$USER_EMAIL" v2 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
AUTH="Authorization: Bearer $KEY"
$S admin revoke "$USER_EMAIL" >/dev/null 2>&1 || true   # start from a non-admin user
assert_eq "test API key minted" "$([ -n "$KEY" ] && echo yes)" "yes"

echo "### 0. behaviour unchanged (characterization)"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2keep" >/dev/null
gw "$KEY" main "CREATE TABLE v2keep(x int)" >/dev/null
# The message deliberately carries no product name (it is raised by the
# database and matched by the console, and the product has been renamed twice).
assert_eq "guardrail error text is unchanged apart from the brand" \
  "$(gw "$KEY" main "DROP TABLE v2keep" | grep -c 'guardrail: DROP TABLE is blocked by policy (set bb.allow_destructive=on to override)')" "1"
assert_eq "REST ledger columns are unchanged" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/ledger?limit=1" | jcols)" \
  "at,actor,actor_kind,tool,branch,command_tag,object_identity,statement,status,risk"
assert_eq "REST verify columns are unchanged" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/ledger/verify" | jcols)" \
  "legacy,chained,broken,first_broken"
# The row_hash formula must never change: recompute a fixed row in SQL and in Python.
SQLHASH="$(pg pg-main "SELECT bb._ledger_hash(ROW(42,'2026-01-02 03:04:05+00','priya','human','psql','s1','main','CREATE TABLE','table','public.t','CREATE TABLE t()','APPLIED',NULL,'abc',NULL)::bb.schema_ledger)")"
PYHASH="$(python3 -c 'import hashlib;print(hashlib.sha256("abc|42|2026-01-02 03:04:05|priya|human|psql|s1|main|CREATE TABLE|table|public.t|CREATE TABLE t()|APPLIED|".encode()).hexdigest())')"
assert_eq "row_hash formula is unchanged" "$SQLHASH" "$PYHASH"
assert_eq "CLI ledger verify still reports intact" "$($S ledger verify 2>&1 | grep -c 'ledger intact')" "1"

echo "### 1a. H1: point-in-time restore uses the generated MinIO credentials"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2pit; CREATE TABLE v2pit(id int); INSERT INTO v2pit SELECT generate_series(1,3);" >/dev/null
$S backup create >/dev/null 2>&1
pg pg-main "SELECT pg_switch_wal();" >/dev/null; sleep 3
RESTORE_OUT="$($S restore --to latest 2>&1)"
assert_eq "PITR restores 3 rows" "$(pg pg-restore 'SELECT count(*) FROM v2pit')" "3"
assert_eq "restore no longer prints a hardcoded password" "$(echo "$RESTORE_OUT" | grep -c 'PGPASSWORD=foxbyte')" "0"
assert_eq "restore container has no minioadmin credentials" \
  "$(sudo docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' pg-restore 2>/dev/null | grep -c '=minioadmin$')" "0"
sudo docker rm -f pg-restore >/dev/null 2>&1

echo "### 1b. H2: only superusers and db_admin members may override the guardrail"
assert_eq "ledger upgrade succeeds on main" "$($S ledger upgrade main >/dev/null 2>&1; echo $?)" "0"
assert_eq "override check is installed" "$(pg pg-main "SELECT to_regprocedure('bb._may_override()') IS NOT NULL")" "t"
assert_eq "db_admin role exists" "$(pg pg-main "SELECT count(*) FROM pg_roles WHERE rolname='db_admin'")" "1"
gw "$KEY" main "CREATE TABLE IF NOT EXISTS v2guard(x int)" >/dev/null
assert_eq "non-admin override is refused" \
  "$(gw "$KEY" main "SET bb.allow_destructive=on; DROP TABLE v2guard" | grep -c 'blocked by policy')" "1"
assert_eq "refused override leaves the table in place" "$(pg pg-main "SELECT to_regclass('public.v2guard') IS NOT NULL")" "t"
assert_eq "refusal carries the db_admin hint" \
  "$(gw "$KEY" main "SET bb.allow_destructive=on; DROP TABLE v2guard" | grep -c 'db_admin')" "1"
$S admin grant "$USER_EMAIL" --branch main >/dev/null 2>&1
assert_eq "admin list shows the granted user" "$($S admin list --branch main 2>&1 | grep -c "$USER_EMAIL")" "1"
gw "$KEY" main "SET bb.allow_destructive=on; DROP TABLE v2guard" >/dev/null
assert_eq "admin override drops the table" "$(pg pg-main "SELECT to_regclass('public.v2guard') IS NULL")" "t"
$S admin revoke "$USER_EMAIL" --branch main >/dev/null 2>&1
gw "$KEY" main "CREATE TABLE IF NOT EXISTS v2guard(x int)" >/dev/null
assert_eq "revoked user is refused again" \
  "$(gw "$KEY" main "SET bb.allow_destructive=on; DROP TABLE v2guard" | grep -c 'blocked by policy')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2guard; DROP TABLE IF EXISTS v2keep; DROP TABLE IF EXISTS v2pit" >/dev/null
assert_eq "superuser override still works (imports/pipelines path)" "$(pg pg-main "SELECT to_regclass('public.v2keep') IS NULL")" "t"

echo "### 1c. H3: agents and MCP run without superuser"
curl -sk -H "$AUTH" -X DELETE "$AGENTS/agents/v2itest/branch" >/dev/null 2>&1
DSN="$(curl -sk -H "$AUTH" -X POST "$AGENTS/agents/v2itest/branch" | jget dsn)"
assert_eq "agent DSN logs in as the agent's own role" \
  "$(python3 -c 'import sys,urllib.parse;print(urllib.parse.urlparse(sys.argv[1]).username)' "$DSN")" "agent-v2itest"
assert_eq "agent role is not a superuser" "$(psql "$DSN" -tAc "SELECT rolsuper FROM pg_roles WHERE rolname=session_user" 2>/dev/null)" "f"
psql "$DSN" -c "CREATE TABLE a(x int); INSERT INTO a VALUES (7);" >/dev/null 2>&1
assert_eq "agent DB is usable via its DSN" "$(psql "$DSN" -tAc 'SELECT x FROM a' 2>/dev/null)" "7"
# K5: the DSN now goes through the gateway (so it works from the host too) and
# its password is a key scoped to this one branch.
AKEY="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.urlparse(sys.argv[1]).password or "")' "$DSN")"
assert_eq "agent DSN routes through the gateway" \
  "$(python3 -c 'import sys,urllib.parse;print(urllib.parse.urlparse(sys.argv[1]).port)' "$DSN")" "6432"
assert_eq "the agent's key cannot open another branch" \
  "$(PGPASSWORD="$AKEY" psql "postgresql://agent-v2itest@127.0.0.1:6432/main?sslmode=require" -tAc 'SELECT 1' 2>&1 | grep -c 'only opens branch')" "1"
assert_eq "the agent's key is refused by the control plane" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $AKEY" https://localhost:8080/api/branches)" "401"
assert_eq "the agent's key is refused by the agent API" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $AKEY" https://localhost:8088/agents)" "401"
assert_eq "agent change attributed to the agent" \
  "$(pg pg-agent-v2itest "SELECT actor||'/'||actor_kind FROM bb.schema_ledger WHERE command_tag='CREATE TABLE' AND object_identity='public.a'")" "agent-v2itest/agent"
assert_eq "agent cannot disable triggers (session_replication_role)" \
  "$(psql "$DSN" -tAc "SET session_replication_role=replica" 2>&1 | grep -c 'permission denied')" "1"
assert_eq "agent cannot override the guardrail" \
  "$(psql "$DSN" -tAc "SET bb.allow_destructive=on; DROP TABLE a" 2>&1 | grep -c 'blocked by policy')" "1"
assert_eq "MCP list_branches does not expose a password" \
  "$(mcp_call list_branches '{}' | grep -c 'postgresql://agent-v2itest@')" "1"
assert_eq "MCP run_sql runs as the client role" "$(mcp_call run_sql '{"sql":"SELECT session_user"}' | grep -c 'db_client')" "1"
assert_eq "MCP run_sql cannot disable triggers" \
  "$(mcp_call run_sql '{"sql":"SET session_replication_role=replica"}' | grep -c 'permission denied')" "1"
# Audit v2 G05: the switch is compiled out of release builds (this suite runs
# one), so setting it changes nothing.
assert_eq "FOX_MCP_SUPERUSER=1 is ignored by a release build" \
  "$(mcp_call run_sql '{"sql":"SELECT session_user"}' FOX_MCP_SUPERUSER=1 | grep -c 'db_client')" "1"
# K6: the MCP server acts as an API key's account, and refuses to run without one.
assert_eq "fox mcp without a key exits non-zero" \
  "$(printf '' | $S mcp >/dev/null 2>/tmp/mcpnokey.log; echo $?)" "1"
assert_eq "…and says how to make one" "$(grep -c 'fox apikey create' /tmp/mcpnokey.log)" "1"
assert_eq "…and names the environment variable a client config sets" "$(grep -c 'FOX_API_KEY' /tmp/mcpnokey.log)" "1"
assert_eq "fox mcp with an invalid key refuses to run" \
  "$(printf '' | FOX_API_KEY=key_notarealkey $S mcp >/dev/null 2>&1; echo $?)|$(printf '' | FOX_API_KEY=key_notarealkey $S mcp 2>&1 >/dev/null | grep -c 'not valid')" "1|1"
# On its own branch: §5b counts main's entries, and these checks would add to them.
$S branch create v2h3 >/dev/null 2>&1
# A branch made at the CLI is an admin's (audit v2 G02); this suite's user is
# not one, so the branches it works on are handed to it.
$S branch owner v2h3 "$USER_EMAIL" >/dev/null 2>&1
assert_eq "MCP run_sql records the key's account as the actor" \
  "$(mcp_call run_sql '{"branch":"v2h3","sql":"CREATE TABLE h3mcp(x int)"}' >/dev/null; pg pg-v2h3 "SELECT DISTINCT actor||'/'||actor_kind FROM bb.schema_ledger WHERE object_identity='public.h3mcp'")" "$USER_EMAIL/agent"
# A branch-scoped key (an agent's) reaches its own branch and nothing else.
# With no branch argument a tool would default to main; a scoped key's call
# must land in its own branch instead.
mcp_call run_sql '{"sql":"CREATE TABLE h3scoped(x int)"}' FOX_API_KEY="$AKEY" >/dev/null
assert_eq "a scoped key's MCP call lands in its own branch, not main" \
  "$(pg pg-agent-v2itest "SELECT to_regclass('public.h3scoped') IS NOT NULL")|$(pg pg-main "SELECT to_regclass('public.h3scoped') IS NULL")" "t|t"
assert_eq "…naming another branch is refused" \
  "$(mcp_call run_sql '{"branch":"main","sql":"SELECT 1"}' FOX_API_KEY="$AKEY" | grep -c 'limited to branch')" "1"
assert_eq "…and so are the tools that reach past one branch" \
  "$(mcp_call list_branches '{}' FOX_API_KEY="$AKEY" | grep -c 'limited to branch')|$(mcp_call create_branch '{"agent_id":"other"}' FOX_API_KEY="$AKEY" | grep -c 'limited to branch')" "1|1"

# H3: actor_kind follows the role, so a client cannot record itself as the other
# kind. bb.actor_kind is an ordinary session setting, and used to be believed.
PGPASSWORD="$KEY" psql "$GATEWAY/v2h3" -q -c "SET bb.actor_kind='agent'; CREATE TABLE h3human(x int);" >/dev/null 2>&1
assert_eq "a human claiming to be an agent is still recorded as human" \
  "$(pg pg-v2h3 "SELECT DISTINCT actor||'/'||actor_kind FROM bb.schema_ledger WHERE object_identity='public.h3human'")" "$USER_EMAIL/human"
psql "$DSN" -q -c "SET bb.actor_kind='human'; CREATE TABLE h3agent(x int);" >/dev/null 2>&1
assert_eq "an agent claiming to be human is still recorded as an agent" \
  "$(pg pg-agent-v2itest "SELECT DISTINCT actor||'/'||actor_kind FROM bb.schema_ledger WHERE object_identity='public.h3agent'")" "agent-v2itest/agent"
$S branch delete v2h3 >/dev/null 2>&1
curl -sk -H "$AUTH" -X DELETE "$AGENTS/agents/v2itest/branch" >/dev/null 2>&1

echo "### 2. ledger 2.0 capture (xid, LSN, provenance, override use)"
# pgerr keeps stderr, for assertions on error messages (pg discards it).
pgerr() { local c="$1"; shift; sudo docker exec "$c" psql -U dbadmin -d appdb -tAc "$*" 2>&1; }
assert_eq "ledger 2.0 is installed on main at start" "$(pg pg-main "SELECT bb.ledger_v2_version()")" "2.0-phase3"
assert_eq "ledger upgrade is idempotent (run twice)" \
  "$($S ledger upgrade main >/dev/null 2>&1 && $S ledger upgrade main >/dev/null 2>&1; echo $?)" "0"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2cap; DROP TABLE IF EXISTS v2off; DROP TABLE IF EXISTS v2safe" >/dev/null
PGOPTIONS='-c bb.task=task-42 -c bb.call_hash=abc123' PGPASSWORD="$KEY" psql "$GATEWAY/main" -qc "CREATE TABLE v2cap(x int)" >/dev/null 2>&1
CAPID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE command_tag='CREATE TABLE' AND object_identity='public.v2cap'")"
assert_eq "every new ledger row gets a capture row" "$(pg pg-main "SELECT count(*) FROM bb.ledger_ext WHERE ledger_id=$CAPID")" "1"
assert_eq "capture records the transaction and WAL position" \
  "$(pg pg-main "SELECT (xid IS NOT NULL AND lsn IS NOT NULL)::text FROM bb.ledger_ext WHERE ledger_id=$CAPID")" "true"
assert_eq "capture records task and call hash from the session" \
  "$(pg pg-main "SELECT task_id||'/'||call_hash FROM bb.ledger_ext WHERE ledger_id=$CAPID")" "task-42/abc123"
assert_eq "capture hash verifies" \
  "$(pg pg-main "SELECT (e.ext_hash = bb._ext_hash(e))::text FROM bb.ledger_ext e WHERE ledger_id=$CAPID")" "true"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE v2cap" >/dev/null
assert_eq "override use is recorded" \
  "$(pg pg-main "SELECT e.override_used::text FROM bb.ledger_ext e JOIN bb.schema_ledger s ON s.id=e.ledger_id WHERE s.command_tag='DROP TABLE' AND s.object_identity='public.v2cap' ORDER BY s.id DESC LIMIT 1")" "true"
# Fail-safe: a capture that errors must never block the user's DDL.
pg pg-main "ALTER TABLE bb.ledger_ext ADD CONSTRAINT v2_test_fail CHECK (false) NOT VALID" >/dev/null
SAFEMARK="$(pg pg-main "SELECT coalesce(max(id), 0) FROM bb.schema_ledger")"   # count only this run's rows
gw "$KEY" main "CREATE TABLE v2safe(x int)" >/dev/null
assert_eq "a failing capture does not block DDL" "$(pg pg-main "SELECT to_regclass('public.v2safe') IS NOT NULL")" "t"
assert_eq "the base ledger still records that DDL" \
  "$(pg pg-main "SELECT count(*) FROM bb.schema_ledger WHERE command_tag='CREATE TABLE' AND object_identity='public.v2safe' AND id > $SAFEMARK")" "1"
pg pg-main "ALTER TABLE bb.ledger_ext DROP CONSTRAINT v2_test_fail" >/dev/null
# Kill switch: bb.v2=off stops capture for new sessions.
pg pg-main "ALTER DATABASE $DB_DATABASE SET bb.v2 = 'off'" >/dev/null
gw "$KEY" main "CREATE TABLE v2off(x int)" >/dev/null
OFFID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity='public.v2off'")"
assert_eq "kill switch disables capture" "$(pg pg-main "SELECT count(*) FROM bb.ledger_ext WHERE ledger_id=$OFFID")" "0"
pg pg-main "ALTER DATABASE $DB_DATABASE RESET bb.v2" >/dev/null
# …but it isn't a client's to flip: a session SET is honoured only for a superuser.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2nocap; DROP TABLE IF EXISTS v2nocap_admin; DROP TABLE IF EXISTS v2nocap_su" >/dev/null
gw "$KEY" main "SET bb.v2 = 'off'; CREATE TABLE v2nocap(x int)" >/dev/null
NCID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity='public.v2nocap'")"
assert_eq "a client's own SET bb.v2 = 'off' does not skip capture" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_ext WHERE ledger_id=${NCID:-0}")" "1"
$S admin grant "$USER_EMAIL" --branch main >/dev/null 2>&1
gw "$KEY" main "SET bb.v2 = 'off'; CREATE TABLE v2nocap_admin(x int)" >/dev/null
NCID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity='public.v2nocap_admin'")"
assert_eq "…nor does a db_admin member's" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_ext WHERE ledger_id=${NCID:-0}")" "1"
$S admin revoke "$USER_EMAIL" --branch main >/dev/null 2>&1
pg pg-main "SET bb.v2 = 'off'; CREATE TABLE v2nocap_su(x int)" >/dev/null
NCID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity='public.v2nocap_su'")"
assert_eq "a superuser's session can still switch capture off" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_ext WHERE ledger_id=${NCID:-0}")" "0"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2nocap; DROP TABLE IF EXISTS v2nocap_admin; DROP TABLE IF EXISTS v2nocap_su" >/dev/null
assert_eq "capture table is append-only" \
  "$(pgerr pg-main "DELETE FROM bb.ledger_ext WHERE ledger_id=$CAPID" | grep -c 'append-only')" "1"
assert_eq "clients cannot write capture rows" \
  "$(gw "$KEY" main "INSERT INTO bb.ledger_ext(ledger_id) VALUES (-1)" | grep -c 'permission denied')" "1"
assert_eq "base hash chain still verifies after 2.0 activity" "$($S ledger verify 2>&1 | grep -c 'ledger intact')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2off; DROP TABLE IF EXISTS v2safe" >/dev/null

echo "### 3. checkpoints, anchors and the independent verifier"
VERIFY="${FOX_VERIFY_BIN:-/tmp/fox-verify}"
ANCH="${FOX_ANCHOR_DIR:-$HOME/.fox/anchors}"
assert_eq "checkpoints table is installed" "$(pg pg-main "SELECT to_regclass('bb.ledger_checkpoints') IS NOT NULL")" "t"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2cp" >/dev/null
gw "$KEY" main "CREATE TABLE v2cp(x int)" >/dev/null
CP_OUT="$($S ledger checkpoint main 2>&1)"
assert_eq "manual checkpoint anchors new ledger entries" "$(echo "$CP_OUT" | grep -c '^checkpoint #')" "1"
CP_FILE="$(echo "$CP_OUT" | awk '$1=="anchor"{print $2}')"
assert_eq "anchor file is read-only" "$(stat -c '%a' "$CP_FILE" 2>/dev/null)" "444"
assert_eq "anchor uses the published format" \
  "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["format"])' "$CP_FILE" 2>/dev/null)" "ledger-anchor/1"
assert_eq "a checkpoint with nothing new is a no-op" "$($S ledger checkpoint main 2>&1 | grep -c 'nothing new')" "1"
assert_eq "database refuses a checkpoint that doesn't continue the sequence" \
  "$(pgerr pg-main "INSERT INTO bb.ledger_checkpoints(from_id,to_id,entry_count,merkle_root,prev_root,algorithm) VALUES (1,1,1,'x','','t')" | grep -c 'must start at')" "1"
assert_eq "checkpoints are append-only" "$(pgerr pg-main "DELETE FROM bb.ledger_checkpoints" | grep -c 'append-only')" "1"

# fresh_branch <name>: a clean branch whose 3 newest ledger entries are anchored.
fresh_branch() {
  $S branch delete "$1" >/dev/null 2>&1; rm -rf "$ANCH/$1"
  $S branch create "$1" >/dev/null 2>&1
  $S branch owner "$1" "$USER_EMAIL" >/dev/null 2>&1
  $S ledger upgrade "$1" >/dev/null 2>&1
  for t in v2i_a v2i_b v2i_c; do pg "pg-$1" "CREATE TABLE $t(x int)" >/dev/null; done
  $S ledger checkpoint "$1" >/dev/null 2>&1
}
integrity_state() { $S ledger integrity "$1" 2>&1 | head -1 | grep -o 'INTACT\|TAMPERED'; }

fresh_branch v2int
V2DSN="postgresql://dbadmin:$KEY@127.0.0.1:6432/v2int"
assert_eq "integrity is INTACT on an untampered branch" "$(integrity_state v2int)" "INTACT"
assert_eq "REST integrity agrees" "$(curl -sk -H "$AUTH" "$API/api/branches/v2int/ledger/integrity" | jget intact)" "True"
assert_eq "MCP ledger_integrity agrees" "$(mcp_call ledger_integrity '{"branch":"v2int"}' | grep -c 'INTACT')" "1"
"$VERIFY" --dsn "$V2DSN" --anchors "$ANCH/v2int" >/dev/null 2>&1
assert_eq "fox-verify on the live database agrees (exit 0)" "$?" "0"
$S ledger export v2int > /tmp/v2int.jsonl 2>/dev/null
assert_eq "export has one line per ledger entry" "$(wc -l < /tmp/v2int.jsonl | tr -d ' ')" "$(pg pg-v2int "SELECT count(*) FROM bb.schema_ledger")"
"$VERIFY" --export /tmp/v2int.jsonl --anchors "$ANCH/v2int" >/dev/null 2>&1
assert_eq "fox-verify on the exported file agrees (exit 0)" "$?" "0"

# Forged edit: change an anchored entry, then rewrite the whole hash chain so the
# in-database check passes again. Only the anchors can catch this.
FORGE="SET session_replication_role = replica;
UPDATE bb.schema_ledger SET statement = statement || ' -- forged' WHERE id = (SELECT max(id) FROM bb.schema_ledger);
DO \$\$ DECLARE r record; prev text := ''; BEGIN
  FOR r IN SELECT id FROM bb.schema_ledger WHERE row_hash IS NOT NULL ORDER BY id LOOP
    UPDATE bb.schema_ledger SET prev_hash = prev WHERE id = r.id;
    UPDATE bb.schema_ledger s SET row_hash = bb._ledger_hash(s) WHERE s.id = r.id RETURNING s.row_hash INTO prev;
  END LOOP; END \$\$;"
pg pg-v2int "$FORGE" >/dev/null
assert_eq "forged edit: the in-database hash-chain check is fooled" "$($S ledger verify v2int 2>&1 | grep -c 'ledger intact')" "1"
assert_eq "forged edit: integrity against the anchors is TAMPERED" "$(integrity_state v2int)" "TAMPERED"
"$VERIFY" --dsn "$V2DSN" --anchors "$ANCH/v2int" >/dev/null 2>&1
assert_eq "forged edit: fox-verify exits 1" "$?" "1"

fresh_branch v2int
pg pg-v2int "SET session_replication_role = replica; DELETE FROM bb.schema_ledger WHERE id = (SELECT max(id) FROM bb.schema_ledger)" >/dev/null
assert_eq "deleted newest anchored entry: the in-database check still passes" "$($S ledger verify v2int 2>&1 | grep -c 'ledger intact')" "1"
assert_eq "deleted newest anchored entry: integrity is TAMPERED" "$(integrity_state v2int)" "TAMPERED"

fresh_branch v2int
pg pg-v2int "SET session_replication_role = replica; DELETE FROM bb.schema_ledger" >/dev/null
assert_eq "wiped ledger: integrity is TAMPERED" "$(integrity_state v2int)" "TAMPERED"

fresh_branch v2int
pg pg-v2int "SET session_replication_role = replica; DELETE FROM bb.ledger_checkpoints" >/dev/null
assert_eq "the anchor files, not the database's copy, are the source of truth" "$(integrity_state v2int)" "INTACT"
$S branch delete v2int >/dev/null 2>&1; rm -rf "$ANCH/v2int" /tmp/v2int.jsonl

echo "### 3b. scheduled checkpoints"
$S stop >/dev/null 2>&1; sleep 1
FOX_CHECKPOINT_INTERVAL=15s $S start >/dev/null 2>&1; main_ready
BEFORE="$(count_main "SELECT count(*) FROM bb.ledger_checkpoints")"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2sched" >/dev/null
gw "$KEY" main "CREATE TABLE v2sched(x int)" >/dev/null
AFTER="$BEFORE"
for i in $(seq 1 12); do
  AFTER="$(count_main "SELECT count(*) FROM bb.ledger_checkpoints")"
  [ -n "$BEFORE" ] && [ -n "$AFTER" ] && [ "$AFTER" -gt "$BEFORE" ] && break
  sleep 5
done
assert_eq "the scheduler anchors new entries on its own" \
  "$([ -n "$BEFORE" ] && [ -n "$AFTER" ] && [ "$AFTER" -gt "$BEFORE" ] && echo yes)" "yes"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2sched; DROP TABLE IF EXISTS v2cp" >/dev/null
$S stop >/dev/null 2>&1; sleep 1
$S start >/dev/null 2>&1; sleep 5; main_ready

echo "### 4. branch from just before a ledger entry"
# Three full restores (CLI by xid, MCP by time, REST) — expect a few minutes.
for b in v2bb v2bb-rest v2bb-time v2bb-x; do $S branch delete "$b" >/dev/null 2>&1; done
# main's integrity result before branch-before runs. Not necessarily INTACT: the
# existing suite's resets delete main's ledger rows, which earlier anchors catch.
main_integrity() { $S ledger integrity main 2>&1 | grep '✗' | sort; }   # its problems, if any
MAIN_INTEGRITY_BEFORE="$(main_integrity)"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2bb_keep; DROP TABLE IF EXISTS v2bb_old; DROP TABLE IF EXISTS v2bb_target; DROP TABLE IF EXISTS v2bb_after" >/dev/null
gw "$KEY" main "CREATE TABLE v2bb_keep(x int)" >/dev/null
gw "$KEY" main "INSERT INTO v2bb_keep SELECT generate_series(1,5)" >/dev/null
$S backup create >/dev/null 2>&1
gw "$KEY" main "INSERT INTO v2bb_keep SELECT generate_series(6,7)" >/dev/null   # after the backup, before the changes
sleep 1
pg pg-main "SET bb.v2 = 'off'; CREATE TABLE v2bb_old(x int)" >/dev/null       # an entry without capture (time fallback)
OLDID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity = 'public.v2bb_old'")"
sleep 1
gw "$KEY" main "CREATE TABLE v2bb_target(x int)" >/dev/null
TID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity = 'public.v2bb_target'")"
gw "$KEY" main "INSERT INTO v2bb_keep VALUES (8)" >/dev/null
gw "$KEY" main "CREATE TABLE v2bb_after(x int)" >/dev/null
assert_eq "the target entry has a captured transaction id" \
  "$(pg pg-main "SELECT (xid IS NOT NULL)::text FROM bb.ledger_ext WHERE ledger_id = $TID")" "true"
assert_eq "the fallback entry has none" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_ext WHERE ledger_id = $OLDID")" "0"
assert_eq "fox ledger entries lists the entry id" "$($S ledger entries --limit 10 | awk '{print $1}' | grep -cx "$TID")" "1"
assert_eq "REST ledger entries lists it" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/ledger/entries?limit=10" | python3 -c 'import sys,json; print(sum(1 for e in json.load(sys.stdin) if e["id"] == int(sys.argv[1])))' "$TID")" "1"
assert_eq "MCP ledger_entries lists it" "$(mcp_call ledger_entries '{"limit":10}' | awk '{print $1}' | grep -cx "$TID")" "1"

OUT="$($S ledger branch-before "$TID" --as v2bb 2>&1)"
$S branch owner v2bb "$USER_EMAIL" >/dev/null 2>&1
assert_eq "CLI branch-before succeeds" "$(echo "$OUT" | grep -c 'is ready')" "1"
assert_eq "it recovered to the entry's transaction id" "$(echo "$OUT" | grep -c 'target     xid')" "1"
assert_eq "the new branch is running" "$(sudo docker inspect -f '{{.State.Status}}' pg-v2bb 2>/dev/null)" "running"
assert_eq "rows written before the change are there (including after the backup)" "$(pg pg-v2bb 'SELECT count(*) FROM v2bb_keep')" "7"
assert_eq "an earlier change is there" "$(pg pg-v2bb "SELECT count(*) FROM pg_tables WHERE tablename = 'v2bb_old'")" "1"
assert_eq "the change itself is not" "$(pg pg-v2bb "SELECT count(*) FROM pg_tables WHERE tablename = 'v2bb_target'")" "0"
assert_eq "later changes are not" "$(pg pg-v2bb "SELECT count(*) FROM pg_tables WHERE tablename = 'v2bb_after'")" "0"
assert_eq "its ledger stops before the entry" "$(pg pg-v2bb "SELECT count(*) FROM bb.schema_ledger WHERE id >= $TID")" "0"
assert_eq "no recovery settings are left behind" \
  "$(pg pg-v2bb "SELECT count(*) FROM pg_file_settings WHERE name LIKE 'recovery_target%' OR name = 'restore_command'")" "0"
assert_eq "it is reachable through the gateway" "$(gw "$KEY" v2bb 'SELECT count(*) FROM v2bb_keep')" "7"
assert_eq "the guardrail is active on it" "$(gw "$KEY" v2bb 'DROP TABLE v2bb_keep' | grep -c 'guardrail')" "1"
assert_eq "main is untouched" \
  "$(pg pg-main "SELECT count(*) FROM pg_tables WHERE tablename IN ('v2bb_target','v2bb_after')")|$(pg pg-main 'SELECT count(*) FROM v2bb_keep')" "2|8"
assert_eq "main's ledger integrity result is unchanged" "$(main_integrity)" "$MAIN_INTEGRITY_BEFORE"

assert_eq "an existing branch name is refused" \
  "$($S ledger branch-before "$TID" --as v2bb 2>&1 | grep -c 'already exists')" "1"
gw "$KEY" main "DROP TABLE v2bb_keep" >/dev/null   # blocked by the guardrail: a BLOCKED entry
BID="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE status = 'BLOCKED'")"
assert_eq "a BLOCKED entry is refused" "$($S ledger branch-before "$BID" --as v2bb-x 2>&1 | grep -c 'BLOCKED')" "1"
assert_eq "a refused request leaves nothing behind" "$(sudo docker inspect pg-v2bb-x >/dev/null 2>&1 || echo none)" "none"
assert_eq "an unknown entry is refused" "$($S ledger branch-before 999999999 --as v2bb-x 2>&1 | grep -c 'not found')" "1"
assert_eq "a source other than main is refused" "$($S ledger branch-before "$TID" --branch v2bb --as v2bb-x 2>&1 | grep -c 'only main')" "1"
assert_eq "a bad entry id is a usage error" "$($S ledger branch-before abc >/dev/null 2>&1; echo $?)" "2"
assert_eq "REST: unknown entry is 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" "$API/api/branches/main/ledger/999999999/branch")" "404"
assert_eq "REST: BLOCKED entry is 400" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" "$API/api/branches/main/ledger/$BID/branch")" "400"
assert_eq "REST: existing name is 409" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" -d '{"name":"v2bb"}' "$API/api/branches/main/ledger/$TID/branch")" "409"
assert_eq "MCP lists branch_before_change" \
  "$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | env FOX_API_KEY="$KEY" "$S" mcp 2>/dev/null | grep -c 'branch_before_change')" "1"
assert_eq "MCP: BLOCKED entry is refused" "$(mcp_call branch_before_change "{\"entry_id\":$BID,\"name\":\"v2bb-x\"}" | grep -c 'BLOCKED')" "1"

assert_eq "REST branch-before creates the branch" \
  "$(curl -sk --max-time 1200 -X POST -H "$AUTH" -d '{"name":"v2bb-rest"}' "$API/api/branches/main/ledger/$TID/branch" | jget branch)" "v2bb-rest"
assert_eq "REST branch holds main before the change" \
  "$(pg pg-v2bb-rest "SELECT count(*) FROM pg_tables WHERE tablename = 'v2bb_target'")|$(pg pg-v2bb-rest 'SELECT count(*) FROM v2bb_keep')" "0|7"

assert_eq "MCP branch-before by time (entry without capture) succeeds" \
  "$(mcp_call branch_before_change "{\"entry_id\":$OLDID,\"name\":\"v2bb-time\"}" | grep -c 'recovered to time')" "1"
assert_eq "time fallback excludes the change and keeps earlier rows" \
  "$(pg pg-v2bb-time "SELECT count(*) FROM pg_tables WHERE tablename = 'v2bb_old'")|$(pg pg-v2bb-time 'SELECT count(*) FROM v2bb_keep')" "0|7"

$S branch delete v2bb >/dev/null 2>&1
assert_eq "the branch deletes like any other" "$(sudo docker inspect pg-v2bb >/dev/null 2>&1 || echo gone)" "gone"
for b in v2bb-rest v2bb-time v2bb-x; do $S branch delete "$b" >/dev/null 2>&1; done
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2bb_keep; DROP TABLE IF EXISTS v2bb_old; DROP TABLE IF EXISTS v2bb_target; DROP TABLE IF EXISTS v2bb_after" >/dev/null

echo "### 5. Blackbox names (aliases of the ledger command, routes and tools)"
assert_eq "fox blackbox verify matches fox ledger verify" "$($S blackbox verify main 2>&1)" "$($S ledger verify main 2>&1)"
assert_eq "fox blackbox entries matches fox ledger entries" "$($S blackbox entries --limit 5 2>&1)" "$($S ledger entries --limit 5 2>&1)"
assert_eq "fox blackbox integrity matches fox ledger integrity" \
  "$($S blackbox integrity main 2>&1 | head -1 | grep -o 'INTACT\|TAMPERED')" "$($S ledger integrity main 2>&1 | head -1 | grep -o 'INTACT\|TAMPERED')"
assert_eq "REST /blackbox/verify matches /ledger/verify" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/blackbox/verify")" "$(curl -sk -H "$AUTH" "$API/api/branches/main/ledger/verify")"
assert_eq "REST /blackbox keeps the ledger columns" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/blackbox?limit=1" | jcols)" \
  "at,actor,actor_kind,tool,branch,command_tag,object_identity,statement,status,risk"
assert_eq "REST /blackbox/entries answers" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "$API/api/branches/main/blackbox/entries?limit=1")" "200"
assert_eq "REST /blackbox routes require auth like the originals" \
  "$(curl -sk -o /dev/null -w '%{http_code}' "$API/api/branches/main/blackbox/verify")" "401"
assert_eq "MCP lists both the Blackbox and the original tool names" \
  "$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | env FOX_API_KEY="$KEY" "$S" mcp 2>/dev/null | python3 -c 'import sys,json; n={t["name"] for t in json.load(sys.stdin)["result"]["tools"]}; print(all(x in n for x in ["verify_blackbox","blackbox_integrity","blackbox_entries","verify_ledger","ledger_integrity","ledger_entries"]))')" "True"
assert_eq "MCP blackbox_integrity matches ledger_integrity" \
  "$(mcp_call blackbox_integrity '{"branch":"main"}' | head -1 | grep -o 'INTACT\|TAMPERED')" "$(mcp_call ledger_integrity '{"branch":"main"}' | head -1 | grep -o 'INTACT\|TAMPERED')"
assert_eq "MCP verify_blackbox matches verify_ledger" \
  "$(mcp_call verify_blackbox '{"branch":"main"}')" "$(mcp_call verify_ledger '{"branch":"main"}')"

echo "### 5b. Blackbox page: filters, session column (L5)"
# A table name of its own per run: the ledger is append-only and nothing clears
# it between runs, so a fixed name counted the previous run's entries as well.
PT="v2page_$(date +%s)"
gw "$KEY" main "CREATE TABLE $PT(x int)" >/dev/null
gw "$KEY" main "ALTER TABLE $PT ADD COLUMN y int; ALTER TABLE $PT DROP COLUMN y" >/dev/null
lcols() { curl -sk -H "$AUTH" "$API/api/branches/main/ledger?$1" | jcols; }
lcount() { curl -sk -H "$AUTH" "$API/api/branches/main/ledger?$1" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["rows"]))'; }
assert_eq "with=session adds the session column" "$(lcols 'limit=1&with=session')" \
  "at,actor,actor_kind,tool,branch,command_tag,object_identity,statement,status,risk,session"
assert_eq "without it the columns are unchanged" "$(lcols 'limit=1')" \
  "at,actor,actor_kind,tool,branch,command_tag,object_identity,statement,status,risk"
assert_eq "table filter" "$(lcount "table=$PT&limit=50")" "3"
assert_eq "table + risk filter" "$(lcount "table=$PT&risk=drop-column&limit=50")" "1"
TODAY="$(pg pg-main "SELECT to_char(now(),'YYYY-MM-DD')")"
assert_eq "date range filter includes today" "$(lcount "table=$PT&since=$TODAY&until=$TODAY%2023:59:59&limit=50")" "3"
assert_eq "date range filter excludes an earlier day" "$(lcount "table=$PT&until=2000-01-01%2023:59:59&limit=50")" "0"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS $PT" >/dev/null

echo "### 6. Blackbox policy gate (warn / block — docs/policy-errors.md)"
# gwv: psql through the gateway with SQLSTATEs shown ("NOTICE:  BBX02: …").
gwv() { PGPASSWORD="$1" psql "$GATEWAY/$2" -X -v VERBOSITY=verbose -tAc "$3" 2>&1; }
detail() { grep -m1 '^DETAIL:' | sed 's/^DETAIL:  //'; }
reset_rules() {
  for r in alter-column-type drop-column drop-index grant-to-public; do
    $S policy warn "$r" >/dev/null 2>&1; $S policy enable "$r" >/dev/null 2>&1
  done
  $S policy remove v2pol-custom >/dev/null 2>&1
  $S admin revoke "$USER_EMAIL" >/dev/null 2>&1
}
reset_rules
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2pol; DROP TABLE IF EXISTS v2pol_forbidden; DROP TABLE IF EXISTS v2pol_ok" >/dev/null
gw "$KEY" main "CREATE TABLE v2pol(a int, b int, c text)" >/dev/null

assert_eq "the four built-in rules are installed, all warn" \
  "$(pg pg-main "SELECT string_agg(rule_id||':'||action, ',' ORDER BY rule_id) FROM bb.policy_rules WHERE builtin")" \
  "alter-column-type:warn,drop-column:warn,drop-index:warn,grant-to-public:warn"
assert_eq "the gate fires after the guardrail (name order)" \
  "$(pg pg-main "SELECT string_agg(evtname, ',' ORDER BY evtname) FROM pg_event_trigger WHERE evtname IN ('bb_guard_start','bb_policy_start')")" \
  "bb_guard_start,bb_policy_start"
assert_eq "fox policy lists the rules" "$($S policy list | grep -c 'alter-column-type\|drop-column\|drop-index\|grant-to-public')" "4"

EVB="$(pg pg-main "SELECT coalesce(max(id),0) FROM bb.ledger_policy_evaluations")"
OUT="$(gwv "$KEY" main "ALTER TABLE v2pol ALTER COLUMN a TYPE bigint")"
assert_eq "warn: the statement runs" \
  "$(pg pg-main "SELECT data_type FROM information_schema.columns WHERE table_name='v2pol' AND column_name='a'")" "bigint"
assert_eq "warn: a NOTICE with SQLSTATE BBX02" "$(echo "$OUT" | grep -c '^NOTICE:  BBX02: Blackbox policy warning: .*(rule alter-column-type)')" "1"
assert_eq "warn: DETAIL is the contract JSON" \
  "$(echo "$OUT" | detail | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["v"], d["rule_id"], d["action"], d["command"], d["blackbox_id"], d["override"], isinstance(d["evaluation_id"], int))')" \
  "1 alter-column-type warn ALTER TABLE None None True"
assert_eq "warn: the evaluation is recorded" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_policy_evaluations WHERE id > $EVB AND rule_id='alter-column-type' AND action='warn'")" "1"
gw "$KEY" main "CREATE INDEX v2pol_b ON v2pol(b)" >/dev/null
assert_eq "warn: DROP INDEX" "$(gwv "$KEY" main "DROP INDEX v2pol_b" | grep -c 'BBX02: .*(rule drop-index)')" "1"
assert_eq "warn: GRANT … TO PUBLIC" "$(gwv "$KEY" main "GRANT SELECT ON v2pol TO PUBLIC" | grep -c 'BBX02: .*(rule grant-to-public)')" "1"
assert_eq "an ordinary change triggers nothing" "$(gwv "$KEY" main "ALTER TABLE v2pol ADD COLUMN d int" | grep -c 'BBX0')" "0"
assert_eq "SET/DROP DEFAULT is not taken for dropping a column" \
  "$(gwv "$KEY" main "ALTER TABLE v2pol ALTER COLUMN d SET DEFAULT 1; ALTER TABLE v2pol ALTER COLUMN d DROP DEFAULT" | grep -c 'drop-column')" "0"

$S policy block drop-column >/dev/null 2>&1
assert_eq "fox policy block sets the action" "$(pg pg-main "SELECT action FROM bb.policy_rules WHERE rule_id='drop-column'")" "block"
OUT="$(gwv "$KEY" main "ALTER TABLE v2pol DROP COLUMN c")"
assert_eq "block: an ERROR with SQLSTATE BBX01" "$(echo "$OUT" | grep -c '^ERROR:  BBX01: Blackbox policy: .*(rule drop-column)')" "1"
assert_eq "block: the statement did not run" \
  "$(pg pg-main "SELECT count(*) FROM information_schema.columns WHERE table_name='v2pol' AND column_name='c'")" "1"
BD="$(echo "$OUT" | detail)"
assert_eq "block: DETAIL is the contract JSON" \
  "$(echo "$BD" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["v"], d["rule_id"], d["action"], d["override"], d["impact"], isinstance(d["evaluation_id"], int), isinstance(d["blackbox_id"], int))')" \
  "1 drop-column block db_admin None True True"
BBID="$(echo "$BD" | python3 -c 'import sys,json; print(json.load(sys.stdin)["blackbox_id"])' 2>/dev/null)"
assert_eq "block: recorded as a BLOCKED Blackbox entry (risk policy) that survived the rollback" \
  "$(pg pg-main "SELECT status||'/'||risk||'/'||command_tag FROM bb.schema_ledger WHERE id=${BBID:-0}")" "BLOCKED/policy/ALTER TABLE"
assert_eq "block: its evaluation survived the rollback" "$(pg pg-main "SELECT action FROM bb.ledger_policy_evaluations WHERE blackbox_id=${BBID:-0}")" "block"
assert_eq "block: the HINT names the override" "$(echo "$OUT" | grep -c "^HINT:  .*bb.policy_allow = 'drop-column'")" "1"
assert_eq "block: a non-admin's bb.policy_allow is ignored" \
  "$(gwv "$KEY" main "SET bb.policy_allow = 'drop-column'; ALTER TABLE v2pol DROP COLUMN c" | grep -c 'BBX01')" "1"
assert_eq "block: turning bb.v2 off in the session does not bypass it" \
  "$(gwv "$KEY" main "SET bb.v2 = 'off'; ALTER TABLE v2pol DROP COLUMN c" | grep -c 'BBX01')" "1"
assert_eq "the hash chain still verifies with policy BLOCKED entries" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/ledger/verify" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0][2])')" "0"

$S admin grant "$USER_EMAIL" --branch main >/dev/null 2>&1
assert_eq "admin: bb.allow_destructive does not override a policy rule" \
  "$(gwv "$KEY" main "SET bb.allow_destructive = on; ALTER TABLE v2pol DROP COLUMN c" | grep -c 'BBX01')" "1"
EVB="$(pg pg-main "SELECT coalesce(max(id),0) FROM bb.ledger_policy_evaluations")"
OUT="$(gwv "$KEY" main "SET bb.policy_allow = 'drop-column'; ALTER TABLE v2pol DROP COLUMN c")"
assert_eq "admin: bb.policy_allow overrides that rule" \
  "$(pg pg-main "SELECT count(*) FROM information_schema.columns WHERE table_name='v2pol' AND column_name='c'")|$(echo "$OUT" | grep -c 'BBX01')" "0|0"
assert_eq "admin: the override is recorded as allowed" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_policy_evaluations WHERE id > $EVB AND rule_id='drop-column' AND action='allowed'")" "1"
assert_eq "admin: the change's capture row records the override" \
  "$(pg pg-main "SELECT e.override_used FROM bb.ledger_ext e JOIN bb.schema_ledger s ON s.id=e.ledger_id WHERE s.object_identity='public.v2pol' AND s.command_tag='ALTER TABLE' ORDER BY s.id DESC LIMIT 1")" "t"

assert_eq "REST: rules listed" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/policies" | python3 -c 'import sys,json; print(sum(1 for r in json.load(sys.stdin) if r["builtin"]))')" "4"
assert_eq "REST: an admin can change a rule (200)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "$AUTH" -d '{"action":"warn"}' "$API/api/branches/main/policies/drop-column")" "200"
assert_eq "REST: the change took effect and names who made it" \
  "$(pg pg-main "SELECT action||'/'||updated_by FROM bb.policy_rules WHERE rule_id='drop-column'")" "warn/$USER_EMAIL"
assert_eq "REST: unknown rule is 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "$AUTH" -d '{"action":"warn"}' "$API/api/branches/main/policies/nope")" "404"
assert_eq "REST: a built-in rule can't be removed (409)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X DELETE -H "$AUTH" "$API/api/branches/main/policies/drop-index")" "409"
$S admin revoke "$USER_EMAIL" --branch main >/dev/null 2>&1
assert_eq "REST: a non-admin can't change a rule (403)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "$AUTH" -d '{"action":"block"}' "$API/api/branches/main/policies/drop-column")" "403"

# L4/H8: the console used to log every user in as the shared db_client role,
# which is never in db_admin, so nobody could override the guardrail from it.
cq() { curl -sk -X POST -H "$AUTH" -H 'Content-Type: application/json' "$API/api/branches/main/query" \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1], "allow_destructive": sys.argv[2] == "1"}))' "$1" "${2:-0}")"; }
admins_you() { curl -sk -H "$AUTH" "$API/api/branches/main/admins" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["you"], d["you_are_admin"])'; }
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2console" >/dev/null
cq "CREATE TABLE v2console(x int)" >/dev/null
assert_eq "console: runs as the signed-in user" \
  "$(cq 'SELECT session_user' | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0][0])')" "$USER_EMAIL"
# L4: the console shows a value, not the Go type pgx decoded it into. A uuid
# column reached the page as a list of 16 numbers, an interval as
# {"Microseconds":…}, an inet with its quotes and a bytea as mangled text.
cells() { cq "$1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0][0])'; }
assert_eq "console: a uuid is a uuid, not 16 numbers" \
  "$(cells "SELECT 'c340984e-87bf-4006-a013-72aca6fc7d77'::uuid")" "c340984e-87bf-4006-a013-72aca6fc7d77"
assert_eq "console: an array of uuids keeps them readable" \
  "$(cells "SELECT ARRAY['c340984e-87bf-4006-a013-72aca6fc7d77'::uuid]")" '["c340984e-87bf-4006-a013-72aca6fc7d77"]'
assert_eq "console: an interval reads as Postgres writes it" \
  "$(cells "SELECT '1 day 2 hours'::interval")" "1 day 02:00:00"
assert_eq "console: an inet carries no quotes" "$(cells "SELECT '192.168.1.1'::inet")" "192.168.1.1/32"
assert_eq "console: a bytea is hex, not raw bytes" "$(cells "SELECT decode('0102','hex')")" '\x0102'
# …and the types that already read well are untouched.
assert_eq "console: numeric, jsonb, arrays and timestamps are unchanged" \
  "$(cells 'SELECT 1234.5678::numeric')|$(cells $'SELECT \'{"a":1}\'::jsonb')|$(cells 'SELECT ARRAY[1,2,3]')|$(cells "SELECT 'hi'::text")" \
  '1234.5678|{"a":1}|[1,2,3]|hi'
assert_eq "REST: admins says the caller is not one" "$(admins_you)" "$USER_EMAIL False"
assert_eq "console: a non-admin's override is still refused" "$(cq 'DROP TABLE v2console' 1 | grep -c 'blocked by policy')" "1"
assert_eq "REST: a non-admin can't grant override permission (403)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" -d "{\"email\":\"$USER_EMAIL\"}" "$API/api/branches/main/admins")" "403"
$S admin grant "$USER_EMAIL" --branch main >/dev/null 2>&1
assert_eq "REST: admins says the caller now is one" "$(admins_you)" "$USER_EMAIL True"
assert_eq "console: without the override an admin is still blocked" "$(cq 'DROP TABLE v2console' | grep -c 'blocked by policy')" "1"
assert_eq "console: with the override an admin's DROP goes through" \
  "$(cq 'DROP TABLE v2console' 1 | grep -c '"error"')|$(pg pg-main "SELECT to_regclass('public.v2console') IS NULL")" "0|t"
assert_eq "REST: granting an account that doesn't exist is 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" -d '{"email":"nobody@foxbyte.dev"}' "$API/api/branches/main/admins")" "404"
assert_eq "REST: revoking someone who isn't an admin is 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X DELETE -H "$AUTH" "$API/api/branches/main/admins/nobody@foxbyte.dev")" "404"
# A policy rule (BBX01) is overridden per rule, not by allow_destructive; the
# console's "Allow & run again" used to send the wrong one for a rule.
cqr() { local sql="$1"; shift; curl -sk -X POST -H "$AUTH" -H 'Content-Type: application/json' "$API/api/branches/main/query" \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1], "allow_rules": sys.argv[2:]}))' "$sql" "$@")"; }
$S policy block drop-column >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2console2" >/dev/null
cq "CREATE TABLE v2console2(a int, b int, c int)" >/dev/null
assert_eq "console: allow_destructive does not override a policy rule" "$(cq 'ALTER TABLE v2console2 DROP COLUMN b' 1 | grep -c 'BBX01')" "1"
assert_eq "console: allow_rules overrides that rule for an admin" \
  "$(cqr 'ALTER TABLE v2console2 DROP COLUMN b' drop-column | grep -c '"error"')|$(pg pg-main "SELECT count(*) FROM information_schema.columns WHERE table_name='v2console2' AND column_name='b'")" "0|0"
assert_eq "console: a malformed rule id is refused (400)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" -H 'Content-Type: application/json' -d '{"sql":"SELECT 1","allow_rules":["DROP; x"]}' "$API/api/branches/main/query")" "400"
$S admin revoke "$USER_EMAIL" --branch main >/dev/null 2>&1
assert_eq "console: allow_rules is ignored for a non-admin" "$(cqr 'ALTER TABLE v2console2 DROP COLUMN c' drop-column | grep -c 'BBX01')" "1"
$S policy warn drop-column >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2console2" >/dev/null
assert_eq "REST: check previews matches without running" \
  "$(curl -sk -X POST -H "$AUTH" -d '{"sql":"ALTER TABLE v2pol DROP COLUMN b"}' "$API/api/branches/main/policies/check" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["command"], ",".join(m["rule_id"] for m in d["matches"]))')" \
  "ALTER TABLE drop-column"
assert_eq "REST: evaluations listed" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/policies/evaluations?limit=5" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)) > 0)')" "True"

assert_eq "CLI check shows the matching rule" "$($S policy check "ALTER TABLE v2pol DROP COLUMN b" | grep -c 'WARN.*drop-column')" "1"
$S policy block drop-column >/dev/null 2>&1
assert_eq "CLI check exits 1 when a rule would block" "$($S policy check "ALTER TABLE v2pol DROP COLUMN b" >/dev/null 2>&1; echo $?)" "1"
assert_eq "MCP policy_check" "$(mcp_call policy_check '{"sql":"ALTER TABLE v2pol DROP COLUMN b"}' | grep -c 'BLOCK.*drop-column')" "1"
assert_eq "clients can't change rules directly" "$(gw "$KEY" main "UPDATE bb.policy_rules SET action='warn'" | grep -c 'permission denied')" "1"

# Fail-safe: when an evaluation can't be recorded, a warn rule never blocks, and
# a block still refuses (with evaluation_id null).
pg pg-main "ALTER TABLE bb.ledger_policy_evaluations ADD CONSTRAINT v2pol_fail CHECK (false) NOT VALID" >/dev/null
OUT="$(gwv "$KEY" main "ALTER TABLE v2pol ALTER COLUMN b TYPE bigint")"
assert_eq "fail-safe: a warn rule that can't record lets the statement run" \
  "$(pg pg-main "SELECT data_type FROM information_schema.columns WHERE table_name='v2pol' AND column_name='b'")|$(echo "$OUT" | grep -c 'evaluation skipped')" "bigint|1"
OUT="$(gwv "$KEY" main "ALTER TABLE v2pol DROP COLUMN b")"
assert_eq "fail-safe: a block still refuses, evaluation_id null" \
  "$(echo "$OUT" | grep -c 'BBX01')|$(echo "$OUT" | detail | python3 -c 'import sys,json; print(json.load(sys.stdin)["evaluation_id"])')" "1|None"
$S policy warn drop-column >/dev/null 2>&1
pg pg-main "ALTER TABLE bb.ledger_policy_evaluations DROP CONSTRAINT v2pol_fail" >/dev/null

$S policy block drop-column >/dev/null 2>&1
pg pg-main "ALTER EVENT TRIGGER bb_policy_start DISABLE" >/dev/null
assert_eq "kill switch: a disabled gate doesn't block" "$(gwv "$KEY" main "ALTER TABLE v2pol DROP COLUMN b" | grep -c 'BBX0')" "0"
pg pg-main "ALTER EVENT TRIGGER bb_policy_start ENABLE" >/dev/null
$S policy warn drop-column >/dev/null 2>&1

HB="$(pg pg-main "SELECT coalesce(max(id),0) FROM bb.policy_rule_history")"
$S policy add v2pol-custom --command "CREATE TABLE" --pattern 'v2pol_forbidden' --block --reason "test rule" >/dev/null 2>&1
assert_eq "custom block rule refuses a matching statement" \
  "$(gwv "$KEY" main "CREATE TABLE v2pol_forbidden(x int)" | grep -c 'BBX01: .*(rule v2pol-custom)')" "1"
assert_eq "…and nothing else" "$(gwv "$KEY" main "CREATE TABLE v2pol_ok(x int)" | grep -c 'BBX0')" "0"
$S policy disable v2pol-custom >/dev/null 2>&1
assert_eq "a disabled rule doesn't fire" "$(gwv "$KEY" main "CREATE TABLE v2pol_forbidden(x int)" | grep -c 'BBX0')" "0"
assert_eq "rule changes are recorded with who made them" \
  "$(pg pg-main "SELECT string_agg(change||':'||changed_by, ',' ORDER BY id) FROM bb.policy_rule_history WHERE id > $HB AND rule_id='v2pol-custom'")" \
  "insert:fox-cli,update:fox-cli"
assert_eq "an invalid pattern is refused" \
  "$($S policy add v2pol-bad --command "CREATE TABLE" --pattern '(' --reason x 2>&1 | grep -c 'invalid pattern')" "1"
assert_eq "a built-in rule can't be removed" "$($S policy remove drop-index 2>&1 | grep -c 'built-in')" "1"
assert_eq "evaluations are append-only" \
  "$(sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "DELETE FROM bb.ledger_policy_evaluations" 2>&1 | grep -c 'append-only')" "1"

assert_eq "the guardrail's DROP TABLE error is unchanged (42501) and adds no policy notice" \
  "$(gwv "$KEY" main "DROP TABLE v2pol" | grep -c '^ERROR:  42501: guardrail: DROP TABLE is blocked by policy (set bb.allow_destructive=on to override)')|$(gwv "$KEY" main "DROP TABLE v2pol" | grep -c 'BBX0')" \
  "1|0"
$S policy block drop-index >/dev/null 2>&1
$S blackbox upgrade main >/dev/null 2>&1
assert_eq "reinstalling keeps rule changes" "$(pg pg-main "SELECT action FROM bb.policy_rules WHERE rule_id='drop-index'")" "block"
assert_eq "reinstalling keeps one gate trigger" "$(pg pg-main "SELECT count(*) FROM pg_event_trigger WHERE evtname='bb_policy_start'")" "1"

reset_rules
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2pol; DROP TABLE IF EXISTS v2pol_forbidden; DROP TABLE IF EXISTS v2pol_ok" >/dev/null

echo "### 6b. rules and risk flags judge the statement that runs (H5, H15, H4, H2)"
# Rules and risk flags used to match everything a client sent in one message —
# comments, string literals and every other statement in it.
reset_rules
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2stm; DROP TABLE IF EXISTS v2stm_a; DROP TABLE IF EXISTS v2stm_b" >/dev/null
gw "$KEY" main "CREATE TABLE v2stm(a int, b int, c int, d int, e int)" >/dev/null

read -r -d '' TOK_SQL <<'SQL'
SELECT string_agg(pos || '=' || body, ' | ' ORDER BY pos) FROM bb._sql_statements(
$q$ALTER TABLE t ADD c text DEFAULT 'a;b''drop column'; -- drop column x
ALTER TABLE "we;ird" DROP COLUMN y /* nested /* drop column */ still */; CREATE FUNCTION f() RETURNS int AS $body$ SELECT 1; -- drop column $body$ LANGUAGE sql; SELECT E'it\'s; drop column', $1, a$b$q$)
SQL
read -r -d '' TOK_WANT <<'WANT'
1=ALTER TABLE t ADD c text DEFAULT '' | 2=ALTER TABLE "we;ird" DROP COLUMN y | 3=CREATE FUNCTION f() RETURNS int AS '' LANGUAGE sql | 4=SELECT E'', $1, a$b
WANT
assert_eq "tokenizer: statements split with comments removed and literals emptied" "$(pg pg-main "$TOK_SQL")" "$TOK_WANT"
read -r -d '' MB_SQL <<'SQL'
SELECT count(*) FROM bb._sql_statements('héllo ünïcode; ALTER TABLE t ADD x text DEFAULT ''ü;ß''')
SQL
assert_eq "tokenizer: multibyte text" "$(pg pg-main "$MB_SQL")" "2"
read -r -d '' TAG_SQL <<'SQL'
SELECT bb._statement_has_tag('CREATE UNIQUE INDEX CONCURRENTLY i ON t(a)','CREATE INDEX')::text
    || bb._statement_has_tag('CREATE OR REPLACE VIEW v AS SELECT 1','CREATE VIEW')::text
    || bb._statement_has_tag('ALTER VIEW "table" RENAME TO x','ALTER TABLE')::text
SQL
assert_eq "tag matching (modifiers skipped; a quoted \"table\" is not a keyword)" "$(pg pg-main "$TAG_SQL")" "truetruefalse"

EVB="$(pg pg-main "SELECT coalesce(max(id),0) FROM bb.ledger_policy_evaluations")"
assert_eq "warn: a string literal mentioning the rule doesn't trigger it" \
  "$(gwv "$KEY" main "ALTER TABLE v2stm ADD COLUMN note text DEFAULT 'drop column later'" | grep -c 'BBX02')" "0"
assert_eq "warn: a comment mentioning the rule doesn't trigger it" \
  "$(gwv "$KEY" main "$(printf -- '-- drop column soon\nALTER TABLE v2stm ADD COLUMN n2 int')" | grep -c 'BBX02')" "0"
assert_eq "warn: add then drop in one run warns once, for the drop" \
  "$(gwv "$KEY" main "ALTER TABLE v2stm ADD COLUMN n3 int; ALTER TABLE v2stm DROP COLUMN n3" | grep -c 'BBX02: .*(rule drop-column)')|$(pg pg-main "SELECT count(*) FROM bb.ledger_policy_evaluations WHERE id > $EVB AND rule_id='drop-column'")" "1|1"
assert_eq "warn: a comment inside the statement doesn't hide it" \
  "$(gwv "$KEY" main "ALTER TABLE v2stm DROP /* x */ COLUMN n2" | grep -c 'BBX02: .*(rule drop-column)')" "1"
assert_eq "risk: a literal mentioning drop column is not flagged" \
  "$(pg pg-main "SELECT status||'/'||coalesce(risk,'-') FROM bb.schema_ledger WHERE object_identity='public.v2stm' AND statement LIKE '%note text%' ORDER BY id DESC LIMIT 1")" "APPLIED/-"
gw "$KEY" main "ALTER TABLE v2stm ADD COLUMN r2 int; ALTER TABLE v2stm DROP COLUMN r2" >/dev/null
assert_eq "risk: in add-then-drop only the drop is flagged" \
  "$(pg pg-main "SELECT string_agg(status||'/'||coalesce(risk,'-'), ',' ORDER BY id) FROM (SELECT * FROM bb.schema_ledger WHERE object_identity='public.v2stm' ORDER BY id DESC LIMIT 2) x")" \
  "APPLIED/-,FLAGGED/drop-column"
assert_eq "preview: a literal doesn't match" \
  "$($S policy check "ALTER TABLE v2stm ADD COLUMN x text DEFAULT 'drop column'" 2>&1 | grep -c 'drop-column')" "0"
assert_eq "preview: a drop in a multi-statement text matches" \
  "$($S policy check "ALTER TABLE v2stm ADD COLUMN x int; ALTER TABLE v2stm DROP COLUMN x" 2>&1 | grep -c 'drop-column')" "1"

$S policy block drop-column >/dev/null 2>&1
assert_eq "block: a harmless statement with the phrase in a literal runs" \
  "$(gwv "$KEY" main "ALTER TABLE v2stm ADD COLUMN n5 text DEFAULT 'drop column'" | grep -c 'ERROR')|$(pg pg-main "SELECT count(*) FROM information_schema.columns WHERE table_name='v2stm' AND column_name='n5'")" "0|1"
EVB="$(pg pg-main "SELECT coalesce(max(id),0) FROM bb.ledger_policy_evaluations")"
S0=$(date +%s)
OUT="$(PGPASSWORD="$KEY" timeout 60 psql "$GATEWAY/main" -X -v VERBOSITY=verbose -tAc "ALTER TABLE v2stm ADD COLUMN n4 int; ALTER TABLE v2stm DROP COLUMN e" 2>&1)"
assert_eq "block: add then drop in one run is refused without hanging (it deadlocked before)" \
  "$(echo "$OUT" | grep -c 'BBX01: .*(rule drop-column)')|$([ $(( $(date +%s) - S0 )) -lt 30 ] && echo fast)" "1|fast"
assert_eq "block: …the whole run is rolled back" \
  "$(pg pg-main "SELECT count(*) FROM information_schema.columns WHERE table_name='v2stm' AND column_name='n4'")" "0"
assert_eq "block: …the evaluation is still recorded, and the skipped Blackbox entry is announced" \
  "$(pg pg-main "SELECT count(*) FROM bb.ledger_policy_evaluations WHERE id > $EVB AND rule_id='drop-column' AND action='block'")|$(echo "$OUT" | grep -c 'not recorded in Blackbox, because this transaction has already written to it')" "1|1"
assert_eq "block: DDL inside a DO block is still caught" \
  "$(gwv "$KEY" main 'DO $$ BEGIN ALTER TABLE v2stm DROP COLUMN d; END $$' | grep -c 'BBX01')" "1"
read -r -d '' BUILT <<'SQL'
DO $$ BEGIN EXECUTE 'ALTER TABLE v2stm DR' || 'OP COLUMN d'; END $$
SQL
assert_eq "block: …including a statement assembled from strings" "$(gwv "$KEY" main "$BUILT" | grep -c 'BBX01')" "1"
assert_eq "a client can't move the statement position" \
  "$(gw "$KEY" main "SELECT bb._statement_texts('start','ALTER TABLE','')" | grep -c 'permission denied')|$(gw "$KEY" main "UPDATE bb.statement_cursor SET pos = 99" | grep -c 'permission denied')" "1|1"
reset_rules

S0=$(date +%s)
OUT="$(PGPASSWORD="$KEY" timeout 60 psql "$GATEWAY/main" -X -v VERBOSITY=verbose -tAc "BEGIN; CREATE TABLE v2stm_a(x int); DROP TABLE v2stm; COMMIT;" 2>&1)"
assert_eq "guardrail: a blocked DROP TABLE after a write in the same transaction no longer hangs, error unchanged" \
  "$(echo "$OUT" | grep -c '42501: guardrail: DROP TABLE is blocked by policy (set bb.allow_destructive=on to override)')|$([ $(( $(date +%s) - S0 )) -lt 30 ] && echo fast)" "1|fast"
assert_eq "no session left waiting" \
  "$(pg pg-main "SELECT count(*) FROM pg_stat_activity WHERE datname='$DB_DATABASE' AND wait_event_type IN ('Lock','Extension') AND pid <> pg_backend_pid()")" "0"

HB="$(pg pg-main "SELECT coalesce(max(id),0) FROM bb.policy_history")"
pg pg-main "SET bb.actor = 'v2-audit'; INSERT INTO bb.policy VALUES ('DROP INDEX','flag') ON CONFLICT (op) DO UPDATE SET action = 'flag'" >/dev/null
gw "$KEY" main "CREATE INDEX v2stm_a_idx ON v2stm(a)" >/dev/null
gw "$KEY" main "DROP INDEX v2stm_a_idx" >/dev/null
assert_eq "flag: a flagged command runs and is recorded FLAGGED" \
  "$(pg pg-main "SELECT status||'/'||risk FROM bb.schema_ledger WHERE command_tag='DROP INDEX' AND object_identity='public.v2stm_a_idx' ORDER BY id DESC LIMIT 1")|$(pg pg-main "SELECT to_regclass('public.v2stm_a_idx') IS NULL")" \
  "FLAGGED/drop|t"
assert_eq "an unknown guardrail action is refused" \
  "$(pgerr pg-main "UPDATE bb.policy SET action = 'blok' WHERE op = 'DROP INDEX'" | grep -c 'policy_action_valid')" "1"
pg pg-main "SET bb.actor = 'v2-audit'; DELETE FROM bb.policy WHERE op = 'DROP INDEX'" >/dev/null
assert_eq "guardrail policy changes are recorded, with who made them" \
  "$(pg pg-main "SELECT string_agg(change||':'||coalesce(old_action,'-')||'>'||coalesce(new_action,'-')||':'||changed_by, ',' ORDER BY id) FROM bb.policy_history WHERE id > $HB")" \
  "insert:->flag:v2-audit,delete:flag>-:v2-audit"
assert_eq "…the history is append-only and readable by clients" \
  "$(pgerr pg-main "DELETE FROM bb.policy_history" | grep -c 'append-only')|$(gw "$KEY" main "SELECT count(*) > 0 FROM bb.policy_history")" "1|t"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2stm; DROP TABLE IF EXISTS v2stm_a; DROP TABLE IF EXISTS v2stm_b" >/dev/null

echo "### 7. agent provenance (sessions, tasks, execute_change)"
# mcp_exec <arguments-json>: one MCP process that introduces itself as v2test-agent
# and calls execute_change; prints the tool's text result.
mcp_exec() {
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"v2test-agent","version":"1"}}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"execute_change\",\"arguments\":$1}}" \
    | env FOX_API_KEY="$KEY" "$S" mcp 2>/dev/null \
    | python3 -c 'import sys,json
for line in sys.stdin:
    m=json.loads(line)
    if m.get("id")==2: print(m["result"]["content"][0]["text"])'
}
jf() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }
LONGID="$(printf 'x%.0s' $(seq 1 201))"   # one character over the 200 limit
for a in v2plain v2prov v2bad; do curl -sk -H "$AUTH" -X DELETE "$AGENTS/agents/$a/branch" >/dev/null 2>&1; done
$S policy warn drop-column >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2exec; DROP TABLE IF EXISTS v2exec_dry" >/dev/null

assert_eq "agent sessions table is installed" "$(pg pg-main "SELECT to_regclass('bb.agent_sessions') IS NOT NULL")" "t"
assert_eq "clients can't write agent sessions" \
  "$(gw "$KEY" main "INSERT INTO bb.agent_sessions(session_id, agent_id) VALUES ('x','y')" | grep -c 'permission denied')" "1"

R="$(curl -sk -H "$AUTH" -X POST "$AGENTS/agents/v2plain/branch")"
assert_eq "Agent API without provenance keeps its response" \
  "$(echo "$R" | python3 -c 'import sys,json; print(",".join(sorted(json.load(sys.stdin))))')" "agent,branch,dsn,host,port,status"
assert_eq "…and sets no session on the agent's branch" \
  "$(pg pg-agent-v2plain "SELECT count(*) FROM pg_db_role_setting s, unnest(s.setconfig) c WHERE c LIKE 'bb.session=%'")" "0"
curl -sk -H "$AUTH" -X DELETE "$AGENTS/agents/v2plain/branch" >/dev/null 2>&1

R="$(curl -sk -H "$AUTH" -X POST -d '{"task_id":"task-77","parent_session_id":"sess-parent-1"}' "$AGENTS/agents/v2prov/branch")"
SID="$(echo "$R" | jf 'd.get("session_id","")')"
assert_eq "Agent API with provenance returns the session, task and parent" \
  "$(echo "$R" | jf 'd["task_id"]+" "+d["parent_session_id"]+" "+str(d["session_id"].startswith("agent-"))')" "task-77 sess-parent-1 True"
assert_eq "the session is recorded on the agent's branch" \
  "$(pg pg-agent-v2prov "SELECT agent_id||'/'||task_id||'/'||parent_session_id||'/'||tool FROM bb.agent_sessions WHERE session_id='$SID'")" \
  "agent-v2prov/task-77/sess-parent-1/agent-api"
psql "$(echo "$R" | jf 'd["dsn"]')" -qc "CREATE TABLE v2prov_t(x int)" >/dev/null 2>&1
PID="$(pg pg-agent-v2prov "SELECT max(id) FROM bb.schema_ledger WHERE object_identity='public.v2prov_t'")"
assert_eq "the agent's own change carries its session, task and parent" \
  "$(pg pg-agent-v2prov "SELECT s.actor||'/'||s.session||'/'||e.task_id||'/'||e.parent_session FROM bb.schema_ledger s JOIN bb.ledger_ext e ON e.ledger_id=s.id WHERE s.id=${PID:-0}")" \
  "agent-v2prov/$SID/task-77/sess-parent-1"
assert_eq "an invalid task id is refused before any branch is made (400)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -X POST -d "{\"task_id\":\"$LONGID\"}" "$AGENTS/agents/v2bad/branch")|$(sudo docker inspect pg-agent-v2bad >/dev/null 2>&1 || echo none)" \
  "400|none"
curl -sk -H "$AUTH" -X DELETE "$AGENTS/agents/v2prov/branch" >/dev/null 2>&1

R="$(mcp_exec '{"sql":"CREATE TABLE v2exec(a int, b int)","task_id":"task-88","parent_session_id":"sess-p"}')"
assert_eq "execute_change applies a change" "$(echo "$R" | jf 'd["status"]+" "+d["command"]')|$(pg pg-main "SELECT to_regclass('public.v2exec') IS NOT NULL")" "applied CREATE TABLE|t"
EID="$(echo "$R" | jf 'd["blackbox_entries"][0] if d["blackbox_entries"] else 0')"
MSID="$(echo "$R" | jf 'd["session_id"]')"
HASH="$(echo "$R" | jf 'd["call_hash"]')"
assert_eq "…and returns the Blackbox entry it wrote" "$([ "${EID:-0}" -gt 0 ] && echo yes)" "yes"
assert_eq "the entry carries agent, tool, session, task, parent and call hash" \
  "$(pg pg-main "SELECT s.actor||'/'||s.actor_kind||'/'||s.tool||'/'||s.session||'/'||e.task_id||'/'||e.parent_session||'/'||e.call_hash FROM bb.schema_ledger s JOIN bb.ledger_ext e ON e.ledger_id=s.id WHERE s.id=${EID:-0}")" \
  "v2test-agent/agent/mcp/$MSID/task-88/sess-p/$HASH"
assert_eq "the MCP session is recorded" \
  "$(pg pg-main "SELECT agent_id||'/'||tool||'/'||task_id FROM bb.agent_sessions WHERE session_id='$MSID'")" "v2test-agent/mcp/task-88"
assert_eq "execute_change runs without superuser rights" \
  "$(mcp_exec '{"sql":"ALTER SYSTEM SET work_mem = 1024"}' | jf 'd["status"]+" "+d["error"]["code"]')" "error 42501"

R="$(mcp_exec '{"sql":"ALTER TABLE v2exec ALTER COLUMN a TYPE bigint"}')"
assert_eq "execute_change reports a policy warning (BBX02) and still applies" \
  "$(echo "$R" | jf 'd["status"]+" "+",".join(n["code"]+":"+(n["policy"]["rule_id"] if n.get("policy") else "") for n in d["notices"])+" "+",".join(m["rule_id"] for m in d["policy_preview"])')" \
  "applied BBX02:alter-column-type alter-column-type"

$S policy block drop-column >/dev/null 2>&1
R="$(mcp_exec '{"sql":"ALTER TABLE v2exec DROP COLUMN b","task_id":"task-89"}')"
assert_eq "execute_change reports a block with the policy rule (BBX01)" \
  "$(echo "$R" | jf 'd["status"]+" "+d["policy"]["rule_id"]+" "+d["error"]["code"]+" "+str(d["policy"]["blackbox_id"] in d["blackbox_entries"])')" \
  "blocked drop-column BBX01 True"
assert_eq "…and the column is still there" \
  "$(pg pg-main "SELECT count(*) FROM information_schema.columns WHERE table_name='v2exec' AND column_name='b'")" "1"
$S policy warn drop-column >/dev/null 2>&1

R="$(mcp_exec '{"sql":"CREATE TABLE v2exec_dry(x int)","dry_run":true}')"
assert_eq "dry_run only previews" "$(echo "$R" | jf 'd["status"]')|$(pg pg-main "SELECT to_regclass('public.v2exec_dry') IS NULL")" "preview|t"
R2="$(mcp_exec '{"sql":"CREATE TABLE v2exec_dry(x int)","dry_run":true}')"
R3="$(mcp_exec '{"sql":"CREATE TABLE v2exec_dry(y int)","dry_run":true}')"
assert_eq "the call hash is the same for the same arguments and differs otherwise" \
  "$([ "$(echo "$R" | jf 'd["call_hash"]')" = "$(echo "$R2" | jf 'd["call_hash"]')" ] && echo same)|$([ "$(echo "$R" | jf 'd["call_hash"]')" != "$(echo "$R3" | jf 'd["call_hash"]')" ] && echo differs)" \
  "same|differs"
assert_eq "execute_change reports a database error" \
  "$(mcp_exec '{"sql":"CREATE TABLE v2exec(a int)"}' | jf 'd["status"]+" "+d["error"]["code"]')" "error 42P07"
assert_eq "an invalid task id is refused" \
  "$(mcp_exec "{\"sql\":\"SELECT 1\",\"task_id\":\"$LONGID\"}" | grep -c 'task_id')" "1"

assert_eq "fox blackbox sessions lists the MCP session" "$($S blackbox sessions main --limit 200 | grep -c "^$MSID ")" "1"
assert_eq "REST sessions shows its entries" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/blackbox/sessions?limit=200" | python3 -c 'import sys,json; print([s["entries"] >= 1 for s in json.load(sys.stdin) if s["session_id"]==sys.argv[1]])' "$MSID")" "[True]"
assert_eq "the hash chain still verifies" \
  "$(curl -sk -H "$AUTH" "$API/api/branches/main/ledger/verify" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0][2])')" "0"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS v2exec; DROP TABLE IF EXISTS v2exec_dry" >/dev/null

echo "### 8. impact analysis and Blackbox diff"
for b in v2imp-br v2diff-a; do $S branch delete "$b" >/dev/null 2>&1; done
$S policy warn drop-column >/dev/null 2>&1
drop_imp() {
  pg pg-main "SET bb.allow_destructive=on; DROP VIEW IF EXISTS v2imp_big; DROP VIEW IF EXISTS v2imp_totals; DROP TABLE IF EXISTS v2imp_items; DROP TABLE IF EXISTS v2imp_orders; DROP TABLE IF EXISTS v2imp_mainonly; DROP TABLE IF EXISTS v2diff_main_only" >/dev/null
}
drop_imp
gw "$KEY" main "CREATE TABLE v2imp_orders(id int PRIMARY KEY, total numeric, note text)" >/dev/null
gw "$KEY" main "CREATE TABLE v2imp_items(id int, order_id int REFERENCES v2imp_orders(id))" >/dev/null
gw "$KEY" main "CREATE VIEW v2imp_totals AS SELECT id, total FROM v2imp_orders" >/dev/null
gw "$KEY" main "CREATE VIEW v2imp_big AS SELECT * FROM v2imp_totals WHERE total > 100" >/dev/null
gw "$KEY" main "CREATE INDEX v2imp_note_idx ON v2imp_orders(note)" >/dev/null

R="$($S impact "DROP TABLE v2imp_orders" --json)"
assert_eq "impact: the table is found and the change is destructive" \
  "$(echo "$R" | jf 'str(d["found"])+" "+d["action"]+" "+str(d["destructive"])+" "+d["target"]+" "+d["type"]')" "True drop True public.v2imp_orders table"
assert_eq "impact: the view on it (depth 1)" \
  "$(echo "$R" | jf '[(x["type"], x["depth"]) for x in d["dependents"] if x["identity"]=="public.v2imp_totals"]')" "[('view', 1)]"
assert_eq "impact: the view on that view (depth 2, via the first)" \
  "$(echo "$R" | jf '[(x["depth"], x["via"]) for x in d["dependents"] if x["identity"]=="public.v2imp_big"]')" "[(2, 'public.v2imp_totals')]"
assert_eq "impact: the foreign key from another table" \
  "$(echo "$R" | jf 'len([x for x in d["dependents"] if x["type"]=="table constraint" and x["relation"]=="public.v2imp_items" and not x["same_relation"]])')" "1"
assert_eq "impact: the index on it" \
  "$(echo "$R" | jf '[(x["relation"], x["same_relation"]) for x in d["dependents"] if x["identity"]=="public.v2imp_note_idx"]')" "[('public.v2imp_orders', True)]"
assert_eq "impact: scored high, with reasons" \
  "$(echo "$R" | jf 'd["level"]+" "+str(d["score"] >= 15)+" "+str(len(d["reasons"]) > 1)')" "high True True"
assert_eq "impact on a column: only what uses that column" \
  "$($S impact "ALTER TABLE v2imp_orders DROP COLUMN total" --json | jf 'd["column"]+" "+d["action"]+" "+",".join(sorted(x["identity"] for x in d["dependents"]))')" \
  "total drop-column public.v2imp_big,public.v2imp_totals"
assert_eq "impact on another column: its index, not the views" \
  "$($S impact "ALTER TABLE v2imp_orders DROP COLUMN note" --json | jf '",".join(sorted(x["identity"] for x in d["dependents"]))')" "public.v2imp_note_idx"
assert_eq "impact reads quoted, schema-qualified names" \
  "$($S impact 'ALTER TABLE public."v2imp_orders" ALTER COLUMN "total" TYPE bigint' --json | jf 'd["target"]+" "+d["column"]+" "+d["action"]')" \
  "public.v2imp_orders total alter-column-type"
assert_eq "a new index is not destructive" \
  "$($S impact "CREATE INDEX v2imp_total_idx ON v2imp_orders(total)" --json | jf 'd["action"]+" "+str(d["destructive"])')" "create-index False"
assert_eq "a missing object is reported, not an error" \
  "$($S impact "DROP TABLE v2imp_nope" --json | jf 'str(d["found"])+" "+d["level"]')" "False none"
assert_eq "a statement without a target asks for --object" "$($S impact "SELECT 1" 2>&1 | grep -c -- '--object')" "1"
assert_eq "--object on a view finds the view built on it" \
  "$($S impact --object v2imp_totals --json | jf '",".join(x["identity"] for x in d["dependents"])')" "public.v2imp_big"
assert_eq "the depth limit is reported (as a client)" \
  "$(gw "$KEY" main "SELECT bb.blast_radius('v2imp_orders', NULL, 1)->>'truncated'")" "true"

$S branch create v2imp-br >/dev/null 2>&1
gw "$KEY" main "CREATE TABLE v2imp_mainonly(x int)" >/dev/null
assert_eq "impact: a branch cloned after the object existed has it (with its parent)" \
  "$($S impact "DROP TABLE v2imp_orders" --json | jf '[(x["present"], x["parent"]) for x in d["branches"] if x["branch"]=="v2imp-br"]')" "[(True, 'main')]"
assert_eq "impact: a newer object isn't on that branch" \
  "$($S impact "DROP TABLE v2imp_mainonly" --json | jf '[x["present"] for x in d["branches"] if x["branch"]=="v2imp-br"]')" "[False]"

$S policy block drop-column >/dev/null 2>&1
assert_eq "impact includes the policy verdict in its score" \
  "$($S impact "ALTER TABLE v2imp_orders DROP COLUMN total" --json | jf '",".join(p["rule_id"]+":"+p["action"] for p in d["policy"])+" "+str(any("would block" in r for r in d["reasons"]))')" \
  "drop-column:block True"
$S policy warn drop-column >/dev/null 2>&1

assert_eq "REST impact matches the CLI" \
  "$(curl -sk -X POST -H "$AUTH" -d '{"sql":"DROP TABLE v2imp_orders"}' "$API/api/branches/main/impact" | jf 'd["target"]+" "+str(len(d["dependents"]))')" \
  "$($S impact "DROP TABLE v2imp_orders" --json | jf 'd["target"]+" "+str(len(d["dependents"]))')"
assert_eq "REST impact without sql or object is 400" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" -d '{}' "$API/api/branches/main/impact")" "400"
assert_eq "MCP impact" \
  "$(mcp_call impact '{"sql":"ALTER TABLE v2imp_orders DROP COLUMN total"}' | jf 'd["column"]+" "+str(d["level"] in ("low","medium","high"))')" "total True"
assert_eq "execute_change includes the impact" \
  "$(mcp_exec '{"sql":"ALTER TABLE v2imp_orders DROP COLUMN total","dry_run":true}' | jf 'd["status"]+" "+d["impact"]["target"]+" "+d["impact"]["column"]')" \
  "preview public.v2imp_orders total"

$S branch create v2diff-a >/dev/null 2>&1
$S branch owner v2diff-a "$USER_EMAIL" >/dev/null 2>&1
gw "$KEY" main "CREATE TABLE v2diff_main_only(x int)" >/dev/null
gw "$KEY" main "ALTER TABLE v2imp_orders ADD COLUMN on_main int" >/dev/null
gw "$KEY" v2diff-a "CREATE TABLE v2diff_branch_only(x int)" >/dev/null
gw "$KEY" v2diff-a "ALTER TABLE v2imp_orders ADD COLUMN on_branch int" >/dev/null
D="$($S blackbox diff main v2diff-a --json)"
assert_eq "diff: the branch's parent and shared history" \
  "$(echo "$D" | jf 'd["b_parent"]+" "+str(d["common_entries"] > 0)+" "+str(d["fork_after_id"] > 0)')" "main True True"
assert_eq "diff: changes only on main" \
  "$(echo "$D" | jf '",".join(sorted(set(x["object_identity"] for x in d["a_only"])))')" "public.v2diff_main_only,public.v2imp_orders"
assert_eq "diff: changes only on the branch" \
  "$(echo "$D" | jf '",".join(sorted(set(x["object_identity"] for x in d["b_only"])))')" "public.v2diff_branch_only,public.v2imp_orders"
assert_eq "diff: the object both changed" \
  "$(echo "$D" | jf '",".join(o["object_identity"] for o in d["both_touched"])')" "public.v2imp_orders"
assert_eq "fox branch diff gives the same diff" \
  "$($S branch diff main v2diff-a --json | jf '(len(d["a_only"]), len(d["b_only"]), len(d["both_touched"]))')" \
  "$(echo "$D" | jf '(len(d["a_only"]), len(d["b_only"]), len(d["both_touched"]))')"
assert_eq "diff: text output names both sides" \
  "$($S branch diff main v2diff-a | grep -c 'only on main\|only on v2diff-a\|changed on both')" "3"
assert_eq "diff of a branch with itself is empty" \
  "$($S blackbox diff main main --json | jf 'len(d["a_only"]) + len(d["b_only"]) + len(d["both_touched"])')" "0"
assert_eq "REST diff on both paths" \
  "$(curl -sk -H "$AUTH" "$API/api/ledger/diff?a=main&b=v2diff-a" | jf 'len(d["both_touched"])')|$(curl -sk -H "$AUTH" "$API/api/blackbox/diff?a=main&b=v2diff-a" | jf 'len(d["both_touched"])')" \
  "1|1"
assert_eq "REST diff with an unknown branch is 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "$API/api/ledger/diff?a=main&b=v2nope")" "404"
assert_eq "MCP blackbox_diff" \
  "$(mcp_call blackbox_diff '{"a":"main","b":"v2diff-a"}' | jf '",".join(o["object_identity"] for o in d["both_touched"])')" "public.v2imp_orders"

for b in v2imp-br v2diff-a; do $S branch delete "$b" >/dev/null 2>&1; done
drop_imp

echo "### 9. a restart records nothing in the Blackbox (H1)"
# The Blackbox's install script re-runs on every start. It used to create the
# event triggers before its own GRANT/REVOKE/ALTER DEFAULT PRIVILEGES block, so
# every start appended those nine statements as unattributed schema changes.
$S branch create v2restart >/dev/null 2>&1
M0="$(pg pg-main 'SELECT count(*) FROM bb.schema_ledger')"
B0="$(pg pg-v2restart 'SELECT count(*) FROM bb.schema_ledger')"
$S stop >/dev/null 2>&1; $S start >/dev/null 2>&1
$S branch resume v2restart >/dev/null 2>&1
assert_eq "a stop and start adds nothing to main's Blackbox" "$(pg pg-main 'SELECT count(*) FROM bb.schema_ledger')" "$M0"
assert_eq "…nor to a branch's" "$(pg pg-v2restart 'SELECT count(*) FROM bb.schema_ledger')" "$B0"
assert_eq "…and none of its entries is the install's own GRANT with no actor" \
  "$(pg pg-main "SELECT count(*) FROM bb.schema_ledger WHERE id > $M0 AND command_tag IN ('GRANT','REVOKE','ALTER DEFAULT PRIVILEGES')")" "0"
gw "$KEY" main "CREATE TABLE v2restart_t (x int)" >/dev/null
assert_eq "a user's change is still recorded, as that user" \
  "$(pg pg-main "SELECT count(*) || '|' || max(actor) FROM bb.schema_ledger WHERE id > $M0 AND object_identity = 'public.v2restart_t'")" "1|$USER_EMAIL"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE v2restart_t" >/dev/null
$S branch delete v2restart >/dev/null 2>&1

echo
echo "==== ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ]
