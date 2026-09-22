#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# End-to-end integration test. Run inside the Linux dev VM (ZFS + Docker):
#   lima bash "/Users/.../Distributed Database/scripts/integration_test.sh"
# Exits non-zero if any assertion fails.
set -uo pipefail

# Refuses to run anywhere but the throwaway test VM (see scripts/lib/test_guard.sh).
# A guard that can't be found must stop the suite, not let it carry on.
. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
# Names in one place (generated from brand.json by `make brand`).
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

S="${FOX_BIN:-/tmp/fox}"
# The Gateway authenticates with an API key, passed via PGPASSWORD where used.
GATEWAY="postgresql://dbadmin@127.0.0.1:6432"
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
# pg <container> <sql>  -> tuples-only result
pg() { local c="$1"; shift; sudo docker exec -e PGPASSWORD=foxbyte "$c" psql -U dbadmin -d appdb -tAc "$*" 2>/dev/null; }
jget() { python3 -c 'import sys,json; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

echo "### 0. a foreign container named \"minio\" does not break the stack"
# The object store used to be called plainly "minio". A container of that name
# is common on a developer's machine, and the two collided: `setup` found the
# foreign one, skipped creating its own, and then waited for ever for it on a
# network it was never attached to -- printing one DNS error per second.
$S stop >/dev/null 2>&1; sleep 1
sudo docker rm -f minio >/dev/null 2>&1
sudo docker run -d --name minio --network bridge alpine:3 sleep 600 >/dev/null 2>&1
START_OUT="$(timeout 600 $S start 2>&1)"; START_RC=$?
[ "$START_RC" = 0 ] || { echo "--- start output ---"; echo "$START_OUT" | tail -20; echo "--- end ---"; }
assert_eq "start succeeds with a foreign \"minio\" present" "$START_RC" "0"
# The stack has just come up for the first time in this VM; give the servers a
# moment before anything connects to them.
sleep 5
assert_eq "…and the object store is ours, on our network" \
  "$(sudo docker inspect -f '{{.State.Running}}' "$DB_OBJECT_STORE" 2>/dev/null)|$(sudo docker inspect -f '{{json .NetworkSettings.Networks}}' "$DB_OBJECT_STORE" 2>/dev/null | grep -c "$DB_NETWORK")" "true|1"
assert_eq "…and the foreign container is untouched" "$(sudo docker inspect -f '{{.State.Running}}' minio 2>/dev/null)" "true"
sudo docker rm -f minio >/dev/null 2>&1

echo "### 1. fresh start + auth"
$S stop >/dev/null 2>&1; sleep 1
# E3: start creates no account and mints no key. A credential is made by the
# person who will use it, not by a background service and left in a file.
rm -rf "$HOME/$BRAND_STATE_DIR/config"
# "The first account" needs an empty account store. A run cut short leaves its
# accounts behind, and then this account is not the first and gets no grant.
rm -f "$HOME/$BRAND_STATE_DIR"/auth.db "$HOME/$BRAND_STATE_DIR"/auth.db-wal "$HOME/$BRAND_STATE_DIR"/auth.db-shm
BANNER="$($S start 2>&1)"; sleep 5
assert_eq "start prints no API key" "$(echo "$BANNER" | grep -c "$DB_KEY_PREFIX[A-Za-z0-9]")" "0"
assert_eq "…and caches none on disk" "$([ -f "$HOME/$BRAND_STATE_DIR/config" ] && echo present || echo none)" "none"
assert_eq "…and says how to make one" "$(echo "$BANNER" | grep -c 'apikey create')" "1"
# Audit v2 G03: the first account is the admin, so the web sign-up needs the
# setup token start printed, and sign-up is closed after it by default.
SETUP_TOKEN="$($S setup-token 2>/dev/null)"
assert_eq "start prints the setup token, and setup-token shows the same one"   "$([ -n "$SETUP_TOKEN" ] && echo "$BANNER" | grep -c -- "$SETUP_TOKEN")" "1"
assert_eq "…kept readable by its owner only" "$(stat -c %a "$HOME/$BRAND_STATE_DIR/setup-token")" "600"
reg() { curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -X POST -d "$1" https://localhost:8080/auth/register; }
assert_eq "providers says this is the first account" "$(curl -sk https://localhost:8080/auth/providers | jget setup)" "True"
assert_eq "the first account without the token is refused" "$(reg '{"email":"x@foxbyte.dev","password":"password123"}')" "403"
assert_eq "…and with a wrong one" "$(reg '{"email":"x@foxbyte.dev","password":"password123","setup_token":"nope"}')" "403"
printf 'password123\n' | $S user create test@foxbyte.dev >/dev/null 2>&1 || true
assert_eq "the token is gone once the first account exists" \
  "$([ -e "$HOME/$BRAND_STATE_DIR/setup-token" ] && echo present || echo gone)|$($S setup-token 2>&1 | grep -c 'already has its first account')" "gone|1"
assert_eq "sign-up is closed by default, even with the old token" \
  "$(reg "{\"email\":\"y@foxbyte.dev\",\"password\":\"password123\",\"setup_token\":\"$SETUP_TOKEN\"}")|$(curl -sk https://localhost:8080/auth/providers | jget signup)" "403|False"
assert_eq "the first account may override the guardrail" \
  "$(pg pg-main "SELECT pg_has_role('test@foxbyte.dev','$DB_ADMIN_ROLE','member')")" "t"
KEY="$($S apikey create test@foxbyte.dev ci 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
AUTH="Authorization: Bearer $KEY"
assert_eq "unauthenticated API is rejected" "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8080/api/status)" "401"
assert_eq "control plane reports main ready" "$(curl -sk -H "$AUTH" https://localhost:8080/api/status | jget mainReady)" "True"
assert_eq "gateway rejects a bad key" "$(PGPASSWORD=nope psql "$GATEWAY/main" -tAc 'select 1' 2>&1 | grep -c 'invalid API key' | awk '{print ($1 >= 1)}')" "1"
assert_eq "gateway accepts the API key" "$(PGPASSWORD="$KEY" psql "$GATEWAY/main" -tAc 'select 1' 2>/dev/null)" "1"

# B1: `fox vm` is implemented; on Linux there is no VM to show or enter.
assert_eq "fox vm on Linux says there is no VM" "$($S vm 2>&1 | grep -c 'there is no VM')|$($S vm >/dev/null 2>&1; echo $?)" "1|0"
assert_eq "fox vm shell on Linux fails with a reason" "$($S vm shell 2>&1 | grep -c 'no VM to open a shell in')|$($S vm shell >/dev/null 2>&1; echo $?)" "1|1"
assert_eq "fox vm rejects an unknown subcommand" "$($S vm reboot >/dev/null 2>&1; echo $?)" "1"

# G5: the console, API and OAuth callbacks are served over https on :8080, so the
# defaults point there (they pointed at http:// and a retired dev server on :5173).
COOKIE="$(curl -sk -i -X POST -H 'Content-Type: application/json' -d '{"email":"test@foxbyte.dev","password":"password123"}' https://localhost:8080/auth/login | grep -i '^set-cookie:')"
assert_eq "login sets a Secure, SameSite=Lax session cookie" \
  "$(echo "$COOKIE" | grep -ci 'secure')|$(echo "$COOKIE" | grep -ci 'samesite=lax')" "1|1"
$S stop >/dev/null 2>&1; sleep 1
FOX_GITHUB_CLIENT_ID=it-client FOX_GITHUB_CLIENT_SECRET=it-secret $S start >/dev/null 2>&1; sleep 5
assert_eq "OAuth calls back to https://localhost:8080 by default" \
  "$(curl -sk -o /dev/null -w '%{redirect_url}' https://localhost:8080/auth/oauth/github | grep -c 'redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Fauth%2Foauth%2Fgithub%2Fcallback')" "1"
$S stop >/dev/null 2>&1; sleep 1
$S start >/dev/null 2>&1; sleep 5

echo "### 1c. safe defaults (audit v2: G07, G08, G09, N1, N2, N4)"
listening() { sudo ss -ltnH "sport = :$1" | awk '{print $4}' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
assert_eq "the control plane listens on loopback only" "$(listening 8080)" "127.0.0.1:8080"
assert_eq "the Gateway listens on loopback only" "$(listening 6432)" "127.0.0.1:6432"
assert_eq "the Agent API listens on loopback only" "$(listening 8088)" "127.0.0.1:8088"
assert_eq "the object store is published on loopback only" \
  "$(sudo docker port "$DB_OBJECT_STORE" | grep -vc -- '-> 127.0.0.1:')" "0"
assert_eq "a branch name that decodes to a path is refused (400)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -X DELETE 'https://localhost:8080/api/branches/x%2F..%2Fmain')" "400"
assert_eq "…and main is still there" "$(pg pg-main 'SELECT 1')" "1"
assert_eq "an agent id that decodes to a path is refused (400)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -X DELETE 'https://localhost:8088/agents/..%2Fmain/branch')" "400"
assert_eq "a pipeline whose source is a file on the server is refused" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' -X POST \
     -d "{\"name\":\"steal\",\"spec\":{\"source\":\"$HOME/$BRAND_STATE_DIR/secrets.json\"}}" https://localhost:8080/api/pipelines)" "400"
$S branch delete itowned >/dev/null 2>&1
$S branch create itowned >/dev/null 2>&1
pg pg-itowned "CREATE TABLE mine(x int); INSERT INTO mine VALUES (7);" >/dev/null
PL_ID="$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d '{"name":"itowned","spec":{"source":"postgres://nobody@127.0.0.1:1/none"}}' https://localhost:8080/api/pipelines | jget id)"
assert_eq "a pipeline named after a branch it did not make refuses to run" \
  "$(curl -sk -N -H "$AUTH" -X POST "https://localhost:8080/api/pipelines/$PL_ID/run" | grep -c 'was not made by this pipeline')" "1"
assert_eq "…and that branch keeps its data" "$(pg pg-itowned 'SELECT x FROM mine')" "7"
curl -sk -o /dev/null -H "$AUTH" -X DELETE "https://localhost:8080/api/pipelines/$PL_ID"
$S branch delete itowned >/dev/null 2>&1

echo "### 1d. accounts own their branches (audit v2: G02, G10, G12, G16)"
# test@ is the first account (an admin). alice and bob are ordinary accounts.
for who in alice bob; do $S user delete "$who@foxbyte.dev" >/dev/null 2>&1; printf 'password123\n' | $S user create "$who@foxbyte.dev" >/dev/null 2>&1; done
KA="$($S apikey create alice@foxbyte.dev it 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
KB="$($S apikey create bob@foxbyte.dev it 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
as() { local k="$1"; shift; curl -sk -H "Authorization: Bearer $k" "$@"; }
code() { local k="$1"; shift; curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $k" "$@"; }
$S branch delete alice-dev >/dev/null 2>&1
assert_eq "alice makes a branch" \
  "$(code "$KA" -H 'Content-Type: application/json' -X POST -d '{"name":"alice-dev"}' https://localhost:8080/api/branches)" "201"
pg pg-alice-dev "CREATE TABLE secret(x int); INSERT INTO secret VALUES (42);" >/dev/null
assert_eq "bob's branch list does not show it" "$(as "$KB" https://localhost:8080/api/branches | grep -c 'alice-dev')" "0"
assert_eq "…alice's does, and the admin's" \
  "$(as "$KA" https://localhost:8080/api/branches | grep -c 'alice-dev')|$(as "$KEY" https://localhost:8080/api/branches | grep -c 'alice-dev')" "1|1"
assert_eq "bob cannot read, query, suspend or delete it (404 each)" \
  "$(code "$KB" https://localhost:8080/api/branches/alice-dev/ledger)|$(code "$KB" -H 'Content-Type: application/json' -X POST -d '{"sql":"select * from secret"}' https://localhost:8080/api/branches/alice-dev/query)|$(code "$KB" -X POST https://localhost:8080/api/branches/alice-dev/suspend)|$(code "$KB" -X DELETE https://localhost:8080/api/branches/alice-dev)" "404|404|404|404"
assert_eq "…nor copy it" \
  "$(code "$KB" -H 'Content-Type: application/json' -X POST -d '{"name":"bob-copy","from":"alice-dev"}' https://localhost:8080/api/branches)" "404"
assert_eq "…nor open it through the Gateway" \
  "$(PGPASSWORD="$KB" psql "$GATEWAY/alice-dev?sslmode=require" -tAc 'select x from secret' 2>&1 | grep -c 'no branch')" "1"
assert_eq "alice opens it through the Gateway" "$(PGPASSWORD="$KA" psql "$GATEWAY/alice-dev?sslmode=require" -tAc 'select x from secret' 2>/dev/null)" "42"
assert_eq "bob uses main, but may not manage it" \
  "$(PGPASSWORD="$KB" psql "$GATEWAY/main?sslmode=require" -tAc 'select 1' 2>/dev/null)|$(code "$KB" -X POST https://localhost:8080/api/branches/main/ledger/checkpoint)" "1|403"
# A branch made at the CLI is an admin's until it is handed to someone.
$S branch delete itcli >/dev/null 2>&1; $S branch create itcli >/dev/null 2>&1
assert_eq "a CLI branch has no owner, and bob cannot reach it" \
  "$($S branch owner itcli | grep -c 'no owner')|$(code "$KB" https://localhost:8080/api/branches/itcli/ledger)" "1|404"
$S branch owner itcli bob@foxbyte.dev >/dev/null
assert_eq "fox branch owner hands it to bob" \
  "$($S branch owner itcli | grep -c 'bob@foxbyte.dev')|$(code "$KB" https://localhost:8080/api/branches/itcli/ledger)" "1|200"
$S branch delete itcli >/dev/null 2>&1
# Agents belong to the account that asked for them.
curl -sk -o /dev/null -H "Authorization: Bearer $KA" -X DELETE https://localhost:8088/agents/itown/branch
assert_eq "alice starts an agent" "$(code "$KA" -X POST https://localhost:8088/agents/itown/branch)" "201"
assert_eq "bob does not see it, and cannot delete it" \
  "$(as "$KB" https://localhost:8088/agents | grep -c 'agent-itown')|$(code "$KB" -X DELETE https://localhost:8088/agents/itown/branch)" "0|404"
assert_eq "…its key is alice's, not the first account's" "$($S apikey list alice@foxbyte.dev 2>/dev/null | grep -c 'agent agent-itown')" "1"
assert_eq "alice deletes her agent" "$(code "$KA" -X DELETE https://localhost:8088/agents/itown/branch)" "200"
# Imports reach public databases; this machine, private networks and metadata are not for bob.
imp() { as "$1" -N -H 'Content-Type: application/json' -X POST -d "{\"source\":\"$2\"}" https://localhost:8080/api/import; }
assert_eq "bob cannot import from this machine" "$(imp "$KB" 'postgres://x@127.0.0.1:5432/x' | grep -c 'only an admin')" "1"
assert_eq "…nor from a container name" "$(imp "$KB" "postgres://x@$DB_OBJECT_STORE:9000/x" | grep -c 'only an admin')" "1"
assert_eq "nobody imports from a metadata address" "$(imp "$KEY" 'postgres://x@169.254.169.254/x' | grep -c 'metadata addresses are refused')" "1"
# Every role has its own password: the install secret no longer opens db_client.
SECRET="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pg_password"])' "$HOME/$BRAND_STATE_DIR/secrets.json")"
assert_eq "the install secret does not log in as db_client" \
  "$(sudo docker exec -e PGPASSWORD="$SECRET" pg-alice-dev psql -h pg-main -U "$DB_CLIENT_ROLE" -d "$DB_DATABASE" -tAc 'select 1' 2>&1 | grep -c 'password authentication failed')" "1"
assert_eq "…and the engine's password file is its owner's only" "$(stat -c %a "$HOME/$BRAND_STATE_DIR/pg.env")" "600"
# Accounts: admins list and delete; everyone changes their own password.
assert_eq "bob may not list accounts; the admin may" \
  "$(code "$KB" https://localhost:8080/api/users)|$(as "$KEY" https://localhost:8080/api/users | grep -c 'bob@foxbyte.dev')" "403|1"
BCOOKIE="$(mktemp)"
curl -sk -c "$BCOOKIE" -o /dev/null -H 'Content-Type: application/json' -d '{"email":"bob@foxbyte.dev","password":"password123"}' https://localhost:8080/auth/login
assert_eq "bob changes his password" \
  "$(curl -sk -b "$BCOOKIE" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -X POST -d '{"current":"password123","new":"password456"}' https://localhost:8080/api/account/password)" "200"
assert_eq "…the old one no longer signs in" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"email":"bob@foxbyte.dev","password":"password123"}' https://localhost:8080/auth/login)" "401"
BOB_ID="$(as "$KEY" https://localhost:8080/api/users | python3 -c 'import sys,json;print([u["id"] for u in json.load(sys.stdin)["users"] if u["email"]=="bob@foxbyte.dev"][0])')"
assert_eq "the admin deletes bob, and his key stops working" \
  "$(code "$KEY" -X DELETE "https://localhost:8080/api/users/$BOB_ID")|$(code "$KB" https://localhost:8080/api/status)" "200|401"
rm -f "$BCOOKIE"
# Audit v2 G28: all of that is in the security log, which is chained and anchored.
AUDIT="$($S audit --limit 500)"
assert_eq "the security log records failed sign-ins, refusals, keys and deletions" \
  "$(echo "$AUDIT" | grep -c 'login.failed' | awk '{print ($1>0)}')|$(echo "$AUDIT" | grep -c 'access.denied' | awk '{print ($1>0)}')|$(echo "$AUDIT" | grep -c 'key.created' | awk '{print ($1>0)}')|$(echo "$AUDIT" | grep 'account.deleted' | grep -c 'bob@foxbyte.dev')" "1|1|1|1"
assert_eq "…and who changed a password" "$(echo "$AUDIT" | grep 'account.password_changed' | grep -c 'bob@foxbyte.dev')" "1"
assert_eq "admins read it over the API; others may not" \
  "$(as "$KEY" 'https://localhost:8080/api/audit?limit=5' | grep -c '"row_hash"' | awk '{print ($1>0)}')|$(code "$KA" https://localhost:8080/api/audit)" "1|403"
assert_eq "it anchors, signed" "$($S audit checkpoint | grep -c 'signed by key')" "1"
assert_eq "…and verifies" "$($S audit verify | grep -c 'security log intact')" "1"
python3 - "$HOME/$BRAND_STATE_DIR/auth.db" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute("DROP TRIGGER security_events_no_update")
c.execute("UPDATE security_events SET actor='someone-else' WHERE id=(SELECT min(id) FROM security_events WHERE kind='login.failed')"); c.commit()
PY
assert_eq "an edited event is caught (exit 1)" "$($S audit verify >/dev/null 2>&1; echo $?)|$($S audit verify | grep -c 'TAMPERED')" "1|1"
curl -sk -o /dev/null -H "Authorization: Bearer $KA" -X DELETE https://localhost:8080/api/branches/alice-dev

echo "### 2. branch isolation"
$S branch delete itb >/dev/null 2>&1
$S branch create itb >/dev/null 2>&1
pg pg-itb "CREATE TABLE iso(x int); INSERT INTO iso VALUES (1);" >/dev/null
assert_eq "branch sees its own write" "$(pg pg-itb 'SELECT count(*) FROM iso')" "1"
assert_eq "main isolated from branch" "$(pg pg-main "SELECT to_regclass('public.iso') IS NULL")" "t"

# B1: branch create --from copies another branch, not main.
$S branch delete itfrom >/dev/null 2>&1
$S branch create itfrom --from itb >/dev/null 2>&1
assert_eq "branch create --from copies that branch's data" "$(pg pg-itfrom 'SELECT count(*) FROM iso')" "1"
assert_eq "…and main still doesn't have it" "$(pg pg-main "SELECT to_regclass('public.iso') IS NULL")" "t"
assert_eq "branch create --from a missing branch says so" "$($S branch create itnope --from no-such-branch 2>&1 | grep -c 'no branch to create from')" "1"
assert_eq "REST: from a missing branch is 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' -X POST -d '{"name":"itnope","from":"no-such-branch"}' https://localhost:8080/api/branches)" "404"
$S branch delete itfrom >/dev/null 2>&1
assert_eq "REST: create from a branch (201, names the parent)" \
  "$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST -d '{"name":"itfrom","from":"itb"}' https://localhost:8080/api/branches | jget from)|$(pg pg-itfrom 'SELECT count(*) FROM iso')" "itb|1"
$S branch delete itfrom >/dev/null 2>&1

echo "### 3. time-travel / PITR"
# The guardrail blocks DROP TABLE without the override, which silently kept the
# previous run's rows (failback now keeps writes made during a failover).
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS pit; CREATE TABLE pit(id int); INSERT INTO pit SELECT generate_series(1,3);" >/dev/null
$S backup create >/dev/null 2>&1
pg pg-main "SELECT pg_switch_wal();" >/dev/null; sleep 3
$S restore --to latest >/dev/null 2>&1; sleep 1
assert_eq "PITR restores 3 rows" "$(pg pg-restore 'SELECT count(*) FROM pit')" "3"
sudo docker rm -f pg-restore >/dev/null 2>&1

echo "### 3b. PITR to a point before the newest base backup (D3)"
# The restore used to fetch LATEST whatever the target was, so a point earlier
# than the newest base backup could not be reached: recovery started after it.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS tt; CREATE TABLE tt(id int);" >/dev/null
$S backup create >/dev/null 2>&1                       # base backup A, before everything below
pg pg-main "INSERT INTO tt SELECT generate_series(1,3);" >/dev/null
pg pg-main "SELECT pg_switch_wal();" >/dev/null; sleep 3
T1="$(pg pg-main "SELECT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') || '+00'")"
sleep 2
pg pg-main "INSERT INTO tt SELECT generate_series(4,9);" >/dev/null
$S backup create >/dev/null 2>&1                       # base backup B, finished AFTER T1
pg pg-main "SELECT pg_switch_wal();" >/dev/null; sleep 4
# The new read-only listing: newest first, with the newest flagged.
BK="$(curl -sk -H "$AUTH" https://localhost:8080/api/backups)"
assert_eq "the API lists base backups, newest first, flagging the newest" \
  "$(echo "$BK" | python3 -c 'import sys,json; b=json.load(sys.stdin); print(len(b) >= 2, b[0].get("newest") is True, b[0]["finished_at"] > b[-1]["finished_at"])')" "True True True"
NEWEST="$(echo "$BK" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["name"])')"
OUT="$($S restore --to "$T1" 2>&1)"; sleep 1
assert_eq "restore says which base backup it starts from" "$(echo "$OUT" | grep -c 'starting from base backup')" "1"
assert_eq "…and it is not the newest one" "$(echo "$OUT" | grep -c "$NEWEST")" "0"
assert_eq "PITR reaches a point before the newest backup (3 rows, not 9)" "$(pg pg-restore 'SELECT count(*) FROM tt')" "3"
sudo docker rm -f pg-restore >/dev/null 2>&1
# A point no base backup precedes is refused, saying what the archive reaches.
OLD="$($S restore --to '2020-01-01 00:00:00+00' 2>&1)"
assert_eq "a point before every base backup is refused" "$(echo "$OLD" | grep -c 'no base backup had finished by')" "1"
assert_eq "…the refusal names the oldest backup" "$(echo "$OLD" | grep -c 'the oldest is from')" "1"
assert_eq "…and nothing was left behind" "$(sudo docker ps -aq --filter 'name=^pg-restore$' | wc -l | tr -d ' ')" "0"
# latest still works exactly as before.
$S restore --to latest >/dev/null 2>&1; sleep 1
assert_eq "restore --to latest still reaches the end of the archive (9 rows)" "$(pg pg-restore 'SELECT count(*) FROM tt')" "9"
sudo docker rm -f pg-restore >/dev/null 2>&1

echo "### 4. suspend / resume"
$S branch suspend itb >/dev/null 2>&1
assert_eq "branch suspends" "$(sudo docker inspect -f '{{.State.Status}}' pg-itb 2>/dev/null)" "exited"
$S branch resume itb >/dev/null 2>&1
assert_eq "branch resumes" "$(sudo docker inspect -f '{{.State.Status}}' pg-itb 2>/dev/null)" "running"
$S branch suspend main >/dev/null 2>&1
assert_eq "suspending main is refused" "$?" "1"
assert_eq "main keeps running" "$(sudo docker inspect -f '{{.State.Status}}' pg-main 2>/dev/null)" "running"

echo "### 5. agent branch API"
RESP="$(curl -sk -H "$AUTH" -X POST https://localhost:8088/agents/itest/branch)"
DSN="$(echo "$RESP" | jget dsn)"
psql "$DSN" -c "CREATE TABLE a(x int); INSERT INTO a VALUES (7);" >/dev/null 2>&1
assert_eq "agent DB is usable via its DSN" "$(psql "$DSN" -tAc 'SELECT x FROM a' 2>/dev/null)" "7"
curl -sk -H "$AUTH" -X DELETE https://localhost:8088/agents/itest/branch >/dev/null
# The DSN carries a key scoped to that branch, and deleting the branch revokes it.
assert_eq "the agent's key dies with its branch" \
  "$(psql "$DSN" -tAc 'SELECT 1' 2>&1 | grep -c 'invalid API key')" "1"

echo "### 5b. continuous import: status and cutover from the API (I8)"
# A real PostgreSQL source with logical replication, on the stack's network,
# running the same image main does.
IMG="$(sudo docker inspect -f '{{.Config.Image}}' pg-main)"
sudo docker rm -f itsrc >/dev/null 2>&1; $S branch delete itrep >/dev/null 2>&1
sudo docker run -d --name itsrc --network "$DB_NETWORK" -e POSTGRES_PASSWORD=srcpw "$IMG" postgres -c wal_level=logical >/dev/null
for i in $(seq 1 60); do sudo docker exec itsrc pg_isready -U postgres -q && break; sleep 1; done
sudo docker exec itsrc psql -U postgres -q -c "CREATE TABLE items(id int PRIMARY KEY, v text); INSERT INTO items VALUES (1,'a'),(2,'b'),(3,'c');" >/dev/null
SSE="$(curl -sk -N --max-time 180 -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  -d '{"source":"postgresql://postgres:srcpw@itsrc:5432/postgres","target":"itrep","continuous":true}' https://localhost:8080/api/import)"
assert_eq "continuous import starts replicating into its branch" \
  "$(echo "$SSE" | grep -A1 '^event: done' | grep -c '"status":"replicating"')" "1"
repl() { curl -sk -H "$AUTH" https://localhost:8080/api/branches/itrep/replication; }
for i in $(seq 1 60); do [ "$(repl | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["tables"] > 0 and d["tables_ready"] == d["tables"])')" = True ] && break; sleep 1; done
assert_eq "status: the initial copy finishes (1 of 1 tables)" \
  "$(repl | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["replicating"], d["tables_ready"], d["tables"])')" "True 1 1"
assert_eq "the initial copy has the rows" "$(pg pg-itrep 'SELECT count(*) FROM items')" "3"
sudo docker exec itsrc psql -U postgres -q -c "INSERT INTO items VALUES (4,'d')" >/dev/null
for i in $(seq 1 30); do [ "$(pg pg-itrep 'SELECT count(*) FROM items')" = 4 ] && break; sleep 1; done
assert_eq "a change on the source streams across" "$(pg pg-itrep 'SELECT count(*) FROM items')" "4"
# A replicating branch has no client connections of its own -- the apply worker
# is a background worker -- so the reaper used to suspend it two minutes in and
# the import silently stopped. A short-idle gateway, with a plain branch as the
# control, proves it now survives.
$S branch create itidle >/dev/null 2>&1
nohup "$S" gateway --addr :6502 --idle 8s >/tmp/itrepgateway.log 2>&1 &
RPI=$!
sleep 28
kill "$RPI" 2>/dev/null
assert_eq "a replicating branch survives the reaper" "$(sudo docker inspect -f '{{.State.Status}}' pg-itrep 2>/dev/null)" "running"
assert_eq "…while an idle plain branch is still suspended" "$(sudo docker inspect -f '{{.State.Status}}' pg-itidle 2>/dev/null)" "exited"
assert_eq "…and it is still streaming afterwards" "$(repl | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["replicating"], d["tables_ready"], d["tables"])')" "True 1 1"
$S branch delete itidle >/dev/null 2>&1
assert_eq "the list of continuous imports includes it" \
  "$(curl -sk -H "$AUTH" https://localhost:8080/api/replication | python3 -c 'import sys,json; print([r["branch"] for r in json.load(sys.stdin)].count("itrep"))')" "1"
assert_eq "cutover makes the branch standalone" \
  "$(curl -sk -H "$AUTH" -X POST https://localhost:8080/api/branches/itrep/replication/cutover | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["status"], d["tables"])')" "standalone 1"
assert_eq "…and it no longer replicates" "$(repl | python3 -c 'import sys,json; print(json.load(sys.stdin)["replicating"])')" "False"
sudo docker exec itsrc psql -U postgres -q -c "INSERT INTO items VALUES (5,'e')" >/dev/null; sleep 5
assert_eq "…so later source changes don't arrive, and the data stays" "$(pg pg-itrep 'SELECT count(*) FROM items')" "4"
assert_eq "cutting over again is refused (409)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -X POST https://localhost:8080/api/branches/itrep/replication/cutover)" "409"
assert_eq "cutover of a branch that never replicated is refused (409)" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -X POST https://localhost:8080/api/branches/itb/replication/cutover)" "409"
$S branch delete itrep >/dev/null 2>&1; sudo docker rm -f itsrc >/dev/null 2>&1

echo "### 6. HA: replication + failover + failback"
$S ha enable >/dev/null 2>&1; sleep 2
assert_eq "standby is streaming" "$(pg pg-main "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'")" "1"
$S ha failover >/dev/null 2>&1; sleep 3
W="$(PGPASSWORD="$KEY" psql "$GATEWAY/main" -tAqc "INSERT INTO pit VALUES (99) RETURNING 'okwrite'" 2>&1 | head -1)"
assert_eq "write succeeds via gateway after failover" "$W" "okwrite"
# After a failover the promoted standby is the only primary: nothing may delete or stop it.
for a in enable disable failover; do
  $S ha "$a" >/dev/null 2>&1
  assert_eq "ha $a is refused after a failover" "$?" "1"
done
$S branch suspend standby >/dev/null 2>&1
assert_eq "suspending the promoted standby is refused" "$?" "1"
assert_eq "promoted standby still running" "$(sudo docker inspect -f '{{.State.Status}}' pg-standby 2>/dev/null)" "running"
# `fox stop` removes containers; `fox up` must bring the promoted standby back, not the old main.
sudo docker rm -f pg-standby >/dev/null 2>&1
$S up >/dev/null 2>&1; sleep 2
assert_eq "up recreates the promoted standby" "$(sudo docker inspect -f '{{.State.Status}}' pg-standby 2>/dev/null)" "running"
assert_eq "up leaves the old main stopped" "$(sudo docker inspect -f '{{.State.Status}}' pg-main 2>/dev/null)" "exited"
assert_eq "the post-failover write is on the standby" "$(pg pg-standby 'SELECT count(*) FROM pit WHERE id=99')" "1"
# D2/D4: the promoted standby archives WAL and is what a backup is taken from.
# Before this, a promoted standby ran with no archiving and `fox backup create`
# still targeted the stopped pg-main, so nothing written after a failover
# could be backed up or restored.
assert_eq "the promoted standby archives WAL" "$(pg pg-standby "SELECT current_setting('archive_mode')")" "on"
pg pg-standby "INSERT INTO pit VALUES (101)" >/dev/null
pg pg-standby "SELECT pg_switch_wal()" >/dev/null; sleep 6
assert_eq "…and its archiver is shipping segments" "$(pg pg-standby 'SELECT archived_count > 0 AND last_failed_wal IS NULL FROM pg_stat_archiver')" "t"
BEFORE="$(curl -sk -H "$AUTH" https://localhost:8080/api/backups | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')"
BOUT="$($S backup create 2>&1)"
assert_eq "backup create says it is backing up the standby" "$(echo "$BOUT" | grep -c 'serving main since the failover')" "1"
assert_eq "…and one more base backup is stored" \
  "$(curl -sk -H "$AUTH" https://localhost:8080/api/backups | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')" "$((BEFORE + 1))"
assert_eq "backup list works with main stopped" "$($S backup list 2>/dev/null | grep -c 'base_')" "$((BEFORE + 1))"
assert_eq "status names the container serving main" "$($S status 2>/dev/null | grep -c 'served by pg-standby since the failover')" "1"
# End to end: a point-in-time restore now reaches a write made after the failover.
pg pg-standby "SELECT pg_switch_wal()" >/dev/null; sleep 5
$S restore --to latest >/dev/null 2>&1; sleep 1
assert_eq "PITR reaches a write made after the failover" "$(pg pg-restore 'SELECT count(*) FROM pit WHERE id=101')" "1"
sudo docker rm -f pg-restore >/dev/null 2>&1
$S ha failback >/tmp/failback.log 2>&1
assert_eq "ha failback exits 0" "$?" "0"
assert_eq "main is primary again (not in recovery)" "$(pg pg-main 'SELECT pg_is_in_recovery()')" "f"
assert_eq "primary pointer is back on main" "$(cat "$HOME/.fox/primary" 2>/dev/null)" "main"
assert_eq "failback kept the post-failover write" "$(pg pg-main 'SELECT count(*) FROM pit WHERE id=99')" "1"
assert_eq "old standby removed" "$(sudo docker ps -aq --filter 'name=^pg-standby$' | wc -l | tr -d ' ')" "0"
W="$(PGPASSWORD="$KEY" psql "$GATEWAY/main" -tAqc "INSERT INTO pit VALUES (100) RETURNING 'okwrite'" 2>&1 | head -1)"
assert_eq "gateway writes to main after failback" "$W" "okwrite"
pg pg-main "SELECT pg_switch_wal()" >/dev/null; sleep 5
assert_eq "main archives WAL again" "$(pg pg-main 'SELECT archived_count > 0 AND last_failed_wal IS NULL FROM pg_stat_archiver')" "t"

echo "### 7. regression: reaper never suspends the standby"
$S ha enable >/dev/null 2>&1; sleep 2
$S branch create rgn >/dev/null 2>&1
nohup "$S" gateway --addr :6501 --idle 8s >/tmp/rgngateway.log 2>&1 &
RP=$!
sleep 28
assert_eq "standby survives the reaper" "$(sudo docker inspect -f '{{.State.Status}}' pg-standby 2>/dev/null)" "running"
assert_eq "ordinary branch is suspended" "$(sudo docker inspect -f '{{.State.Status}}' pg-rgn 2>/dev/null)" "exited"
kill "$RP" 2>/dev/null
$S branch delete rgn >/dev/null 2>&1
$S ha disable >/dev/null 2>&1

echo "### 8. Blackbox (schema ledger, RECORD layer)"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ledg CASCADE" >/dev/null 2>&1
# Clean slate: the ledger is append-only now, so clearing it for a deterministic
# count requires deliberately disabling triggers (session_replication_role).
pg pg-main "SET session_replication_role=replica; DELETE FROM bb.schema_ledger; SET session_replication_role=DEFAULT" >/dev/null 2>&1
PGPASSWORD="$KEY" psql "$GATEWAY/main" -qc "CREATE TABLE ledg(x int)" >/dev/null 2>&1
assert_eq "ledger captures DDL, attributed to the human key" \
  "$(pg pg-main "SELECT actor_kind FROM bb.schema_ledger WHERE command_tag='CREATE TABLE' AND object_identity='public.ledg'")" "human"
BLK="$(PGPASSWORD="$KEY" psql "$GATEWAY/main" -qc "DROP TABLE ledg" 2>&1 | grep -c 'blocked by policy')"
assert_eq "guardrail blocks a destructive DROP" "$BLK" "1"
assert_eq "blocked attempt is recorded durably" \
  "$(pg pg-main "SELECT count(*) FROM bb.schema_ledger WHERE status='BLOCKED' AND command_tag='DROP TABLE'")" "1"
# Tamper-evidence: the ledger is append-only, and the hash chain verifies intact.
assert_eq "ledger is append-only (a plain DELETE is blocked)" \
  "$(sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "DELETE FROM bb.schema_ledger WHERE id=(SELECT max(id) FROM bb.schema_ledger)" 2>&1 | grep -c 'append-only')" "1"
assert_eq "hash chain verifies intact (0 broken rows)" \
  "$(pg pg-main "SELECT count(*) FROM (SELECT (row_hash <> bb._ledger_hash(s.*) OR prev_hash IS DISTINCT FROM coalesce(lag(row_hash) OVER (ORDER BY id),'')) AS broken FROM bb.schema_ledger s WHERE row_hash IS NOT NULL) x WHERE broken")" "0"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ledg" >/dev/null 2>&1

echo "### 9. ETL pipeline (extract -> transform -> test)"
sudo docker rm -f mongo-src >/dev/null 2>&1
sudo docker run -d --name mongo-src --network "$DB_NETWORK" mongo:7 >/dev/null 2>&1
for i in $(seq 1 40); do sudo docker exec mongo-src mongosh --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break; sleep 1; done
sudo docker exec mongo-src mongosh --quiet shop --eval \
  'db.buildings.insertMany([{name:"Empire State",floors:102,addr:{city:"New York"}},{name:"Willis Tower",floors:108,addr:{city:"Chicago"}},{name:"Aon Center",floors:83,addr:{city:"Chicago"}}])' >/dev/null 2>&1
$S branch delete etltest >/dev/null 2>&1
cat > /tmp/etl_ok.json << 'JSON'
{"source":"mongodb://mongo-src/shop","models":[{"name":"stg_buildings","sql":"SELECT name, floors, addr->>'city' AS city FROM {{ source('buildings') }}"},{"name":"city_counts","sql":"SELECT city, count(*) AS n FROM {{ ref('stg_buildings') }} GROUP BY city"}],"tests":[{"name":"name not null","type":"not_null","model":"stg_buildings","column":"name"}]}
JSON
$S pipeline run /tmp/etl_ok.json --as etltest >/dev/null 2>&1
assert_eq "ETL passing pipeline exits 0" "$?" "0"
assert_eq "ETL landed raw source in the raw schema" "$(pg pg-etltest "SELECT to_regclass('raw.buildings') IS NOT NULL")" "t"
assert_eq "ETL model flattened jsonb into a column" "$(pg pg-etltest "SELECT city FROM public.stg_buildings WHERE name='Empire State'")" "New York"
assert_eq "ETL aggregate model computed" "$(pg pg-etltest "SELECT n FROM public.city_counts WHERE city='Chicago'")" "2"

$S branch delete etlfail >/dev/null 2>&1
cat > /tmp/etl_fail.json << 'JSON'
{"source":"mongodb://mongo-src/shop","models":[{"name":"stg_b","sql":"SELECT name FROM {{ source('buildings') }}"}],"tests":[{"name":"needs 100 rows","type":"row_count_min","model":"stg_b","min":100}]}
JSON
$S pipeline run /tmp/etl_fail.json --as etlfail >/dev/null 2>&1
assert_eq "ETL failing test yields non-zero exit" "$?" "1"
assert_eq "ETL failed run keeps its data" "$(pg pg-etlfail "SELECT count(*) FROM public.stg_b")" "3"

echo "### 10. schema fidelity (source field names preserved exactly)"
sudo docker exec mongo-src mongosh --quiet shop --eval \
  'db.leaseAiChats.insertOne({userId:new ObjectId(), createdAt:new Date(), gallery:[{fileName:"a.jpg"}]})' >/dev/null 2>&1
$S branch delete faithtest >/dev/null 2>&1
cat > /tmp/faith.json << 'JSON'
{"source":"mongodb://mongo-src/shop","models":[{"name":"stg","sql":"SELECT \"userId\", \"createdAt\", \"gallery\" FROM {{ source('leaseAiChats') }}"}]}
JSON
$S pipeline run /tmp/faith.json --as faithtest >/dev/null 2>&1
assert_eq "camelCase column preserved (userId, not userid)" "$(pg pg-faithtest "SELECT count(*) FROM information_schema.columns WHERE table_schema='raw' AND table_name='leaseAiChats' AND column_name='userId'")" "1"
assert_eq "nested array kept as jsonb" "$(pg pg-faithtest "SELECT data_type FROM information_schema.columns WHERE table_schema='raw' AND table_name='leaseAiChats' AND column_name='gallery'")" "jsonb"
assert_eq "transform resolves the case-sensitive source" "$(pg pg-faithtest "SELECT count(*) FROM public.stg")" "1"

echo "### 11. imports fail on bad input instead of reporting success"
printf 'CREATE TABLE good(x int);\nINSERT INTO good VALUES (1),(2);\nINSERT INTO missing_table VALUES (1);\n' > /tmp/imp_bad.sql
$S branch delete impbad >/dev/null 2>&1
OUT="$($S import --from /tmp/imp_bad.sql --as impbad 2>&1)"
assert_eq ".sql with a failing statement exits 1" "$?" "1"
assert_eq "the failing statement is listed" "$(grep -c '1 statement(s) failed' <<<"$OUT")" "1"
assert_eq "the rest of the dump still loaded" "$(pg pg-impbad 'SELECT count(*) FROM good')" "2"
printf 'CREATE TABLE ok1(x int);\nINSERT INTO ok1 VALUES (1);\n' > /tmp/imp_ok.sql
$S branch delete impok >/dev/null 2>&1
$S import --from /tmp/imp_ok.sql --as impok >/dev/null 2>&1
assert_eq "a clean .sql still imports (exit 0)" "$?" "0"
printf '[{"a":1},{bad},{"a":3}]' > /tmp/imp_bad.json
$S branch delete jsonbad >/dev/null 2>&1
OUT="$($S import --from /tmp/imp_bad.json --as jsonbad 2>&1)"
assert_eq "JSON array with an invalid element exits 1" "$?" "1"
assert_eq "the invalid element is named" "$(grep -c 'element 2 is not valid JSON' <<<"$OUT")" "1"
printf '[{"a":1},{"a":2}]' > /tmp/imp_ok.json
$S branch delete jsonok >/dev/null 2>&1
$S import --from /tmp/imp_ok.json --as jsonok >/dev/null 2>&1
assert_eq "a valid JSON array still imports (exit 0)" "$?" "0"

echo "### 11b. an image that cannot be pulled is built from the copy inside fox (A3)"
# The published image is an optimisation. An unreachable registry or a private
# package used to end a first install with "unauthorized" and advice to set a
# variable the Mac cannot pass into its VM. fox carries the build context. The
# start runs from /tmp, away from the checkout, so it is the built-in copy that
# is used; the .invalid registry can never be pulled from.
IMG_TEST="registry.invalid/$BRAND_SLUG/postgres-walg:18"
sudo docker rmi -f "$IMG_TEST" >/dev/null 2>&1
$S stop >/dev/null 2>&1
OUT="$(cd /tmp && FOX_PG_IMAGE="$IMG_TEST" $S start 2>&1)"
assert_eq "start succeeds with an image no registry has" "$?" "0"
assert_eq "…having built it from the Dockerfile built into fox" "$(grep -c 'from the Dockerfile built into' <<<"$OUT")" "1"
assert_eq "…and main runs on it" "$(sudo docker inspect -f '{{.Config.Image}}' pg-main 2>/dev/null)" "$IMG_TEST"
$S stop >/dev/null 2>&1; $S start >/dev/null 2>&1
sudo docker rmi -f "$IMG_TEST" >/dev/null 2>&1

echo "### 12. fox uninstall (B1)"
# Removal used to be a list of commands to run by hand. This runs last: it takes
# the stack apart, so nothing after it has a stack to use.
$S uninstall --keep-data --yes >/tmp/uninstall-keep.log 2>&1
assert_eq "uninstall --keep-data removes the containers" \
  "$(sudo docker ps -aq --filter "label=$DB_MANAGED_LABEL" | wc -l | tr -d ' ')" "0"
assert_eq "…and keeps the storage pool" "$(sudo zpool list -H -o name "$DB_POOL" 2>/dev/null)" "$DB_POOL"
assert_eq "…and keeps archived WAL and base backups" \
  "$(sudo docker volume ls --format '{{.Name}}' | grep -cx "$DB_OBJECT_STORE-data")" "1"
assert_eq "…and keeps accounts and secrets" "$([ -f "$HOME/$BRAND_STATE_DIR/secrets.json" ] && echo kept)" "kept"

$S uninstall --yes >/tmp/uninstall-all.log 2>&1
assert_eq "uninstall removes the storage pool" \
  "$(sudo zpool list -H -o name "$DB_POOL" 2>/dev/null | wc -l | tr -d ' ')" "0"
assert_eq "…and the archived WAL and base backups" \
  "$(sudo docker volume ls --format '{{.Name}}' | grep -cx "$DB_OBJECT_STORE-data")" "0"
assert_eq "…and the accounts, keys and anchors" "$([ -d "$HOME/$BRAND_STATE_DIR" ] && echo present || echo gone)" "gone"
assert_eq "…and says so" "$(grep -c "is removed" /tmp/uninstall-all.log)" "1"

# Safe to run twice: everything checks before it removes.
$S uninstall --yes >/tmp/uninstall-again.log 2>&1
assert_eq "running it again is harmless" "$?" "0"
assert_eq "…and finds no data left to remove" \
  "$(grep -c 'removing the databases' /tmp/uninstall-again.log)" "0"

echo "### cleanup"
$S branch delete itb >/dev/null 2>&1
$S branch delete etltest >/dev/null 2>&1
$S branch delete etlfail >/dev/null 2>&1
$S branch delete faithtest >/dev/null 2>&1
sudo docker rm -f mongo-src >/dev/null 2>&1
for b in impbad impok jsonbad jsonok; do $S branch delete "$b" >/dev/null 2>&1; done
rm -f /tmp/imp_bad.sql /tmp/imp_ok.sql /tmp/imp_bad.json /tmp/imp_ok.json /tmp/failback.log

echo
echo "==== ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ]
