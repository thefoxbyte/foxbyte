#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# End-to-end integration test. Run inside the Linux dev VM (ZFS + Docker):
#   lima bash "$PWD/scripts/integration_test.sh"
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
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }

# A helper this suite does not define used to be silent. bash printed "command
# not found" on stderr, the assertion produced neither a PASS nor a FAIL, and
# the run still reported zero failures -- which is how eight assertions in
# section 6b ran as nothing at all while the suite looked green. An unknown
# command is a failed assertion now, and 127 keeps the shell's own meaning.
#
# The flag file is not belt-and-braces: bash runs this handler in a subshell, so
# incrementing FAIL here would be thrown away with the subshell and the summary
# would still say zero. The file is the only thing that crosses back.
MISSING_CMD_FLAG="$(mktemp -t fox-missing-cmd.XXXXXX)"; rm -f "$MISSING_CMD_FLAG"
command_not_found_handle() {
  echo "  FAIL: this suite called a command that does not exist: $1"
  echo "$1" >> "$MISSING_CMD_FLAG"
  return 127
}
# pg <container> <sql>  -> tuples-only result
pg() { local c="$1"; shift; sudo docker exec -e PGPASSWORD=foxbyte "$c" psql -U dbadmin -d appdb -tAc "$*" 2>/dev/null; }
# pgt is pg with a deadline, for section 6's zero-data-loss block. The failure
# that feature can have is a commit that never returns, and an unguarded psql
# would hang the whole suite instead of failing one assertion.
pgt() { local t="$1" c="$2"; shift 2; timeout "$t" sudo docker exec -e PGPASSWORD=foxbyte "$c" psql -q -U dbadmin -d appdb -tAc "$*" 2>/dev/null; }
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
# The security log lives in that store, and its anchors are outside it: kept,
# they would anchor events this fresh store does not have — which `fox audit
# verify` rightly calls tampering.
rm -rf "$HOME/$BRAND_STATE_DIR/anchors/_security-log"
# Zero-data-loss mode is an intent that outlives the containers, so a run cut
# short after `ha sync on` leaves it behind -- and then `ha enable` in section 6
# dutifully puts the mode back, and the first assertion there ("commits do not
# wait by default") fails for a reason that has nothing to do with it.
rm -f "$HOME/$BRAND_STATE_DIR/sync-commit"
# And the primary pointer, for the same reason: a run cut short after a failover
# leaves 'main' pointing at the promoted standby. `stop` above has already
# removed every container, so there is no promoted standby left to protect, and
# an absent pointer means main -- which is what a fresh start expects.
rm -f "$HOME/$BRAND_STATE_DIR/primary"
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
# Browser security headers (14 Oct 2026 audit, S3). Every answer refuses to be
# framed and says not to sniff its type; HSTS is never sent to a loopback name, where it
# would force https onto every local dev server.
hdr() { curl -skI -H "$AUTH" "$1" | tr -d '\r' | grep -i "^$2:" | cut -d' ' -f2-; }
assert_eq "every answer refuses framing and type sniffing" \
  "$(hdr https://localhost:8080/api/status x-frame-options)|$(hdr https://localhost:8080/api/status x-content-type-options)|$(hdr https://localhost:8080/api/status referrer-policy)" "DENY|nosniff|same-origin"
assert_eq "the Agent API forbids loading or framing anything it returns" \
  "$(hdr https://localhost:8088/agents content-security-policy)" "default-src 'none'; frame-ancestors 'none'"
assert_eq "no HSTS to localhost" "$(hdr https://localhost:8080/api/status strict-transport-security)" ""
# The console's own page and its policy are checked by integration_ui.sh, whose build has the console in it.
# A change a browser sends from another site is refused (14 Oct 2026 audit, S4);
# the same request from this console, or from no browser at all, is not.
xs() { curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' -X POST "$@"; }
assert_eq "a change sent from another site's page is refused, on both APIs and at sign-in" \
  "$(xs -H 'Origin: https://evil.example' -d '{"name":"xsite"}' https://localhost:8080/api/branches)|$(xs -H 'Origin: https://evil.example' https://localhost:8088/agents/xsite/branch)|$(xs -H 'Origin: https://evil.example' -d '{"email":"test@foxbyte.dev","password":"password123"}' https://localhost:8080/auth/login)" "403|403|403"
assert_eq "…as is one from a sandboxed page, and one the browser marks cross-site" \
  "$(xs -H 'Origin: null' -d '{"name":"xsite"}' https://localhost:8080/api/branches)|$(xs -H 'Sec-Fetch-Site: cross-site' -d '{"name":"xsite"}' https://localhost:8080/api/branches)" "403|403"
assert_eq "…and nothing was made" "$($S branch list 2>/dev/null | grep -c xsite)" "0"
assert_eq "the console's own origin, and a client that is no browser, sign in as before" \
  "$(xs -H 'Origin: https://localhost:8080' -d '{"email":"test@foxbyte.dev","password":"password123"}' https://localhost:8080/auth/login)|$(xs -d '{"email":"test@foxbyte.dev","password":"password123"}' https://localhost:8080/auth/login)" "200|200"

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
# A grant or revoke made at the CLI, in another process, reaches the running
# servers within a second: each one watches the security log for admin changes
# (access: AdminEpoch) instead of trusting what it remembered for 30 seconds.
assert_eq "bob is no admin, and the console has just said so (and remembered it)" \
  "$(code "$KB" https://localhost:8080/api/users)" "403"
$S admin grant bob@foxbyte.dev >/dev/null 2>&1; sleep 2
assert_eq "a CLI grant reaches the console and the Gateway within seconds, not 30" \
  "$(code "$KB" https://localhost:8080/api/users)|$(PGPASSWORD="$KB" psql "$GATEWAY/alice-dev?sslmode=require" -tAc 'select x from secret' 2>/dev/null)" "200|42"
$S admin revoke bob@foxbyte.dev >/dev/null 2>&1; sleep 2
assert_eq "…and so does a CLI revoke" \
  "$(code "$KB" https://localhost:8080/api/users)|$(PGPASSWORD="$KB" psql "$GATEWAY/alice-dev?sslmode=require" -tAc 'select x from secret' 2>&1 | grep -c 'no branch')" "403|1"
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
# Through the gateway, as a client -- not as the superuser the import runs as.
# The two had never been distinguished here, and they were not the same: the
# target's public schema is dropped and recreated during preparation, which
# took the grants db_client needs with it, so imported data could be read by
# the import itself and by no client at all.
assert_eq "a gateway client can read what was imported" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/itrep" -tAc 'SELECT count(*) FROM items' 2>&1 | head -1)" "3"
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

# ---- reads from the standby (HA plan phase 7) ------------------------------
#
# The standby holds a complete, continuously updated copy and, between
# failovers, answers nothing. A read-only session asks for it by name:
# "main:standby" rather than "main". These assert the four things that make
# that safe to offer -- the copy is current, it cannot be written to, the
# reader is the same person there as on the primary, and the name grants
# nothing the branch name would not.
PGPASSWORD="$KEY" psql "$GATEWAY/main" -tAqc "CREATE TABLE IF NOT EXISTS roread(x int); INSERT INTO roread VALUES (7)" >/dev/null 2>&1
sleep 2
assert_eq "a read-only session is answered by the standby, which is in recovery" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'SELECT pg_is_in_recovery()' 2>&1 | head -1)" "t"
assert_eq "…and carries the write the primary has just taken" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'SELECT x FROM roread' 2>&1 | head -1)" "7"
assert_contains "…while a write there is refused by Postgres itself" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'INSERT INTO roread VALUES (8)' 2>&1 | head -1)" "read-only transaction"
# The per-user role is cluster-wide and physically replicated, so attribution
# on the copy is the same as on the primary rather than degrading to the shared
# role -- which is what makes a read there interchangeable with a read here.
assert_eq "…as the same person, not the shared role" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'SELECT session_user' 2>&1 | head -1)" "test@foxbyte.dev"
# A branch of alice's, made here rather than borrowed from section 1d, which
# deletes alice-dev when it is finished with it: a refusal about a branch that
# no longer exists takes a different path and would prove nothing about this
# one.
# Asserted rather than assumed: a setup step that fails quietly turns the two
# assertions below into assertions about nothing, which is how eight of them in
# section 6b once ran as no-ops while the suite reported green.
assert_eq "alice makes a branch, for the two assertions below" \
  "$(code "$KA" -H 'Content-Type: application/json' -X POST -d '{"name":"roalice"}' https://localhost:8080/api/branches)" "201"
assert_contains "a branch has no standby of its own, and is told so" \
  "$(PGPASSWORD="$KA" psql "$GATEWAY/roalice:standby" -tAc 'SELECT 1' 2>&1 | head -1)" "only main has a standby"
# The suffix chooses a backend; it is never a different thing to be allowed. An
# account that may not open alice's branch may not open a copy of it either --
# and the refusal names the branch rather than the key it asked for, because it
# is the gateway's ordinary answer to a name somebody may not open, reached
# before anything looked at the suffix.
#
# A third account, made here rather than borrowed: section 1d's bob is deleted
# a few lines after it finishes with him (that deletion is one of its
# assertions), and borrowing him made this pass against a dead credential
# instead of against the ACL. The key is proved to work first for the same
# reason -- "refused" is only interesting when the refusal is the one meant.
printf 'password123\n' | $S user create roreader@foxbyte.dev >/dev/null 2>&1
KRO="$($S apikey create roreader@foxbyte.dev it 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "…the account that tests this has a key that works" \
  "$(PGPASSWORD="$KRO" psql "$GATEWAY/main" -tAc 'select 1' 2>&1 | head -1)" "1"
assert_contains "…and a copy of a branch it may not open is refused the same way, naming no copy" \
  "$(PGPASSWORD="$KRO" psql "$GATEWAY/roalice:standby" -tAc 'select 1' 2>&1 | head -1)" 'no branch "roalice"'
$S user delete roreader@foxbyte.dev >/dev/null 2>&1
curl -sk -o /dev/null -H "Authorization: Bearer $KA" -X DELETE https://localhost:8080/api/branches/roalice
# Discoverable without reading the plan: the endpoint is printed where somebody
# is already looking for a connection string, and `ha status` says how stale it
# is, because staleness is the price of the feature rather than a fault in it.
assert_eq "\`connect\` offers the read-only endpoint" \
  "$($S connect main --dsn 2>/dev/null | grep -c 'main:standby')" "1"
assert_eq "\`ha status\` says how far behind the copy is" \
  "$($S ha status 2>/dev/null | grep -c 'behind the primary')" "1"
# ---- end phase 7 -----------------------------------------------------------

# ---- accounts and keys reach the other machine (HA plan phase 2) -----------
#
# A failover that leaves nobody able to sign in is not a failover. The primary
# writes its accounts, keys and the records authored around them into a
# database of its own inside the replicated cluster; a machine that follows a
# primary elsewhere reads them from its own copy and applies them into its own
# SQLite. Nothing about signing in touches Postgres, which is why the store did
# not move into main: that would make logins impossible during the one window
# this exists for.
#
# The control plane carries them on a timer, so these wait for it rather than
# calling anything. What is being tested is the part that runs by itself.
statedg() { sudo docker exec "$1" psql -U dbadmin -d statedb -tAc "SELECT digest FROM shared WHERE id=1" 2>/dev/null | tr -d ' \n'; }
SD=""
for _ in $(seq 1 16); do SD="$(statedg pg-main)"; [ -n "$SD" ] && break; sleep 5; done
assert_eq "the primary carries its accounts into the replicated database" \
  "$([ -n "$SD" ] && echo shipped || echo nothing)" "shipped"
# Replicated, not shipped twice: the document travels in the WAL the standby is
# already streaming, which is the whole reason this needs no second channel.
assert_eq "…and the standby has the same document, through replication" "$(statedg pg-standby)" "$SD"
assert_eq "…carrying the seven tables a second machine needs" \
  "$(sudo docker exec pg-main psql -U dbadmin -d statedb -tAc "SELECT string_agg(k, ',' ORDER BY k) FROM shared, jsonb_object_keys(payload->'tables') k WHERE id=1" 2>/dev/null)" \
  "api_keys,branch_owners,change_requests,oauth_identities,pipelines,pipeline_targets,users"
# Sessions are deliberately absent: a browser session is minutes old and cheap
# to replace, and carrying bearer tokens between machines would widen what a
# stolen document is worth for the convenience of not signing in again.
assert_eq "…and not the session tokens" \
  "$(sudo docker exec pg-main psql -U dbadmin -d statedb -tAc "SELECT payload::text LIKE '%sessions%' FROM shared WHERE id=1" 2>/dev/null)" "f"
# The one privilege that makes this database different from appdb. Asked of
# Postgres over the container's socket, which trusts the connection, so what is
# being tested is the CONNECT privilege and not a password.
assert_contains "the roles clients log in as cannot read it" \
  "$(sudo docker exec pg-main psql -U "$DB_CLIENT_ROLE" -d statedb -tAc 'select 1' 2>&1 | head -1)" \
  "permission denied for database"
# An account made now reaches the other machine, which is the claim.
printf 'password123\n' | $S user create shipped@foxbyte.dev >/dev/null 2>&1
SD2=""
for _ in $(seq 1 10); do SD2="$(statedg pg-main)"; [ -n "$SD2" ] && [ "$SD2" != "$SD" ] && break; sleep 5; done
assert_eq "a new account changes the document the other machine reads" \
  "$([ -n "$SD2" ] && [ "$SD2" != "$SD" ] && echo changed || echo unchanged)" "changed"

# The other side of it, as far as one machine can show: a node that follows a
# primary elsewhere treats its accounts as a copy. The join state is what says
# so, and writing it is how a single machine can be asked the question at all --
# applying a real document from a real second machine is what the unit tests in
# internal/auth cover, with two stores.
printf '{"address":"10.9.9.9","port":5432,"role":"db_replica","at":"2026-10-13T00:00:00Z"}\n' > "$HOME/$BRAND_STATE_DIR/node-joined.json"
assert_contains "a follower refuses to create an account, since the next copy would remove it" \
  "$(printf 'password123\n' | $S user create ghost@foxbyte.dev 2>&1 | head -1)" "accounts are a copy"
# The firmest of the refusals: a key revoked on a copy comes back with the next
# one, so the person told it was revoked would be wrong about the one thing
# they most need to be right about.
assert_contains "…and refuses to revoke a key, which would silently undo itself" \
  "$($S apikey revoke test@foxbyte.dev whatever 2>&1 | head -1)" "a key revoked here would be undone"
sleep 12   # one round of the carrier
assert_contains "…and reads the primary's document from its own copy" \
  "$($S ha status 2>&1 | sed -n '/=== accounts and keys ===/,/=== reads/p')" "are a copy of the primary's, current as of"
rm -f "$HOME/$BRAND_STATE_DIR/node-joined.json"
assert_eq "…and owns them again once it follows nobody" \
  "$($S ha status 2>&1 | grep -c 'this node owns the accounts and keys')" "1"

# The role passwords, which are the other half of a failover between machines:
# a copy carries the *primary's* roles, whose passwords come from the primary's
# install secret, and `node join` carries no secret. Phase 7 measured what that
# costs; the promotion rewrites them instead. Reproduced here by changing one
# role's password behind the gateway, which is the same divergence.
RRKEY="$($S apikey create test@foxbyte.dev rr 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "a client reaches main as itself" \
  "$(PGPASSWORD="$RRKEY" psql "$GATEWAY/main" -tAc 'select session_user' 2>&1 | head -1)" "test@foxbyte.dev"
sudo docker exec pg-main psql -U dbadmin -d "$DB_DATABASE" -qc "ALTER ROLE \"test@foxbyte.dev\" PASSWORD 'not-the-derived-one'" >/dev/null 2>&1
assert_contains "…and fails once that role's password is not the one this install derives" \
  "$(PGPASSWORD="$RRKEY" psql "$GATEWAY/main" -tAc 'select 1' 2>&1 | head -1)" "authentication failed"
assert_contains "\`ha repair-roles\` rewrites only the roles this install manages" \
  "$($S ha repair-roles 2>&1 | head -1)" "test@foxbyte.dev"
assert_eq "…and the client works again, holding the same key" \
  "$(PGPASSWORD="$RRKEY" psql "$GATEWAY/main" -tAc 'select session_user' 2>&1 | head -1)" "test@foxbyte.dev"
$S user delete shipped@foxbyte.dev >/dev/null 2>&1
# ---- end phase 2 -----------------------------------------------------------

# ---- who may copy the database (HA plan phase 1) ---------------------------
#
# `ha enable` used to append `host replication all all` and let the standby
# connect as the bootstrap superuser: any role, from any address, with the
# credential that owns the database. These assert the replacement against a
# live install, because that is the only place pg_hba means anything.
assert_eq "the standby connects as a role of its own, not the superuser" \
  "$(pg pg-main "SELECT usename FROM pg_stat_replication")" "db_replica"
# Two assertions rather than one concatenation: Postgres renders a boolean cast
# to text as "true"/"false", not the t/f that -At prints for a bare boolean, so
# the first version of this compared against "ft" and read "falsetrue".
assert_eq "…which is not a superuser" \
  "$(pg pg-main "SELECT usesuper FROM pg_user WHERE usename='db_replica'")" "f"
assert_eq "…and may replicate" \
  "$(pg pg-main "SELECT userepl FROM pg_user WHERE usename='db_replica'")" "t"
assert_eq "…holds no table grants" \
  "$(pg pg-main "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee='db_replica'")" "0"
assert_eq "…and is a member of nothing" \
  "$(pg pg-main "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='db_replica'")" "0"
# The rule, and the absence of the one it replaced. pg_hba is first-match-wins,
# so the wide rule left anywhere in the file would still admit everyone.
assert_eq "the wide rule is gone from pg_hba, not merely outranked" \
  "$(sudo docker exec -u postgres pg-main bash -c 'grep -cE "^host[[:space:]]+replication[[:space:]]+all[[:space:]]+all" "$PGDATA/pg_hba.conf" || true')" "0"
assert_eq "…replaced by one naming the role and this install's own network" \
  "$(sudo docker exec -u postgres pg-main bash -c 'grep -cF "host replication db_replica samenet scram-sha-256" "$PGDATA/pg_hba.conf" || true')" "1"
# The property that matters, asked of Postgres rather than of the file: the
# superuser can no longer open a replication connection over the network, while
# its ordinary connections are untouched.
cp "$HOME/$BRAND_STATE_DIR/pg.env" /tmp/su.env 2>/dev/null; chmod 600 /tmp/su.env 2>/dev/null
assert_contains "the superuser can no longer replicate from the network" \
  "$(sudo docker run --rm --network dbnet --env-file /tmp/su.env "$(sudo docker inspect -f '{{.Config.Image}}' pg-main)" \
      psql "postgresql://dbadmin@pg-main/appdb?replication=true" -tAc "IDENTIFY_SYSTEM" 2>&1 | head -1)" \
  "no pg_hba.conf entry"
assert_eq "…while its ordinary connections still work" \
  "$(sudo docker run --rm --network dbnet --env-file /tmp/su.env "$(sudo docker inspect -f '{{.Config.Image}}' pg-main)" \
      psql "postgresql://dbadmin@pg-main/appdb" -tAc "SELECT 'ordinary-ok'" 2>&1 | head -1)" "ordinary-ok"
rm -f /tmp/su.env
assert_eq "\`check\` says only that role may copy it" \
  "$($S check 2>&1 | grep -c '^ok    replication .*db_replica')" "1"
# ---- publishing the primary for a standby elsewhere (phase 1) --------------
#
# The engine otherwise keeps Postgres off every network: startContainer
# publishes no host port, because a direct connection would bypass the gateway,
# its API key, TLS and ledger attribution. `node expose` is the one command
# that reverses that, and these assert how narrowly.
#
# The cross-machine half of this was measured between two VMs on a shared
# network; what a single-VM suite can hold is the shape of what gets published.
assert_eq "nothing is published on a fresh install" \
  "$($S node status 2>&1 | grep -c 'not published')" "1"
assert_contains "expose without --yes refuses and says what it would do" \
  "$($S node expose --address 10.9.9.9 --peer 10.9.9.10 2>&1)" "over TLS only"
assert_contains "…refusing a loopback address another machine cannot reach" \
  "$($S node expose --address 127.0.0.1 --peer 10.9.9.10 --yes 2>&1)" "loopback"
assert_contains "…and an address that is every interface" \
  "$($S node expose --address 0.0.0.0 --peer 10.9.9.10 --yes 2>&1)" "every interface"
assert_contains "…and a peer that is a name rather than an address" \
  "$($S node expose --address 10.9.9.9 --peer db1.internal --yes 2>&1)" "not an IP address"
# The real thing, on this VM's own address: a published port, TLS, and two
# rules -- samenet for a standby here, hostssl for the one that is not.
VMIP="$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)"
$S node expose --address "$VMIP" --peer 10.9.9.10 --yes >/tmp/expose.log 2>&1
assert_eq "expose exits 0" "$?" "0"
assert_eq "…publishing the port on that address only, not every interface" \
  "$(sudo docker port pg-main 2>/dev/null | grep -c "$VMIP:5432")" "1"
assert_eq "…with TLS actually serving" "$(pg pg-main 'SHOW ssl')" "on"
assert_eq "…admitting the other machine only over TLS" \
  "$(sudo docker exec -u postgres pg-main bash -c 'grep -cF "hostssl replication db_replica 10.9.9.10/32 scram-sha-256" "$PGDATA/pg_hba.conf"')" "1"
# The private key must not be in the data directory: pg_basebackup copies
# PGDATA, so a key kept there is handed to every standby that joins.
assert_eq "…and the private key is not where a base backup would copy it" \
  "$(sudo ls /dbpool/branches/main/pgdata/ 2>/dev/null | grep -c 'fox-replication' || true)" "0"
assert_contains "…and the join token carries a CA and one role's password" \
  "$($S node token 2>/dev/null | head -c 400 | base64 -d 2>/dev/null || $S node token 2>/dev/null | tr -d '\n' | python3 -c 'import base64,sys; print(base64.urlsafe_b64decode(sys.stdin.read()+"==").decode())')" \
  "db_replica"
assert_eq "…and not the install secret" \
  "$($S node token 2>/dev/null | tr -d '\n' | python3 -c 'import base64,sys,re
raw = base64.urlsafe_b64decode(sys.stdin.read()+"==").decode()
import os
secret = open(os.path.expanduser("~/.fox/pg.env")).read().split("PGPASSWORD=")[1].split("\n")[0]
print("leaked" if secret in raw else "clean")')" "clean"
assert_contains "\`check\` says the primary is published" "$($S check 2>&1 | grep replication)" "published at"
# Taking it back off the network removes the port and the peer rule, and keeps
# the rule a standby on this machine uses.
$S node unexpose >/dev/null 2>&1
assert_eq "unexpose exits 0" "$?" "0"
assert_eq "…so no host port is published" "$(sudo docker port pg-main 2>/dev/null | wc -l | tr -d ' ')" "0"
assert_eq "…the peer rule is gone" \
  "$(sudo docker exec -u postgres pg-main bash -c 'grep -c "^hostssl" "$PGDATA/pg_hba.conf" || true')" "0"
assert_eq "…and the local standby's rule is kept" \
  "$(sudo docker exec -u postgres pg-main bash -c 'grep -cF "host replication db_replica samenet" "$PGDATA/pg_hba.conf"')" "1"
# Publishing and unpublishing each restart main, which interrupts replication.
# The standby has to come back on its own -- and everything below here, the
# zero-data-loss block included, depends on it having done so. Waited for
# rather than raced: `ha sync on` rightly refuses while nothing is streaming,
# and the first version of this block failed five assertions in section 6 for
# exactly that reason.
STREAMING=no
for _ in $(seq 1 30); do
  [ "$(pg pg-main "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'")" = "1" ] \
    && { STREAMING=yes; break; }
  sleep 2
done
assert_eq "the standby streams again after the primary was restarted twice" "$STREAMING" "yes"

# ---- node join: the refusals a single VM can hold --------------------------
#
# The working path needs two machines and was verified between two VMs on a
# shared network: a standby copied over TLS, a row written on the primary
# arriving on the other machine, the primary killed with SIGKILL, the survivor
# promoted and taking writes with every acknowledged row intact. What a
# single-VM suite can assert is that the command refuses what it should and
# that a local standby is unaffected by any of it.
assert_eq "this install follows no other primary" "$($S node status 2>&1 | grep -c 'standby of')" "0"
assert_contains "a join token that is not one is refused with a sentence" \
  "$($S node join '!!! not a token !!!' 2>&1)" "does not look like a join token"
assert_contains "…and one that decodes to nothing useful" \
  "$($S node join bm90LWEtdG9rZW4 2>&1)" "could not be read"
assert_contains "…as is one that carries nothing usable" \
  "$($S node join "$(printf '{"v":1}' | base64 | tr -d '=' | tr '/+' '_-')" 2>&1)" "carries no"
assert_contains "…and one minted by a later release" \
  "$($S node join "$(printf '{"v":9,"address":"a","port":1,"role":"r","password":"p","ca":"c","database":"d"}' | base64 | tr -d '=\n' | tr '/+' '_-')" 2>&1)" "different releases"
# A machine that already has a standby of its own main cannot also be a standby
# of somebody else's: it is the same container and the same storage.
# A syntactically valid token that points nowhere: the standby collision is
# checked before anything is dialled, so this never leaves the machine. Minted
# here rather than with `node token`, which has nothing to print by this point
# — the block above ended with `node unexpose`, and the first version of this
# assertion got "unexpected end of JSON input" for exactly that reason.
FAKETOK="$(python3 -c '
import base64, json
print(base64.urlsafe_b64encode(json.dumps({
  "v": 1, "address": "10.9.9.9", "port": 5432, "role": "db_replica",
  "password": "x", "ca": "-----BEGIN CERTIFICATE-----\nx\n", "database": "appdb",
}).encode()).decode().rstrip("="))')"
assert_contains "joining is refused while this install has its own standby" \
  "$($S node join "$FAKETOK" 2>&1)" "already has a standby of its own main"
assert_eq "…and that standby is untouched by the refusal" \
  "$(pg pg-main "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'")" "1"
assert_contains "leaving is a no-op on an install that follows nobody" \
  "$($S node leave 2>&1)" "follows no other primary"
# Fencing (phase 3) is asserted by what this section already does, and
# deliberately adds nothing here.
#
# A standby of this machine's own main needs no fence: HAFailover stops the
# local primary, which is the whole of it when both are containers here. The
# proof that the new check does not refuse that is the plain `ha failover`
# below, which passes with no --force.
#
# The cross-machine refusal needs two machines and was verified between two VMs
# on a shared network: refused with the primary alive and the standby left in
# recovery, promoted once that primary was genuinely stopped, and --force
# warning before it proceeds.
#
# The first version of this block ran its own failover *and failback* here, and
# a failback destroys the standby -- so the zero-data-loss block, the drill and
# much of what follows ran with no standby at all. Twenty-one failures from one
# redundant assertion.
# ---- end phase 1 -----------------------------------------------------------

# ---- zero-data-loss mode (HA plan phase 5) --------------------------------
#
# Every write in this block is wrapped in `timeout`, because the failure this
# feature can have is a commit that never returns: an unguarded psql would hang
# the whole suite instead of failing one assertion.
assert_eq "commits do not wait by default" "$(pg pg-main "SELECT current_setting('synchronous_standby_names')")" ""
$S ha sync on >/tmp/sync-on.log 2>&1
assert_eq "\`ha sync on\` exits 0" "$?" "0"
assert_eq "…and the standby is counted as a quorum member" \
  "$(pg pg-main "SELECT sync_state FROM pg_stat_replication WHERE application_name='fox_standby'")" "quorum"
assert_eq "…which needs the standby to call itself that" \
  "$(pg pg-standby "SELECT current_setting('cluster_name')")" "fox_standby"
assert_eq "a commit still completes while a standby is there to wait for" \
  "$(pgt 15 pg-main "INSERT INTO pit VALUES (97) RETURNING 'ok'")" "ok"

# The cost, demonstrated rather than described: with the standby gone, a commit
# does not fail -- it waits, for as long as it takes.
sudo docker stop pg-standby >/dev/null 2>&1; sleep 3
pgt 10 pg-main "INSERT INTO pit VALUES (98)" >/dev/null
assert_eq "with the standby gone, a commit waits instead of failing" "$?" "124"
assert_eq "…and \`check\` calls that a failure, not a warning" \
  "$($S check 2>&1 | grep -c '^FAIL  durability')" "1"
assert_eq "…naming the one command that releases them" \
  "$($S check 2>&1 | grep -A1 'durability' | grep -c 'ha sync off')" "1"

# The escape hatch, which is the property that makes the mode safe to offer:
# it works *while* commits are stalled, because ALTER SYSTEM and a reload need
# no commit of their own.
$S ha sync off >/tmp/sync-off.log 2>&1
assert_eq "\`ha sync off\` exits 0 while commits are stalled" "$?" "0"
assert_eq "…and releases them" \
  "$(pgt 15 pg-main "INSERT INTO pit VALUES (96) RETURNING 'ok'")" "ok"
assert_eq "…and the write that was waiting is not lost" "$(pg pg-main 'SELECT count(*) FROM pit WHERE id=98')" "1"

# Back on, so the failover below is made with the mode in effect -- which is
# the state that produced the trap this guards against.
sudo docker start pg-standby >/dev/null 2>&1; sleep 6
$S ha sync on >/dev/null 2>&1
assert_eq "the mode goes back on once the standby returns" \
  "$(pg pg-main "SELECT sync_state FROM pg_stat_replication WHERE application_name='fox_standby'")" "quorum"

$S ha failover >/dev/null 2>&1; sleep 3
# The trap. ALTER SYSTEM writes postgresql.auto.conf and pg_basebackup copies
# PGDATA, so a standby built while the mode was on carries the setting. Promote
# it and it waits for a standby of its own that does not exist: every write
# stops at the moment of a failover, which is the moment it must not.
assert_eq "the promoted standby is not waiting for a standby of its own" \
  "$(pg pg-standby "SELECT current_setting('synchronous_standby_names')")" ""
assert_eq "…so a commit on it completes" \
  "$(pgt 15 pg-standby "INSERT INTO pit VALUES (95) RETURNING 'ok'")" "ok"
assert_eq "…and the mode is reported as asked-for but not in effect" \
  "$($S check 2>&1 | grep -c '^warn  durability')" "1"
$S ha sync off >/dev/null 2>&1   # clear the intent, so nothing below waits
# ---- end phase 5 -----------------------------------------------------------

W="$(PGPASSWORD="$KEY" psql "$GATEWAY/main" -tAqc "INSERT INTO pit VALUES (99) RETURNING 'okwrite'" 2>&1 | head -1)"
assert_eq "write succeeds via gateway after failover" "$W" "okwrite"
# Phase 7, in the state that matters most: the standby is now the primary, so
# there is no second copy. A read-only DSN that silently became a connection to
# the primary would keep working, keep looking right, and put every read back
# on the machine the reader was trying to spare.
assert_contains "after a failover the read-only name is refused, not quietly served by the primary" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'SELECT 1' 2>&1 | head -1)" "was promoted"
assert_contains "…and it names what rebuilds one" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'SELECT 1' 2>&1 | head -1)" "ha failback"
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
# And with the standby gone, the read-only name says so rather than falling
# back to the primary -- `ha failback` leaves no standby, which is the state an
# operator is least likely to expect.
assert_contains "after a failback there is no copy to read, and the refusal says which command makes one" \
  "$(PGPASSWORD="$KEY" psql "$GATEWAY/main:standby" -tAc 'SELECT 1' 2>&1 | head -1)" "ha enable"
W="$(PGPASSWORD="$KEY" psql "$GATEWAY/main" -tAqc "INSERT INTO pit VALUES (100) RETURNING 'okwrite'" 2>&1 | head -1)"
assert_eq "gateway writes to main after failback" "$W" "okwrite"
pg pg-main "SELECT pg_switch_wal()" >/dev/null; sleep 5
assert_eq "main archives WAL again" "$(pg pg-main 'SELECT archived_count > 0 AND last_failed_wal IS NULL FROM pg_stat_archiver')" "t"

echo "### 6b. failover drill (HA plan phase 6)"
# The drill is the deliverable of phase 6: "we fail over in about a minute" is a
# claim, and a dated report from a real failover is evidence. So what is
# asserted here is mostly that the report says the right things -- including the
# things that stop it being misquoted.
assert_contains "a drill without --yes refuses, and says it is an outage" \
  "$($S ha drill 2>&1)" "real outage"
assert_contains "a drill with no standby refuses, and names the way in" \
  "$($S ha drill --yes 2>&1)" "ha enable"
$S ha enable >/dev/null 2>&1; sleep 5
$S ha sync on >/dev/null 2>&1
D=/tmp/drill.out
$S ha drill --yes --writes 60 --failback >"$D" 2>&1
assert_eq "a drill runs and exits 0" "$?" "0"
assert_contains "…reporting the writes it lost" "$(cat "$D")" "Acknowledged writes lost (RPO)"
assert_contains "…and the time until the new primary took a write" "$(cat "$D")" "Kill to a write on the new primary (RTO)"
# With zero-data-loss mode on, zero is a guarantee of the configuration. The
# report has to say which of the two it is, because only one may be quoted.
assert_contains "…calling zero a property of the configuration, not a sample" \
  "$(cat "$D")" "property of the configuration"
assert_contains "…saying RTO excludes noticing the failure" "$(cat "$D")" "does not include noticing the failure"
assert_contains "…and what the drill did not test" "$(cat "$D")" "What this drill did not test"
DREPORT="$(sed -n 's/^Saved to //p' "$D" | tail -1)"
assert_eq "…and the report was saved" "$([ -s "$DREPORT" ] && echo yes)" "yes"
assert_contains "…dated, so it is evidence rather than a note" "$(head -1 "$DREPORT")" "Failover drill"
assert_eq "--failback returns the install to main" "$(cat "$HOME/.fox/primary" 2>/dev/null)" "main"
assert_eq "…and the drill left no schema of its own behind" \
  "$(pg pg-main "SELECT count(*) FROM information_schema.schemata WHERE schema_name='fox_drill'")" "0"
$S ha sync off >/dev/null 2>&1
$S ha disable >/dev/null 2>&1

# ---- automatic failover, with a witness (HA plan phase 3) -------------------
#
# The fence already refuses a promotion while the primary answers. What it
# cannot do is tell a dead primary from one this machine merely cannot reach:
# two machines cannot answer that about each other, so somebody else has to
# look. The witness is that third opinion, and `ha watch` promotes only when
# both it and this machine agree the primary has gone.
#
# Everything here runs on one host, so the "primary elsewhere" is a port
# nothing is listening on and the join record that names it is written by hand.
# What is being tested is the decision, which is the part that runs unattended.
WITPORT=7071
DEADPORT=59999
assert_contains "automatic failover refuses to run without a witness" \
  "$($S ha watch 2>&1 | head -2)" "needs a witness"
assert_contains "…and on a machine that follows nobody" \
  "$($S ha watch --witness http://127.0.0.1:$WITPORT/ha/primary 2>&1 | head -2)" "not following a primary"
# The witness itself: one question, answered truthfully both ways.
$S ha witness --primary 127.0.0.1:8080 --addr 127.0.0.1:$WITPORT >/tmp/wit-up.log 2>&1 &
WUP=$!
$S ha witness --primary 127.0.0.1:$DEADPORT --addr 127.0.0.1:7072 >/tmp/wit-down.log 2>&1 &
WDOWN=$!
$S ha witness --primary 127.0.0.1:8080 --addr 127.0.0.1:7073 --token s3cret >/tmp/wit-tok.log 2>&1 &
WTOK=$!
sleep 2
assert_eq "a witness says so when it reaches the primary" \
  "$(curl -s http://127.0.0.1:$WITPORT/ha/primary | jget reachable)" "True"
assert_eq "…and when it does not" \
  "$(curl -s http://127.0.0.1:7072/ha/primary | jget reachable)" "False"
# 404, not 401: a witness that confirms it is one to anybody who asks is a map
# of somebody's database cluster.
assert_eq "a stranger is not told that this is a witness at all" \
  "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7073/ha/primary)" "404"
assert_eq "…and the token gets an answer" \
  "$(curl -s -H 'Authorization: Bearer s3cret' http://127.0.0.1:7073/ha/primary | jget reachable)" "True"

$S ha enable >/dev/null 2>&1; sleep 5
printf '{"address":"127.0.0.1","port":%s,"role":"db_replica","at":"2026-10-13T00:00:00Z"}\n' "$DEADPORT" > "$HOME/$BRAND_STATE_DIR/node-joined.json"
# The refusal that matters most: this machine cannot reach the primary, but
# somebody else can, so this machine is the one that is cut off. Promoting here
# would make a second primary.
assert_contains "a watcher refuses while the witness still reaches the primary" \
  "$($S ha watch --witness http://127.0.0.1:$WITPORT/ha/primary --once --after 0s --dry-run 2>&1 | tail -1)" \
  "the one that is cut off"
# And having no second opinion is not agreement.
assert_contains "…and refuses when the witness cannot be asked at all" \
  "$($S ha watch --witness http://127.0.0.1:7999/ha/primary --once --after 0s --dry-run 2>&1 | tail -1)" \
  "A promotion needs two opinions"
assert_contains "…but promotes when both agree the primary has gone" \
  "$($S ha watch --witness http://127.0.0.1:7072/ha/primary --once --after 0s --dry-run 2>&1 | tail -1)" \
  "promoting"
# A dry run decided all three and changed nothing.
assert_eq "…and a dry run promoted nothing" "$(cat "$HOME/$BRAND_STATE_DIR/primary" 2>/dev/null)" "main"

# ---- a site drill, measured from the surviving machine (phase 6) -----------
#
# A local drill kills the primary beside it. On a machine that follows a primary
# elsewhere there is nothing here to kill, so it is refused and names the drill
# that does apply -- which waits for the other machine to go, promotes nothing
# itself, and measures what a client waited.
assert_contains "a local drill is refused on a machine that follows a primary elsewhere" \
  "$($S ha drill --yes --writes 10 2>&1 | head -2)" "ha drill --takeover"
# For real now: the watcher promotes, the drill measures.
( sleep 6; "$S" ha watch --witness http://127.0.0.1:7072/ha/primary --after 0s >/tmp/watch-real.log 2>&1 ) &
TD=/tmp/takeover.out
timeout 180 $S ha drill --takeover --wait 90s >"$TD" 2>&1
assert_eq "the takeover drill runs and exits 0" "$?" "0"
assert_contains "…measuring the time a client waited, noticing included" "$(cat "$TD")" "includes* noticing"
assert_contains "…refusing to guess the data loss it cannot see from this side" \
  "$(cat "$TD")" "not measurable from this side"
assert_contains "…and crediting the watcher rather than a person" "$(cat "$TD")" "with a witness agreeing"
# The report stops disclaiming what this drill actually did, which is the whole
# of phase 6: it used to say "there is only one site" in every copy.
assert_contains "…and no longer disclaims a second site it had" "$(cat "$TD")" "Nothing it set out to"
assert_eq "…nor claims detection was manual" "$(grep -c 'were manual' "$TD")" "0"
assert_eq "the promotion is in the hash-chained security log" \
  "$($S audit 2>/dev/null | grep -c 'ha.promoted')" "1"
kill "$WUP" "$WDOWN" "$WTOK" 2>/dev/null
rm -f "$HOME/$BRAND_STATE_DIR/node-joined.json"
$S ha failback >/dev/null 2>&1; sleep 2
$S ha disable >/dev/null 2>&1
assert_eq "the install is back on main with no standby" \
  "$(cat "$HOME/$BRAND_STATE_DIR/primary" 2>/dev/null)|$(sudo docker ps -aq --filter 'name=^pg-standby$' | wc -l | tr -d ' ')" "main|0"
# ---- end phases 3 and 6 ----------------------------------------------------

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

# ---- zero-data-loss mode must not survive losing the standby (phase 5) -----
#
# `fox stop` removes every managed container, the standby among them, but ALTER
# SYSTEM wrote synchronous_standby_names into main's postgresql.auto.conf and
# that survives. So the engine came back up still waiting for a standby that no
# longer existed -- and Init's own writes, the role sync and InstallLedger, are
# commits. They would have waited for ever: `up` never returning, nothing on the
# screen saying why, and the database unwritable.
$S ha sync on >/dev/null 2>&1
assert_eq "the mode is on before the standby goes" \
  "$(pg pg-main "SELECT current_setting('synchronous_standby_names')")" "ANY 1 (fox_standby)"
sudo docker rm -f pg-standby >/dev/null 2>&1
timeout 240 "$S" up >/tmp/sync-restart.log 2>&1
assert_eq "\`up\` returns instead of hanging on a commit nothing can satisfy" "$?" "0"
assert_eq "…having cleared the setting before its first write" \
  "$(pg pg-main "SELECT current_setting('synchronous_standby_names')")" ""
assert_eq "…so a write completes" "$(pgt 15 pg-main "INSERT INTO pit VALUES (94) RETURNING 'ok'")" "ok"
assert_eq "…and \`check\` says the mode was asked for but is not in effect" \
  "$($S check 2>&1 | grep -c '^warn  durability')" "1"
$S ha sync off >/dev/null 2>&1
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
# Staging renames public to raw, which used to carry the Blackbox's dblink out
# of its triggers' reach: a refused change was then misreported and unrecorded.
assert_eq "…and the pipeline's branch keeps the guardrail's dblink where its triggers look" \
  "$(pg pg-etltest "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE extname='dblink'")" "public"

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

echo "### 11c. backups to a remote target (audit v2: G18, G19, G17)"
# A second MinIO on the engine's network stands in for a remote bucket, created
# with Object Lock and a default retention as the docs recommend.
RS=it-remote-s3; RAK=itremotekey; RSK=itremotesecret123
MINIO_IMG="$(sudo docker inspect -f '{{.Config.Image}}' "$DB_OBJECT_STORE")"
# By digest first: an image pulled as tag@digest (which the engine does) is
# listed with the tag <none>, and "repo:<none>" is not a reference docker runs.
MC_IMG="$(sudo docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep -m1 '/mc@' | grep -v '@<none>')"
[ -n "$MC_IMG" ] || MC_IMG="$(sudo docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '/mc:' | grep -v ':<none>')"
sudo docker rm -f "$RS" >/dev/null 2>&1
sudo docker run -d --name "$RS" --network "$DB_NETWORK" -e MINIO_ROOT_USER="$RAK" -e MINIO_ROOT_PASSWORD="$RSK" "$MINIO_IMG" server /data >/dev/null
rmc() { sudo docker run --rm --network "$DB_NETWORK" -e MC_HOST_r="http://$RAK:$RSK@$RS:9000" "$MC_IMG" "$@" 2>&1; }
for i in $(seq 1 20); do rmc ls r >/dev/null 2>&1 && break; sleep 1; done
rmc mb --with-lock r/itremote >/dev/null; rmc retention set --default GOVERNANCE 1d r/itremote >/dev/null
assert_eq "a plain-HTTP target is refused without --allow-http" \
  "$(FOX_BACKUP_S3_SECRET_KEY="$RSK" $S backup target set s3://itremote/fox --endpoint "http://$RS:9000" --access-key "$RAK" --path-style 2>&1 | grep -c 'allow-http')" "1"
OUT="$(FOX_BACKUP_S3_SECRET_KEY="$RSK" $S backup target set s3://itremote/fox --endpoint "http://$RS:9000" --access-key "$RAK" --path-style --allow-http 2>&1)"
assert_eq "setting a remote target reports its Object Lock and moves backups there" \
  "$(echo "$OUT" | grep -c 'with Object Lock')|$(echo "$OUT" | grep -c 'Backups now go to s3://itremote/fox')" "1|1"
grep -q 'Backups now go to' <<<"$OUT" || { echo "      what it said:"; tail -4 <<<"$OUT" | sed 's/^/      /'; }
assert_eq "…the first base backup is taken there" "$(rmc ls --recursive r/itremote/fox/basebackups_005/ | grep -c 'backup_stop_sentinel.json' | awk '{print ($1>0)}')" "1"
assert_eq "…and the key is in a 0600 file, not on a command line" \
  "$(stat -c %a "$HOME/$BRAND_STATE_DIR/backup-target.json")|$(stat -c %a "$HOME/$BRAND_STATE_DIR/s3.env")|$(sudo docker inspect -f '{{join .Args " "}}' pg-main | grep -c "$RSK")" "600|600|0"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS remote_t; CREATE TABLE remote_t(x int); INSERT INTO remote_t SELECT generate_series(1,4);" >/dev/null
# Its own statement: one psql -c runs as one transaction, so a switch in the same
# string comes before the commit, and the commit would wait for archive_timeout.
pg pg-main "SELECT pg_switch_wal()" >/dev/null
sleep 8
assert_eq "WAL archives to the remote bucket" "$(rmc ls --recursive r/itremote/fox/wal_005/ | grep -c . | awk '{print ($1>0)}')" "1"
$S restore --to latest >/dev/null 2>&1; sleep 1
assert_eq "point-in-time restore reads from the remote target" "$(pg pg-restore 'SELECT count(*) FROM remote_t')" "4"
sudo docker rm -f pg-restore >/dev/null 2>&1
$S blackbox checkpoint main >/dev/null 2>&1; $S audit checkpoint >/dev/null 2>&1
assert_eq "anchors are copied to the target, under Object Lock" \
  "$(rmc ls --recursive r/itremote/fox/anchors/main/ | grep -c '.json' | awk '{print ($1>0)}')|$(rmc retention info --recursive r/itremote/fox/anchors/main/ | grep -c GOVERNANCE | awk '{print ($1>0)}')" "1|1"
assert_eq "…the security log's too" "$(rmc ls --recursive r/itremote/fox/anchors/_security-log/ | grep -c '.json' | awk '{print ($1>0)}')" "1"
read -r AKEYNAME AVID <<<"$(rmc ls --versions --json r/itremote/fox/anchors/main/ | python3 -c 'import sys,json
j=json.loads(sys.stdin.readline()); print(j["key"], j["versionId"])')"
assert_eq "an anchor copied there cannot be removed" \
  "$(rmc rm --version-id "$AVID" "r/itremote/fox/anchors/main/$AKEYNAME" | grep -ci 'retention\|locked\|denied\|worm' | awk '{print ($1>0)}')|$(rmc ls "r/itremote/fox/anchors/main/$AKEYNAME" | grep -c .)" "1|1"
STATUS="$($S status 2>&1)"
assert_eq "fox status names the target and the newest backup" \
  "$(echo "$STATUS" | grep -c 'target:   s3://itremote/fox')|$(echo "$STATUS" | grep -c 'newest:')" "1|1"
assert_eq "the status API reports it too" "$(curl -sk -H "$AUTH" https://localhost:8080/api/status | python3 -c 'import sys,json;b=json.load(sys.stdin)["backup"];print(b["remote"],b["stale"])')" "True False"
# G3 (expert review plan): anchors in a bucket of their own, each locked in
# COMPLIANCE mode, which nobody can lift before it expires. GOVERNANCE, the
# backup bucket's mode above, can be bypassed by anyone allowed to.
rmc mb r/itplain >/dev/null; rmc mb --with-lock r/itanchors >/dev/null
assert_eq "an anchor target without Object Lock is refused" \
  "$(FOX_ANCHOR_S3_SECRET_KEY="$RSK" $S blackbox anchor-target set s3://itplain --endpoint "http://$RS:9000" --access-key "$RAK" --path-style --allow-http 2>&1 | grep -c 'does not have Object Lock')" "1"
OUT="$(FOX_ANCHOR_S3_SECRET_KEY="$RSK" $S blackbox anchor-target set s3://itanchors --endpoint "http://$RS:9000" --access-key "$RAK" --path-style --allow-http --retention-days 1 2>&1)"
assert_eq "one with Object Lock is set, saying how long each anchor is locked" \
  "$(echo "$OUT" | grep -c 'COMPLIANCE mode for 1 days')|$(echo "$OUT" | grep -c 'Copied [1-9][0-9]* anchor')" "1|1"
grep -q 'Copied' <<<"$OUT" || { echo "      what it said:"; tail -4 <<<"$OUT" | sed 's/^/      /'; }
assert_eq "…warning that it shares the backup target's key" "$(echo "$OUT" | grep -c "backup target's access key")" "1"
assert_eq "…its key kept in a 0600 file" "$(stat -c %a "$HOME/$BRAND_STATE_DIR/anchor-target.json")" "600"
assert_eq "anchors there are locked in COMPLIANCE mode" \
  "$(rmc retention info --recursive r/itanchors/anchors/main/ | grep -c COMPLIANCE | awk '{print ($1>0)}')|$(rmc retention info --recursive r/itanchors/anchors/_security-log/ | grep -c COMPLIANCE | awk '{print ($1>0)}')" "1|1"
read -r CKEY CVID <<<"$(rmc ls --versions --json r/itanchors/anchors/main/ | python3 -c 'import sys,json
j=json.loads(sys.stdin.readline()); print(j["key"], j["versionId"])')"
assert_eq "…which even a governance bypass cannot remove" \
  "$(rmc rm --version-id "$CVID" --bypass "r/itanchors/anchors/main/$CKEY" | grep -ci 'retention\|locked\|denied\|worm' | awk '{print ($1>0)}')|$(rmc ls "r/itanchors/anchors/main/$CKEY" | grep -c .)" "1|1"
N0="$(rmc ls --recursive r/itanchors/anchors/main/ | grep -c '.json')"
pg pg-main "CREATE TABLE IF NOT EXISTS anchor_target_t(x int)" >/dev/null
$S blackbox checkpoint main >/dev/null 2>&1
assert_eq "a new anchor follows them there" "$(rmc ls --recursive r/itanchors/anchors/main/ | grep -c '.json')" "$((N0 + 1))"
# G3b: an auditor checks the anchors in the bucket, with keys of their own and
# nothing from this machine but the ledger rows. On a branch of its own: earlier
# sections rewrite main's history (and its anchors outlive them), and a name
# used by an earlier run would find that run's anchors. fox-verify runs here,
# not on the engine's network, so the store is reached at its address.
VB="itanc$(date +%s)"
$S branch create "$VB" >/dev/null 2>&1
$S branch owner "$VB" test@foxbyte.dev >/dev/null 2>&1
pg "pg-$VB" "CREATE TABLE verified_t(x int)" >/dev/null
$S blackbox checkpoint "$VB" >/dev/null 2>&1
RSIP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$RS")"
VDSN="postgresql://dbadmin:$KEY@127.0.0.1:6432/$VB?sslmode=require"
fv() { FOX_VERIFY_S3_SECRET_KEY="$RSK" /tmp/fox-verify --dsn "$VDSN" --anchors-s3 "s3://itanchors/anchors/$VB" \
  --s3-endpoint "http://$RSIP:9000" --s3-access-key "$RAK" --s3-path-style "$@" 2>&1; }
$S blackbox anchor-key > /tmp/it-anchor.pub 2>/dev/null
OUT="$(fv --pubkey /tmp/it-anchor.pub --anchors "$HOME/$BRAND_STATE_DIR/anchors/$VB")"; RC=$?
assert_eq "fox-verify reads the anchors from the bucket and finds the record intact" \
  "$RC|$(grep -c 'ledger integrity: INTACT' <<<"$OUT")|$(grep -c "anchors read from s3://itanchors/anchors/$VB" <<<"$OUT")" "0|1|1"
[ "$RC" = 0 ] || { echo "      what it said:"; head -8 <<<"$OUT" | sed 's/^/      /'; }
assert_eq "…saying that the rows before the fork are anchored under main" "$(grep -c 'anchored under the parent' <<<"$OUT")" "1"
pg "pg-$VB" "CREATE TABLE unanchored_t(x int)" >/dev/null; sleep 2
OUT="$(fv --max-anchor-age 1s)"; RC=$?
assert_eq "…and reports anchoring that has stopped while rows kept arriving" "$RC|$(grep -c 'anchoring has stopped' <<<"$OUT")" "1|1"
$S blackbox checkpoint "$VB" >/dev/null 2>&1
read -r DKEY _ <<<"$(rmc ls --versions --json "r/itanchors/anchors/$VB/" | python3 -c 'import sys,json
j=json.loads(sys.stdin.readline()); print(j["key"], j["versionId"])')"
rmc rm "r/itanchors/anchors/$VB/$DKEY" >/dev/null
OUT="$(fv)"; RC=$?
assert_eq "a delete marker over an anchor is reported, and its locked version still checked" \
  "$RC|$(grep -c 'was deleted from the bucket' <<<"$OUT")|$(grep -c 'Merkle root mismatch' <<<"$OUT")" "1|1|0"
printf '{"format":"ledger-anchor/1","merkle_root":"forged"}\n' | sudo docker run --rm -i --network "$DB_NETWORK" \
  -e MC_HOST_r="http://$RAK:$RSK@$RS:9000" "$MC_IMG" pipe "r/itanchors/anchors/$VB/$DKEY" >/dev/null 2>&1
OUT="$(fv)"; RC=$?
assert_eq "an anchor overwritten in the bucket is reported, and the first version is what is checked" \
  "$RC|$(grep -c 'was overwritten in the bucket' <<<"$OUT")|$(grep -c 'Merkle root mismatch' <<<"$OUT")" "1|1|0"
$S branch delete "$VB" >/dev/null 2>&1
assert_eq "fox check reports the target and its lock" \
  "$($S check 2>&1 | grep -c '^ok    anchor target .*itanchors.*COMPLIANCE')" "1"
assert_eq "removing it says what stays locked" "$($S blackbox anchor-target none 2>&1 | grep -c 'locked until their retention ends')" "1"
assert_eq "…and fox check warns again" "$($S check 2>&1 | grep -c '^warn  anchor target')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS anchor_target_t" >/dev/null
assert_eq "going back to the local store works" "$($S backup target local 2>&1 | grep -c 'local object store')" "1"
assert_eq "…and main archives there again" "$($S backup target | grep -c 'local object store')" "1"
sudo docker rm -f "$RS" >/dev/null 2>&1

echo "### 11d. the first run: sample data, check, connect (onboarding batch 1)"
# The suites run with FOX_NO_DEMO=1 (scripts/lib/test_guard.sh), so the seed is
# exercised here, deliberately, on a branch of its own.
$S branch delete demoseed >/dev/null 2>&1
# From main, before the clone, because a branch is a clone of main and this
# section's first assertion is that the seed has *not* run on it. The suites set
# FOX_NO_DEMO=1 (lib/test_guard.sh) so they never seed it themselves — but a
# `fox start` run by hand on this VM does, and then the clone inherits three
# tables and two assertions here fail for a reason that has nothing to do with
# the seed. Safe to drop: test_guard.sh refuses to run this suite anywhere but
# the throwaway VM.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS public.events, public.projects, public.users CASCADE" >/dev/null 2>&1
$S branch create demoseed >/dev/null 2>&1
# Not "the branch is empty": it is a clone of main, which earlier sections wrote
# to. What matters is that the sample tables are not there until the seed runs.
assert_eq "a fresh branch has no sample tables" \
  "$(pg pg-demoseed "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','projects','events')")" "0"
$S demo seed demoseed >/tmp/demoseed.log 2>&1
assert_eq "fox demo seed creates the three sample tables" \
  "$(pg pg-demoseed "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','projects','events')")" "3"
assert_eq "…with five rows each" \
  "$(pg pg-demoseed 'SELECT (SELECT count(*) FROM users)::text || (SELECT count(*) FROM projects)::text || (SELECT count(*) FROM events)::text')" "555"
assert_eq "…and a foreign key between them" \
  "$(pg pg-demoseed "SELECT count(*) FROM information_schema.table_constraints WHERE table_schema='public' AND constraint_type='FOREIGN KEY' AND table_name IN ('projects','events')")" "2"
# The sequences must be past the seeded ids, or a user's first insert collides.
assert_eq "…the sequences are past the sample rows" \
  "$(pg pg-demoseed "WITH i AS (INSERT INTO users (email, name) VALUES ('new@example.com','New') RETURNING id) SELECT id FROM i")" "6"
assert_eq "the sample schema is recorded in the Blackbox" \
  "$($S blackbox demoseed 2>/dev/null | grep -c 'CREATE TABLE' | awk '{print ($1>=3)}')" "1"
# Running it again must change nothing: it runs on every first start.
$S demo seed demoseed >/dev/null 2>&1
assert_eq "seeding twice changes nothing" \
  "$?|$(pg pg-demoseed 'SELECT count(*) FROM projects')" "0|5"
assert_eq "fox demo sql prints the SQL without running it" "$($S demo sql | grep -c 'CREATE TABLE IF NOT EXISTS users')" "1"
$S demo drop demoseed >/dev/null 2>&1
assert_eq "fox demo drop removes them again" \
  "$(pg pg-demoseed "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','projects','events')")" "0"

# fox connect --dsn prints a line a person can paste, and no key of its own.
CONN="$($S connect demoseed --dsn 2>&1)"
assert_eq "fox connect prints the gateway DSN for the branch" \
  "$(echo "$CONN" | grep -c 'postgresql://dbadmin:<API_KEY>@localhost:6432/demoseed?sslmode=require')" "1"
assert_eq "…and says where the password comes from, without minting one" \
  "$(echo "$CONN" | grep -c 'apikey create')|$(echo "$CONN" | grep -c "${DB_KEY_PREFIX}")" "1|0"
assert_eq "fox branch create ends with a connection string and a time" \
  "$($S branch create democonn 2>&1 | grep -c 'is ready in')" "1"
$S branch delete democonn >/dev/null 2>&1

# fox check is the install diagnosing itself: with the stack up it passes.
CHECK="$($S check 2>&1)"; CHECK_RC=$?
assert_eq "fox check exits 0 on a working install" "$CHECK_RC" "0"
assert_eq "…and reports main, the servers, the ports and the Blackbox" \
  "$(echo "$CHECK" | grep -c '^ok  ' | awk '{print ($1>=8)}')|$(echo "$CHECK" | grep -c 'FAIL')" "1|0"
# A check that the API refuses an unauthenticated caller: a 401 is the install
# working, and check says so rather than calling it a fault.
assert_eq "…including that the API refuses a caller with no key" \
  "$(echo "$CHECK" | grep -c 'API is closed')" "1"
# With a server stopped it must say which one, and fail.
$S logs gateway >/dev/null 2>&1
sudo pkill -f "fox gateway" >/dev/null 2>&1; sleep 2
CHECK="$($S check 2>&1)"; CHECK_RC=$?
assert_eq "a stopped gateway makes fox check fail and name it" \
  "$CHECK_RC|$(echo "$CHECK" | grep -c 'FAIL  gateway')" "1|1"
$S start >/dev/null 2>&1; sleep 3
assert_eq "…and it passes again once the stack is back" "$($S check >/dev/null 2>&1; echo $?)" "0"
$S branch delete demoseed >/dev/null 2>&1

echo "### 11e. the claims are checkable (onboarding batch 3)"
# A backup nothing has restored is a hope. This runs the real check: a probe row,
# its WAL segment archived, the newest base backup restored into a container of
# its own, and the row read back.
#
# A base backup first, deliberately. §11c moved the backup target to a second
# object store and back, and backups stay where they were written — so the local
# archive has a gap across that period, and a replay from a base backup older than
# the gap stops before the newest writes. That is documented behaviour, not a
# fault, and taking a backup on the target in force is what a person does after
# moving one.
$S backup create >/dev/null 2>&1
VERIFY="$($S backup verify 2>&1)"; VERIFY_RC=$?
assert_eq "fox backup verify proves a restore works" "$VERIFY_RC" "0"
[ "$VERIFY_RC" = 0 ] || { echo "--- what it said ---"; tail -12 <<<"$VERIFY"; echo "--- end ---"; }
assert_eq "…and says what it restored from" "$(grep -c 'the probe row was there' <<<"$VERIFY")" "1"
assert_eq "…it leaves no container of its own behind" \
  "$(sudo docker ps -a --format '{{.Names}}' | grep -cx 'pg-restore-check')" "0"
assert_eq "…and does not disturb a person's own fox restore container" \
  "$(sudo docker ps -a --format '{{.Names}}' | grep -cx 'pg-restore')" "0"
# The result is on disk for fox check and fox status to read.
assert_eq "the result is recorded" \
  "$(python3 -c "import json;d=json.load(open('$HOME/$BRAND_STATE_DIR/restore-check.json'));print(d['ok'], d['tables']>0, len(d['token'])>0)")" "True True True"
assert_eq "fox check reports that a restore has been proven" \
  "$($S check 2>&1 | grep -c 'restore proven .*yes')" "1"
# The probe table lives in the Blackbox's own schema, which its triggers skip, so
# proving a restore must not add anything to the record of schema changes.
assert_eq "…and it records nothing in the Blackbox" \
  "$($S blackbox main --limit 200 2>/dev/null | grep -c 'restore_probe')" "0"

# Long-lived containers must come back on their own; transient ones must not.
for c in pg-main objstore; do
  assert_eq "$c restarts on crash" \
    "$(sudo docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$c" 2>/dev/null)" "unless-stopped"
done
$S branch create rsttest >/dev/null 2>&1
assert_eq "a branch does too" \
  "$(sudo docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' pg-rsttest 2>/dev/null)" "unless-stopped"
# Crashed, it comes back by itself — the point of the policy. The process inside
# is killed, not the container: `docker kill` counts as a stop by the user, which
# "unless-stopped" deliberately honours.
sudo docker exec pg-rsttest bash -c 'kill -9 1' >/dev/null 2>&1
for _ in $(seq 20); do [ "$(sudo docker inspect -f '{{.State.Running}}' pg-rsttest 2>/dev/null)" = "true" ] && break; sleep 1; done
assert_eq "…and a killed branch comes back without anyone running fox" \
  "$(sudo docker inspect -f '{{.State.Running}}' pg-rsttest 2>/dev/null)" "true"
# Suspending is stopping on purpose: docker must leave it alone.
$S branch suspend rsttest >/dev/null 2>&1; sleep 3
assert_eq "…but a suspended branch stays suspended" \
  "$(sudo docker inspect -f '{{.State.Running}}' pg-rsttest 2>/dev/null)" "false"
$S branch delete rsttest >/dev/null 2>&1

# Every command the engine runs has a deadline now: with a tiny one, the failure
# says so instead of hanging for ever.
OUT="$(FOX_EXEC_TIMEOUT=1ms $S status 2>&1)"
assert_eq "a command that outlives its deadline says so" \
  "$(grep -c 'did not finish within' <<<"$OUT" | awk '{print ($1>0)}')" "1"
assert_eq "…and FOX_EXEC_TIMEOUT=off restores the old behaviour" \
  "$(FOX_EXEC_TIMEOUT=off $S status >/dev/null 2>&1; echo $?)" "0"

# Revoking a key that is not there is refused, rather than reported as revoked.
assert_eq "revoking an unknown API key id is refused" \
  "$($S apikey revoke test@foxbyte.dev no-such-key 2>&1 | grep -c 'has no API key')" "1"
assert_eq "…and over the API it is a 404" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -X DELETE -H "$AUTH" https://localhost:8080/api/keys/no-such-key)" "404"

echo "### 11f. versioned API paths and pgvector (onboarding batch 5)"
# /api/v1/… reaches the same handlers as /api/…: new code can pin a version, and
# everything written against the unversioned paths keeps working (audit v2 G35).
for p in status branches backups; do
  assert_eq "GET /api/v1/$p answers as /api/$p does" \
    "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "https://localhost:8080/api/v1/$p")|$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "https://localhost:8080/api/$p")" "200|200"
done
assert_eq "…and the bodies are the same" \
  "$(curl -sk -H "$AUTH" https://localhost:8080/api/v1/status | md5sum | cut -c1-32)" \
  "$(curl -sk -H "$AUTH" https://localhost:8080/api/status | md5sum | cut -c1-32)"
assert_eq "a branch path works versioned too" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" https://localhost:8080/api/v1/branches/main/ledger/verify)" "200"
assert_eq "…and so does the Blackbox alias inside it" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" https://localhost:8080/api/v1/branches/main/blackbox/verify)" "200"
assert_eq "an unauthenticated versioned call is still refused" \
  "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8080/api/v1/branches)" "401"
assert_eq "the bare version says where to go" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" https://localhost:8080/api/v1)" "307"
assert_eq "an unknown versioned path is a 404, not a redirect loop" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" https://localhost:8080/api/v1/nonsense)" "404"

# pgvector is in the image, so an agent that needs embeddings does not have to
# leave the database it was given (audit v2 G34). Nothing is enabled until asked.
assert_eq "pgvector is available but not enabled" \
  "$(pg pg-main "SELECT count(*) FROM pg_available_extensions WHERE name='vector'")|$(pg pg-main "SELECT count(*) FROM pg_extension WHERE extname='vector'")" "1|0"
assert_eq "…and CREATE EXTENSION vector works" \
  "$(pg pg-main 'CREATE EXTENSION IF NOT EXISTS vector' >/dev/null 2>&1; pg pg-main "SELECT count(*) FROM pg_extension WHERE extname='vector'")" "1"
assert_eq "…with a vector column and a distance query" \
  "$(pg pg-main "CREATE TABLE IF NOT EXISTS vtest(id int, e vector(3)); INSERT INTO vtest VALUES (1,'[1,0,0]'),(2,'[0,1,0]')" >/dev/null 2>&1; pg pg-main "SELECT id FROM vtest ORDER BY e <-> '[1,0,0]' LIMIT 1")" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS vtest" >/dev/null 2>&1

echo "### 11g. the console runs a script, not just one statement"
# Postgres refuses more than one command in the extended protocol, which is what
# pgx speaks, so the console used to answer "cannot insert multiple commands" to
# anything with a semicolon in it. It falls back to the simple protocol now, and
# returns a result per statement.
q() { # q <sql> -> the raw JSON
  curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST \
    -d "$(python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1]}))' "$1")" \
    https://localhost:8080/api/branches/main/query
}
jq_py() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

SCRIPT='CREATE TABLE ms_demo(id int); INSERT INTO ms_demo VALUES (1),(2),(3); SELECT count(*) FROM ms_demo;'
OUT="$(q "$SCRIPT")"
assert_eq "a three-statement script runs" "$(jq_py 'len(d.get("results",[]))' <<<"$OUT")" "3"
assert_eq "…and each statement reports its own command"   "$(jq_py '",".join(r.get("command","") .split()[0] for r in d["results"])' <<<"$OUT")" "CREATE,INSERT,SELECT"
assert_eq "…and the last statement's rows are the top-level ones, as before"   "$(jq_py 'd["rows"][0][0]' <<<"$OUT")" "3"
assert_eq "…and the rows are typed, not raw text"   "$(jq_py 'type(d["rows"][0][0]).__name__' <<<"$OUT")" "int"

# One statement must answer exactly as it always did: the SDKs and the console's
# own browse mode read the top-level fields.
OUT="$(q 'SELECT 1 AS one')"
assert_eq "a single statement still answers in the old shape"   "$(jq_py '"%s|%s|%s" % (d["columns"][0], d["rows"][0][0], len(d["results"]))' <<<"$OUT")" "one|1|1"

# A script is one transaction unless it opens its own, so a failure halfway
# leaves nothing behind. That is the property worth proving: a half-applied
# migration is the thing people fear about a console.
OUT="$(q 'INSERT INTO ms_demo VALUES (4); SELECT * FROM no_such_table;')"
assert_eq "a script that fails reports the error"   "$(jq_py '"yes" if d.get("error") else "no"' <<<"$OUT")" "yes"
assert_eq "…and says nothing was applied"   "$(jq_py '"yes" if "nothing was applied" in d.get("note","") else "no"' <<<"$OUT")" "yes"
assert_eq "…and nothing was: the row count is unchanged"   "$(pg pg-main 'SELECT count(*) FROM ms_demo')" "3"

# The guardrail is a trigger, so it fires on a statement inside a script exactly
# as it does on one sent alone. A script must not become a way around it.
# TRUNCATE rather than an unqualified DELETE: the DML guard is deliberately
# agent-only ("a human's unqualified DELETE is their own decision"), while
# TRUNCATE is blocked for everyone without an explicit override.
OUT="$(q 'SELECT 1; TRUNCATE ms_demo;')"
assert_eq "the TRUNCATE guardrail still fires inside a script" "$(jq_py '"yes" if d.get("error") else "no"' <<<"$OUT")" "yes"
assert_eq "…and the rows are still there" "$(pg pg-main 'SELECT count(*) FROM ms_demo')" "3"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ms_demo" >/dev/null 2>&1

echo "### 11h. an ordinary account's import runs as that account"
# An admin's import runs as the superuser, as it always has. Anyone else's runs
# what the source supplied as their own role, with psql's backslash commands
# switched off: it can do on the new branch what they could do there through the
# Gateway, and no more. ivy is an ordinary account.
$S user delete ivy@foxbyte.dev >/dev/null 2>&1; printf 'password123\n' | $S user create ivy@foxbyte.dev >/dev/null 2>&1
KI="$($S apikey create ivy@foxbyte.dev it 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
for b in ivyimp ivyimp2 ivyext admimp admext; do $S branch delete "$b" >/dev/null 2>&1; done
up() { # up <key> <file> <target> -> the SSE stream
  curl -sk -N -H "Authorization: Bearer $1" -F "file=@$2" -F "target=$3" https://localhost:8080/api/import/file; }
IVYSQL="$(mktemp -d)/ivy.sql"
printf 'CREATE SCHEMA ivy_s;\nCREATE TABLE ivy_t (a int);\nINSERT INTO ivy_t VALUES (1);\n' > "$IVYSQL"
assert_contains "ivy imports a .sql script" "$(up "$KI" "$IVYSQL" ivyimp)" "event: done"
assert_eq "…its tables belong to db_client, as through the Gateway, not to the superuser" \
  "$(pg pg-ivyimp "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname='ivy_t'")|$(pg pg-ivyimp "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='ivy_s'")" "db_client|db_client"
assert_eq "…the Blackbox names ivy" \
  "$(pg pg-ivyimp "SELECT count(*) FROM bb.schema_ledger WHERE object_identity='public.ivy_t' AND actor='ivy@foxbyte.dev'")" "1"
assert_eq "…the leave to make schemas lasted only for the import" \
  "$(pg pg-ivyimp "SELECT has_database_privilege('db_client', current_database(), 'CREATE')")" "f"
assert_eq "…and ivy reads it through the Gateway" \
  "$(PGPASSWORD="$KI" psql "$GATEWAY/ivyimp?sslmode=require" -tAc 'select a from ivy_t' 2>/dev/null)" "1"
assert_contains "an admin's import of the same script runs as the superuser, as before" "$(up "$KEY" "$IVYSQL" admimp)" "event: done"
assert_eq "…so its tables are the superuser's" "$(pg pg-admimp "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname='ivy_t'")" "dbadmin"
# A file a current pg_dump wrote restricts itself, after its header comments,
# and loads without complaint. Shaped by hand rather than dumped from a branch:
# a FoxByte table carries the Blackbox's triggers, and a dump of one collides
# with the ones the new branch adds, for an admin as much as for ivy.
DUMP="$(mktemp -d)/dump.sql"
printf -- '--\n-- PostgreSQL database dump\n--\n\n\\restrict Kfoxdump1\n\nSET statement_timeout = 0;\nCREATE TABLE public.ivy_d (a integer);\nCOPY public.ivy_d (a) FROM stdin;\n7\n\\.\n\n\\unrestrict Kfoxdump1\n' > "$DUMP"
assert_contains "ivy imports a pg_dump-shaped file cleanly" "$(up "$KI" "$DUMP" ivyimp2)" "event: done"
assert_eq "…with its row, copied in" "$(pg pg-ivyimp2 'SELECT a FROM ivy_d')" "7"
# psql's own commands are not SQL, and no role limits them: in ivy's import they
# do not run. \echo is harmless; the point is that it is refused.
printf 'CREATE TABLE ivy_m (a int);\n\\echo fox-meta-ran\n' > "$IVYSQL"
OUT="$(up "$KI" "$IVYSQL" ivyext)"
assert_eq "a psql command in ivy's script is refused and counted as a failure" \
  "$(echo "$OUT" | grep -c 'backslash commands are restricted')|$(echo "$OUT" | grep -c '1 statement(s) failed')" "1|1"
$S branch delete ivyext >/dev/null 2>&1
printf 'CREATE EXTENSION IF NOT EXISTS vector;\nCREATE TABLE ivy_v (a int);\n' > "$IVYSQL"
OUT="$(up "$KI" "$IVYSQL" ivyext)"
assert_eq "an extension only a superuser may make is refused for ivy, and the error says to ask an admin" \
  "$(echo "$OUT" | grep -c 'permission denied to create extension')|$(echo "$OUT" | grep -c 'needs an admin')" "1|1"
assert_contains "…an admin's import makes it, as before" "$(up "$KEY" "$IVYSQL" admext)" "event: done"
for b in ivyimp ivyimp2 ivyext admimp admext; do $S branch delete "$b" >/dev/null 2>&1; done
$S user delete ivy@foxbyte.dev >/dev/null 2>&1

echo "### 11i. an imported branch keeps the guardrail's record of what it refused"
# An import resets the new branch's public schema, and the Blackbox's dblink
# used to go with it. A refused change still did not run, but the client was
# told "function dblink_exec(text, text) does not exist" and the Blackbox kept
# no record of the attempt.
blocked() { pg "$1" "SELECT count(*) FROM bb.schema_ledger WHERE status='BLOCKED'"; }
client() { sudo docker exec "$1" psql -U db_client -d appdb -c "$2" 2>&1; }
$S branch delete dblimp >/dev/null 2>&1
printf 'CREATE TABLE dbl_t (a int);\nINSERT INTO dbl_t VALUES (1);\n' > /tmp/dblimp.sql
$S import --from /tmp/dblimp.sql --as dblimp >/dev/null 2>&1
assert_eq "an imported branch has the guardrail's dblink" \
  "$(pg pg-dblimp "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE extname='dblink'")" "public"
B0="$(blocked pg-dblimp)"
assert_contains "a client's DROP TABLE there is refused by the guardrail, by name" \
  "$(client pg-dblimp 'DROP TABLE dbl_t')" "guardrail: DROP TABLE is blocked by policy"
assert_eq "…and the Blackbox records the attempt" "$(blocked pg-dblimp)" "$((B0 + 1))"
# A branch imported before the fix lost it; the next start puts it back.
sudo docker exec -e PGOPTIONS="-c bb.allow_destructive=on" pg-dblimp psql -q -U dbadmin -d appdb -c "DROP EXTENSION dblink" >/dev/null 2>&1
assert_eq "(a branch without it, as an older import left one)" "$(pg pg-dblimp "SELECT count(*) FROM pg_extension WHERE extname='dblink'")" "0"
$S branch suspend dblimp >/dev/null 2>&1; $S branch resume dblimp >/dev/null 2>&1
assert_eq "the next start puts it back" "$(pg pg-dblimp "SELECT count(*) FROM pg_extension WHERE extname='dblink'")" "1"
assert_contains "…and a refused change is reported as one again" "$(client pg-dblimp 'DROP TABLE dbl_t')" "guardrail: DROP TABLE is blocked by policy"
$S branch delete dblimp >/dev/null 2>&1

echo "### 11j. fox sql: run SQL and copy the result (point 1.1)"
# The console's Copy menu writes the same text (web/src/copyformat.ts): both
# follow web/src/copyformat.vectors.json, which the unit tests of each check.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS cp_demo; DROP TABLE IF EXISTS cp_copy; DROP TABLE IF EXISTS cp_bb;
  CREATE TABLE cp_demo (id int, name text, note text, f text);
  INSERT INTO cp_demo VALUES (1, 'Ada, Countess', NULL, '=1+1'), (2, 'say \"hi\"', E'two\nlines', '-5');
  GRANT ALL ON cp_demo TO db_client;" >/dev/null
Q="SELECT id, name, note, f FROM cp_demo ORDER BY id"
OUT="$($S sql "SELECT id, name FROM cp_demo ORDER BY id" 2>&1)"
assert_eq "fox sql prints a table to read" "$(grep -c '^id  *name' <<<"$OUT")|$(grep -c '(2 rows)' <<<"$OUT")" "1|1"
assert_eq "…CSV: quoted where needed, NULL empty, a formula escaped, a negative number left alone" \
  "$($S sql --format csv "$Q")" $'id,name,note,f\n1,"Ada, Countess",,\'=1+1\n2,"say ""hi""","two\nlines",-5'
assert_eq "…--raw leaves a formula as it is" "$($S sql --format csv --raw --no-header "SELECT f FROM cp_demo WHERE id = 1")" "=1+1"
assert_eq "…tab-separated, without the header" "$($S sql --format tsv --no-header "SELECT id, name FROM cp_demo WHERE id = 1")" $'1\tAda, Countess'
assert_eq "…Markdown" "$($S sql --format markdown "SELECT id, note FROM cp_demo ORDER BY id")" $'| id | note |\n| --- | --- |\n| 1 | NULL |\n| 2 | two<br>lines |'
assert_eq "…JSON keeps the types" \
  "$($S sql --format json "$Q" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d), d[0]["id"], d[0]["note"], d[1]["name"])')" '2 1 None say "hi"'
# INSERTs are the one format meant to be run again: paste them into another
# table and it must hold the same rows.
pg pg-main "CREATE TABLE cp_copy (LIKE cp_demo); GRANT ALL ON cp_copy TO db_client;" >/dev/null
$S sql --format insert --table cp_copy "$Q" | $S sql - >/dev/null 2>&1
assert_eq "…INSERT statements run back into another table give the same rows" \
  "$(pg pg-main 'SELECT count(*) FROM cp_copy')|$(pg pg-main 'SELECT count(*) FROM (SELECT * FROM cp_demo EXCEPT SELECT * FROM cp_copy) d')" "2|0"
assert_eq "…and refuse to be written without a table" "$($S sql --format insert "$Q" >/dev/null 2>&1; echo $?)" "2"
# 1.2: an Excel workbook, opened here by a reader other than the code that
# wrote it (Python's zipfile and its XML parser), as a spreadsheet would.
$S sql --format xlsx "$Q" > /tmp/cp.xlsx
assert_eq "…an Excel workbook: a sound zip whose sheet holds the rows, types kept" \
  "$(python3 - /tmp/cp.xlsx <<'PYX'
import sys, zipfile, xml.etree.ElementTree as ET
z = zipfile.ZipFile(sys.argv[1])
bad = z.testzip()
ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
root = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
rows = root.findall('.//s:row', ns)
a2 = root.find(".//s:c[@r='A2']", ns)
d2 = root.find(".//s:c[@r='D2']", ns)
print(bad, len(rows), a2.get('t'), a2.find('s:v', ns).text, ''.join(d2.itertext()))
PYX
)" "None 3 None 1 =1+1"
assert_eq "SQL can come on stdin" "$(echo "SELECT 40 + 2 AS n" | $S sql --format csv --no-header -)" "42"
OUT="$($S sql "SELECT * FROM no_such_table" 2>&1)"; RC=$?
assert_eq "a failing statement exits 1 and says why" "$RC|$(grep -c '^ERROR: .*no_such_table' <<<"$OUT")" "1|1"
assert_eq "it runs as the client role, not the superuser" "$($S sql --format csv --no-header "SELECT current_user")" "db_client"
$S sql "CREATE TABLE cp_bb (x int)" >/dev/null 2>&1
assert_eq "…and the Blackbox names who ran it, and with what" \
  "$(pg pg-main "SELECT (actor LIKE 'cli:%')::text || '|' || tool FROM bb.schema_ledger WHERE object_identity = 'public.cp_bb' ORDER BY id DESC LIMIT 1")" "true|fox sql"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS cp_demo; DROP TABLE IF EXISTS cp_copy; DROP TABLE IF EXISTS cp_bb" >/dev/null

echo "### 11k. fox export: the whole result, streamed (point 1.3)"
# fox sql and the console stop at 1,000 rows; an export does not. It is the
# same text row for row, read only, one statement, as the caller's own role,
# and recorded in the security log by a fingerprint rather than the query.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ex_big; DROP TABLE IF EXISTS ex_rls;
  CREATE TABLE ex_big AS SELECT g AS id, CASE WHEN g % 500 = 0 THEN '=cmd' ELSE 'row ' || g END AS note FROM generate_series(1, 2500) g;
  CREATE TABLE ex_rls (owner text, v int);
  INSERT INTO ex_rls VALUES ('alice@foxbyte.dev', 1), ('test@foxbyte.dev', 2);
  ALTER TABLE ex_rls ENABLE ROW LEVEL SECURITY;
  CREATE POLICY own_rows ON ex_rls USING (owner = session_user);
  GRANT SELECT, UPDATE ON ex_big, ex_rls TO db_client;" >/dev/null
EQ="SELECT id, note FROM ex_big ORDER BY id"
$S export "$EQ" > /tmp/ex.csv 2>/tmp/ex.err; RC=$?
assert_eq "fox export writes every row, past the 1,000 fox sql stops at" \
  "$RC|$(wc -l < /tmp/ex.csv | tr -d ' ')|$(grep -c '^2500 rows exported' /tmp/ex.err)" "0|2501|1"
assert_eq "…and its first rows are exactly what fox sql prints" \
  "$(head -1001 /tmp/ex.csv | cmp -s - <($S sql --format csv "$EQ" 2>/dev/null) && echo same)" "same"
assert_eq "…spreadsheet-safe by default, --raw as it is" \
  "$(sed -n 501p /tmp/ex.csv)|$($S export --raw --no-header "SELECT note FROM ex_big WHERE id = 500" 2>/dev/null)" "500,'=cmd|=cmd"
assert_eq "…tab-separated" "$($S export --format tsv --no-header "SELECT id, note FROM ex_big WHERE id = 7" 2>/dev/null)" $'7\trow 7'
assert_eq "…JSON, every row" \
  "$($S export --format json "$EQ" 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d), d[0]["id"], d[-2]["note"], d[-1]["note"])')" "2500 1 row 2499 =cmd"
$S export --format xlsx "$EQ" > /tmp/ex.xlsx 2>/dev/null
assert_eq "…an Excel workbook of every row, which another reader opens" \
  "$(python3 - /tmp/ex.xlsx <<'PYX'
import sys, zipfile, xml.etree.ElementTree as ET
z = zipfile.ZipFile(sys.argv[1])
ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
root = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
last = root.findall('.//s:row', ns)[-1]
print(z.testzip(), len(root.findall('.//s:row', ns)), last.get('r'), last.find('s:c/s:v', ns).text)
PYX
)" "None 2501 2501 2500"
assert_eq "…which goes down a pipe like any file" \
  "$($S export --format xlsx "SELECT 1" 2>/dev/null | head -c 2)" "PK"
assert_eq "SQL can come on stdin" "$(echo "SELECT 40 + 2 AS n" | $S export --no-header - 2>/dev/null)" "42"
OUT="$($S export "UPDATE ex_big SET note = 'changed' WHERE id = 1 RETURNING id" 2>&1)"; RC=$?
assert_eq "an export is read only: an UPDATE … RETURNING is refused, and changes nothing" \
  "$RC|$(grep -c 'read-only transaction' <<<"$OUT")|$(pg pg-main "SELECT note FROM ex_big WHERE id = 1")" "1|1|row 1"
OUT="$($S export "SELECT 1; SELECT 2" 2>&1)"; RC=$?
assert_eq "…one statement only" "$RC|$(grep -c 'one statement' <<<"$OUT")" "1|1"
OUT="$($S export "SELECT * FROM no_such_table" 2>&1)"; RC=$?
assert_eq "…a failing statement exits 1 and says why" "$RC|$(grep -c '^ERROR: .*no_such_table' <<<"$OUT")" "1|1"
assert_eq "…as the client role, so row-level security holds (the CLI sees no one's rows)" \
  "$($S export --no-header "SELECT current_user" 2>/dev/null)|$($S export "SELECT v FROM ex_rls" 2>&1)" $'db_client|v\n0 rows exported'
FP="$(printf '%s' "$EQ" | sha256sum | cut -c1-12)"
AUDIT="$($S audit --limit 100 2>/dev/null | grep 'data.export')"
assert_eq "every export is in the security log, with a fingerprint of the query and not its text" \
  "$(grep -c "2500 row(s), query $FP" <<<"$AUDIT" | awk '{print ($1>=3)}')|$(grep -c 'ex_big\|no_such_table' <<<"$AUDIT")|$(grep -c 'stopped: SQLSTATE 25006' <<<"$AUDIT" | awk '{print ($1>0)}')" "1|0|1"

# The console's "Everything the query returns": the same endpoint, as the
# signed-in user's own role.
EXU=https://localhost:8080/api/branches/main/export
as "$KEY" -D /tmp/ex.hdr -o /tmp/ex-http.csv -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"$EQ\"}" "$EXU"
assert_eq "POST …/export streams every row, the same bytes as fox export, named as a download" \
  "$(cmp -s /tmp/ex.csv /tmp/ex-http.csv && echo same)|$(grep -ci 'content-disposition: attachment; filename="main-export.csv"' /tmp/ex.hdr)|$(grep -ci 'content-type: text/csv' /tmp/ex.hdr)" "same|1|1"
assert_eq "…a workbook too" \
  "$(as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"$EQ\",\"format\":\"xlsx\"}" "$EXU" | head -c 2)" "PK"
assert_eq "…as the user, so row-level security gives alice her rows only" \
  "$(as "$KA" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT session_user AS u, v FROM ex_rls","header":false}' "$EXU")" "alice@foxbyte.dev,1"
assert_eq "…a refusal before the first row is a 400 that says why" \
  "$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT * FROM no_such_table"}' "$EXU")|$(as "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"UPDATE ex_big SET id = id RETURNING id"}' "$EXU" | grep -c 'read-only transaction')|$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT 1","format":"pdf"}' "$EXU")" "400|1|400"
$S branch delete itexp >/dev/null 2>&1; $S branch create itexp >/dev/null 2>&1
assert_eq "…and a branch the caller cannot reach is not found (404)" \
  "$(code "$KA" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT 1"}' https://localhost:8080/api/branches/itexp/export)" "404"
$S branch delete itexp >/dev/null 2>&1
assert_eq "…and the console's exports are in the security log under the user" \
  "$($S audit --limit 100 2>/dev/null | grep 'data.export' | grep -c 'alice@foxbyte.dev' | awk '{print ($1>0)}')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ex_big; DROP TABLE IF EXISTS ex_rls" >/dev/null
rm -f /tmp/ex.csv /tmp/ex.err /tmp/ex.xlsx /tmp/ex.hdr /tmp/ex-http.csv

echo "### 11l. query history: what each person ran, never a result (points 8.1, 8.3)"
# The SQL, branch, time, duration, rows and outcome, kept 90 days, each
# person's own; console and API through /query, fox sql and fox export at the
# CLI. Not psql through the gateway, which passes bytes and sees no SQL.
HU=https://localhost:8080/api
hjson() { python3 -c 'import sys,json; d=json.load(sys.stdin); d=d.get("entries",d) if isinstance(d,dict) else d; '"$1"; }
$S history on >/dev/null 2>&1; $S history retention 90 >/dev/null 2>&1
$S history purge >/dev/null 2>&1; as "$KEY" -X DELETE "$HU/history" >/dev/null; as "$KA" -X DELETE "$HU/history" >/dev/null
assert_eq "fox history status says it is on, for 90 days" "$($S history status | grep -c 'is on for this install, kept 90 days')" "1"
M="hist_$RANDOM$RANDOM"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS hist_t; CREATE TABLE hist_t (v text); INSERT INTO hist_t VALUES ('zz-secret-row-value'), ('zz-secret-row-value-2'); GRANT SELECT ON hist_t TO db_client" >/dev/null
$S sql "SELECT v AS $M FROM hist_t" >/dev/null 2>&1
$S sql "SELECT * FROM no_such_table_$M" >/dev/null 2>&1
$S export "SELECT v AS ${M}_x FROM hist_t" >/dev/null 2>&1
assert_eq "fox sql and fox export are in the history of whoever is at the machine: the statement, rows, outcome" \
  "$($S history --json | hjson 'print(*["/".join([e["source"], e["kind"], str(e["rows"]), str(e["ok"])]) for e in d if "'"$M"'" in e["sql"]], sep=" ")')" \
  "cli/export/2/True cli/query/0/False cli/query/2/True"
assert_contains "…a failure keeps why" "$($S history --json | hjson 'print([e["error"] for e in d if "no_such_table_'"$M"'" in e["sql"]][0])')" "no_such_table_$M"
assert_contains "…and fox history prints it to read" "$($S history --limit 5)" "SELECT v AS $M FROM hist_t"

as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT v AS ${M}_api FROM hist_t\"}" "$HU/branches/main/query" >/dev/null
as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT v AS ${M}_hidden FROM hist_t\",\"history\":false}" "$HU/branches/main/query" >/dev/null
as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT v AS ${M}_exp FROM hist_t\"}" "$HU/branches/main/export" >/dev/null
MINE="$(as "$KEY" "$HU/history?limit=50")"
assert_eq "the API records what a key runs, with its rows; an export too; history:false is not kept" \
  "$(hjson 'print(*sorted("/".join([e["source"], e["kind"], str(e["rows"])]) for e in d if "'"$M"'" in e["sql"]), sep=" ")' <<<"$MINE")|$(grep -c "${M}_hidden" <<<"$MINE")" \
  "api/export/2 api/query/2|0"
assert_eq "…each person reads only their own: alice sees none of it, nor the CLI's" \
  "$(as "$KA" "$HU/history?limit=500" | grep -c "$M")|$(grep -c "${M}_x\|no_such_table_$M" <<<"$MINE")" "0|0"
# Never a result: the rows those queries returned are nowhere in the store.
assert_eq "no result is kept: the rows those queries returned are nowhere in the store" \
  "$(python3 - "$HOME/$BRAND_STATE_DIR/auth.db" <<'PYH'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
hits = 0
for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
    for row in c.execute(f'SELECT * FROM "{t}"'):
        hits += sum('zz-secret-row-value' in str(v) for v in row)
print(hits)
PYH
)" "0"
GWM="gw_$RANDOM"
PGPASSWORD="$KEY" psql "$GATEWAY/main?sslmode=require" -tAc "SELECT 1 AS $GWM" >/dev/null 2>&1
assert_eq "…and psql through the gateway is not seen (the documented limit)" "$(as "$KEY" "$HU/history?limit=50" | grep -c "$GWM")" "0"

# Off for one person, off for the install; settings are an admin's.
assert_eq "anyone turns their own off" "$(as "$KA" -H 'Content-Type: application/json' -X PUT -d '{"mine":false}' "$HU/history/settings" | hjson 'print(d["mine"])')" "False"
as "$KA" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT 1 AS ${M}_alice_off\"}" "$HU/branches/main/query" >/dev/null
as "$KA" -H 'Content-Type: application/json' -X PUT -d '{"mine":true}' "$HU/history/settings" >/dev/null
as "$KA" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT 1 AS ${M}_alice_on\"}" "$HU/branches/main/query" >/dev/null
assert_eq "…nothing is kept while it is off, and it keeps again when on" \
  "$(as "$KA" "$HU/history" | grep -c "${M}_alice_off")|$(as "$KA" "$HU/history" | grep -c "${M}_alice_on")" "0|1"
assert_eq "…but the install's switch and retention are an admin's" \
  "$(code "$KA" -H 'Content-Type: application/json' -X PUT -d '{"enabled":false}' "$HU/history/settings")|$(code "$KA" -H 'Content-Type: application/json' -X PUT -d '{"retention_days":7}' "$HU/history/settings")" "403|403"
$S history off >/dev/null
$S sql "SELECT 1 AS ${M}_install_off" >/dev/null 2>&1
$S history on >/dev/null
assert_eq "fox history off keeps nothing new" "$($S history --json | grep -c "${M}_install_off")" "0"
assert_eq "…retention is 1 to 3650 days" \
  "$($S history retention 0 >/dev/null 2>&1; echo $?)|$($S history retention 30 | grep -c 'kept 30 days')|$(as "$KEY" "$HU/history/settings" | hjson 'print(d["retention_days"])')" "1|1|30"
$S history retention 90 >/dev/null

# A person's history, for a request about their own data: read and deleted at
# the machine, and both in the security log; never the SQL itself.
assert_contains "the operator lists who has history" "$($S history --people)" "alice@foxbyte.dev"
assert_contains "…reads a person's, for them" "$($S history --user alice@foxbyte.dev)" "${M}_alice_on"
assert_contains "…and deletes it" "$($S history purge --user alice@foxbyte.dev)" "from alice@foxbyte.dev's query history"
assert_eq "…which is gone" "$(as "$KA" "$HU/history/settings" | hjson 'print(d["count"])')" "0"
AUD="$($S audit --limit 60 2>/dev/null)"
assert_eq "…and the security log has both, with no SQL" \
  "$(grep 'history.read' <<<"$AUD" | grep -c 'alice@foxbyte.dev' | awk '{print ($1>0)}')|$(grep 'history.purged' <<<"$AUD" | grep -c 'alice@foxbyte.dev' | awk '{print ($1>0)}')|$(grep 'history\.' <<<"$AUD" | grep -c "$M\|SELECT")" "1|1|0"
assert_eq "anyone deletes their own over the API" \
  "$(as "$KEY" -X DELETE "$HU/history" | hjson 'print(d["deleted"] > 0)')|$(as "$KEY" "$HU/history/settings" | hjson 'print(d["count"])')" "True|0"
assert_eq "…and purge --everyone asks first" "$($S history purge --everyone >/dev/null 2>&1; echo $?)" "2"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS hist_t" >/dev/null

echo "### 11m. history: search, run again, copy, saved queries (point 8.2)"
N="h82_$RANDOM$RANDOM"
$S history purge >/dev/null 2>&1
$S sql "SELECT 1 AS ${N}_a" >/dev/null 2>&1
$S sql "SELECT * FROM no_tbl_${N}" >/dev/null 2>&1
$S sql "SELECT 'x' AS ${N}_b" >/dev/null 2>&1
assert_eq "fox history --search finds text in a statement, and --failed the ones that failed" \
  "$($S history --json --search "${N}_" | hjson 'print(len(d))')|$($S history --json --failed --search "$N" | hjson 'print(len(d), d[0]["ok"])')" "2|1 False"
assert_eq "…a % or _ in the search is itself, not a wildcard" "$($S history --json --search "h82%" | hjson 'print(len(d))')" "0"
IDA="$($S history --json --search "${N}_a" | hjson 'print(d[0]["id"])')"
assert_eq "fox history show prints one statement exactly, to copy" "$($S history show "$IDA")" "SELECT 1 AS ${N}_a"
assert_eq "fox history run runs it again, as fox sql does" "$($S history run "$IDA" --format csv --no-header)" "1"
assert_eq "…and that run is kept as a new entry" "$($S history --json --search "${N}_a" | hjson 'print(len(d))')" "2"
$S branch delete ith82 >/dev/null 2>&1; $S branch create ith82 >/dev/null 2>&1
$S sql --branch ith82 "SELECT current_database() AS ${N}_where" >/dev/null 2>&1
IDB="$($S history --json --search "${N}_where" | hjson 'print(d[0]["id"])')"
assert_eq "…on the branch it ran on, unless --branch says otherwise" \
  "$($S history --json --search "${N}_where" | hjson 'print(d[0]["branch"])')|$($S history run "$IDB" >/dev/null 2>&1; $S history --json --search "${N}_where" | hjson 'print(d[0]["branch"])')|$($S history run "$IDB" --branch main >/dev/null 2>&1; $S history --json --search "${N}_where" | hjson 'print(d[0]["branch"])')" "ith82|ith82|main"
$S branch delete ith82 >/dev/null 2>&1
assert_eq "…an id that is not yours, or not there, is refused" "$($S history run 999999999 >/dev/null 2>&1; echo $?)" "1"

assert_contains "fox history save keeps an entry under a name" "$($S history save "first $N" --from "$IDA")" "Saved as \"first $N\""
assert_eq "…a name is used once" "$($S history save "first $N" "SELECT 2" >/dev/null 2>&1; echo $?)" "1"
$S history save "seven $N" "SELECT 7 AS v" >/dev/null
printf -- '-- a leading comment\nSELECT 8 AS v\n' | $S history save "comment $N" - >/dev/null
assert_eq "fox history saved lists them by name" "$($S history saved --json --search "$N" | hjson 'print(*[q["name"] for q in d], sep="|")')" "comment $N|first $N|seven $N"
assert_eq "…and runs one, even one that starts with a comment" \
  "$($S history run --saved "seven $N" --format csv --no-header)|$($S history run --saved "comment $N" --format csv --no-header)" "7|8"
assert_eq "…shows one exactly" "$($S history show --saved "first $N")" "SELECT 1 AS ${N}_a"
$S history unsave "seven $N" >/dev/null
assert_eq "fox history unsave deletes one" "$($S history saved --json --search "seven $N" | hjson 'print(len(d))')" "0"

# Over the API, the console's half: search, and saved queries that are yours.
SQ="$HU/saved-queries"
as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT * FROM no_tbl_api_${N}\"}" "$HU/branches/main/query" >/dev/null
assert_eq "GET /api/history?q=…&failed=1 searches your history" \
  "$(as "$KEY" "$HU/history?q=no_tbl_api_${N}&failed=1" | hjson 'print(len(d), d[0]["ok"])')" "1 False"
SID="$(as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"name\":\"api $N\",\"sql\":\"SELECT 9\"}" "$SQ" | hjson 'print(d["id"])')"
assert_eq "POST /api/saved-queries saves one; the same name again is 409" \
  "$([ -n "$SID" ] && echo saved)|$(code "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"name\":\"api $N\",\"sql\":\"SELECT 1\"}" "$SQ")" "saved|409"
assert_eq "…nobody else sees, renames or deletes it (404)" \
  "$(as "$KA" "$SQ" | grep -c "api $N")|$(code "$KA" -H 'Content-Type: application/json' -X PUT -d '{"name":"x"}' "$SQ/$SID")|$(code "$KA" -X DELETE "$SQ/$SID")" "0|404|404"
assert_eq "…its owner renames, finds and deletes it" \
  "$(as "$KEY" -H 'Content-Type: application/json' -X PUT -d "{\"name\":\"renamed $N\"}" "$SQ/$SID" | hjson 'print(d["name"])')|$(as "$KEY" "$SQ?q=renamed%20$N" | hjson 'print(len(d["queries"]))')|$(code "$KEY" -X DELETE "$SQ/$SID")" "renamed $N|1|204"
as "$KA" -H 'Content-Type: application/json' -X POST -d "{\"name\":\"alice $N\",\"sql\":\"SELECT 1\"}" "$SQ" >/dev/null
assert_contains "erasing a person's history at the machine takes their saved queries too" \
  "$($S history purge --user alice@foxbyte.dev)" "and 1 saved query"
assert_eq "…which are gone" "$(as "$KA" "$SQ" | hjson 'print(len(d["queries"]))')" "0"
for n in "first $N" "comment $N"; do $S history unsave "$n" >/dev/null 2>&1; done

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

# Anything the suite called that does not exist, counted now that the subshells
# it happened in are gone.
if [ -s "$MISSING_CMD_FLAG" ]; then
  MISSING="$(wc -l < "$MISSING_CMD_FLAG" | tr -d ' ')"
  FAIL=$((FAIL + MISSING))
  echo
  echo "  $MISSING assertion(s) called a command this suite does not define:"
  sort -u "$MISSING_CMD_FLAG" | sed 's/^/    /'
fi
rm -f "$MISSING_CMD_FLAG"

echo
echo "==== ${PASS} passed, ${FAIL} failed ===="
vm_pause_report
[ "$FAIL" -eq 0 ]
