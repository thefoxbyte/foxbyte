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
sudo docker rm -fv minio >/dev/null 2>&1
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
sudo docker rm -fv minio >/dev/null 2>&1

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
# The audit log's anchors (F6 step 6) likewise: they hold the store a run cut
# short left, which the next run's store will not match.
rm -rf "${HOME:?}/${BRAND_STATE_DIR:?}/anchors/_audit-log"
# Zero-data-loss mode is an intent that outlives the containers, so a run cut
# short after `ha sync on` leaves it behind -- and then `ha enable` in section 6
# dutifully puts the mode back, and the first assertion there ("commits do not
# wait by default") fails for a reason that has nothing to do with it.
rm -f "$HOME/$BRAND_STATE_DIR/sync-commit"
# Masking's key and masked accounts (F5): §11ai starts from an install that
# has never set masking up.
sudo rm -rf "${HOME:?}/${BRAND_STATE_DIR:?}/mask"; rm -f "${HOME:?}/${BRAND_STATE_DIR:?}/masked-accounts.json" "${HOME:?}/${BRAND_STATE_DIR:?}/mask-keys.json" "${HOME:?}/${BRAND_STATE_DIR:?}/unmask-grants.json"
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
sudo docker rm -fv pg-restore >/dev/null 2>&1

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
sudo docker rm -fv pg-restore >/dev/null 2>&1
# A point no base backup precedes is refused, saying what the archive reaches.
OLD="$($S restore --to '2020-01-01 00:00:00+00' 2>&1)"
assert_eq "a point before every base backup is refused" "$(echo "$OLD" | grep -c 'no base backup had finished by')" "1"
assert_eq "…the refusal names the oldest backup" "$(echo "$OLD" | grep -c 'the oldest is from')" "1"
assert_eq "…and nothing was left behind" "$(sudo docker ps -aq --filter 'name=^pg-restore$' | wc -l | tr -d ' ')" "0"
# latest still works exactly as before.
$S restore --to latest >/dev/null 2>&1; sleep 1
assert_eq "restore --to latest still reaches the end of the archive (9 rows)" "$(pg pg-restore 'SELECT count(*) FROM tt')" "9"
sudo docker rm -fv pg-restore >/dev/null 2>&1

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
sudo docker rm -fv itsrc >/dev/null 2>&1; $S branch delete itrep >/dev/null 2>&1
sudo docker run -d --name itsrc --network "$DB_NETWORK" -e POSTGRES_PASSWORD=srcpw "$IMG" postgres -c wal_level=logical >/dev/null
# Over TCP, not the socket: on a container's first start the entrypoint runs a
# temporary server that answers on the socket and then shuts down, and a probe
# that passes then lets the next psql land in the gap (the engine's waitReady
# says the same). Seen on a fresh VM, failing every check in this section.
for i in $(seq 1 60); do sudo docker exec itsrc pg_isready -h 127.0.0.1 -U postgres -q && break; sleep 1; done
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
# The console's queries are not gateway connections: each is its own short
# connection from the control plane. So the reaper took a branch someone was
# using in the console for an idle one, and stopped it under them, a query in
# flight hanging and the next refused (found 20 Oct 2026, when the console's UI
# tests ran long enough to cross the window). The console's use now counts.
$S branch delete itbusy >/dev/null 2>&1; $S branch delete itidle2 >/dev/null 2>&1
$S branch create itbusy >/dev/null 2>&1; $S branch create itidle2 >/dev/null 2>&1
nohup "$S" gateway --addr :6502 --idle 8s >/tmp/itbusygateway.log 2>&1 &
RPB=$!
for _ in $(seq 1 10); do
  curl -sk -o /dev/null -H "$AUTH" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT 1"}' https://localhost:8080/api/branches/itbusy/query
  sleep 3
done
assert_eq "a branch in use in the console survives the reaper" "$(sudo docker inspect -f '{{.State.Status}}' pg-itbusy 2>/dev/null)" "running"
assert_eq "…while an idle one beside it is suspended" "$(sudo docker inspect -f '{{.State.Status}}' pg-itidle2 2>/dev/null)" "exited"
sleep 25
kill "$RPB" 2>/dev/null
assert_eq "…and once nobody uses it, it is suspended too" "$(sudo docker inspect -f '{{.State.Status}}' pg-itbusy 2>/dev/null)" "exited"
$S branch delete itbusy >/dev/null 2>&1; $S branch delete itidle2 >/dev/null 2>&1
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
$S branch delete itrep >/dev/null 2>&1; sudo docker rm -fv itsrc >/dev/null 2>&1

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
# Streaming is asynchronous and the primary re-ships whenever an account
# changes, so one read of each could catch the standby a moment behind: wait for
# the two to agree, as a reader of the copy would.
SB=""
for _ in $(seq 1 15); do SD="$(statedg pg-main)"; SB="$(statedg pg-standby)"; [ -n "$SB" ] && [ "$SB" = "$SD" ] && break; sleep 1; done
assert_eq "…and the standby has the same document, through replication" "$SB" "$SD"
# The applications that may assert their users (F1) ride along: without them a
# failover would refuse every application's tokens.
assert_eq "…carrying the tables a second machine needs" \
  "$(sudo docker exec pg-main psql -U dbadmin -d statedb -tAc "SELECT string_agg(k, ',' ORDER BY k) FROM shared, jsonb_object_keys(payload->'tables') k WHERE id=1" 2>/dev/null)" \
  "api_keys,app_keys,apps,branch_owners,change_requests,install_info,oauth_identities,pipelines,pipeline_targets,users"
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
sudo docker rm -fv pg-standby >/dev/null 2>&1
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
sudo docker rm -fv pg-restore >/dev/null 2>&1
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
sudo docker rm -fv pg-standby >/dev/null 2>&1
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
sudo docker rm -fv mongo-src >/dev/null 2>&1
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
sudo docker rm -fv "$RS" >/dev/null 2>&1
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
sudo docker rm -fv pg-restore >/dev/null 2>&1
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
sudo docker rm -fv "$RS" >/dev/null 2>&1

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
[ "$CHECK_RC" = 0 ] || { echo "--- what failed ---"; grep -A1 '^FAIL' <<<"$CHECK"; echo "--- end ---"; }
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
CHECK="$($S check 2>&1)"; CHECK_RC=$?
assert_eq "…and it passes again once the stack is back" "$CHECK_RC" "0"
[ "$CHECK_RC" = 0 ] || { echo "--- what failed ---"; grep -A1 '^FAIL' <<<"$CHECK"; echo "--- end ---"; }
# The pool's health and the disk under it. On 2026-10-26 this VM's disk filled,
# ZFS suspended the pool, and every postgres on it hung for eight hours while the
# storage line still said the pool had 29G free: a pool in a sparse file counts
# space its disk no longer has. A real suspension would take this suite with it,
# so that path is unit-tested (TestPoolAndDiskLines); here the disk is filled to
# a warning, well short of where the pool's file could no longer grow.
assert_eq "fox check reports the pool's health" "$(grep -c '^ok    pool health  *ONLINE (zfs)' <<<"$CHECK")" "1"
assert_eq "…and the disk under the pool's file and Docker's data" \
  "$(grep -c "^ok    disk / .*free of .*holding the storage pool's file and Docker's images and volumes" <<<"$CHECK")" "1"
FILLER=/var/tmp/fox-it-disk-filler
AVAIL_K="$(df -P -k / | awk 'NR==2 {print $4}')"
FILL_K=$((AVAIL_K - 3500 * 1024))
if [ "$FILL_K" -gt 0 ] && sudo fallocate -l "${FILL_K}K" "$FILLER"; then
  CHECK="$($S check 2>&1)"; CHECK_RC=$?
  sudo rm -f "$FILLER"
  assert_eq "a disk filling up under the pool is a warning, not yet a failure" \
    "$CHECK_RC|$(grep -c '^warn  disk / .*filling up' <<<"$CHECK")" "0|1"
  assert_eq "…which says the pool's own count of free space is not the disk's" \
    "$(grep -c 'the pool counts .* free, but its file can grow by only' <<<"$CHECK")" "1"
  assert_eq "…and names only the safe cleanups" \
    "$(grep -A1 '^warn  disk /' <<<"$CHECK" | grep -c 'docker volume prune')|$(grep -A1 '^warn  disk /' <<<"$CHECK" | grep -c 'prune -a')" "1|0"
  assert_eq "…and it is ok again once the space is back" "$($S check 2>&1 | grep -c '^ok    disk / ')" "1"
else
  sudo rm -f "$FILLER"
  bad "could not fill the disk to test the disk-space line (avail ${AVAIL_K}K)"
fi
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
# Unused anonymous volumes, counted before the restore check so it is part of
# what must leave none behind (§11e2 below).
unused_vols() { sudo docker volume ls -q --filter dangling=true --filter label=com.docker.volume.anonymous | wc -l | tr -d ' '; }
VOLS_BEFORE="$(unused_vols)"
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

# A check that main's restart interrupts is not a restore that failed. The
# scheduled check once ran while §11c restarted main, wrote "writing the probe
# row: exit status 128" as the last check, and `fox check` reported "restore
# proven" as FAIL for the next hour. Now a check waits for main to be up, and one
# that cannot reach it says so and records nothing.
main_up() { for i in $(seq 1 60); do sudo docker exec pg-main pg_isready -h 127.0.0.1 -q 2>/dev/null && return 0; sleep 1; done; return 1; }
sudo docker stop pg-main >/dev/null 2>&1
( sleep 6; sudo docker start pg-main >/dev/null 2>&1 ) &
VERIFY="$($S backup verify 2>&1)"; VERIFY_RC=$?
wait
assert_eq "a check started while main is down waits for it, then proves the restore" \
  "$VERIFY_RC|$(grep -c 'Waiting for main to be up' <<<"$VERIFY")|$(grep -c 'the probe row was there' <<<"$VERIFY")" "0|1|1"
[ "$VERIFY_RC" = 0 ] || { echo "--- what it said ---"; tail -12 <<<"$VERIFY"; echo "--- end ---"; }
TOKEN_BEFORE="$(python3 -c "import json;print(json.load(open('$HOME/$BRAND_STATE_DIR/restore-check.json'))['token'])")"
sudo docker stop pg-main >/dev/null 2>&1
VERIFY="$($S backup verify 2>&1)"; VERIFY_RC=$?
sudo docker start pg-main >/dev/null 2>&1; main_up
assert_eq "one that main never comes back for fails, saying it could not check and recorded nothing" \
  "$VERIFY_RC|$(grep -c 'could not check: main was not available' <<<"$VERIFY")|$(grep -c 'nothing was recorded' <<<"$VERIFY")|$(grep -c 'did not restore' <<<"$VERIFY")" "1|1|1|0"
assert_eq "…the last real check is still the one on record" \
  "$(python3 -c "import json;d=json.load(open('$HOME/$BRAND_STATE_DIR/restore-check.json'));print(d['token']=='$TOKEN_BEFORE', d['ok'])")" "True True"
assert_eq "…so fox check still reports the restore as proven" \
  "$($S check 2>&1 | grep -c 'restore proven .*yes')" "1"

echo "### 11e2. a removed container takes its volume with it"
# The Postgres image declares VOLUME /var/lib/postgresql, so every branch
# container comes with an anonymous volume. Removing a container without -v
# left that volume behind, so a VM's disk filled up over months of branches
# deleted, stops and starts, and restore checks (each left its restored copy of
# main). Each of those must now leave the count of unused volumes as it was.
$S branch create volleak >/dev/null 2>&1
assert_eq "a branch container has a volume of its own" \
  "$(sudo docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}x{{end}}{{end}}' pg-volleak 2>/dev/null)" "x"
$S branch suspend volleak >/dev/null 2>&1; $S branch resume volleak >/dev/null 2>&1
$S branch delete volleak >/dev/null 2>&1
$S stop >/dev/null 2>&1; $S start >/dev/null 2>&1
assert_eq "a restore check, a branch deleted, and a stop and start leave no volume behind" \
  "$(unused_vols)" "$VOLS_BEFORE"
# An install from before the fix carries them, so fox check counts them and
# names the prune that keeps named volumes. One is made here to be found: a
# container created from the same image and removed the old way.
PG_IMAGE="$(sudo docker inspect -f '{{.Config.Image}}' pg-main)"
sudo docker create --name volleak-old "$PG_IMAGE" >/dev/null 2>&1
OLD_VOL="$(sudo docker inspect -f '{{range .Mounts}}{{.Name}}{{end}}' volleak-old 2>/dev/null)"
sudo docker rm -f volleak-old >/dev/null 2>&1
CHECK="$($S check 2>&1)"; CHECK_RC=$?
assert_eq "fox check counts a volume left by an older version, as a warning" \
  "$CHECK_RC|$(echo "$CHECK" | grep -c '^warn  docker volumes .*unused anonymous volume')" "0|1"
assert_eq "…and names the prune that keeps named volumes, not prune -a" \
  "$(echo "$CHECK" | grep -c 'docker volume prune   ')|$(echo "$CHECK" | grep -c 'prune -a')" "1|0"
[ -n "$OLD_VOL" ] && sudo docker volume rm "$OLD_VOL" >/dev/null 2>&1
assert_eq "…and once it is gone it is not counted" "$(unused_vols)" "$VOLS_BEFORE"

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

echo "### 11n. query suggestions: did you mean (point 9.2)"
# A table or column that does not exist gets the name probably meant, when one
# the caller can read is clearly closest. Autocomplete and snippets (9.1, 9.3)
# are the console's, and are in the Playwright suite.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS sg_customers, \"SgProducts\", sg_hidden_tbl;
  CREATE TABLE sg_customers (id int PRIMARY KEY, full_name text); CREATE TABLE \"SgProducts\" (id int);
  CREATE TABLE sg_hidden_tbl (id int); REVOKE ALL ON sg_hidden_tbl FROM PUBLIC, db_client;
  GRANT SELECT ON sg_customers, \"SgProducts\" TO db_client;" >/dev/null
OUT="$($S sql "SELECT * FROM sg_custmers" 2>&1)"; RC=$?
assert_eq "fox sql: a misspelt table gets the name meant, and still fails" "$RC|$(grep -c '^Did you mean sg_customers?$' <<<"$OUT")" "1|1"
assert_eq "…a misspelt column too" "$($S sql "SELECT ful_name FROM sg_customers" 2>&1 | grep -c '^Did you mean full_name?$')" "1"
assert_eq "…written as it must be, quoted when it must" "$($S sql "SELECT * FROM sgproduct" 2>&1 | grep -c '^Did you mean \"SgProducts\"?$')" "1"
assert_eq "…nothing when nothing is close" "$($S sql "SELECT * FROM zz_nothing_like_this" 2>&1 | grep -c 'Did you mean')" "0"
assert_eq "…and never a table the caller cannot read" "$($S sql "SELECT * FROM sg_hiden_tbl" 2>&1 | grep -c 'Did you mean')" "0"
assert_eq "…once, for a failed script" "$($S sql "SELECT 1; SELECT * FROM sg_custmers" 2>&1 | grep -c '^Did you mean sg_customers?$')" "1"
QU=https://localhost:8080/api/branches/main
assert_eq "the API answers it as data, with where Postgres pointed" \
  "$(as "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT * FROM sg_custmers"}' "$QU/query" | hjson 'print(d["suggestion"]["kind"], d["suggestion"]["wrong"], d["suggestion"]["insert"], d["position"])')" "table sg_custmers sg_customers 15"
# (A statement Postgres refuses while parsing never gets a result of its own,
# so the script carries it.)
assert_eq "…on a failed script" \
  "$(as "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT 1; SELECT * FROM sg_custmers"}' "$QU/query" | hjson 'print(d["suggestion"]["insert"])')" "sg_customers"
assert_eq "…and on an export refused before its first row" \
  "$(as "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT * FROM sg_custmers"}' "$QU/export" | hjson 'print(d["suggestion"]["insert"])')" "sg_customers"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS sg_customers, \"SgProducts\", sg_hidden_tbl" >/dev/null

echo "### 11o. fox schema: the object browser, read only (point 12.1)"
# Every kind of object a branch can hold, then: the tree, what is left out,
# each object's parts, and its CREATE script run on a fresh branch giving the
# same object back.
$S branch delete itcat >/dev/null 2>&1; $S branch delete itcat2 >/dev/null 2>&1
$S branch create itcat >/dev/null 2>&1
sudo docker exec -i -e PGPASSWORD=foxbyte pg-itcat psql -U dbadmin -d appdb -v ON_ERROR_STOP=1 -q >/dev/null 2>&1 <<'CATSQL'
SET bb.allow_destructive=on;
DROP SCHEMA IF EXISTS shop CASCADE;
CREATE SCHEMA shop;
COMMENT ON SCHEMA shop IS 'the shop';
CREATE TYPE shop.status AS ENUM ('new', 'paid', 'it''s shipped');
CREATE TYPE shop.money2 AS (amount numeric(12,2), currency char(3));
CREATE DOMAIN shop.email AS text NOT NULL CHECK (VALUE LIKE '%@%');
CREATE TYPE shop.floatrange AS RANGE (subtype = float8);
CREATE SEQUENCE shop.invoice_no START 1000 INCREMENT 5;
CREATE TABLE shop.customers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email shop.email UNIQUE,
  "Full Name" text NOT NULL DEFAULT 'anon',
  created timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE shop.customers IS 'people who buy';
COMMENT ON COLUMN shop.customers.email IS 'where we write';
CREATE TABLE shop.orders (
  id serial PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES shop.customers(id) ON DELETE CASCADE,
  status shop.status NOT NULL DEFAULT 'new',
  qty int CHECK (qty > 0),
  price numeric(10,2),
  total numeric GENERATED ALWAYS AS (qty * price) STORED,
  invoice int DEFAULT nextval('shop.invoice_no')
);
CREATE INDEX orders_status_idx ON shop.orders (status) WHERE status <> 'paid';
CREATE FUNCTION shop.touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.qty := coalesce(NEW.qty, 1); RETURN NEW; END $$;
CREATE TRIGGER orders_touch BEFORE INSERT ON shop.orders FOR EACH ROW EXECUTE FUNCTION shop.touch();
CREATE FUNCTION shop.order_total(o_id int) RETURNS numeric LANGUAGE sql STABLE AS $$ SELECT total FROM shop.orders WHERE id = o_id $$;
CREATE FUNCTION shop.order_total(o_id int, discount numeric) RETURNS numeric LANGUAGE sql STABLE AS $$ SELECT total - discount FROM shop.orders WHERE id = o_id $$;
CREATE PROCEDURE shop.pay(o_id int) LANGUAGE sql AS $$ UPDATE shop.orders SET status = 'paid' WHERE id = o_id $$;
CREATE VIEW shop.open_orders AS SELECT o.id, c."Full Name" AS who FROM shop.orders o JOIN shop.customers c ON c.id = o.customer_id WHERE o.status <> 'paid';
CREATE MATERIALIZED VIEW shop.order_counts AS SELECT status, count(*) AS n FROM shop.orders GROUP BY status;
CREATE TABLE shop.events (at date NOT NULL, what text) PARTITION BY RANGE (at);
CREATE TABLE shop.events_2026 PARTITION OF shop.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE shop.secret (x int); REVOKE ALL ON shop.secret FROM PUBLIC, db_client;
GRANT USAGE ON SCHEMA shop TO db_client;
GRANT SELECT ON shop.customers, shop.orders, shop.events, shop.open_orders, shop.order_counts TO db_client;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA shop TO db_client;
CATSQL
TREE="$($S schema --branch itcat)"
assert_contains "fox schema shows each schema and what is in it, by kind" "$TREE" $'shop\n  tables (3)\n    customers\n    events [partitioned]\n    orders\n  views (2)\n    open_orders\n    order_counts [materialized]\n  functions (3)\n    order_total(o_id integer)\n    order_total(o_id integer, discount numeric)\n    touch()\n  procedures (1)\n    pay(IN o_id integer)\n  sequences (2)\n    invoice_no\n    orders_id_seq\n  types (4)\n    email [domain]\n    floatrange [range]\n    money2 [composite]\n    status [enum]'
assert_eq "…not what is part of something else, nor an extension's, nor a table the caller cannot read" \
  "$(grep -c 'customers_id_seq\|floatmultirange\|dblink_connect\|secret' <<<"$TREE")" "0"
assert_eq "…the extensions, and FoxByte's own schema only when asked" \
  "$(grep -c '^  dblink ' <<<"$TREE")|$(grep -c '^bb$' <<<"$TREE")|$($S schema --branch itcat --all | grep -c '^bb$')" "1|0|1"
assert_eq "fox schema --search finds by name, --kind narrows" \
  "$($S schema --branch itcat --search order_t | grep -c 'function  shop.order_total')|$($S schema --branch itcat --search order --kind view | grep -c '^view')" "2|2"
OBJ="$($S schema --branch itcat shop.orders)"
assert_contains "fox schema <table> shows its columns" "$OBJ" "total        numeric        generated ((qty)::numeric * price)"
assert_contains "…its constraints" "$OBJ" "orders_customer_id_fkey: FOREIGN KEY (customer_id) REFERENCES shop.customers(id) ON DELETE CASCADE"
assert_contains "…its indexes" "$OBJ" "orders_status_idx: CREATE INDEX orders_status_idx ON shop.orders USING btree (status) WHERE (status <> 'paid'::shop.status)"
assert_contains "…its triggers, FoxByte's marked" "$OBJ" "bb_record_dml (FoxByte): CREATE TRIGGER bb_record_dml"
assert_eq "…and its CREATE script, without FoxByte's triggers" \
  "$($S schema --branch itcat orders --ddl | grep -c '^CREATE TRIGGER orders_touch')|$($S schema --branch itcat orders --ddl | grep -c 'bb_')" "1|0"
assert_eq "a name with overloads shows each" "$($S schema --branch itcat order_total --ddl | grep -c '^CREATE OR REPLACE FUNCTION shop.order_total')" "2"
assert_eq "an unknown name says so" "$($S schema --branch itcat nope_no_such >/dev/null 2>&1; echo $?)" "1"
CATORDER="shop status money2 email floatrange invoice_no orders_id_seq touch customers orders events order_total open_orders order_counts pay"
: > /tmp/cat-rt.sql
for o in $CATORDER; do $S schema --branch itcat "$o" --ddl >> /tmp/cat-rt.sql; echo >> /tmp/cat-rt.sql; done
$S branch create itcat2 >/dev/null 2>&1
sudo docker exec -i -e PGPASSWORD=foxbyte pg-itcat2 psql -U dbadmin -d appdb -v ON_ERROR_STOP=1 -q < /tmp/cat-rt.sql >/dev/null 2>&1; RC=$?
pg pg-itcat2 "GRANT USAGE ON SCHEMA shop TO db_client; GRANT SELECT ON ALL TABLES IN SCHEMA shop TO db_client; GRANT USAGE ON ALL SEQUENCES IN SCHEMA shop TO db_client;" >/dev/null
SAME=0; for o in $CATORDER; do [ "$($S schema --branch itcat "$o" --ddl)" = "$($S schema --branch itcat2 "$o" --ddl)" ] && SAME=$((SAME+1)); done
assert_eq "every CREATE script, run on a fresh branch, makes the same object again (15 of 15)" "$RC|$SAME" "0|15"
CU=https://localhost:8080/api/branches/itcat/schema
OID="$(as "$KEY" "$CU" | hjson 'print([o["oid"] for o in d["objects"] if o["kind"]=="table" and o["name"]=="orders"][0])')"
assert_eq "GET …/schema lists the objects, and …/schema/{kind}/{oid} gives one and its script" \
  "$(as "$KEY" "$CU" | hjson 'print(sorted({o["kind"] for o in d["objects"]}))')|$(as "$KEY" "$CU/table/$OID" | hjson 'print(d["ddl"].splitlines()[0], len(d["constraints"]))')" \
  "['extension', 'function', 'procedure', 'schema', 'sequence', 'table', 'type', 'view']|CREATE TABLE shop.orders ( 3"
assert_eq "…an object not in the caller's list is 404, and a branch out of reach is too" \
  "$(code "$KEY" "$CU/table/1")|$(code "$KEY" "$CU/function/$OID")|$(code "$KA" "$CU")" "404|404|404"
$S branch delete itcat >/dev/null 2>&1; $S branch delete itcat2 >/dev/null 2>&1; rm -f /tmp/cat-rt.sql

echo "### 11p. the data grid's save: rows edited together, as the user (point 12.2)"
# Sorting, filtering and paging are the console's own queries (Playwright);
# the save is the engine's: one transaction, a table with a key, the row as
# it was loaded, every value a parameter.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS gp_items, gp_nokey, gp_mine;
  CREATE TABLE gp_items (id int PRIMARY KEY, name text, qty int CHECK (qty > 0), total int GENERATED ALWAYS AS (qty * 2) STORED);
  INSERT INTO gp_items (id, name, qty) VALUES (1, 'one', 1), (2, 'two', 2), (3, 'three', 3);
  CREATE TABLE gp_nokey (v text); CREATE TABLE gp_mine (id int PRIMARY KEY, owner text, v text);
  INSERT INTO gp_mine VALUES (1, 'alice@foxbyte.dev', 'a'), (2, 'test@foxbyte.dev', 't');
  ALTER TABLE gp_mine ENABLE ROW LEVEL SECURITY; CREATE POLICY own ON gp_mine USING (owner = session_user);
  GRANT ALL ON gp_items, gp_nokey, gp_mine TO db_client;" >/dev/null
RU=https://localhost:8080/api/branches/main/rows
save() { as "$1" -H 'Content-Type: application/json' -X POST -d "$2" "$RU"; }
scode() { code "$1" -H 'Content-Type: application/json' -X POST -d "$2" "$RU"; }
assert_eq "a save adds, changes and deletes rows together" \
  "$(save "$KEY" '{"table":"gp_items","changes":[{"op":"delete","key":{"id":"3"}},{"op":"update","key":{"id":"1"},"values":{"name":"ONE","qty":"5"},"old":{"name":"one","qty":"1"}},{"op":"insert","values":{"id":"4","name":"x'"'"'); DROP TABLE gp_items; --","qty":null}}]}' | hjson 'print(d["inserted"], d["updated"], d["deleted"])')" "1 1 1"
assert_eq "…as written: a value is only ever a value, NULL is NULL, and a generated column follows" \
  "$(pg pg-main "SELECT string_agg(id||':'||name||':'||coalesce(qty::text,'null')||':'||coalesce(total::text,'null'), ' ' ORDER BY id) FROM gp_items")" \
  "1:ONE:5:10 2:two:2:4 4:x'); DROP TABLE gp_items; --:null:null"
assert_eq "a row changed since it was loaded stops the whole save (409), and nothing in it applies" \
  "$(scode "$KEY" '{"table":"gp_items","changes":[{"op":"insert","values":{"id":"9","name":"nine","qty":"1"}},{"op":"update","key":{"id":"2"},"values":{"name":"TWO"},"old":{"name":"stale"}}]}')|$(pg pg-main "SELECT count(*) FROM gp_items WHERE id = 9")|$(pg pg-main "SELECT name FROM gp_items WHERE id = 2")" "409|0|two"
assert_eq "…so does a row deleted since (409)" "$(scode "$KEY" '{"table":"gp_items","changes":[{"op":"delete","key":{"id":"3"}}]}')" "409"
OUT="$(save "$KEY" '{"table":"gp_items","changes":[{"op":"insert","values":{"id":"10","qty":"1"}},{"op":"update","key":{"id":"2"},"values":{"qty":"0"},"old":{"qty":"2"}}]}')"
assert_eq "a constraint refuses the save, says which change and why, and nothing applies" \
  "$(hjson 'print(d["error"].split(":")[0], "gp_items_qty_check" in d["error"])' <<<"$OUT")|$(pg pg-main "SELECT count(*) FROM gp_items WHERE id = 10")" "change 2 (update) True|0"
assert_eq "a generated column, an unknown column and a table without a key are refused" \
  "$(save "$KEY" '{"table":"gp_items","changes":[{"op":"update","key":{"id":"2"},"values":{"total":"1"}}]}' | grep -c 'generated')|$(save "$KEY" '{"table":"gp_items","changes":[{"op":"insert","values":{"nope":"1"}}]}' | grep -c 'no column')|$(save "$KEY" '{"table":"gp_nokey","changes":[{"op":"insert","values":{"v":"1"}}]}' | grep -c 'no primary key')" "1|1|1"
assert_eq "as the person editing: row-level security lets alice change her row, and not someone else's (409)" \
  "$(scode "$KA" '{"table":"gp_mine","changes":[{"op":"update","key":{"id":"1"},"values":{"v":"A"},"old":{"v":"a"}}]}')|$(scode "$KA" '{"table":"gp_mine","changes":[{"op":"delete","key":{"id":"2"}}]}')|$(pg pg-main "SELECT string_agg(v, ',' ORDER BY id) FROM gp_mine")" "200|409|A,t"
assert_eq "…and a branch out of reach is not found (404)" \
  "$($S branch delete itgp >/dev/null 2>&1; $S branch create itgp >/dev/null 2>&1; code "$KA" -H 'Content-Type: application/json' -X POST -d '{"table":"x","changes":[]}' https://localhost:8080/api/branches/itgp/rows; $S branch delete itgp >/dev/null 2>&1)" "404"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS gp_items, gp_nokey, gp_mine" >/dev/null

echo "### 11q. row tracking: who changed each row, and when (points 5.1, 6.1)"
# Opt-in per table; created_at, updated_at and last_modified_by kept by a
# trigger that overrides what a statement writes; last_modified_by is the
# login (session_user), which a session cannot change.
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS trk_a, trk_b, trk_c, trk_d, trk_n, trk_m;
  CREATE TABLE trk_a (id int PRIMARY KEY, v text); INSERT INTO trk_a VALUES (1, 'a'), (2, 'b');
  CREATE TABLE trk_b (id int PRIMARY KEY); INSERT INTO trk_b VALUES (1);
  CREATE TABLE trk_c (id int PRIMARY KEY); CREATE TABLE trk_d (id int, created_at date);
  GRANT ALL ON trk_a, trk_b, trk_c, trk_d TO db_client;" >/dev/null
assert_contains "fox track <table> starts tracking it" "$($S track trk_a)" "public.trk_a is tracked: created_at (when made), updated_at (when last changed), last_modified_by (who last changed it), last_modified_for (whom for, where an application said so). Rows already there are left empty."
assert_eq "…and fox track lists it" "$($S track | grep '^public.trk_a ' | tr -s ' ')" "public.trk_a created_at updated_at last_modified_by last_modified_for"
assert_eq "rows from before are left empty" "$(pg pg-main "SELECT count(*) FROM trk_a WHERE created_at IS NULL AND updated_at IS NULL AND last_modified_by IS NULL")" "2"
$S sql "INSERT INTO trk_a (id, v, created_at, updated_at, last_modified_by) VALUES (3, 'c', '2000-01-01', '2000-01-01', 'mallory')" >/dev/null 2>&1
assert_eq "an insert is stamped, whatever the statement wrote, with the login that made it" \
  "$(pg pg-main "SELECT (created_at > now() - interval '5 minutes')::text || '|' || (updated_at = created_at)::text || '|' || last_modified_by FROM trk_a WHERE id = 3")" "true|true|db_client"
TQ=https://localhost:8080/api/branches/main/query
as "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"INSERT INTO trk_a (id, v) VALUES (4, '"'"'d'"'"')"}' "$TQ" >/dev/null
C4="$(pg pg-main "SELECT created_at FROM trk_a WHERE id = 4")"
sleep 1
as "$KA" -H 'Content-Type: application/json' -X POST -d '{"sql":"UPDATE trk_a SET v = '"'"'D'"'"', created_at = '"'"'1999-01-01'"'"', last_modified_by = '"'"'mallory'"'"' WHERE id = 4"}' "$TQ" >/dev/null
assert_eq "an update moves updated_at, keeps created_at, and names the person whose login changed it" \
  "$(pg pg-main "SELECT (created_at = '$C4')::text || '|' || (updated_at > created_at)::text || '|' || last_modified_by FROM trk_a WHERE id = 4")" "true|true|alice@foxbyte.dev"
assert_eq "…the Blackbox records the table's change under who asked" \
  "$(pg pg-main "SELECT string_agg(command_tag, ',' ORDER BY id) FROM bb.schema_ledger WHERE object_identity IN ('public.trk_a', 'bb_track on public.trk_a') AND command_tag IN ('ALTER TABLE','CREATE TRIGGER') AND actor LIKE 'cli:%'")" "ALTER TABLE,CREATE TRIGGER"
assert_eq "the trigger cannot be dropped or disabled without the override" \
  "$(sudo docker exec -e PGPASSWORD=foxbyte pg-main psql -U dbadmin -d appdb -tAc "DROP TRIGGER bb_track ON trk_a" 2>&1 | grep -c 'cannot be dropped')|$(sudo docker exec -e PGPASSWORD=foxbyte pg-main psql -U dbadmin -d appdb -tAc "ALTER TABLE trk_a DISABLE TRIGGER bb_track" 2>&1 | grep -c 'cannot be disabled')" "1|1"
assert_contains "--label-existing gives rows already there this moment" "$($S track trk_b --label-existing)" "labelled with this moment"
assert_eq "…which they hold" "$(pg pg-main "SELECT count(*) FROM trk_b WHERE created_at IS NOT NULL AND updated_at IS NOT NULL")" "1"
$S track trk_c --created made --no-updated --by who --no-for >/dev/null
assert_eq "the columns can be named, or left out" \
  "$(pg pg-main "SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid = 'trk_c'::regclass AND attnum > 0 AND NOT attisdropped")" "id,made,who"
OUT="$($S track trk_d 2>&1)"; RC=$?
assert_eq "a column of the wrong type is refused, and says why" "$RC|$(grep -c 'is date, and tracking keeps timestamp with time zone' <<<"$OUT")" "1|1"
assert_contains "fox track <table> --off stops it" "$($S track trk_a --off)" "Its columns, and what they hold, are still there."
$S sql "UPDATE trk_a SET v = 'z' WHERE id = 4" >/dev/null 2>&1
assert_eq "…and the columns stay, no longer written" \
  "$(pg pg-main "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'trk_a'::regclass AND tgname = 'bb_track'")|$(pg pg-main "SELECT last_modified_by FROM trk_a WHERE id = 4")" "0|alice@foxbyte.dev"
$S track --new on >/dev/null
$S sql "CREATE TABLE trk_n (id int PRIMARY KEY)" >/dev/null 2>&1
$S track --new off >/dev/null
$S sql "CREATE TABLE trk_m (id int PRIMARY KEY)" >/dev/null 2>&1
assert_eq "--new on tracks tables as they are made, and --new off stops" \
  "$($S track | grep -c '^public.trk_n ')|$($S track | grep -c '^public.trk_m ')" "1|0"
assert_eq "every change is in the security log" "$($S audit --limit 30 | grep -c 'tracking.changed' | awk '{print ($1>=6)}')" "1"
TU=https://localhost:8080/api/branches/main/tracking
assert_eq "the API lists what is tracked, to anyone who uses the branch" \
  "$(as "$KA" "$TU" | hjson 'print(sorted(t["name"] for t in d["tables"] if t["name"].startswith("trk_")))')" "['trk_b', 'trk_c', 'trk_n']"
assert_eq "…and only the branch's owner or an admin changes it" \
  "$(code "$KA" -X PUT "$TU/tables/public/trk_m")|$(code "$KEY" -X PUT "$TU/tables/public/trk_m")|$(code "$KEY" -X DELETE "$TU/tables/public/trk_m")|$(code "$KA" -H 'Content-Type: application/json' -X PUT -d '{"on":true}' "$TU/new")" "403|200|200|403"
assert_eq "…and says why when Postgres refuses" "$(as "$KEY" -X PUT "$TU/tables/public/trk_d" | grep -c 'is date')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS trk_a, trk_b, trk_c, trk_d, trk_n, trk_m" >/dev/null

echo "### 11r. personal-data discovery: where a branch holds personal data, review, and keeping it current (points 4.1, 4.2, 4.6, 4.7)"
# Every identifier here is synthetic: made to pass its check, never a person's.
# 234567890124, 345678901238 and 456789012341 pass Verhoeff; 4111111111111111
# is the usual Luhn test card; 27AAPFU0939F1ZV carries a valid GSTIN check
# character.
$S branch delete piit >/dev/null 2>&1
$S branch create piit >/dev/null 2>&1
pg pg-piit "CREATE TABLE customers (id int PRIMARY KEY, full_name text, aadhaar_no text, ref text, pan text,
    phone text, email text, dob date, gstin text, card_no text, upi text, notes text, prefs jsonb, last_ip inet);
  INSERT INTO customers VALUES
    (1, 'A Person', '2345 6789 0124', '345678901238', 'ABCPE1234F', '+91 98765 43210', 'a@example.com', '1990-05-17',
     '27AAPFU0939F1ZV', '4111111111111111', 'person@okhdfc', 'called back',
     '{\"contact\": {\"mobile\": \"+91 98765 43210\"}, \"kyc\": {\"aadhaar\": \"234567890124\"}, \"orders\": [{\"email\": \"a@example.com\"}], \"theme\": \"dark\"}',
     '10.0.0.1'),
    (2, 'B Person', '456789012341', '234567890124', 'AAACB1234C', '9876543211', 'b@example.org', '2015-01-01',
     NULL, NULL, NULL, NULL,
     '{\"contact\": {\"mobile\": \"9876543211\"}, \"kyc\": {\"aadhaar\": 456789012341}, \"orders\": [{\"email\": \"b@example.org\"}, {\"email\": \"c@example.net\"}]}',
     '10.0.0.2');
  -- A document past the size the scan reads (256 KB as stored): hex does not
  -- compress much, so this is well over it.
  CREATE TABLE big_docs (id int PRIMARY KEY, doc jsonb);
  INSERT INTO big_docs SELECT 1, jsonb_build_object('email', 'x@example.com', 'blob', string_agg(md5(g::text), '')) FROM generate_series(1, 20000) g;
  CREATE TABLE orders (id bigint PRIMARY KEY, status text); INSERT INTO orders VALUES (1, 'open'), (2, 'closed');" >/dev/null
LEDGER_BEFORE="$(pg pg-piit "SELECT count(*) FROM bb.schema_ledger")"
SCANS_LOGGED="$($S audit --limit 1000 | grep -c 'personal-data.scanned')"
SCAN="$($S pii scan --branch piit 2>&1)"; SCAN_RC=$?
assert_eq "fox pii scan reads every table and exits 0" \
  "$SCAN_RC|$(grep -c '^Scanned piit: .* table(s), .* column(s) read, up to 1000 rows each' <<<"$SCAN")" "0|1"
[ "$SCAN_RC" = 0 ] || { echo "--- what it said ---"; tail -8 <<<"$SCAN"; echo "--- end ---"; }
PJ="$($S pii --branch piit --json 2>/dev/null)"
found() { hjson "print(' '.join(sorted(f['column']+f['path']+':'+f['category']+':'+f['confidence']+':'+f['rule'] for f in d['findings'] if f['table']=='$1')))" <<<"$PJ"; }
assert_eq "…and finds each identifier by its name and its values, with its check digit where it has one" \
  "$(found customers)" \
  "aadhaar_no:aadhaar:high:name+value card_no:card:high:name+value dob:child:high:name+value dob:date_of_birth:high:name+value email:email:high:name+value gstin:gstin:high:name+value last_ip:ip_address:high:name+value pan:pan:high:name+value phone:mobile:high:name+value prefs$.contact.mobile:mobile:high:name+value prefs$.kyc.aadhaar:aadhaar:high:name+value prefs$.orders[*].email:email:high:name+value ref:aadhaar:high:value upi:upi:high:name+value"
assert_eq "…finds nothing in a table that holds none" "$(found orders)" ""
assert_eq "…counts how much of the sample matched: one of two dates of birth is a child's" \
  "$(hjson "print([(f['matched'], f['sampled']) for f in d['findings'] if f['category']=='child'][0])" <<<"$PJ")" "(1, 2)"
assert_eq "…walks JSON path by path, an array's elements as one path, a number kept as its digits" \
  "$(hjson "print(sorted((f['path'], f['matched'], f['sampled']) for f in d['findings'] if f['column']=='prefs'))" <<<"$PJ")" \
  "[('$.contact.mobile', 2, 2), ('$.kyc.aadhaar', 2, 2), ('$.orders[*].email', 3, 3)]"
assert_eq "…does not read a document past its size limit, and says so" \
  "$(found big_docs)|$(grep -c '1 JSON document(s) larger than 256 KB were not read' <<<"$SCAN")" "|1"
assert_eq "…and says what it cannot claim, JSON included" \
  "$(grep -c 'not that it was issued' <<<"$SCAN")|$(grep -c 'JSON documents were read path by path' <<<"$SCAN")" "1|1"
# The point of keeping counts: the findings must not become a second copy of
# the data they point at.
assert_eq "no value is stored, in the findings or the scan's record" \
  "$(pg pg-piit "SELECT count(*) FROM (SELECT f::text t FROM bb.pii_findings f UNION ALL SELECT s::text FROM bb.pii_scans s) x
     WHERE t ~ '(234567890124|456789012341|2345 6789 0124|ABCPE1234F|98765 43210|a@example\.com|c@example\.net|1990-05-17|4111111111111111|person@okhdfc|27AAPFU0939F1ZV)'")" "0"
assert_eq "…and a client role cannot read where personal data is" \
  "$(sudo docker exec -e PGPASSWORD=foxbyte pg-piit psql -U dbadmin -d appdb -tAc "SET ROLE db_client; SELECT count(*) FROM bb.pii_findings" 2>&1 | grep -c 'permission denied')" "1"
assert_eq "a scan reads only: the Blackbox records nothing for it" "$(pg pg-piit "SELECT count(*) FROM bb.schema_ledger")" "$LEDGER_BEFORE"
assert_eq "…and it is in the security log, with its coverage" \
  "$($S audit --limit 1000 | grep -c 'personal-data.scanned')|$($S audit --limit 1000 | grep 'personal-data.scanned' | grep -vc 'table(s)')" "$((SCANS_LOGGED+1))|0"
# A reviewer's decision (step 4.6) must survive the next scan; a column that
# has gone stays listed, marked as not seen.
fid() { hjson "print([f['id'] for f in d['findings'] if f['table']=='$1' and f['column']=='$2' and f['path']=='$3'][0])" <<<"$PJ"; }
AID="$(fid customers aadhaar_no '')"
MARK="$($S pii mark "$AID" confirm --note 'the KYC column' --branch piit 2>&1)"; MARK_RC=$?
pg pg-piit "SET bb.allow_destructive = on; ALTER TABLE customers DROP COLUMN pan" >/dev/null
SCAN2="$($S pii scan --branch piit 2>&1)"
assert_eq "a scan again keeps a decision already made" \
  "$(pg pg-piit "SELECT state FROM bb.pii_findings WHERE column_name = 'aadhaar_no'")" "confirmed"
assert_eq "…and lists a finding it no longer sees as not seen, rather than dropping it" \
  "$(grep 'customers.pan ' <<<"$SCAN2" | grep -c 'not seen in the latest scan')" "1"
assert_eq "a sample outside 1 to 100000 is refused" \
  "$($S pii scan --branch piit --sample 100001 >/dev/null 2>&1; echo $?)|$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"sample":-5}' https://localhost:8080/api/branches/piit/personal-data/scan)" "1|400"
PU=https://localhost:8080/api/branches/piit/personal-data
# Someone with no access to a branch is told it is not there (404), so its
# name is not confirmed; someone who may use it but not manage it, as anyone may
# use main, is refused (403).
assert_eq "the API scans and lists for the branch's owner or an admin, and no one else" \
  "$(code "$KEY" -X POST "$PU/scan")|$(code "$KEY" "$PU")|$(code "$KA" "$PU")|$(code "$KA" -X POST "$PU/scan")|$(code "$KA" https://localhost:8080/api/branches/main/personal-data)|$(code "$KA" -X POST https://localhost:8080/api/branches/main/personal-data/scan)|$(code "$KEY" https://localhost:8080/api/branches/nosuchbranch/personal-data)" "200|200|404|404|403|403|404"
assert_eq "…answering with what it found" \
  "$(as "$KEY" "$PU" | hjson "print(sum(1 for f in d['findings'] if f['category']=='aadhaar'), d['scan']['actor'])")" "3 test@foxbyte.dev"

# Review (4.6): a person decides what each finding is, from masked samples.
assert_eq "fox pii mark records the decision, who made it, and why" \
  "$MARK_RC|$(grep -c ': confirmed\.$' <<<"$MARK")|$(pg pg-piit "SELECT state || '|' || (decided_by LIKE 'cli:%')::text || '|' || note FROM bb.pii_findings WHERE id = $AID")" \
  "0|1|confirmed|true|the KYC column"
assert_eq "…kept for good: the record of decisions cannot be changed or emptied" \
  "$(pg pg-piit "DELETE FROM bb.pii_decisions" >/dev/null; pg pg-piit "UPDATE bb.pii_decisions SET state = 'rejected'" >/dev/null; pg pg-piit "SELECT string_agg(state, ',') FROM bb.pii_decisions WHERE finding_id = $AID")" "confirmed"
SAMP="$($S pii samples "$AID" --branch piit 2>&1)"
assert_eq "masked samples show the kind of value, never the value" \
  "$(grep -c 'XXXX XXXX 0124 *looks like one' <<<"$SAMP")|$(grep -c 'XXXXXXXX2341' <<<"$SAMP")|$(grep -cE '234567890124|2345 6789 0124|456789012341' <<<"$SAMP")" "1|1|0"
PID="$(fid customers prefs '$.kyc.aadhaar')"
assert_eq "…inside a JSON document too, following the finding's path" \
  "$($S pii samples "$PID" --branch piit 2>&1 | grep -cE 'XXXXXXXX0124|XXXXXXXX2341')" "2"
assert_eq "…and both are in the security log" \
  "$($S audit --limit 50 | grep -c 'personal-data.marked' | awk '{print ($1>=1)}')|$($S audit --limit 50 | grep -c 'personal-data.sampled' | awk '{print ($1>=2)}')" "1|1"
$S branch delete piit2 >/dev/null 2>&1
$S branch create piit2 --from piit >/dev/null 2>&1
assert_eq "a decision travels with the branch: one made from it carries it" \
  "$(pg pg-piit2 "SELECT state FROM bb.pii_findings WHERE id = $AID")" "confirmed"
$S branch delete piit2 >/dev/null 2>&1
# Samples are read as the reviewer's own role: what row-level security hides
# from them, or a grant withholds, they are not shown. The scan, as the
# superuser, still finds both.
pg pg-piit "CREATE TABLE hidden_people (id int PRIMARY KEY, aadhaar_no text);
  INSERT INTO hidden_people VALUES (1, '234567890124'), (2, '456789012341');
  GRANT SELECT ON hidden_people TO db_client; ALTER TABLE hidden_people ENABLE ROW LEVEL SECURITY;
  CREATE TABLE closed_people (id int PRIMARY KEY, aadhaar_no text); INSERT INTO closed_people VALUES (1, '234567890124');
  REVOKE ALL ON closed_people FROM db_client" >/dev/null
$S pii scan --branch piit >/dev/null 2>&1
PJ="$($S pii --branch piit --json 2>/dev/null)"
HID="$(fid hidden_people aadhaar_no '')"; CID="$(fid closed_people aadhaar_no '')"; EID="$(fid customers email '')"
assert_eq "samples through the API are read as the reviewer: none past row-level security, though the operator sees two" \
  "$(as "$KEY" "$PU/findings/$HID/samples" | hjson "print(d['read'], len(d['samples']), d['as'])")|$($S pii samples "$HID" --branch piit --json | hjson "print(d['read'])")" \
  "0 0 test@foxbyte.dev|2"
assert_eq "…and a location their grants withhold is refused, saying so" \
  "$(code "$KEY" "$PU/findings/$CID/samples")|$(as "$KEY" "$PU/findings/$CID/samples" | grep -c 'your role cannot read this location')" "403|1"
assert_eq "the API decides, and refuses a state, a finding, or a sample count it does not know" \
  "$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"state":"rejected","note":"test data"}' "$PU/findings/$EID/mark")|$(pg pg-piit "SELECT state || '|' || decided_by FROM bb.pii_findings WHERE id = $EID")|$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"state":"maybe"}' "$PU/findings/$EID/mark")|$(code "$KEY" "$PU/findings/999999")|$(code "$KEY" "$PU/findings/$EID/samples?n=50")" \
  "200|rejected|test@foxbyte.dev|400|404|400"
assert_eq "…for the branch's owner or an admin only" \
  "$(code "$KA" "$PU/findings/$EID")|$(code "$KA" -H 'Content-Type: application/json' -X POST -d '{"state":"confirmed"}' "$PU/findings/$EID/mark")|$(code "$KA" "$PU/findings/$EID/samples")" "404|404|404"
$S pii mark "$AID" reopen --branch piit >/dev/null 2>&1
assert_eq "a finding can be reopened, and its history keeps both decisions in order" \
  "$(as "$KEY" "$PU/findings/$AID" | hjson "print(d['finding']['state'], [x['state'] for x in d['decisions']])")" "suggested ['confirmed', 'suggested']"
assert_eq "fox pii --state suggested is the review queue" \
  "$($S pii --branch piit --state suggested | grep -c 'customers.aadhaar_no ')|$($S pii --branch piit --state suggested | grep -c 'customers.email ')" "1|0"

# Keeping it current (4.7). The first scan of a branch is its baseline; what
# appears after it is unclassified until someone has looked.
assert_eq "what was there at the first scan is known, not unclassified" \
  "$(pg pg-piit "SELECT count(*) FROM bb.pii_columns WHERE table_name = 'customers' AND json_path = '' AND status <> 'known'")" "0"
pg pg-piit "ALTER TABLE customers ADD COLUMN alt_mobile text, ADD COLUMN tier text;
  UPDATE customers SET alt_mobile = '9876543212', tier = 'gold';
  UPDATE customers SET prefs = prefs || '{\"bank\": {\"ifsc\": \"HDFC0001234\"}}' WHERE id = 1;
  CREATE TABLE coupons (id int PRIMARY KEY, code text); INSERT INTO coupons VALUES (1, 'DIWALI10')" >/dev/null
NEWSCAN="$($S pii scan --branch piit --new 2>&1)"
assert_eq "fox pii scan --new reads only what has changed, and says what it left" \
  "$(grep -c '^Scanned piit (what is new):' <<<"$NEWSCAN")|$(grep -c 'were not read again' <<<"$NEWSCAN")|$(grep -c 'new column(s) or path(s) since the first scan are unclassified' <<<"$NEWSCAN")" "1|1|1"
UJ="$($S pii unclassified --branch piit --json 2>/dev/null)"
assert_eq "fox pii unclassified lists the new columns, the new table, and a new path inside JSON" \
  "$(hjson "print(' '.join(sorted(c['table']+'.'+c['column']+c['path'] for c in d if c['table'] in ('customers', 'coupons'))))" <<<"$UJ")" \
  "coupons.code coupons.id customers.alt_mobile customers.prefs\$.bank.ifsc customers.tier"
assert_eq "…and a finding on a table that scan skipped is not called not seen; only the dropped column's is" \
  "$($S pii --branch piit | grep -c 'not seen in the latest scan')|$($S pii --branch piit | grep 'not seen in the latest scan' | grep -c 'customers.pan ')" "1|1"
cid() { hjson "print([c['id'] for c in d if c['table']=='$1' and c['column']=='$2' and c['path']=='$3'][0])" <<<"$UJ"; }
ALT="$(cid customers alt_mobile '')"; TIER="$(cid customers tier '')"
assert_eq "a new column with a finding undecided cannot be accepted; its findings are decided one by one" \
  "$($S pii accept "$ALT" --branch piit >/dev/null 2>&1; echo $?)|$($S pii accept "$ALT" --branch piit 2>&1 | grep -c 'decide its findings first')|$(code "$KEY" -X POST "$PU/columns/$ALT/accept")" "1|1|409"
assert_eq "one that holds nothing to classify is accepted, with who and why, and leaves the list" \
  "$($S pii accept "$TIER" --note 'a loyalty tier' --branch piit >/dev/null 2>&1; echo $?)|$(pg pg-piit "SELECT status || '|' || (reviewed_by LIKE 'cli:%')::text || '|' || note FROM bb.pii_columns WHERE id = $TIER")|$($S pii unclassified --branch piit | grep -c 'customers.tier ')" \
  "0|reviewed|true|a loyalty tier|0"
PJ="$($S pii --branch piit --json 2>/dev/null)"
AMF="$(fid customers alt_mobile '')"
$S pii mark "$AMF" confirm --branch piit >/dev/null 2>&1
assert_eq "deciding the last finding at a new column reviews the column too" \
  "$(pg pg-piit "SELECT status FROM bb.pii_columns WHERE id = $ALT")" "reviewed"
$S pii mark "$AMF" reopen --branch piit >/dev/null 2>&1
assert_eq "…and reopening it puts the column back, and both are kept in its record" \
  "$(pg pg-piit "SELECT status FROM bb.pii_columns WHERE id = $ALT")|$(pg pg-piit "SELECT string_agg(status, ',' ORDER BY id) FROM bb.pii_column_reviews WHERE column_id = $ALT")" "unclassified|reviewed,unclassified"
assert_eq "…a record that cannot be changed or emptied" \
  "$(pg pg-piit "DELETE FROM bb.pii_column_reviews" >/dev/null; pg pg-piit "SELECT count(*) FROM bb.pii_column_reviews WHERE column_id IN ($ALT, $TIER)")" "3"
EMAILCOL="$(pg pg-piit "SELECT id FROM bb.pii_columns WHERE table_name = 'customers' AND column_name = 'email' AND json_path = ''")"
assert_eq "the API accepts for the owner or an admin, and refuses a baseline column, an unknown one, and anyone else" \
  "$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"note":"a coupon code"}' "$PU/columns/$(cid coupons code '')/accept")|$(code "$KEY" -X POST "$PU/columns/$EMAILCOL/accept")|$(code "$KEY" -X POST "$PU/columns/999999/accept")|$(code "$KA" -X POST "$PU/columns/$(cid coupons id '')/accept")|$(code "$KA" "$PU/unclassified")" \
  "200|400|404|404|404"
assert_eq "…which lists what is left, and the security log has each acceptance" \
  "$(as "$KEY" "$PU/unclassified" | hjson "print(sorted(c['column'] for c in d['columns'] if c['table'] in ('customers', 'coupons')))")|$($S audit --limit 50 | grep -c 'personal-data.accepted' | awk '{print ($1>=2)}')" \
  "['alt_mobile', 'id', 'prefs']|1"
assert_eq "a scan takes an inventory number only for what is new, so the numbers people type stay small" \
  "$(pg pg-piit "SELECT max(id) - count(*) FROM bb.pii_columns")" "0"
$S branch delete piit >/dev/null 2>&1

echo "### 11s. the access review report (point 4.8)"
# Who can reach what, with which keys, who may override the guardrails where,
# and who has gone quiet. An account and a key are backdated in the account
# store to be found dormant and stale: nothing else here is that old.
AUTHDB="$HOME/$BRAND_STATE_DIR/auth.db"
printf 'password123\n' | $S user create dormant@foxbyte.dev >/dev/null 2>&1
$S apikey create dormant@foxbyte.dev old-key >/dev/null 2>&1
$S apikey create alice@foxbyte.dev '=1+1' >/dev/null 2>&1
python3 - "$AUTHDB" <<'PY'
import sqlite3, sys, time
db = sqlite3.connect(sys.argv[1], timeout=10)
day = 86400
now = int(time.time())
db.execute("UPDATE users SET created = ? WHERE email = 'dormant@foxbyte.dev'", (now - 200 * day,))
db.execute("""UPDATE api_keys SET created = ?, last_used = NULL
              WHERE name = 'old-key' AND user_id = (SELECT id FROM users WHERE email = 'dormant@foxbyte.dev')""", (now - 150 * day,))
db.commit()
PY
$S branch delete arq >/dev/null 2>&1
$S branch create arq >/dev/null 2>&1
$S branch owner arq alice@foxbyte.dev >/dev/null 2>&1
$S admin grant alice@foxbyte.dev --branch arq >/dev/null 2>&1
REV="$($S access review 2>&1)"; REV_RC=$?
assert_eq "fox access review produces the report, and says what it cannot claim" \
  "$REV_RC|$(grep -c '^ACCOUNTS$' <<<"$REV")|$(grep -c '^KEYS$' <<<"$REV")|$(grep -c '^BRANCHES$' <<<"$REV")|$(grep -c 'No masking is in place yet' <<<"$REV")" "0|1|1|1|1"
RJ="$($S access review --json 2>/dev/null)"
acct() { hjson "a=[x for x in d['accounts'] if x['email']=='$1'][0]; print($2)" <<<"$RJ"; }
assert_eq "an install admin reaches every branch" "$(acct test@foxbyte.dev "a['admin'], a['reaches']")" "True every branch (an install admin)"
assert_eq "an account reaches main and what it owns, and may override where it was granted" \
  "$(acct alice@foxbyte.dev "a['admin'], 'arq' in a['owns'], 'arq' in a['overrideOn'], a['reaches'].startswith('main, and the')")" "False True True True"
assert_eq "an account with no activity in the window is dormant, a recent one is not" \
  "$(acct dormant@foxbyte.dev "a['dormant'], a['lastActive']")|$(acct test@foxbyte.dev "a['dormant']")" "True None|False"
assert_eq "a key never used and older than the window is stale, and says why" \
  "$(hjson "k=[x for x in d['keys'] if x['name']=='old-key'][0]; print(k['stale'], k['why'], k['kind'], k['owner'])" <<<"$RJ")" \
  "True never used, made 150 days ago account dormant@foxbyte.dev"
assert_eq "a branch shows its owner and who may override its guardrails" \
  "$(hjson "b=[x for x in d['branches'] if x['name']=='arq'][0]; print(b['owner'], 'alice@foxbyte.dev' in b['admins'], b['asked'])" <<<"$RJ")" \
  "alice@foxbyte.dev True True"
assert_eq "no secret is in it: a key is its prefix, never the key" \
  "$(grep -c -- "$KEY" <<<"$RJ")|$(grep -c 'key_hash' <<<"$RJ")" "0|0"
assert_eq "its tables come as CSV, with a value that would be a formula made safe" \
  "$($S access review --csv keys | head -1)|$($S access review --csv keys | grep -c "'=1+1" | awk '{print ($1>=1)}')|$($S access review --csv keys | grep -c ',=1+1')|$($S access review --csv branches | head -1)" \
  "id,name,prefix,owner,kind,identity,reach,created,last_used,age_days,stale,why|1|0|branch,state,owner,admins,admins_read"
$S branch suspend arq >/dev/null 2>&1
assert_eq "a suspended branch is not woken to be asked, and the report says so" \
  "$($S access review --json | hjson "b=[x for x in d['branches'] if x['name']=='arq'][0]; print(b['asked'], any('were not running' in l for l in d['limits']))")|$($S branch list 2>/dev/null | grep -w arq | grep -c running)" \
  "False True|0"
assert_eq "…and each report is in the security log" "$($S audit --limit 20 | grep -c 'access.reviewed' | awk '{print ($1>=3)}')" "1"
AR=https://localhost:8080/api/access-review
assert_eq "the API gives the report to an admin, and to no one else" \
  "$(code "$KEY" "$AR")|$(as "$KEY" "$AR" | hjson "print(d['summary']['accounts'] >= 3, d['dormantDays'])")|$(code "$KA" "$AR")" "200|True 90|403"
assert_eq "…as CSV too, and refuses a window or a table it does not know" \
  "$(curl -sk -o /dev/null -w '%{content_type}' -H "Authorization: Bearer $KEY" "$AR?format=csv&section=accounts")|$(as "$KEY" "$AR?format=csv&section=branches" | head -1)|$(code "$KEY" "$AR?dormant=0")|$(code "$KEY" "$AR?format=csv&section=passwords")" \
  "text/csv; charset=utf-8|branch,state,owner,admins,admins_read|400|400"
$S branch delete arq >/dev/null 2>&1
# The applications (F1): each registration, its keys and what each asserted,
# and what a reviewer should question.
ARD="$(mktemp -d)"
( cd "$(dirname "$0")/.." && go build -o "$ARD/mint" ./scripts/f1/mint ) || bad "the token tool builds"
printf 'password123\n' | $S user create rev-svc@foxbyte.dev >/dev/null 2>&1
RK="$($S apikey create rev-svc@foxbyte.dev app 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
"$ARD/mint" keygen "$ARD" k1 >"$ARD/k1.pub"; "$ARD/mint" keygen "$ARD" k2 >"$ARD/k2.pub"
for a in revapp adminapp; do $S app remove $a >/dev/null 2>&1; done
$S app register revapp --account rev-svc@foxbyte.dev --key "$ARD/k1.pub" --kid k1 >/dev/null 2>&1
$S app register adminapp --account test@foxbyte.dev --key "$ARD/k2.pub" --kid k2 >/dev/null 2>&1
ARAUD="$($S app list --json | python3 -c 'import sys,json; print(json.load(sys.stdin)["install_id"])')"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ar_f1_a, ar_f1_b" >/dev/null
PGPASSWORD="$RK" psql "$GATEWAY/main?sslmode=require" -X -q >/dev/null 2>&1 <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$("$ARD/mint" token "$ARD/k1.seed" -kid k1 -iss revapp -aud "$ARAUD" -sub alice)' \g
CREATE TABLE ar_f1_a (id int);
CREATE TABLE ar_f1_b (id int);
COMMIT;
SQL
ARJ="$($S access review --json 2>/dev/null)"
arapp() { python3 -c "import sys,json; d=json.load(sys.stdin); a=[x for x in d['applications'] if x['name']=='$1'][0]; print($2)" <<<"$ARJ"; }
assert_eq "the report lists each application with its account and keys" \
  "$(arapp revapp "a['account'], [k['kid'] for k in a['keys']], a['keys'][0]['active']")" "rev-svc@foxbyte.dev ['k1'] True"
assert_eq "…what each key asserted, on main" "$(arapp revapp "a['keys'][0]['records'].get('main', 0) >= 2, a['keys'][0]['lastAsserted'] is not None")" "True True"
assert_eq "…and what a reviewer should question: an application on an install admin's account" \
  "$(arapp adminapp "any('install admin' in f for f in a['findings'])")|$(arapp revapp "len(a['findings'])")" "True|0"
assert_eq "the summary counts them" "$(python3 -c 'import sys,json; s=json.load(sys.stdin)["summary"]; print(s["applications"] >= 2, s["appsWithFindings"] >= 1)' <<<"$ARJ")" "True True"
assert_eq "fox access review prints them, with the findings" \
  "$($S access review | grep -c '^APPLICATIONS$')|$($S access review | grep -c '! adminapp: Its account is an install admin')" "1|1"
assert_eq "…and as CSV, one row per key" \
  "$($S access review --csv applications | head -1)|$($S access review --csv applications | grep -c '^revapp,rev-svc@foxbyte.dev,none,300,k1,')" \
  "application,account,on_invalid,token_life_seconds,kid,key_created,key_age_days,active,revoked,compromised_since,records,sessions,last_asserted,findings|1"
for a in revapp adminapp; do $S app remove $a >/dev/null 2>&1; done
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS ar_f1_a, ar_f1_b" >/dev/null
rm -rf "$ARD"

echo "### 11t. listing backups starts no container while main runs"
# A throwaway container on the bridge network creates and destroys a network
# interface, and a browser on the same machine takes that for the network
# changing and aborts every request it has in flight ("Failed to fetch"). The
# Dashboard lists backups on every visit, so the console's own suite saw one
# every few seconds and failed a test at random. With main running, the listing
# runs inside it.
EVLOG="$(mktemp)"
sudo timeout 8 docker events --filter type=container --filter event=start --format '{{.Actor.Attributes.name}}' >"$EVLOG" 2>/dev/null &
EVPID=$!
sleep 1
for _ in 1 2 3; do as "$KEY" https://localhost:8080/api/backups >/dev/null; done
wait "$EVPID" 2>/dev/null
assert_eq "listing backups through the API, three times, starts no container" \
  "$(grep -c . "$EVLOG")|$(as "$KEY" https://localhost:8080/api/backups | python3 -c 'import sys,json; print(len(json.load(sys.stdin)) > 0)')" "0|True"
rm -f "$EVLOG"
# Without a running primary the backups are still in object storage, and
# listing them falls back to a throwaway container.
sudo docker stop pg-main >/dev/null 2>&1
assert_eq "…and with main stopped they are still listed, from a container of their own" \
  "$($S check 2>&1 | grep '^[a-z]* *backups ' | grep -c 'could not be listed')" "0"
$S start >/dev/null 2>&1; sleep 3

echo "### 11u. application identity: an application says which of its users a change was for (F1)"
# An application registered against the account its connections use calls
# bb.act_for($1) with a short-lived token signed by its own key, and the
# Blackbox records each change as made by the account and for the user. The
# SQL's own cases (signatures, claims, savepoints, pooling, cost) are
# integration_f1.sh's; these are the engine's: registration, the copy into
# branches, the Gateway, the API and the console's columns.
F1D="$(mktemp -d)"
( cd "$(dirname "$0")/.." && go build -o "$F1D/mint" ./scripts/f1/mint ) || bad "the token tool builds"
printf 'password123\n' | $S user create shop-svc@foxbyte.dev >/dev/null 2>&1
SK="$($S apikey create shop-svc@foxbyte.dev app 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
SAK="$($S apikey create shop-svc@foxbyte.dev bot --agent 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
"$F1D/mint" keygen "$F1D" k1 >"$F1D/k1.pub"
"$F1D/mint" keygen "$F1D" k2 >"$F1D/k2.pub"
$S app remove shop >/dev/null 2>&1
for b in f1b f1s; do $S branch delete "$b" >/dev/null 2>&1; done
# 2 is the first with the extension; later ones keep it (3 added pgAudit).
assert_eq "the engine image is revision 2 or later, which has the extension" \
  "$([ "$(sudo docker image inspect -f '{{index .Config.Labels "dev.dbengine.image-revision"}}' "$(sudo docker inspect -f '{{.Config.Image}}' pg-main)")" -ge 2 ] && echo yes)" "yes"
appev() { $S audit --limit 5000 | grep -c "app\.$1"; }
EV0="$(appev registered)|$(appev key_added)|$(appev key_revoked)|$(appev removed)"
REG="$($S app register shop --account shop-svc@foxbyte.dev --key "$F1D/k1.pub" --kid k1 2>&1)"
assert_contains "fox app register registers it, with its key" "$REG" "Added key k1 to shop"
AUD="$($S app list --json | python3 -c 'import sys,json; print(json.load(sys.stdin)["install_id"])')"
assert_eq "every running branch can check a token" "$($S app list | grep -c 'Not ready')" "0"
tok() { local key="$1"; shift; "$F1D/mint" token "$F1D/$key.seed" -kid "$key" -iss shop -aud "$AUD" "$@"; }
# f1do <key> <branch> <token> <table>: through the Gateway, a transaction that
# asserts with the token and then makes a table.
f1do() {
  PGPASSWORD="$1" psql "$GATEWAY/$2?sslmode=require" -X -q -tA 2>&1 <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$3' \g
CREATE TABLE $4 (id int);
COMMIT;
SQL
}
# forof <branch> <table>: who the Blackbox says creating it was for.
forof() { $S blackbox "$1" --limit 30 | grep -w "public.$2" | head -1 | awk -F'|' '{gsub(/^ +| +$/, "", $3); print $3}'; }
T1="$(tok k1 -sub alice)"
assert_eq "asserted through the Gateway, the Blackbox records whom the change was for" \
  "$(f1do "$SK" main "$T1" f1_a >/dev/null; forof main f1_a)" "alice, asserted by shop"
assert_eq "…beside the account that made it" "$($S blackbox main --limit 30 | grep -w public.f1_a | grep -c shop-svc@foxbyte.dev)" "1"
assert_eq "the same token from another account is refused, and the change is for nobody" \
  "$(f1do "$KA" main "$T1" f1_b >/dev/null; forof main f1_b)" "none: token refused: wrong session role"
if [ -n "$SAK" ]; then
  assert_eq "…and from the same account's agent key" \
    "$(f1do "$SAK" main "$T1" f1_c >/dev/null; forof main f1_c)" "none: token refused: wrong session role"
else
  bad "an agent key for the application's account could be made"
fi
assert_eq "a value set by hand is not taken for an assertion" \
  "$(PGPASSWORD="$SK" psql "$GATEWAY/main?sslmode=require" -X -q -tA -c "BEGIN; SET LOCAL bb.app.actor = 'mallory'; CREATE TABLE f1_d (id int); COMMIT;" >/dev/null 2>&1; forof main f1_d)" \
  "none: an application actor was present and failed its check"
assert_eq "the token is in no log: not the Gateway's, the control plane's, nor Postgres's" \
  "$(cat "$HOME/$BRAND_STATE_DIR/gateway.log" "$HOME/$BRAND_STATE_DIR/controlplane.log" 2>/dev/null | grep -c -F "$T1")|$(sudo docker logs pg-main 2>&1 | grep -c -F "$T1")" "0|0"

# A branch is a copy of main: it is given its own name before anyone reaches it.
$S branch create f1b >/dev/null 2>&1
$S branch owner f1b shop-svc@foxbyte.dev >/dev/null 2>&1
TB="$(tok k1 -sub bob -branch f1b)"
assert_eq "a token for one branch is accepted there" "$(f1do "$SK" f1b "$TB" f1_e >/dev/null; forof f1b f1_e)" "bob, asserted by shop"
assert_eq "…and refused on main" "$(f1do "$SK" main "$TB" f1_f >/dev/null; forof main f1_f)" "none: token refused: wrong branch"

# Rotation, revocation at once on a running branch, and on a suspended one
# before its first transaction.
$S app key add shop --key "$F1D/k2.pub" --kid k2 >/dev/null 2>&1
assert_eq "during a rotation both keys are accepted" \
  "$(f1do "$SK" main "$(tok k2 -sub carol)" f1_g >/dev/null; forof main f1_g)|$(f1do "$SK" main "$(tok k1 -sub dan)" f1_h >/dev/null; forof main f1_h)" \
  "carol, asserted by shop|dan, asserted by shop"
$S branch create f1s >/dev/null 2>&1
$S branch owner f1s shop-svc@foxbyte.dev >/dev/null 2>&1
$S branch suspend f1s >/dev/null 2>&1
$S app key revoke shop k2 >/dev/null 2>&1
assert_eq "a revoked key is refused from the next transaction on a running branch" \
  "$(f1do "$SK" main "$(tok k2 -sub carol)" f1_i >/dev/null; forof main f1_i)" "none: token refused: revoked key"
assert_eq "…and on a branch that was suspended when it was revoked, once woken" \
  "$(f1do "$SK" f1s "$(tok k2 -sub carol)" f1_j >/dev/null; forof f1s f1_j)" "none: token refused: revoked key"

# A key reported compromised: what it asserted from then on says so.
SINCE="$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)"
$S app key revoke shop k1 --compromised-since "$SINCE" >/dev/null 2>&1
assert_eq "what a key reported compromised asserted is shown so, never as plain asserted" \
  "$(forof main f1_a)" "alice, asserted by shop (key reported compromised)"
LJ="$(as "$KEY" "https://localhost:8080/api/branches/main/ledger?with=for&table=f1_a")"
assert_eq "the API says the same, beside the account" \
  "$(python3 -c 'import sys,json; d=json.load(sys.stdin); r=dict(zip(d["columns"], d["rows"][0])); print(r["actor"], r["app_for"], r["app_state"], r["app_kid"])' <<<"$LJ")" \
  "shop-svc@foxbyte.dev alice asserted by shop (key reported compromised) k1"
assert_eq "the default listing is unchanged" \
  "$(as "$KEY" "https://localhost:8080/api/branches/main/ledger?table=f1_a" | python3 -c 'import sys,json; print("app_for" in json.load(sys.stdin)["columns"])')" "False"

AP=https://localhost:8080/api/apps
assert_eq "the API lists the applications to an admin, and to no one else" \
  "$(code "$KEY" "$AP")|$(as "$KEY" "$AP" | python3 -c 'import sys,json; d=json.load(sys.stdin); a=d["apps"][0]; print(a["name"], a["account"], len(a["keys"]), d["install_id"] == "'"$AUD"'")')|$(code "$KA" "$AP")" \
  "200|shop shop-svc@foxbyte.dev 2 True|403"
$S app remove shop >/dev/null 2>&1
assert_eq "each registration, key, revocation and removal is in the security log" \
  "$(awk -F'|' -v a="$(appev registered)" -v b="$(appev key_added)" -v c="$(appev key_revoked)" -v d="$(appev removed)" '{print a-$1 "|" b-$2 "|" c-$3 "|" d-$4}' <<<"$EV0")" "1|2|2|1"
assert_eq "removing an application refuses its tokens, and keeps what it asserted" \
  "$(f1do "$SK" main "$(tok k1 -sub erin)" f1_k >/dev/null; forof main f1_k)|$($S blackbox main --limit 60 | grep -w public.f1_g | grep -c 'carol, asserted by shop')" \
  "none: token refused: unknown key|1"
PGPASSWORD="$KEY" psql "$GATEWAY/main?sslmode=require" -X -q -c "SET bb.allow_destructive=on; DROP TABLE IF EXISTS f1_a, f1_b, f1_c, f1_d, f1_f, f1_g, f1_h, f1_i, f1_k" >/dev/null 2>&1
for b in f1b f1s; do $S branch delete "$b" >/dev/null 2>&1; done
rm -rf "$F1D"

echo "### 11v. last_modified_for: whom each row was last changed for, through the Gateway (point 5.2)"
# Row tracking's fourth column: what an application asserted (11u), or a
# client claimed, about whom a change was for. The SQL's own cases (a value set
# by hand, another application's login, the cost) are integration_f1.sh's.
F5D="$(mktemp -d)"
( cd "$(dirname "$0")/.." && go build -o "$F5D/mint" ./scripts/f1/mint ) || bad "the token tool builds"
printf 'password123\n' | $S user create trk-svc@foxbyte.dev >/dev/null 2>&1
TK="$($S apikey create trk-svc@foxbyte.dev app 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
"$F5D/mint" keygen "$F5D" k1 >"$F5D/k1.pub"
$S app remove trkapp >/dev/null 2>&1
$S app register trkapp --account trk-svc@foxbyte.dev --key "$F5D/k1.pub" --kid k1 >/dev/null 2>&1
AUD5="$($S app list --json | python3 -c 'import sys,json; print(json.load(sys.stdin)["install_id"])')"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS trk_f, trk_g;
  CREATE TABLE trk_f (id int PRIMARY KEY, v text); CREATE TABLE trk_g (id int PRIMARY KEY, v text);
  INSERT INTO trk_g VALUES (1, 'old');
  GRANT ALL ON trk_f, trk_g TO db_client;" >/dev/null
$S track trk_f >/dev/null
# gw5 <sql…>: one transaction through the Gateway as the application's account.
gw5() { PGPASSWORD="$TK" psql "$GATEWAY/main?sslmode=require" -X -q -tA 2>&1; }
gw5 >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$("$F5D/mint" token "$F5D/k1.seed" -kid k1 -iss trkapp -aud "$AUD5" -sub alice)' \g
INSERT INTO trk_f VALUES (1, 'a');
COMMIT;
SQL
gw5 >/dev/null <<'SQL'
BEGIN; SET LOCAL bb.claimed_actor = 'bob'; INSERT INTO trk_f VALUES (2, 'b'); COMMIT;
SQL
gw5 >/dev/null <<'SQL'
INSERT INTO trk_f VALUES (3, 'c');
SQL
assert_eq "a row keeps the login and, where the application asserted one, whom it was for" \
  "$(pg pg-main "SELECT string_agg(id || ':' || last_modified_by || ':' || coalesce(last_modified_for, 'NULL'), ' ' ORDER BY id) FROM trk_f")" \
  "1:trk-svc@foxbyte.dev:asserted:trkapp:alice 2:trk-svc@foxbyte.dev:claimed:bob 3:trk-svc@foxbyte.dev:NULL"
$S app key revoke trkapp k1 >/dev/null 2>&1
gw5 >/dev/null <<SQL
BEGIN;
SELECT bb.act_for(\$1) \bind '$("$F5D/mint" token "$F5D/k1.seed" -kid k1 -iss trkapp -aud "$AUD5" -sub alice)' \g
UPDATE trk_f SET v = 'z' WHERE id = 1;
COMMIT;
SQL
assert_eq "a revoked key's token is not taken: the row is changed for nobody" "$(pg pg-main "SELECT coalesce(last_modified_for, 'NULL') FROM trk_f WHERE id = 1")" "NULL"
$S track trk_g --no-for >/dev/null
assert_eq "--no-for tracks a table as before, with three columns" \
  "$(pg pg-main "SELECT count(*) FROM pg_attribute WHERE attrelid = 'trk_g'::regclass AND attname = 'last_modified_for'")" "0"
assert_contains "tracking it again adds the for column, and says so" "$($S track trk_g)" "was tracked already, and now keeps last_modified_for too"
assert_eq "…and nothing else: its rows keep what they had, and the trigger was replaced, not dropped" \
  "$(pg pg-main "SELECT v || '|' || coalesce(last_modified_for, 'NULL') FROM trk_g WHERE id = 1")|$(pg pg-main "SELECT count(*) FROM bb.schema_ledger WHERE command_tag = 'DROP TRIGGER' AND object_identity LIKE '%trk_g%'")" "old|NULL|0"
assert_contains "…a third time it changes nothing" "$($S track trk_g)" "is tracked already"
assert_eq "fox track lists the for column" "$($S track | grep '^public.trk_g ' | tr -s ' ')" "public.trk_g created_at updated_at last_modified_by last_modified_for"
assert_eq "the API says which tables keep it" \
  "$(as "$KA" https://localhost:8080/api/branches/main/tracking | hjson 'print(sorted((t["name"], t["for"]) for t in d["tables"] if t["name"] in ("trk_f", "trk_g")))')" \
  "[('trk_f', 'last_modified_for'), ('trk_g', 'last_modified_for')]"
$S track --new on >/dev/null
assert_eq "--new on keeps it on the tables made from then" \
  "$(as "$KA" https://localhost:8080/api/branches/main/tracking | hjson 'print(d["settings"]["for"])')" "last_modified_for"
$S track --new off >/dev/null
$S app remove trkapp >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS trk_f, trk_g" >/dev/null
rm -rf "$F5D"

echo "### 11w. agent provenance: whom an agent's session was started for (F1, Agent API act_for)"
# An application that starts an agent through the Agent API may say which of
# its users it acts for, with the same token bb.act_for takes. The engine
# checks it by the same rules (the account, never its agent key; this install;
# the agent's own branch) and records the verdict on the session, never the
# token. What the agent then changes shows the session's whom-for.
F6D="$(mktemp -d)"
( cd "$(dirname "$0")/.." && go build -o "$F6D/mint" ./scripts/f1/mint ) || bad "the token tool builds"
printf 'password123\n' | $S user create agt-svc@foxbyte.dev >/dev/null 2>&1
AK="$($S apikey create agt-svc@foxbyte.dev app 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
AAK="$($S apikey create agt-svc@foxbyte.dev bot --agent 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
"$F6D/mint" keygen "$F6D" k1 >"$F6D/k1.pub"
"$F6D/mint" keygen "$F6D" ks >"$F6D/ks.pub"
for a in agentapp strictapp; do $S app remove $a >/dev/null 2>&1; done
$S app register agentapp --account agt-svc@foxbyte.dev --key "$F6D/k1.pub" --kid k1 >/dev/null 2>&1
$S app register strictapp --account agt-svc@foxbyte.dev --key "$F6D/ks.pub" --kid ks --on-invalid refuse >/dev/null 2>&1
AUD6="$($S app list --json | python3 -c 'import sys,json; print(json.load(sys.stdin)["install_id"])')"
mint6() { local k="$1" iss="$2"; shift 2; "$F6D/mint" token "$F6D/$k.seed" -kid "$k" -iss "$iss" -aud "$AUD6" "$@"; }
AGAPI=https://localhost:8088/agents
for a in f1ag f1ag2 f1ag3 f1ag4; do curl -sk -o /dev/null -H "Authorization: Bearer $AK" -X DELETE "$AGAPI/$a/branch"; done
T6="$(mint6 k1 agentapp -sub alice)"
R6="$(curl -sk -H "Authorization: Bearer $AK" -H 'Content-Type: application/json' -X POST \
  -d '{"task_id":"t-f1","act_for":"'"$T6"'"}' "$AGAPI/f1ag/branch")"
assert_eq "an agent started with act_for says whom its session is for" \
  "$(python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("app_for"), d.get("app_state"), d.get("task_id"))' <<<"$R6")" "alice asserted by agentapp t-f1"
assert_eq "…and fox blackbox sessions says so" \
  "$($S blackbox sessions agent-f1ag | grep -c 'alice, asserted by agentapp')" "1"
assert_eq "…and the API" \
  "$(as "$KEY" https://localhost:8080/api/branches/agent-f1ag/ledger/sessions | python3 -c 'import sys,json; s=json.load(sys.stdin)[0]; print(s["app_for"], s["app_state"], s["app_kid"])')" "alice asserted by agentapp k1"
DSN6="$(python3 -c 'import sys,json; print(json.load(sys.stdin)["dsn"])' <<<"$R6")"
psql "$DSN6" -q -c "CREATE TABLE f1_agent_did (id int)" >/dev/null 2>&1
assert_eq "what the agent then changes is shown as made in a session for alice" \
  "$($S blackbox agent-f1ag --limit 20 | grep -w public.f1_agent_did | awk -F'|' '{gsub(/^ +| +$/, "", $3); print $3}')" "session for alice, asserted by agentapp"
assert_eq "the token is kept nowhere: not on the session, not in a log" \
  "$(pg pg-agent-f1ag "SELECT count(*) FROM bb.agent_sessions WHERE row_to_json(agent_sessions)::text LIKE '%$(cut -d. -f3 <<<"$T6" | cut -c1-20)%'")|$(cat "$HOME/$BRAND_STATE_DIR/api.log" 2>/dev/null | grep -c -F "$T6")" "0|0"
R7="$(curl -sk -H "Authorization: Bearer $AAK" -H 'Content-Type: application/json' -X POST \
  -d '{"act_for":"'"$(mint6 k1 agentapp -sub alice)"'"}' "$AGAPI/f1ag2/branch")"
assert_eq "from the application's own agent key it is not taken, and the session says why" \
  "$(python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("app_for"), d.get("app_state"), d.get("app_note"))' <<<"$R7")" "None none token refused: wrong session role"
R8="$(curl -sk -H "Authorization: Bearer $AK" -H 'Content-Type: application/json' -X POST \
  -d '{"act_for":"'"$(mint6 k1 agentapp -sub alice -branch agent-other)"'"}' "$AGAPI/f1ag3/branch")"
assert_eq "a token for another branch is not taken" \
  "$(python3 -c 'import sys,json; print(json.load(sys.stdin).get("app_note"))' <<<"$R8")" "token refused: wrong branch"
assert_eq "an application that registered refuse is refused, and no branch is made" \
  "$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $AK" -H 'Content-Type: application/json' -X POST \
      -d '{"act_for":"'"$(mint6 ks strictapp -sub alice -aud install-other)"'"}' "$AGAPI/f1ag4/branch")|$($S branch list 2>/dev/null | grep -c 'agent-f1ag4')" "403|0"
assert_eq "without act_for an agent's session says nothing about whom it is for" \
  "$(curl -sk -H "Authorization: Bearer $AK" -H 'Content-Type: application/json' -X POST -d '{"task_id":"t-plain"}' "$AGAPI/f1ag4/branch" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("app_state" in d)')|$($S blackbox sessions agent-f1ag4 | awk 'NR==2 {print $3}')" "False|-"
for a in f1ag f1ag2 f1ag3 f1ag4; do curl -sk -o /dev/null -H "Authorization: Bearer $AK" -X DELETE "$AGAPI/$a/branch"; done
for a in agentapp strictapp; do $S app remove $a >/dev/null 2>&1; done
rm -rf "$F6D"

echo "### 11x. a new account's role is made once, however many ask at once"
# A console page sends several requests together, and each logs in as the
# user's own role, made on first use. Made by several at once, Postgres refused
# all but one ("tuple concurrently updated"); while the console fell back to the
# shared role nobody saw it, and since it refuses instead, a person was told
# they could not be logged in as themselves.
printf 'password123\n' | $S user create racer@foxbyte.dev >/dev/null 2>&1
RKEY="$($S apikey create racer@foxbyte.dev race 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
$S branch delete racebr >/dev/null 2>&1; $S branch create racebr >/dev/null 2>&1; $S branch owner racebr racer@foxbyte.dev >/dev/null 2>&1
RD="$(mktemp -d)"
for i in $(seq 1 20); do
  as "$RKEY" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT session_user"}' https://localhost:8080/api/branches/racebr/query >"$RD/q$i" &
done
wait
assert_eq "twenty console queries at once, on first use, all run as the user's own role" \
  "$(cat "$RD"/q* | grep -c '"racer@foxbyte.dev"')|$(cat "$RD"/q* | grep -c '"error"')" "20|0"
$S branch delete racebr2 >/dev/null 2>&1; $S branch create racebr2 >/dev/null 2>&1; $S branch owner racebr2 racer@foxbyte.dev >/dev/null 2>&1
for i in $(seq 1 10); do
  PGPASSWORD="$RKEY" psql "$GATEWAY/racebr2?sslmode=require" -X -tAc 'SELECT session_user' >"$RD/g$i" 2>&1 &
done
wait
assert_eq "…and ten Gateway logins at once" "$(cat "$RD"/g* | grep -c '^racer@foxbyte.dev$')" "10"
rm -rf "$RD"
for b in racebr racebr2; do $S branch delete "$b" >/dev/null 2>&1; done

echo "### 11y. the audit log, on and off (F6 Gate 1, step 1)"
# pgAudit in default mode, with bb_identity's hook keeping every value out of
# the server log. Off unless an admin turns it on: it costs capacity, and
# turning it on restarts main.
args() { sudo docker inspect -f '{{json .Args}}' "pg-$1" 2>/dev/null | grep -c 'shared_preload_libraries=pgaudit,bb_identity'; }
auditlog() { sudo sh -c "cat /dbpool/audit/$1/*.json 2>/dev/null"; }
$S branch delete audbefore >/dev/null 2>&1; $S branch create audbefore >/dev/null 2>&1
assert_eq "off by default: status says so, and main runs without pgAudit" \
  "$($S audit-log status | grep -c 'The audit log is off')|$(args main)" "1|0"
assert_eq "setup without --yes says what it will do, and what it costs, and changes nothing" \
  "$($S audit-log setup | grep -c 'Run again with --yes\|What it costs')|$(args main)" "2|0"
$S audit-log setup --yes >/tmp/audit-setup.log 2>&1; rc=$?
main_up
assert_eq "setup --yes: main restarts with pgAudit and bb_identity loaded" \
  "$rc|$(args main)|$(pg pg-main 'SHOW shared_preload_libraries')" "0|1|pgaudit,bb_identity"
assert_eq "…in default mode: no statement text, no parameters, marked tables through bb_audit" \
  "$(pg pg-main 'SHOW pgaudit.log')|$(pg pg-main 'SHOW pgaudit.log_statement')|$(pg pg-main 'SHOW pgaudit.log_parameter')|$(pg pg-main 'SHOW pgaudit.role')|$(pg pg-main "SELECT count(*) FROM pg_roles WHERE rolname IN ('bb_audit','bb_audit_read')")" \
  "ddl, role|off|off|bb_audit|2"
assert_eq "…its log is outside every database, in a dataset of its own with a quota" \
  "$(sudo test -d /dbpool/audit/main && echo dir)|$(sudo zfs get -H -o value quota dbpool/audit)|$(sudo stat -c %u /dbpool/audit/main)" "dir|2G|999"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS audit_probe; CREATE TABLE audit_probe (id int PRIMARY KEY, email text UNIQUE)" >/dev/null
pg pg-main "INSERT INTO audit_probe VALUES (1, 'ravi.kumar.f6@example.in')" >/dev/null
sudo docker exec pg-main psql -U dbadmin -d appdb -c "INSERT INTO audit_probe VALUES (2, 'ravi.kumar.f6@example.in')" >/dev/null 2>&1
# Letters first: '739146258013x' overflows before the x is read, which is 22003.
sudo docker exec pg-main psql -U dbadmin -d appdb -c "SELECT 'aadhaar 739146258013'::int" >/dev/null 2>&1
sleep 1.5
# At least one CREATE TABLE: the engine's own work on main (a restore check's
# probe table) is audited too, as every login's schema changes are.
assert_eq "a schema change is in main's log, and the errors are there as their codes" \
  "$([ "$(auditlog main | grep -c 'AUDIT: SESSION,[0-9]*,[0-9]*,DDL,CREATE TABLE')" -ge 1 ] && echo yes)|$(auditlog main | grep -c 'OUTCOME,ERROR,23505')|$(auditlog main | grep -c 'OUTCOME,ERROR,22P02')" "yes|1|1"
assert_eq "…and no value the statements held reaches the log, nor the container's output" \
  "$(auditlog main | grep -c 'ravi.kumar.f6\|739146258013')|$(sudo docker logs pg-main 2>&1 | grep -c 'ravi.kumar.f6\|739146258013')" "0|0"
assert_contains "fox check reports it, with its space" "$($S check 2>&1 | grep 'audit log')" "on, default mode"
assert_eq "turning it on is in the security log" "$($S audit log --limit 20 | grep -c 'audit-log.on')" "1"
AJ="$(curl -sk -H "$AUTH" https://localhost:8080/api/audit-log)"
assert_eq "the console's API says it is on, in default mode, and names the branch still running without it" \
  "$(echo "$AJ" | jget on)|$(echo "$AJ" | jget mode)|$(echo "$AJ" | python3 -c 'import sys,json; print("audbefore" in json.load(sys.stdin)["pending"])')" \
  "True|default|True"
assert_contains "…as does status" "$($S audit-log status)" "audbefore"
$S branch create audafter >/dev/null 2>&1
pg pg-audafter "CREATE TABLE after_probe (id int)" >/dev/null
sleep 1.5
# Its log has more than the probe's table: the engine installs the Blackbox on
# a new branch, and those schema changes are audited too.
assert_eq "a branch made after runs it too, with its own log" \
  "$(args audafter)|$([ "$(auditlog audafter | grep -c 'CREATE TABLE')" -ge 1 ] && echo yes)|$(pg pg-audafter 'SHOW pgaudit.log_statement')" "1|yes|off"
$S branch suspend audbefore >/dev/null 2>&1; $S branch resume audbefore >/dev/null 2>&1
assert_eq "a branch made before picks it up when it is woken, and is no longer waiting" \
  "$(args audbefore)|$(pg pg-audbefore 'SHOW pgaudit.role')|$($S audit-log status | grep -c audbefore)" "1|bb_audit|0"
assert_eq "setup again is harmless" "$($S audit-log setup | grep -c 'Already on')" "1"

$S audit-log off --yes >/tmp/audit-off.log 2>&1; rc=$?
main_up
assert_eq "off --yes: main restarts without pgAudit, and its policy is gone" \
  "$rc|$(args main)|$(pg pg-main 'SHOW log_min_error_statement')" "0|0|error"
assert_eq "…the log already kept stays, and the roles, so marks survive" \
  "$(sudo test -d /dbpool/audit/main && echo kept)|$(pg pg-main "SELECT count(*) FROM pg_roles WHERE rolname = 'bb_audit'")" "kept|1"
$S branch suspend audafter >/dev/null 2>&1; $S branch resume audafter >/dev/null 2>&1
assert_eq "…a branch woken after runs without it" "$(args audafter)|$($S audit-log status | grep -c 'The audit log is off')" "0|1"
assert_eq "turning it off is in the security log" "$($S audit log --limit 20 | grep -c 'audit-log.off')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS audit_probe" >/dev/null
for b in audbefore audafter; do $S branch delete "$b" >/dev/null 2>&1; done

echo "### 11z. marking tables for the audit log (F6 Gate 1, step 2)"
# A mark is a grant to bb_audit: pgAudit logs a statement on a table the audit
# role holds the privilege for. Writes by default, reads when asked, by every
# login; a branch made after carries the marks.
gw() { PGPASSWORD="$1" psql "$GATEWAY/main?sslmode=require" -X -q -tA -c "$2" 2>&1; }
objlines() { auditlog main | grep -c "AUDIT: OBJECT,[0-9]*,[0-9]*,$1,TABLE,public.$2,"; }
# Counted from here: confirming personal data in 11r marked a table too (step 6).
MARKS0="$($S audit log --limit 100000 | grep -c 'audit-log.marked')"
pg pg-main "SET bb.allow_destructive=on; DROP VIEW IF EXISTS aud_v; DROP TABLE IF EXISTS aud_orders, aud_notes, aud_cards;
  CREATE TABLE aud_orders (id int PRIMARY KEY, email text); CREATE TABLE aud_notes (id int, body text);
  CREATE TABLE aud_cards (id int, number text); CREATE VIEW aud_v AS SELECT * FROM aud_orders;
  GRANT ALL ON aud_orders, aud_notes, aud_cards, aud_v TO db_client" >/dev/null
OUT="$($S audit-log table aud_orders 2>&1)"; rc=$?
assert_eq "a table can be marked with audit off, and the mark waits for it" \
  "$rc|$(echo "$OUT" | grep -c 'take effect when it is turned on')|$($S audit-log tables | grep -c 'public.aud_orders  *writes$')" "0|1|1"
$S audit-log setup --yes >/dev/null 2>&1; main_up
gw "$KEY" "INSERT INTO aud_orders VALUES (1, 'priya.f6@example.in')" >/dev/null
gw "$KEY" "UPDATE aud_orders SET email = 'priya2.f6@example.in' WHERE id = 1" >/dev/null
gw "$KEY" "INSERT INTO aud_notes VALUES (1, 'priya.f6@example.in')" >/dev/null
gw "$KEY" "SELECT count(*) FROM aud_orders" >/dev/null
sleep 1.5
assert_eq "with audit on, a marked table's writes are logged; an unmarked table's, and its reads, are not" \
  "$(objlines 'WRITE,INSERT' aud_orders)|$(objlines 'WRITE,UPDATE' aud_orders)|$(objlines 'WRITE,INSERT' aud_notes)|$(objlines 'READ,SELECT' aud_orders)" "1|1|0|0"
assert_eq "…under the login that wrote, with nothing the statements held" \
  "$(auditlog main | grep 'public.aud_orders' | grep -c '"user":"test@foxbyte.dev"')|$(auditlog main | grep -c 'priya')" "2|0"
$S audit-log table aud_cards --reads >/dev/null 2>&1
gw "$KEY" "SELECT count(*) FROM aud_cards" >/dev/null; sleep 1.5
assert_eq "--reads: its reads are logged too" "$(objlines 'READ,SELECT' aud_cards)" "1"
$S audit-log table aud_cards >/dev/null 2>&1
gw "$KEY" "SELECT count(*) FROM aud_cards" >/dev/null; sleep 1.5
assert_eq "…and marking again without it takes reads off" \
  "$(objlines 'READ,SELECT' aud_cards)|$($S audit-log tables | grep -c 'public.aud_cards  *writes$')" "1|1"
OUT="$($S audit-log table aud_v 2>&1)"; rc=$?
assert_eq "a view is refused, with what to mark instead" "$([ $rc -ne 0 ] && echo refused)|$(echo "$OUT" | grep -c 'is not a table: mark the tables it reads and writes')" "refused|1"
OUT="$($S audit-log table no_such_table 2>&1)"; rc=$?
assert_eq "…and a table that does not exist" "$([ $rc -ne 0 ] && echo refused)|$(echo "$OUT" | grep -c 'does not exist')" "refused|1"
$S audit-log table aud_orders --off >/dev/null 2>&1
gw "$KEY" "INSERT INTO aud_orders VALUES (2, 'x@example.in')" >/dev/null; sleep 1.5
assert_eq "--off: its writes are no longer logged" "$(objlines 'WRITE,INSERT' aud_orders)|$($S audit-log tables | grep -c aud_orders)" "1|0"

MJ="$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/main/audit/tables)"
assert_eq "the API lists the marks, and that audit is on" \
  "$(echo "$MJ" | jget audit_on)|$(echo "$MJ" | python3 -c 'import sys,json; print(" ".join(t["name"]+":"+str(t["writes"])+":"+str(t["reads"]) for t in json.load(sys.stdin)["tables"]))')" \
  "True|aud_cards:True:False"
assert_eq "an admin marks a table through it, reads and all" \
  "$(code "$KEY" -X PUT -H 'Content-Type: application/json' -d '{"reads":true}' https://localhost:8080/api/branches/main/audit/tables/public/aud_notes)|$($S audit-log tables | grep -c 'public.aud_notes  *writes and reads$')" "200|1"
printf 'password123\n' | $S user create aud-other@foxbyte.dev >/dev/null 2>&1
AOK="$($S apikey create aud-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "someone who does not manage the branch may not change its marks" \
  "$(code "$AOK" -X DELETE https://localhost:8080/api/branches/main/audit/tables/public/aud_notes)|$($S audit-log tables | grep -c aud_notes)" "403|1"
# Five so far: aud_orders marked and unmarked, aud_cards twice, aud_notes by
# the API. The refusals (a view, a missing table, the 403) are not changes.
assert_eq "each change is in the security log" "$(( $($S audit log --limit 100000 | grep -c 'audit-log.marked') - MARKS0 ))" "5"

$S branch create audmarkbr >/dev/null 2>&1
assert_eq "a branch made after has the same marks" \
  "$($S audit-log tables --branch audmarkbr | grep -c 'aud_cards\|aud_notes')" "2"
# The owner of a table can take its mark off, as with any grant on what they
# own. Not silently: pgAudit logs the REVOKE, under their login.
# Made by the user, so theirs; no DROP first, which the guardrail refuses a
# user without the override (the install is new each run).
gw "$KEY" "CREATE TABLE aud_own (id int)" >/dev/null
$S audit-log table aud_own >/dev/null 2>&1
gw "$KEY" "REVOKE ALL ON aud_own FROM bb_audit" >/dev/null; sleep 1.5
assert_eq "a table's owner can take its mark off, and the log shows who did" \
  "$($S audit-log tables | grep -c aud_own)|$(auditlog main | grep '"user":"test@foxbyte.dev"' | grep -c 'AUDIT: SESSION,[0-9]*,[0-9]*,ROLE,REVOKE')" "0|1"

$S audit-log off --yes >/dev/null 2>&1; main_up
assert_eq "the marks stay when audit is turned off" "$($S audit-log tables | grep -c 'aud_cards\|aud_notes')" "2"
$S branch delete audmarkbr >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive=on; DROP VIEW IF EXISTS aud_v; DROP TABLE IF EXISTS aud_orders, aud_notes, aud_cards, aud_own" >/dev/null
$S user delete aud-other@foxbyte.dev >/dev/null 2>&1

echo "### 11aa. the audit log's records (F6 Gate 1, step 3)"
# The collector moves the raw lines into a hash-chained store, keeping only a
# record's fields, and removes raw files once collected and two days old.
STORE=/dbpool/audit/.store
store_all() { sudo sh -c "zcat $STORE/*.jsonl.gz 2>/dev/null"; }
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud3_orders; CREATE TABLE aud3_orders (id int PRIMARY KEY, email text); GRANT ALL ON aud3_orders TO db_client" >/dev/null
$S audit-log table aud3_orders >/dev/null 2>&1
$S audit-log setup --yes >/dev/null 2>&1; main_up
gw "$KEY" "INSERT INTO aud3_orders VALUES (1, 'meera.f6@example.in')" >/dev/null
gw "$KEY" "INSERT INTO aud3_orders VALUES (1, 'meera.f6@example.in')" >/dev/null
sleep 1.5
SHOW="$($S audit-log show --table aud3_orders 2>&1)"
assert_eq "show: each write, by whom, and how its transaction ended, the failed one with its SQLSTATE" \
  "$(echo "$SHOW" | grep 'test@foxbyte.dev' | grep 'INSERT' | grep -c 'public.aud3_orders  *commit')|$(echo "$SHOW" | grep 'INSERT' | grep -c 'rollback (23505)')" "1|1"
assert_eq "the store is the install user's, beside the logs and readable by nobody else, one file a day" \
  "$(sudo stat -c '%U %a' $STORE)|$(sudo sh -c "ls $STORE/*.jsonl.gz" | grep -c "$(date -u +%F).jsonl.gz")" "$(id -un) 700|1"
assert_eq "…and it keeps no value, no client address and no application name" \
  "$(store_all | grep -c 'meera')|$(store_all | grep -c 'remote_host\|application_name\|172\.')" "0|0"
assert_eq "verify: the chain is intact" "$($S audit-log verify | grep -c '^audit log intact')" "1"

RJ="$(curl -sk -H "$AUTH" 'https://localhost:8080/api/audit-log/records?table=aud3_orders')"
assert_eq "the API gives the records, joined to their transactions" \
  "$(echo "$RJ" | python3 -c 'import sys,json; r=json.load(sys.stdin)["records"]; print(sorted((e["command"], e.get("txn_outcome",""), e.get("error","")) for e in r if e["kind"]=="statement"))')" \
  "[('INSERT', 'COMMIT', ''), ('INSERT', 'ROLLBACK', '23505')]"
printf 'password123\n' | $S user create aud-reader@foxbyte.dev >/dev/null 2>&1
ARK="$($S apikey create aud-reader@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "…to admins only, and each read is in the security log" \
  "$(code "$ARK" https://localhost:8080/api/audit-log/records)|$([ "$($S audit log --limit 50 | grep -c 'audit-log.read')" -ge 2 ] && echo yes)" "403|yes"
$S user delete aud-reader@foxbyte.dev >/dev/null 2>&1

# A raw file read to its end and two days old is removed: one made here, as a
# database that stopped writing leaves one, with a line of its own.
OLD=/dbpool/audit/main/audit-Old-00.json
echo '{"timestamp":"2026-11-01 09:00:00.000 UTC","user":"old@foxbyte.dev","session_id":"x.1","vxid":"9/9","error_severity":"LOG","message":"AUDIT: OBJECT,1,1,WRITE,INSERT,TABLE,public.aud3_old,<not logged>,<not logged>"}' | sudo tee "$OLD" >/dev/null
sudo chown 999:999 "$OLD"; sudo touch -d '3 days ago' "$OLD"
$S audit-log collect >/dev/null 2>&1
assert_eq "a raw file collected and two days old is removed, after its lines are in the store" \
  "$(sudo test -e "$OLD" && echo kept || echo removed)|$(store_all | grep -c 'public.aud3_old')" "removed|1"
assert_eq "…and the current one stays" "$(sudo sh -c 'ls /dbpool/audit/main/audit-*.json' | wc -l | awk '{print ($1 >= 1)}')" "1"
assert_eq "the collector runs in the control plane too: status reports the records it keeps" \
  "$($S audit-log status | grep -c 'kept 365 days')" "1"

$S audit-log off --yes >/dev/null 2>&1; main_up
assert_eq "turning audit off keeps the records, and they still verify" \
  "$($S audit-log show --table aud3_orders | grep -c INSERT)|$($S audit-log verify | grep -c '^audit log intact')" "2|1"
# Edited once audit is off, so nothing is appended while the edit is there.
DAY="$STORE/$(date -u +%F).jsonl.gz"
cp "$DAY" /tmp/audit-day.bak
zcat "$DAY" | sed '0,/test@foxbyte.dev/s//mallory@foxbyte.dev/' | gzip > /tmp/audit-day.edit && cp /tmp/audit-day.edit "$DAY"
OUT="$($S audit-log verify 2>&1)"; rc=$?
assert_eq "a record edited after it was written is found, and verify fails" \
  "$rc|$(echo "$OUT" | grep -c 'TAMPERED')|$(echo "$OUT" | grep -c 'was changed after it was written')" "1|1|1"
assert_eq "…and the edited file is left as it is, not cut to the size the collector wrote" \
  "$(cmp -s /tmp/audit-day.edit "$DAY" && echo kept)" "kept"
cp /tmp/audit-day.bak "$DAY"; rm -f /tmp/audit-day.bak /tmp/audit-day.edit
assert_eq "…and put back, it verifies again" "$($S audit-log verify | grep -c '^audit log intact')" "1"
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud3_orders" >/dev/null

echo "### 11ab. gaps and delivery (F6 Gate 1, step 4)"
# A full log drops lines without a word, so what goes wrong is found from the
# outside: a heartbeat that does not arrive, statement numbers that skip, a
# mark taken off outside FoxByte.
$S audit-log setup --yes >/dev/null 2>&1; main_up
OUT="$($S audit-log heartbeat 2>&1)"
$S audit-log collect >/dev/null 2>&1
assert_eq "a heartbeat on demand reaches the store from main, and is not shown among the records" \
  "$(echo "$OUT" | grep -c 'A heartbeat from main')|$([ "$(store_all | grep -c '"kind":"heartbeat"')" -ge 1 ] && echo yes)|$($S audit-log show --json --limit 1000 | grep -c '"kind":"heartbeat"')" "1|yes|0"
assert_eq "…and with it arriving, status finds nothing wrong" "$($S audit-log status | grep -c 'Nothing found wrong')" "1"

# Lines lost: a session whose statement numbers jump from 2 to 6, as a full log
# leaves them.
NOW="$(date -u '+%Y-%m-%d %H:%M:%S.000 UTC')"
GAPF=/dbpool/audit/main/audit-Gap-00.json
for n in 1 2 6; do
  echo "{\"timestamp\":\"$NOW\",\"user\":\"test@foxbyte.dev\",\"session_id\":\"gapsess.1\",\"vxid\":\"8/$n\",\"error_severity\":\"LOG\",\"message\":\"AUDIT: OBJECT,$n,1,WRITE,INSERT,TABLE,public.gapt,<not logged>,<not logged>\"}"
done | sudo tee "$GAPF" >/dev/null
sudo chown 999:999 "$GAPF"
$S audit-log collect >/dev/null 2>&1
assert_eq "statement numbers that skip are a gap: a record in the chain, where it was found" \
  "$($S audit-log show --branch main --limit 1000 | grep 'GAP' | grep -c '3 line(s) missing')|$(store_all | grep '"kind":"gap"' | grep '"statement":3,' | grep -c '"missing":3,')" "1|1"
assert_eq "…a warning in fox check, naming the session's login and the statements" \
  "$($S check 2>&1 | grep '^warn  audit gap' | grep -c 'main: 3 audit line(s) missing in a session of test@foxbyte.dev (statements 3 to 5)')" "1"
assert_eq "…and the chain still verifies, the gap record in it" "$($S audit-log verify | grep -c '^audit log intact')" "1"
sudo rm -f "$GAPF"

# A mark taken off outside FoxByte: by the table's owner, with REVOKE.
gw "$KEY" "CREATE TABLE aud4_t (id int)" >/dev/null
$S audit-log table aud4_t >/dev/null 2>&1
gw "$KEY" "REVOKE ALL ON aud4_t FROM bb_audit" >/dev/null
assert_eq "a mark set through FoxByte and taken off outside it is found, saying who set it" \
  "$($S check 2>&1 | grep '^warn  audit mark' | grep -c 'main: public.aud4_t was marked by .*taken off outside FoxByte')" "1"
AJ="$(curl -sk -H "$AUTH" https://localhost:8080/api/audit-log)"
assert_eq "…the API reports it" \
  "$(echo "$AJ" | python3 -c 'import sys,json; print(sum(1 for f in json.load(sys.stdin)["findings"] if f["kind"]=="mark" and "aud4_t" in f["detail"]))')" "1"
$S audit-log table aud4_t >/dev/null 2>&1
assert_eq "…and marking it again puts it right" "$($S check 2>&1 | grep -c '^warn  audit mark')" "0"
$S audit-log table aud4_t --off >/dev/null 2>&1
assert_eq "taking a mark off through FoxByte is not a finding" "$($S check 2>&1 | grep -c '^warn  audit mark')" "0"

$S audit-log off --yes >/dev/null 2>&1; main_up
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud4_t" >/dev/null

echo "### 11ac. forensic mode, retention and purge (F6 Gate 1, step 5a)"
# Forensic mode keeps statement text, values and all: beside the records, not
# in their chain, so it expires and is purged for a person without breaking
# it. A reload, never a restart.
started() { sudo docker inspect -f '{{.State.StartedAt}}' "pg-$1"; }
forensic_all() { sudo sh -c "zcat $STORE/forensic/*.jsonl.gz 2>/dev/null"; }
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud5_orders; CREATE TABLE aud5_orders (id int PRIMARY KEY, email text); GRANT ALL ON aud5_orders TO db_client" >/dev/null
$S audit-log table aud5_orders >/dev/null 2>&1
$S audit-log setup --yes >/dev/null 2>&1; main_up
OUT="$($S audit-log mode forensic 2>&1)"; rc=$?
assert_eq "forensic mode is refused without a reason" "$([ $rc -ne 0 ] && echo refused)|$(echo "$OUT" | grep -c -- '--reason')" "refused|1"
assert_eq "…and with one but no --yes, it says what it keeps and changes nothing" \
  "$($S audit-log mode forensic --reason 'incident 5' | grep -c "each audited statement's text is kept")|$(pg pg-main 'SHOW pgaudit.log_statement')" "1|off"
BEFORE="$(started main)"
$S audit-log mode forensic --reason 'incident 5' --yes >/dev/null 2>&1
assert_eq "with --yes it is on at once, by a reload: main was not restarted" \
  "$(pg pg-main 'SHOW pgaudit.log_statement')|$(pg pg-main 'SHOW pgaudit.log_parameter')|$([ "$(started main)" = "$BEFORE" ] && echo same)" "on|off|same"
gw "$KEY" "INSERT INTO aud5_orders VALUES (1, 'anjali.f6@example.in')" >/dev/null
sleep 1.5
SHOW="$($S audit-log show --table aud5_orders --text 2>&1)"
assert_eq "show --text gives the statement, values and all" "$(echo "$SHOW" | grep -c "INSERT INTO aud5_orders VALUES (1, 'anjali.f6@example.in')")" "1"
assert_eq "…kept beside the chain: the records hold its hash, the forensic file the text" \
  "$(store_all | grep -c 'anjali')|$(store_all | grep 'public.aud5_orders' | grep -c '"text_sha":"')|$(forensic_all | grep -c 'anjali')" "0|1|1"
assert_eq "…and the chain, with the text checked against it, verifies" "$($S audit-log verify | grep -c '^audit log intact')" "1"
assert_eq "fox check says forensic mode is on, where, by whom and why" \
  "$($S check 2>&1 | grep '^warn  audit mode' | grep -c 'every branch.*incident 5')" "1"
assert_eq "the API gives admins the text" \
  "$(curl -sk -H "$AUTH" 'https://localhost:8080/api/audit-log/records?table=aud5_orders' | grep -c 'anjali.f6@example.in')" "1"

assert_eq "purge without --yes says what it removes, and removes nothing" \
  "$($S audit-log purge --user test@foxbyte.dev | grep -c 'Their records stay')|$(forensic_all | grep -c 'anjali')" "1|1"
assert_eq "purge --yes removes the person's text" "$($S audit-log purge --user test@foxbyte.dev --yes | grep -c 'Removed 1 statement text')" "1"
assert_eq "…the record stays, saying its text was removed, and the chain still verifies" \
  "$($S audit-log show --table aud5_orders --text | grep -c '(removed: past its retention, or purged)')|$(forensic_all | grep -c 'anjali')|$($S audit-log verify | grep -c '^audit log intact')" "1|0|1"

$S audit-log mode default >/dev/null 2>&1
gw "$KEY" "INSERT INTO aud5_orders VALUES (2, 'ravi2.f6@example.in')" >/dev/null; sleep 1.5
assert_eq "back to default mode: no statement text from then on, and fox check no longer warns" \
  "$(pg pg-main 'SHOW pgaudit.log_statement')|$($S audit-log show --table aud5_orders --text | grep -c 'ravi2')|$($S check 2>&1 | grep -c '^warn  audit mode')" "off|0|0"
$S branch create aud5br >/dev/null 2>&1
$S audit-log mode forensic --branch aud5br --reason 'one branch' --yes >/dev/null 2>&1
assert_eq "forensic mode on one branch leaves the others in default mode" \
  "$(pg pg-aud5br 'SHOW pgaudit.log_statement')|$(pg pg-main 'SHOW pgaudit.log_statement')" "on|off"
$S audit-log mode default --branch aud5br >/dev/null 2>&1
assert_eq "…and goes back" "$(pg pg-aud5br 'SHOW pgaudit.log_statement')" "off"
$S branch delete aud5br >/dev/null 2>&1
assert_eq "each change of mode, and the purge, is in the security log" \
  "$($S audit log --limit 200 | grep -c 'audit-log.mode')|$($S audit log --limit 200 | grep -c 'audit-log.purged')" "4|1"

assert_eq "retention: records 90 days, and text cannot outlive them" \
  "$($S audit-log retention 90 | grep -c 'kept 90 days')|$($S audit-log retention 120 --forensic 2>&1 | grep -c 'cannot be kept longer')|$($S audit-log retention)" \
  "1|1|Records are kept 90 days; forensic mode's statement text 30 days."
$S audit-log retention 365 >/dev/null 2>&1
$S audit-log off --yes >/dev/null 2>&1; main_up
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud5_orders" >/dev/null

echo "### 11ad. forwarding to a SIEM (F6 Gate 1, step 5b)"
# A copy of every record, from the store, over TLS: to an HTTPS collector as
# JSON lines, or to syslog as RFC 5424. Two receivers stand in for a SIEM,
# each with a certificate of its own that only the CA given is trusted for.
FWD=/tmp/fwd; rm -rf "$FWD"; mkdir -p "$FWD"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=siem \
  -addext subjectAltName=IP:127.0.0.1 -keyout "$FWD/key.pem" -out "$FWD/ca.pem" >/dev/null 2>&1
echo 200 > "$FWD/status"
cat > "$FWD/https_recv.py" <<'EOF'
import http.server, json, ssl, sys
d = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        code = int(open(d + "/status").read())
        if code == 200:
            with open(d + "/https.log", "a") as f:
                f.write(json.dumps({"path": self.path, "auth": self.headers.get("Authorization", ""),
                                    "type": self.headers.get("Content-Type", "")}) + "\n")
            with open(d + "/https.jsonl", "ab") as f:
                f.write(body)
        self.send_response(code); self.end_headers()
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 18443), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(d + "/ca.pem", d + "/key.pem")
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()
EOF
cat > "$FWD/syslog_recv.py" <<'EOF'
import socket, ssl, sys, threading
d = sys.argv[1]
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(d + "/ca.pem", d + "/key.pem")
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", 16514)); ls.listen()
def serve(conn):
    f = conn.makefile("rb")
    while True:
        n = b""
        while not n.endswith(b" "):
            ch = f.read(1)
            if not ch:
                return
            n += ch
        msg = f.read(int(n))
        with open(d + "/syslog.log", "ab") as out:
            out.write(msg + b"\n")
while True:
    conn, _ = ls.accept()
    try:
        threading.Thread(target=serve, args=(c.wrap_socket(conn, server_side=True),), daemon=True).start()
    except ssl.SSLError:
        conn.close()
EOF
setsid python3 "$FWD/https_recv.py" "$FWD" >"$FWD/https.err" 2>&1 < /dev/null & echo $! > "$FWD/https.pid"
setsid python3 "$FWD/syslog_recv.py" "$FWD" >"$FWD/syslog.err" 2>&1 < /dev/null & echo $! > "$FWD/syslog.pid"
sleep 1
received() { cat "$FWD/https.jsonl" 2>/dev/null; }
seqs() { received | python3 -c 'import sys,json; print(" ".join(str(json.loads(l)["seq"]) for l in sys.stdin if l.strip()))'; }
printf 'fwd-tok-%s\n' "$RANDOM$RANDOM" > "$FWD/token"; TOK="$(cat "$FWD/token")"
URL=https://127.0.0.1:18443/ingest

OUT="$($S audit-log forward http://127.0.0.1:18443/ingest 2>&1)"; rc=$?
assert_eq "plain http:// is refused: every record names a login" "$([ $rc -ne 0 ] && echo refused)|$(echo "$OUT" | grep -c 'unencrypted')" "refused|1"
OUT="$($S audit-log forward https://siem:secret@127.0.0.1:18443/ 2>&1)"; rc=$?
assert_eq "…and so is a URL holding a password, with where a token goes instead" "$([ $rc -ne 0 ] && echo refused)|$(echo "$OUT" | grep -c 'token-file')" "refused|1"
OUT="$($S audit-log forward syslog://127.0.0.1:16514 --token-file "$FWD/token" --yes 2>&1)"; rc=$?
assert_eq "…and a token for syslog, which knows its clients by TLS" "$([ $rc -ne 0 ] && echo refused)|$(echo "$OUT" | grep -c 'https:// only')" "refused|1"
OUT="$($S audit-log forward "$URL" --ca "$FWD/ca.pem" --token-file "$FWD/token" 2>&1)"
assert_eq "without --yes it says what goes, and that no values do, and sets nothing" \
  "$(echo "$OUT" | grep -c 'who did what to which object')|$(echo "$OUT" | grep -c 'No values')|$($S audit-log forward | grep -c 'Not forwarding')" "1|1|1"

pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud6_orders; CREATE TABLE aud6_orders (id int PRIMARY KEY, email text); GRANT ALL ON aud6_orders TO db_client" >/dev/null
$S audit-log table aud6_orders >/dev/null 2>&1
$S audit-log setup --yes >/dev/null 2>&1; main_up
$S audit-log collect >/dev/null 2>&1
assert_eq "with --yes, forwarding is set" \
  "$($S audit-log forward "$URL" --ca "$FWD/ca.pem" --token-file "$FWD/token" --yes | grep -c "Forwarding to $URL")" "1"
assert_eq "…the token kept for it readable by this user only, and in neither the settings nor the security log" \
  "$(stat -c %a "$HOME/$BRAND_STATE_DIR/audit-forward-token")|$(grep -c "$TOK" "$HOME/$BRAND_STATE_DIR/audit-settings.json")|$($S audit log --limit 50 | grep -c "$TOK")|$($S audit log --limit 50 | grep -c 'audit-log.forward')" "600|0|0|1"
START="$($S audit-log forward | sed -n 's/^delivered up to record \([0-9]*\) .*/\1/p')"
gw "$KEY" "INSERT INTO aud6_orders VALUES (1, 'kiran.f6@example.in')" >/dev/null
gw "$KEY" "INSERT INTO aud6_orders VALUES (1, 'kiran.f6@example.in')" >/dev/null
sleep 1.5
$S audit-log forward --now >/dev/null 2>&1
assert_eq "forward --now: the collector receives the writes, from the next record on, nothing earlier" \
  "$(received | grep 'public.aud6_orders' | grep -c '"command":"INSERT"')|$(seqs | tr ' ' '\n' | awk -v s="$START" '$1 <= s' | wc -l | tr -d ' ')" "2|0"
assert_eq "…as JSON lines, with the token in the Authorization header and not the URL" \
  "$(grep -c "\"auth\": \"Bearer $TOK\"" "$FWD/https.log")|$(grep -c '"path": "/ingest"' "$FWD/https.log")|$(grep -c 'application/x-ndjson' "$FWD/https.log")" \
  "$(wc -l < "$FWD/https.log" | tr -d ' ')|$(wc -l < "$FWD/https.log" | tr -d ' ')|$(wc -l < "$FWD/https.log" | tr -d ' ')"
assert_eq "…with no value a statement held, and the failed write's outcome" \
  "$(received | grep -c 'kiran')|$(received | grep -c '"sqlstate":"23505"')" "0|1"
CHAIN="$(received | python3 -c '
import sys, json
r = [json.loads(l) for l in sys.stdin if l.strip()]
print("linked" if all(b["prev"] == a["hash"] and b["seq"] == a["seq"] + 1 for a, b in zip(r, r[1:])) and all(x["source"] == "bb-audit" for x in r) else "broken")')"
assert_eq "…each with its place in the chain: the copy there links record to record" "$CHAIN" "linked"
assert_eq "status and fox check say how far delivery has got" \
  "$($S audit-log status | grep -c 'delivered up to record .* (0 waiting)')|$($S check 2>&1 | grep '^ok    audit forward' | grep -c '127.0.0.1:18443: delivered up to record')" "1|1"

# The collector fails: the records wait, and go once it works again.
echo 503 > "$FWD/status"
gw "$KEY" "INSERT INTO aud6_orders VALUES (2, 'x@example.in')" >/dev/null; sleep 1.5
OUT="$($S audit-log forward --now 2>&1)"; rc=$?
assert_eq "a collector that fails: forward --now says so, and the records wait in the store" \
  "$rc|$(echo "$OUT" | grep -c '503')|$($S audit-log forward | grep -c 'FAILING since')|$($S audit-log forward | grep -c '([1-9][0-9]* waiting)')" "1|1|1|1"
python3 - "$STORE/forward.json" <<'EOF'
import json, sys, datetime
p = sys.argv[1]; s = json.load(open(p))
s["err_since"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump(s, open(p, "w"))
EOF
assert_eq "…failing for more than five minutes, it is a warning in fox check" \
  "$($S check 2>&1 | grep '^warn  audit forward' | grep -c 'records have not reached 127.0.0.1:18443 since .*503')" "1"
echo 200 > "$FWD/status"
$S audit-log forward --now >/dev/null 2>&1
# Against the position delivered, not the store's head: a heartbeat collected
# a moment later has not been sent yet, and is not missing.
POS="$($S audit-log forward | sed -n 's/^delivered up to record \([0-9]*\) .*/\1/p')"
assert_eq "…and once it works, what waited goes: every record since forwarding was set, none twice" \
  "$(seqs | tr ' ' '\n' | sort -n | uniq | awk -v s="$START" -v h="$POS" '$1 > s && $1 <= h' | wc -l | tr -d ' ')|$(seqs | tr ' ' '\n' | sort | uniq -d | wc -l | tr -d ' ')|$($S check 2>&1 | grep -c '^warn  audit forward')" \
  "$((POS - START))|0|0"

# Statement text goes only when asked for.
$S audit-log mode forensic --reason 'forwarding test' --yes >/dev/null 2>&1
gw "$KEY" "INSERT INTO aud6_orders VALUES (3, 'leela.f6@example.in')" >/dev/null; sleep 1.5
$S audit-log forward --now >/dev/null 2>&1
assert_eq "in forensic mode the record goes with its text's hash, and not the text" \
  "$(received | grep 'public.aud6_orders' | grep -c '"text_sha":"')|$(received | grep -c 'leela')" "1|0"
$S audit-log forward "$URL" --ca "$FWD/ca.pem" --text --from-start --yes >/dev/null 2>&1
$S audit-log forward --now >/dev/null 2>&1
assert_eq "with --text (and --from-start, every record still kept) the text goes too" \
  "$(received | grep -c "INSERT INTO aud6_orders VALUES (3, 'leela.f6@example.in')")|$(received | python3 -c 'import sys,json; print(min(json.loads(l)["seq"] for l in sys.stdin if l.strip()) <= 2)')" "1|True"
assert_eq "…set again without a token, none is sent" "$(tail -1 "$FWD/https.log" | grep -c '"auth": ""')" "1"
$S audit-log mode default >/dev/null 2>&1

# Syslog over TLS, RFC 5424 framed as RFC 5425 says.
$S audit-log forward syslog://127.0.0.1:16514 --ca "$FWD/ca.pem" --yes >/dev/null 2>&1
gw "$KEY" "INSERT INTO aud6_orders VALUES (4, 'y@example.in')" >/dev/null; sleep 1.5
$S audit-log forward --now >/dev/null 2>&1; sleep 1
assert_eq "syslog://: RFC 5424 messages over TLS, facility log audit, the record's JSON as the message" \
  "$(grep 'public.aud6_orders' "$FWD/syslog.log" | grep -c '^<110>1 [0-9T:.-]*Z [^ ]* bb-audit - statement - {')" "1"
# Set again without its CA: the system's CAs do not vouch for the receiver's
# certificate, so the connection fails before a record is sent.
$S audit-log forward syslog://127.0.0.1:16514 --yes >/dev/null 2>&1
SYSN="$(wc -l < "$FWD/syslog.log")"
gw "$KEY" "INSERT INTO aud6_orders VALUES (6, 'w@example.in')" >/dev/null; sleep 1.5
assert_eq "…without the CA that vouches for the server's certificate, it refuses to send, and the server gets nothing" \
  "$($S audit-log forward --now 2>&1 | grep -c 'x509\|SIEM did not take the records')|$(( $(wc -l < "$FWD/syslog.log") - SYSN ))" "2|0"

# The console's route: the token and CA in the body, never a path; never sent back.
printf 'password123\n' | $S user create aud-fwd@foxbyte.dev >/dev/null 2>&1
AFK="$($S apikey create aud-fwd@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
BODY="$(python3 -c 'import json,sys; print(json.dumps({"url": sys.argv[1], "token": sys.argv[2], "ca_pem": open(sys.argv[3]).read()}))' "$URL" "$TOK" "$FWD/ca.pem")"
assert_eq "the API: someone who is not an admin may not set it" \
  "$(code "$AFK" -X PUT -H 'Content-Type: application/json' -d "$BODY" https://localhost:8080/api/audit-log/forward)" "403"
assert_eq "…an admin may, and the reply holds where, never the token" \
  "$(code "$KEY" -X PUT -H 'Content-Type: application/json' -d "$BODY" https://localhost:8080/api/audit-log/forward)|$(curl -sk -H "$AUTH" https://localhost:8080/api/audit-log | python3 -c 'import sys,json; f=json.load(sys.stdin)["forward"]; print(f["host"], f["token"], f["ca"])')|$(curl -sk -H "$AUTH" https://localhost:8080/api/audit-log | grep -c "$TOK")" \
  "200|127.0.0.1:18443 True True|0"
# The control plane forwards on its own, every minute: no --now.
BEFORE="$(received | wc -l)"
gw "$KEY" "INSERT INTO aud6_orders VALUES (5, 'z@example.in')" >/dev/null
for _ in $(seq 1 50); do [ "$(received | wc -l)" -gt "$BEFORE" ] && break; sleep 3; done
assert_eq "the control plane collects and forwards on its own, every minute" "$([ "$(received | wc -l)" -gt "$BEFORE" ] && echo sent)" "sent"
SJ="$(curl -sk -H "$AUTH" -X POST https://localhost:8080/api/audit-log/forward/send)"
assert_eq "…and the console can send now" "$(echo "$SJ" | python3 -c 'import sys,json; r=json.load(sys.stdin); print("error" in r, r["waiting"])')" "False 0"
assert_eq "stopping it through the API removes the token kept for it" \
  "$(code "$KEY" -X DELETE https://localhost:8080/api/audit-log/forward)|$([ -e "$HOME/$BRAND_STATE_DIR/audit-forward-token" ] && echo kept || echo gone)|$($S audit-log forward | grep -c 'Not forwarding')" "200|gone|1"
# Six: four set at the command line (https, again with --text, syslog, syslog
# without its CA), and the API's set and stop. The refusals are not changes.
assert_eq "every change to forwarding is in the security log" "$($S audit log --limit 200 | grep -c 'audit-log.forward')" "6"
$S user delete aud-fwd@foxbyte.dev >/dev/null 2>&1
kill "$(cat "$FWD/https.pid")" "$(cat "$FWD/syslog.pid")" 2>/dev/null
pkill -f "$FWD/(https|syslog)_recv.py" 2>/dev/null
$S audit-log off --yes >/dev/null 2>&1; main_up
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS aud6_orders" >/dev/null
rm -rf "$FWD"

echo "### 11ae. anchors, automatic marks and SECURITY DEFINER functions (F6 Gate 1, step 6)"
# Enterprise anchors the records' chain outside the store, as it does the
# Blackbox's; a table holding confirmed personal data has its writes audited
# without anyone marking it; and a definer function naming a marked table is
# said, because pgAudit does not see the statements inside it.
AANCH="$HOME/$BRAND_STATE_DIR/anchors/_audit-log"
pg pg-main "SET bb.allow_destructive=on; DROP FUNCTION IF EXISTS aud7_pay(int); DROP TABLE IF EXISTS aud7_orders;
  CREATE TABLE aud7_orders (id int PRIMARY KEY, email text); GRANT ALL ON aud7_orders TO db_client;
  CREATE FUNCTION aud7_pay(i int) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS \$f\$ BEGIN INSERT INTO aud7_orders VALUES (i, 'paid'); END \$f\$;
  GRANT EXECUTE ON FUNCTION aud7_pay(int) TO db_client" >/dev/null
$S audit-log table aud7_orders >/dev/null 2>&1
$S audit-log setup --yes >/dev/null 2>&1; main_up
gw "$KEY" "INSERT INTO aud7_orders VALUES (1, 'x@example.in')" >/dev/null; sleep 1.5
ANC="$($S audit-log anchor 2>&1)"
assert_eq "anchor: the chain's head, signed with the install's anchor key, written read-only outside the store" \
  "$(grep -c '^audit log anchored: records [0-9]*–[0-9]*, signed by key ' <<<"$ANC")|$(ls "$AANCH" 2>/dev/null | grep -c '\.json$' | awk '{print ($1>=1)}')|$(stat -c %a "$AANCH/$(ls "$AANCH" | grep '\.json$' | tail -1)")" "1|1|444"
VER="$($S audit-log verify 2>&1)"
assert_eq "verify checks the store against every anchor, and their signatures" \
  "$(grep -c '^audit log intact' <<<"$VER")|$(grep -c '^anchored: [0-9]* anchor(s), up to record [0-9]*, each matching the store' <<<"$VER")|$(grep -c 'every anchor is signed by key' <<<"$VER")" "1|1|1"
assert_eq "status and the console say how far anchoring has got" \
  "$($S audit-log status | grep -c '^  anchors  [0-9]*, up to record')|$(curl -sk -H "$AUTH" https://localhost:8080/api/audit-log | python3 -c 'import sys,json; a=json.load(sys.stdin)["anchors"]; print(a["anchors"] >= 1, a["writes"])')" "1|True True"
# What the chain alone cannot see: the records an anchor holds taken away,
# with state.json put back to match. Done holding the collector's lock, and
# put back the same way.
cat > /tmp/aud7_cut.py <<'EOF'
import gzip, json, os, sys
store, anchors = sys.argv[1], sys.argv[2]
to = max(json.load(open(os.path.join(anchors, a)))["to_id"] for a in os.listdir(anchors) if a.endswith(".json"))
st = json.load(open(os.path.join(store, "state.json")))
head = None
for name in sorted(d for d in os.listdir(store) if d.endswith(".jsonl.gz")):
    path = os.path.join(store, name)
    recs = [json.loads(l) for l in gzip.open(path).read().decode().splitlines() if l]
    keep = [r for r in recs if r["seq"] < to]
    if keep:
        head = keep[-1]
    if len(keep) != len(recs):
        with gzip.open(path, "wb") as f:
            f.write("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in keep).encode())
        st["days"][name[:-len(".jsonl.gz")]] = os.path.getsize(path)
st["seq"], st["head"] = head["seq"], head["hash"]
json.dump(st, open(os.path.join(store, "state.json"), "w"))
EOF
rm -rf /tmp/aud7_store.bak; mkdir -p /tmp/aud7_store.bak
flock "$STORE/lock" sh -c 'cp -p "$1"/*.jsonl.gz "$1"/state.json /tmp/aud7_store.bak/ && python3 /tmp/aud7_cut.py "$1" "$2"' _ "$STORE" "$AANCH"
OUT="$($S audit-log verify 2>&1)"; rc=$?
assert_eq "records an anchor holds, taken away with the state edited to match: verify fails, where the chain alone would pass" \
  "$rc|$(grep -c 'TAMPERED' <<<"$OUT")|$(grep -c 'anchored records were removed\|no longer matches it' <<<"$OUT" | awk '{print ($1>=1)}')" "1|1|1"
flock "$STORE/lock" sh -c 'cp -p /tmp/aud7_store.bak/* "$1"/' _ "$STORE"
assert_eq "…and put back, it verifies again" "$($S audit-log verify | grep -c '^audit log intact')" "1"

# Automatic marks, on a branch of their own. Every identifier is synthetic:
# 234567890124 and 456789012341 pass Verhoeff.
gw7() { PGPASSWORD="$1" psql "${GATEWAY}/aud7pii?sslmode=require" -X -q -tA -c "$2" 2>&1; }
$S branch delete aud7pii >/dev/null 2>&1; $S branch create aud7pii >/dev/null 2>&1
pg pg-aud7pii "CREATE TABLE aud7_people (id int PRIMARY KEY, aadhaar_no text, email text); GRANT ALL ON aud7_people TO db_client;
  INSERT INTO aud7_people VALUES (1, '2345 6789 0124', 'a@example.com'), (2, '456789012341', 'b@example.org')" >/dev/null
$S pii scan --branch aud7pii >/dev/null 2>&1
AID7="$($S pii --branch aud7pii --json 2>/dev/null | hjson "print([f['id'] for f in d['findings'] if f['table']=='aud7_people' and f['column']=='aadhaar_no'][0])")"
amarks() { $S audit log --limit 100000 | grep 'audit-log.marked' | grep -c "$1"; }
MARKED0="$(amarks aud7_people)"
M7="$($S pii mark "$AID7" confirm --branch aud7pii 2>&1)"
assert_eq "confirming personal data marks its table: its writes are audited, and the security log says so" \
  "$(grep -c 'public.aud7_people now has its writes audited' <<<"$M7")|$($S audit-log tables --branch aud7pii | grep -c 'public.aud7_people  *writes$')|$(( $(amarks aud7_people) - MARKED0 ))" "1|1|1"
gw7 "$KEY" "INSERT INTO aud7_people VALUES (3, NULL, NULL)" >/dev/null; sleep 1.5
assert_eq "…so a write to it is in the audit log" "$($S audit-log show --branch aud7pii --table aud7_people | grep -c INSERT)" "1"
$S audit-log table aud7_people --reads --branch aud7pii >/dev/null 2>&1
$S pii mark "$AID7" reopen --branch aud7pii >/dev/null 2>&1
M7B="$($S pii mark "$AID7" confirm --branch aud7pii 2>&1)"
assert_eq "confirming again marks nothing more, and leaves the reads someone marked" \
  "$(grep -c 'now has its writes audited' <<<"$M7B")|$($S audit-log tables --branch aud7pii | grep -c 'public.aud7_people  *writes and reads$')" "0|1"
$S audit-log table aud7_people --off --branch aud7pii >/dev/null 2>&1
assert_eq "taken off, the tables say it holds confirmed personal data and is not audited" \
  "$($S audit-log tables --branch aud7pii | grep -c 'Confirmed personal data, writes not audited: public.aud7_people')" "1"
printf 'password123\n' | $S user create aud7-other@foxbyte.dev >/dev/null 2>&1
A7K="$($S apikey create aud7-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
# Someone else cannot reach this branch at all, so it is not found; on main,
# which every account may use, they are refused, as where personal data sits
# is the owner's.
assert_eq "the API lists it for the branch's owner or an admin, and to no one else, as where personal data sits" \
  "$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/aud7pii/personal-data/unaudited | python3 -c 'import sys,json; print(json.load(sys.stdin)["tables"])')|$(code "$A7K" https://localhost:8080/api/branches/aud7pii/personal-data/unaudited)|$(code "$A7K" https://localhost:8080/api/branches/main/personal-data/unaudited)|$(code "$A7K" -X POST https://localhost:8080/api/branches/main/audit/tables/personal-data)" \
  "['public.aud7_people']|404|403|403"
CU="$($S audit-log table --personal-data --branch aud7pii 2>&1)"
assert_eq "table --personal-data marks it again, its writes, and says so" \
  "$(grep -c '^public.aud7_people on aud7pii: its writes are audited' <<<"$CU")|$($S audit-log tables --branch aud7pii | grep -c 'public.aud7_people  *writes$')|$(( $(amarks aud7_people) - MARKED0 ))" "1|1|4"
assert_eq "…and a second time finds nothing to do, nor does the console's" \
  "$($S audit-log table --personal-data --branch aud7pii | grep -c 'already has its writes audited')|$(curl -sk -H "$AUTH" -X POST https://localhost:8080/api/branches/aud7pii/audit/tables/personal-data | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r.get("marked"), r.get("personal_unmarked"))')" \
  "1|None None"

# SECURITY DEFINER: said, and true.
DEF="$($S audit-log tables 2>&1)"
assert_eq "a SECURITY DEFINER function naming a marked table is listed: pgAudit does not see inside it" \
  "$(grep -c 'Not audited: these SECURITY DEFINER functions' <<<"$DEF")|$(grep -c 'aud7_pay(integer), as .*: public.aud7_orders' <<<"$DEF")" "1|1"
assert_eq "…a warning in fox check, a finding in the console, and beside the marks in the API" \
  "$($S check 2>&1 | grep 'audit definer' | grep -c 'main: aud7_pay')|$(curl -sk -H "$AUTH" https://localhost:8080/api/audit-log | python3 -c 'import sys,json; print(sum(1 for f in json.load(sys.stdin)["findings"] if f["kind"]=="definer" and f.get("branch")=="main" and "aud7_pay" in f["detail"]))')|$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/main/audit/tables | python3 -c 'import sys,json; print("aud7_pay(integer)" in [d["function"] for d in json.load(sys.stdin)["definers"]])')" \
  "1|1|True"
gw "$KEY" "SELECT aud7_pay(2)" >/dev/null; sleep 1.5
assert_eq "…which is so: a write through it is not in the audit log" "$($S audit-log show --table aud7_orders | grep -c INSERT)" "1"
pg pg-main "ALTER FUNCTION aud7_pay(int) SECURITY INVOKER" >/dev/null
gw "$KEY" "SELECT aud7_pay(3)" >/dev/null; sleep 1.5
assert_eq "made SECURITY INVOKER, it is no longer listed, and what it writes is audited" \
  "$($S audit-log tables | grep -c 'aud7_pay')|$($S audit-log show --table aud7_orders | grep -c INSERT)" "0|2"
$S user delete aud7-other@foxbyte.dev >/dev/null 2>&1
$S branch delete aud7pii >/dev/null 2>&1
$S audit-log off --yes >/dev/null 2>&1; main_up
pg pg-main "SET bb.allow_destructive=on; DROP FUNCTION IF EXISTS aud7_pay(int); DROP TABLE IF EXISTS aud7_orders" >/dev/null
rm -rf /tmp/aud7_cut.py /tmp/aud7_store.bak

echo "### 11af. the evidence export (F6 Gate 1, step 6b)"
# One document for an auditor: what the audit log covered and what it did
# not, the chain and its anchors, delivery, activity and every change to it.
# Never a statement's text or a value.
pg pg-main "SET bb.allow_destructive=on; DROP FUNCTION IF EXISTS aud8_pay(int); DROP TABLE IF EXISTS aud8_orders;
  CREATE TABLE aud8_orders (id int PRIMARY KEY, email text); GRANT ALL ON aud8_orders TO db_client;
  CREATE FUNCTION aud8_pay(i int) RETURNS void LANGUAGE sql SECURITY DEFINER AS \$f\$ INSERT INTO aud8_orders VALUES (i, 'paid') \$f\$" >/dev/null
$S audit-log table aud8_orders >/dev/null 2>&1
$S audit-log setup --yes >/dev/null 2>&1; main_up
gw "$KEY" "INSERT INTO aud8_orders VALUES (1, 'kavya.f6@example.in')" >/dev/null; sleep 1.5
$S audit-log anchor >/dev/null 2>&1
EVID="$($S audit-log evidence --since 1d 2>/dev/null)"
ej() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" <<<"$EVID"; }
assert_eq "evidence: its format and period, and coverage as the design states it, never more" \
  "$(ej 'd["format"]')|$(ej 'd["coverage"]["on"]')|$(ej 'any("SECURITY DEFINER" in s for s in d["coverage"]["not_logged"]) and any("superuser" in s for s in d["coverage"]["not_logged"])')|$(ej 'len(d["limits"]) >= 3')" \
  "audit-evidence/1|True|True|True"
assert_eq "…each running branch: its marks, and the definer functions that escape them" \
  "$(ej '[b for b in d["coverage"]["branches"] if b["name"]=="main"][0]["read"]')|$(ej 'any(m["name"]=="aud8_orders" and m["writes"] for m in [b for b in d["coverage"]["branches"] if b["name"]=="main"][0]["marks"])')|$(ej '"aud8_pay(integer)" in [f["function"] for f in [b for b in d["coverage"]["branches"] if b["name"]=="main"][0]["definers"]]')" \
  "True|True|True"
assert_eq "…the chain intact and anchored, with the anchors' key" \
  "$(ej 'd["integrity"]["intact"]')|$(ej 'd["integrity"]["anchors"] >= 1')|$(ej 'len(d["integrity"]["key_id"]) > 0')" "True|True|True"
assert_eq "…the period's activity, and the changes to the audit log, by whom" \
  "$(ej 'd["activity"]["records"] >= 1')|$(ej 'any(c["kind"]=="audit-log.on" for c in d["changes"])')|$(ej 'any(c["kind"]=="audit-log.marked" and "aud8_orders" in c["detail"] for c in d["changes"])')|$(ej 'all("ip" not in c for c in d["changes"])')" \
  "True|True|True|True"
assert_eq "…no records unless asked for, and no value the statements held" \
  "$(ej '"records" in d')|$(grep -c 'kavya' <<<"$EVID")" "False|0"
EVR="$($S audit-log evidence --since 1d --records 2>/dev/null)"
assert_eq "--records: the period's records with their place in the chain, and the anchors with their key" \
  "$(python3 -c 'import sys,json; d=json.load(sys.stdin); r=d["records"]; print(len(r) >= 1, all("hash" in x and "prev" in x for x in r), len(d["anchors"]) >= 1, len(d["public_key"]))' <<<"$EVR")" \
  "True True True 64"
# What a reviewer can check with the file alone: each record names the one
# before it, and each anchor's record in the period is the one it holds.
assert_eq "…which checks without FoxByte: record links record, and the anchors match" \
  "$(python3 -c '
import sys,json
d=json.load(sys.stdin); r=d["records"]; by={x["seq"]:x for x in r}
links=all(b["prev"]==a["hash"] for a,b in zip(r,r[1:]) if b["seq"]==a["seq"]+1)
held=[a for a in d["anchors"] if a["to_id"] in by]
print(links, len(held) >= 1 and all(by[a["to_id"]]["hash"]==a["last_row_hash"] for a in held))' <<<"$EVR")" "True True"
assert_eq "…and still no statement text or value" "$(grep -c 'kavya\|INSERT INTO aud8' <<<"$EVR")" "0"
assert_eq "a period that ends before it starts is refused" \
  "$($S audit-log evidence --since 2026-11-02 --until 2026-11-01 2>&1 >/dev/null | grep -c 'ends before it starts')" "1"
printf 'password123\n' | $S user create aud8-other@foxbyte.dev >/dev/null 2>&1
A8K="$($S apikey create aud8-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "the API: someone who is not an admin may not export it; an admin gets it as a file" \
  "$(code "$A8K" https://localhost:8080/api/audit-log/evidence)|$(curl -sk -D - -o /dev/null -H "$AUTH" 'https://localhost:8080/api/audit-log/evidence?since=7d' | grep -ci 'content-disposition: attachment; filename="audit-evidence-')" "403|1"
assert_eq "every export is in the security log" "$($S audit log --limit 100 | grep -c 'audit-log.evidence')" "3"
$S user delete aud8-other@foxbyte.dev >/dev/null 2>&1
$S audit-log off --yes >/dev/null 2>&1; main_up
pg pg-main "SET bb.allow_destructive=on; DROP FUNCTION IF EXISTS aud8_pay(int); DROP TABLE IF EXISTS aud8_orders" >/dev/null

echo "### 11ag. the hardening report (point 3.2)"
# FoxByte's own checks, not the CIS Benchmark: each pass, fail, manual or n/a,
# with the evidence and the fix. A weakness made on purpose is found.
HJ="$($S hardening --json 2>/dev/null)"
hj() { python3 -c "import sys,json; d=json.load(sys.stdin); c={x['id']:x for x in d['checks']}; print($1)" <<<"$HJ"; }
assert_eq "fox hardening --json: every check, each with a known status and level, and the basis it stands on" \
  "$(hj 'len(d["checks"]) >= 35 and all(x["status"] in ("pass","fail","manual","n/a") and x["level"] in ("basic","strict") for x in d["checks"])')|$(hj '"Not the CIS Benchmark" in d["basis"]')|$(hj 'sum(d["summary"].values()) == len(d["checks"])')" \
  "True|True|True"
assert_eq "…main as FoxByte sets it up: a supported version, SCRAM, durable writes, no network exposure, TLS at the Gateway" \
  "$(hj 'c["install.supported"]["status"]')|$(hj 'c["roles.scram"]["status"]')|$(hj 'c["set.durability"]["status"]')|$(hj 'c["conn.exposure"]["status"]')|$(hj 'c["conn.tls"]["status"]')|$(hj 'c["roles.bypassrls"]["status"]')|$(hj 'c["files.datadir"]["status"]')" \
  "pass|pass|pass|pass|pass|pass|pass"
assert_eq "…with the audit log off, says so and how to turn it on" \
  "$(hj 'c["audit.on"]["status"]')|$(hj '"audit-log setup" in c["audit.on"]["fix"]')" "fail|True"
pg pg-main "DROP ROLE IF EXISTS hard_weak; CREATE ROLE hard_weak LOGIN SUPERUSER PASSWORD 'x'; DROP ROLE IF EXISTS hard_rls; CREATE ROLE hard_rls BYPASSRLS" >/dev/null
OUT="$($S hardening --failed 2>&1)"
assert_eq "a superuser that can log in, and a role that ignores row-level security, are found and named" \
  "$(grep -A1 'roles.superusers' <<<"$OUT" | grep -c 'hard_weak')|$(grep -A1 'roles.bypassrls' <<<"$OUT" | grep -c 'hard_rls')|$(grep -c '^  pass ' <<<"$OUT")" "1|1|0"
pg pg-main "DROP ROLE IF EXISTS hard_weak; DROP ROLE IF EXISTS hard_rls" >/dev/null
assert_eq "--level strict lists strict checks only" \
  "$($S hardening --level strict --json | python3 -c 'import sys,json; print({x["level"] for x in json.load(sys.stdin)["checks"]})')" "{'strict'}"
$S audit-log setup --yes >/dev/null 2>&1; main_up
assert_eq "with the audit log on, pgAudit and its classes pass" \
  "$($S hardening --json | python3 -c 'import sys,json; c={x["id"]:x for x in json.load(sys.stdin)["checks"]}; print(c["audit.on"]["status"], c["audit.classes"]["status"])')" "pass pass"
$S audit-log off --yes >/dev/null 2>&1; main_up
assert_eq "a branch not running is not woken: it says to start it" \
  "$($S branch create hardsleep >/dev/null 2>&1; $S branch suspend hardsleep >/dev/null 2>&1; $S hardening --branch hardsleep 2>&1 | grep -c 'is not running')" "1"
$S branch delete hardsleep >/dev/null 2>&1
printf 'password123\n' | $S user create hard-other@foxbyte.dev >/dev/null 2>&1
HK="$($S apikey create hard-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "the API: an admin gets the report; someone who is not an admin does not" \
  "$(curl -sk -H "$AUTH" 'https://localhost:8080/api/hardening?branch=main' | python3 -c 'import sys,json; print(json.load(sys.stdin)["branch"])')|$(code "$HK" https://localhost:8080/api/hardening)" "main|403"
$S user delete hard-other@foxbyte.dev >/dev/null 2>&1
# Five: the four from the command line that produced one, and the API's.
assert_eq "every report is in the security log" "$($S audit log --limit 100 | grep -c 'hardening.reported')" "5"

echo "### 11ah. hardening fixes and profiles (points 3.3, 3.4)"
# Enterprise: the safe fixes, after a preview, one check at a time or by
# profile, each checked again; what is a person's to fix stays theirs. On a
# branch of its own, so main keeps its settings.
$S branch delete hardfix2 >/dev/null 2>&1; $S branch delete hardfix >/dev/null 2>&1; $S branch create hardfix >/dev/null 2>&1
gwh() { PGPASSWORD="$1" psql "${GATEWAY}/hardfix?sslmode=require" -X -q -tA -c "$2" 2>&1; }
showh() { pg pg-hardfix "SHOW $1"; }
sudo docker exec -i pg-hardfix psql -U dbadmin -d appdb -q >/dev/null 2>&1 <<'EOF'
ALTER SYSTEM SET log_connections = off;
ALTER SYSTEM SET log_disconnections = off;
ALTER SYSTEM SET idle_in_transaction_session_timeout = 0;
SELECT pg_reload_conf();
EOF
pg pg-hardfix "GRANT CREATE ON SCHEMA public TO PUBLIC" >/dev/null
PRE="$($S hardening fix log.connections --branch hardfix 2>&1)"
assert_eq "fix without --yes says what it changes and runs, and changes nothing" \
  "$(grep -c 'change: log_connections: off → on' <<<"$PRE")|$(grep -c "runs:   ALTER SYSTEM SET log_connections = 'on'" <<<"$PRE")|$(grep -c 'Run again with --yes' <<<"$PRE")|$(showh log_connections)" "1|1|1|off"
FIX="$($S hardening fix log.connections --branch hardfix --yes 2>&1)"; rc=$?
assert_eq "with --yes it is made with a reload, and checked again: it now passes" \
  "$rc|$(grep -c 'log.connections: fail → pass' <<<"$FIX")|$(showh log_connections)" "0|1|on"
assert_eq "a check that passes has nothing to fix; one that is a person's says so, and how" \
  "$($S hardening fix log.connections --branch hardfix 2>&1 | grep -c 'is pass')|$(pg pg-hardfix "DROP ROLE IF EXISTS hard_su; CREATE ROLE hard_su LOGIN SUPERUSER" >/dev/null; $S hardening fix roles.superusers --branch hardfix 2>&1 | grep -c 'is for a person to fix: ALTER ROLE')" "1|1"
pg pg-hardfix "DROP ROLE IF EXISTS hard_su" >/dev/null
assert_eq "CREATE on the public schema taken from PUBLIC: it passes, and clients still create tables through the Gateway" \
  "$($S hardening fix roles.public_schema --branch hardfix --yes 2>&1 | grep -c 'roles.public_schema: fail → pass')|$(gwh "$KEY" "CREATE TABLE hard_after (id int); SELECT 'made'")" "1|made"
BASE="$($S hardening profile baseline --branch hardfix 2>&1)"
assert_eq "profile baseline without --yes: each fix it makes, what it leaves to a person, and nothing changed" \
  "$(grep -c '^log.disconnections on hardfix' <<<"$BASE")|$(grep -c 'conn.idle' <<<"$BASE")|$(grep -c 'Run again with --yes' <<<"$BASE")|$(showh log_disconnections)" "1|0|1|off"
STRICT="$($S hardening profile strict --branch hardfix --yes 2>&1)"; rc=$?
assert_eq "profile strict with --yes: basic and strict fixes made and checked, and the profile recorded" \
  "$rc|$(showh log_disconnections)|$(showh idle_in_transaction_session_timeout)|$(grep -c 'The strict profile: .* made on hardfix, 0 did not hold' <<<"$STRICT")|$($S hardening --branch hardfix | grep -c 'Profile strict applied by')" \
  "0|on|10min|1|1"
assert_eq "…after which nothing failing is left that a fix could make" \
  "$($S hardening --branch hardfix --json | python3 -c 'import sys,json; print([c["id"] for c in json.load(sys.stdin)["checks"] if c.get("fixable")])')" "[]"
$S branch create hardfix2 --from hardfix >/dev/null 2>&1
assert_eq "a branch made afterwards has the fixes: they live in the branch's own data directory" \
  "$(pg pg-hardfix2 'SHOW log_connections')|$(pg pg-hardfix2 'SHOW idle_in_transaction_session_timeout')" "on|10min"
printf 'password123\n' | $S user create hardfix-other@foxbyte.dev >/dev/null 2>&1
HFK="$($S apikey create hardfix-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
sudo docker exec -i pg-hardfix psql -U dbadmin -d appdb -q >/dev/null 2>&1 <<'EOF'
ALTER SYSTEM SET log_hostname = on;
SELECT pg_reload_conf();
EOF
assert_eq "the API: an admin gets the preview; someone who is not an admin does not; a profile that is not one is refused" \
  "$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -d '{"branch":"hardfix","check":"log.hostname"}' https://localhost:8080/api/hardening/fix | python3 -c 'import sys,json; print(json.load(sys.stdin)["fix"]["changes"])')|$(code "$HFK" -X POST -H 'Content-Type: application/json' -d '{"branch":"hardfix","check":"log.hostname"}' https://localhost:8080/api/hardening/fix)|$(code "$KEY" -X POST -H 'Content-Type: application/json' -d '{"branch":"hardfix","profile":"lax"}' https://localhost:8080/api/hardening/profile)" \
  "['log_hostname: on → off']|403|400"
assert_eq "…and an admin's fix through it is made and checked" \
  "$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -d '{"branch":"hardfix","check":"log.hostname","apply":true}' https://localhost:8080/api/hardening/fix | python3 -c 'import sys,json; r=json.load(sys.stdin)["result"]; print(r["before"]["status"], r["after"]["status"], "error" in r)')|$(showh log_hostname)" \
  "fail pass False|off"
$S user delete hardfix-other@foxbyte.dev >/dev/null 2>&1
assert_eq "every fix and every profile is in the security log" \
  "$([ "$($S audit log --limit 200 | grep -c 'hardening.fixed')" -ge 5 ] && echo yes)|$($S audit log --limit 200 | grep -c 'hardening.profile')" "yes|1"
$S branch delete hardfix2 >/dev/null 2>&1; $S branch delete hardfix >/dev/null 2>&1

echo "### 11ai. masking personal data (F5 Gate 1, step 1)"
# Enterprise: rules on confirmed findings; a masked account reads the masks of
# marked tables and ordinary tables as they are, and cannot write to marked
# tables; admins and a branch's owner always see real values. On main, as an
# account reaches main and the branches it owns, and on those it sees real
# values. Its tables and rules are taken off at the end.
$S branch delete maskown >/dev/null 2>&1; $S branch delete maskold >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS m_customers, m_orders, m_kyc, m_plain CASCADE" >/dev/null
$S branch create maskold >/dev/null 2>&1
gwm() { PGPASSWORD="$1" psql "${GATEWAY}/$2?sslmode=require" -X -q -tA -c "$3" 2>&1; }
pg pg-main "CREATE TABLE m_customers (id bigint PRIMARY KEY, email text, phone text, aadhaar_no text, prefs jsonb, city text, full_name text);
  INSERT INTO m_customers VALUES
    (1, 'asha@example.com', '+91 98765 43210', '234567890124', '{\"contact\": {\"mobile\": \"+91 98765 43210\"}, \"theme\": \"dark\"}', 'Pune', 'Asha Rao'),
    (2, 'ravi@example.org', '9876543211', '456789012341', '{\"contact\": {\"mobile\": \"9876543211\"}}', 'Goa', 'Ravi Kumar');
  CREATE TABLE m_orders (id bigint PRIMARY KEY, customer_email text, total int);
  INSERT INTO m_orders VALUES (10, 'asha@example.com', 500), (11, 'ravi@example.org', 700);
  CREATE TABLE m_kyc (id int PRIMARY KEY, aadhaar_no text); INSERT INTO m_kyc VALUES (1, '234567890124');
  CREATE TABLE m_plain (id int PRIMARY KEY, v text); INSERT INTO m_plain VALUES (1, 'open');" >/dev/null
printf 'password123\n' | $S user create mask-analyst@foxbyte.dev >/dev/null 2>&1
MK="$($S apikey create mask-analyst@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "before masking, nothing is masked: an account reads real values" \
  "$($S mask | head -1)|$(gwm "$MK" main "SELECT email FROM m_customers WHERE id = 1")" "Masking: not set up on this install.|asha@example.com"
PRE="$($S mask setup 2>&1)"
assert_eq "setup without --yes says what it makes and that the branch restarts, and makes nothing" \
  "$(grep -c 'main restarts to mount the key' <<<"$PRE")|$(grep -c 'Run again with --yes' <<<"$PRE")|$(sudo test -e "${HOME:?}/${BRAND_STATE_DIR:?}/mask" && echo made || echo none)" "1|1|none"
SET="$($S mask setup --yes 2>&1)"; rc=$?
assert_eq "with --yes: the key is made, the server's alone, mounted read-only, and the branch set up" \
  "$rc|$(sudo stat -c '%u %a' "${HOME:?}/${BRAND_STATE_DIR:?}/mask") $(sudo stat -c '%u %a %s' "${HOME:?}/${BRAND_STATE_DIR:?}/mask/default.key")|$(sudo docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/bb-mask"}}{{.RW}}{{end}}{{end}}' pg-main)|$(pg pg-main "SELECT to_regrole('db_masked') IS NOT NULL AND to_regclass('bb.mask_rules') IS NOT NULL")" \
  "0|999 700 999 400 32|false|t"
[ "$rc" = 0 ] || { echo "--- what it said ---"; tail -8 <<<"$SET"; echo "--- end ---"; }
assert_eq "…and the key is in no table, log or message the setup produced" \
  "$(sudo docker logs pg-main 2>&1 | grep -c "$(sudo od -An -tx1 "${HOME:?}/${BRAND_STATE_DIR:?}/mask/default.key" | tr -d ' \n')")|$(grep -c 'Done.' <<<"$SET")" "0|1"
assert_eq "a branch started before it is listed as masking nothing until it starts again; main restarted with the key" \
  "$($S mask --json | hjson "print('maskold' in d['pending'], 'main' in d['pending'])")" "True False"
$S branch delete maskold >/dev/null 2>&1
NOPE="$($S mask rule m_customers.email --yes 2>&1)"; rc=$?
assert_eq "a rule is refused where no reviewer confirmed personal data" \
  "$rc|$(grep -c 'no confirmed personal data at public.m_customers.email' <<<"$NOPE")" "1|1"
$S pii scan >/dev/null 2>&1
MJ="$($S pii --json 2>/dev/null)"
mfid() { hjson "print([f['id'] for f in d['findings'] if f['table']=='$1' and f['column']=='$2' and f['path']=='$3'][0])" <<<"$MJ"; }
for at in "m_customers email" "m_customers phone" "m_customers aadhaar_no" "m_orders customer_email" "m_kyc aadhaar_no"; do
  $S pii mark "$(mfid $at '')" confirm >/dev/null 2>&1
done
$S pii mark "$(mfid m_customers prefs '$.contact.mobile')" confirm >/dev/null 2>&1
COST="$($S mask rule m_customers.email 2>&1)"
assert_eq "a rule without --yes says what it costs first, and sets nothing" \
  "$(grep -c '3.6 times as long' <<<"$COST")|$(grep -c 'a quarter slower' <<<"$COST")|$(grep -c 'Run again with --yes' <<<"$COST")|$($S mask --json | hjson "print(len(d['rules']))")" "1|1|1|0"
assert_eq "…and a partial mask says it costs nothing on writes" \
  "$($S mask rule m_kyc.aadhaar_no partial 2>&1 | grep -c 'nothing on writes')" "1"
assert_eq "Aadhaar is never hashed: refused, saying why" \
  "$($S mask rule m_customers.aadhaar_no hash --yes 2>&1 | grep -c 'never hashed or faked')" "1"
for c in m_customers.email m_customers.phone m_customers.aadhaar_no m_orders.customer_email m_kyc.aadhaar_no; do
  $S mask rule "$c" --yes >/dev/null 2>&1 || bad "setting the rule on $c"
done
$S mask rule m_customers.prefs --path '$.contact.mobile' --yes >/dev/null 2>&1 || bad "setting the rule on a JSON path"
assert_eq "each rule is the category's default, and every table's masks are made" \
  "$($S mask --json | hjson "print(sorted(r['table']+'.'+r['column']+r.get('path','')+':'+r['rule'] for r in d['rules']), sorted(d['ready']))")" \
  "['m_customers.aadhaar_no:partial', 'm_customers.email:hash', 'm_customers.phone:partial', 'm_customers.prefs\$.contact.mobile:partial', 'm_kyc.aadhaar_no:partial', 'm_orders.customer_email:hash'] ['m_customers', 'm_kyc', 'm_orders']"
assert_eq "a table with only partial masks gets no shadow and no trigger: nothing more on a write" \
  "$(pg pg-main "SELECT to_regclass('bb_mask.public__m_kyc') IS NULL, (SELECT count(*) FROM pg_trigger WHERE tgrelid = 'm_kyc'::regclass AND tgname LIKE 'bb_mask%')")" "t|0"
assert_eq "an admin cannot be masked: they can change the masks" \
  "$($S mask account test@foxbyte.dev --yes 2>&1 | grep -c 'is an admin')|$($S mask --json | hjson "print(len(d['accounts']))")" "1|0"
assert_eq "masking an account without --yes says what changes, and masks nobody" \
  "$($S mask account mask-analyst@foxbyte.dev 2>&1 | grep -c 'Run again with --yes')|$(gwm "$MK" main "SELECT email FROM m_customers WHERE id = 1")" "1|asha@example.com"
$S mask account mask-analyst@foxbyte.dev --yes >/dev/null 2>&1 || bad "masking the account"
assert_eq "a masked account reads masks: a keyed hash, partial values, a JSON path, the rest of the row as it is" \
  "$(gwm "$MK" main "SELECT length(email), email ~ '^[0-9a-f]{64}\$', phone, aadhaar_no, prefs->'contact'->>'mobile', prefs->>'theme', city, full_name FROM m_customers WHERE id = 1")" \
  "64|t|XXXXXXXXXXX3210|XXXXXXXX0124|XXXXXXXXXXX3210|dark|Pune|Asha Rao"
assert_eq "…joins on the hash: the same value, the same mask" \
  "$(gwm "$MK" main "SELECT count(*) FROM m_customers c JOIN m_orders o ON o.customer_email = c.email")" "2"
assert_eq "…a table with only partial masks too" "$(gwm "$MK" main "SELECT aadhaar_no FROM m_kyc")" "XXXXXXXX0124"
assert_eq "…is refused the real table, the shadow and the hash" \
  "$(gwm "$MK" main "SELECT email FROM public.m_customers" | grep -c 'permission denied')|$(gwm "$MK" main "SELECT * FROM bb_mask.public__m_customers" | grep -c 'permission denied')|$(gwm "$MK" main "SELECT bb_f1.bbid_mask_hmac('default', 'x')" | grep -c 'permission denied')" "1|1|1"
assert_eq "…cannot write to a marked table, and can to an ordinary one" \
  "$(gwm "$MK" main "UPDATE m_customers SET city = 'x' WHERE id = 1" | grep -cE 'permission denied|cannot update view')|$(gwm "$MK" main "UPDATE m_kyc SET aadhaar_no = 'x'" | grep -cE 'permission denied|cannot update')$(pg pg-main "SELECT aadhaar_no FROM m_kyc" | grep -c '^234567890124$')|$(gwm "$MK" main "INSERT INTO m_plain VALUES (2, 'by the analyst'); SELECT v FROM m_plain WHERE id = 2")" "1|11|by the analyst"
assert_eq "…cannot put its search_path back to the real tables" \
  "$(gwm "$MK" main "SET search_path = public; SELECT email FROM m_customers" | grep -c 'permission denied')" "1"
gwm "$KEY" main "INSERT INTO m_customers VALUES (3, 'neha@example.com', '9123456780', '345678901238', NULL, 'Delhi', 'Neha');
  UPDATE m_customers SET email = 'ravi.k@example.org' WHERE id = 2; UPDATE m_customers SET id = 4 WHERE id = 1; DELETE FROM m_customers WHERE id = 3" >/dev/null
assert_eq "the application's writes keep the masks up: inserts, changes, a moved key and a delete" \
  "$(pg pg-main "SELECT (SELECT count(*) FROM m_customers), (SELECT count(*) FROM bb_mask.public__m_customers), (SELECT count(*) FROM m_customers c JOIN bb_mask.public__m_customers m USING (id))")|$(gwm "$MK" main "SELECT id, email ~ '^[0-9a-f]{64}\$' FROM m_customers ORDER BY id" | tr '\n' ' ')" \
  "2|2|2|2|t 4|t "
assert_eq "…and an admin reads real values throughout" "$(gwm "$KEY" main "SELECT email FROM m_customers WHERE id = 2")" "ravi.k@example.org"
code "$MK" -X POST -H 'Content-Type: application/json' -d '{"name":"maskown","from":"main"}' https://localhost:8080/api/branches >/dev/null
# Owners once saw real values on their branches; a masked account made one of
# main and read everything there. Now it is masked on its own branches too
# (step 4).
assert_eq "the masked account reads masks on a branch it owns too: owning one does not unmask" \
  "$(gwm "$MK" maskown "SELECT email ~ '^[0-9a-f]{64}\$', phone FROM m_customers WHERE id = 2")" "t|XXXXXX3211"
assert_eq "the API: an admin reads where masking stands and the cost of a rule; the masked account is refused both" \
  "$(curl -sk -H "$AUTH" 'https://localhost:8080/api/masking?branch=main' | hjson "print(len(d['rules']), [a['email'] for a in d['accounts']])")|$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -d '{"branch":"main","table":"m_customers","column":"email"}' https://localhost:8080/api/masking/rule | hjson "print('3.6 times' in d['cost'])")|$(code "$MK" 'https://localhost:8080/api/masking?branch=main')|$(code "$MK" -X POST -H 'Content-Type: application/json' -d '{"email":"mask-analyst@foxbyte.dev","off":true}' https://localhost:8080/api/masking/account)" \
  "6 ['mask-analyst@foxbyte.dev']|True|403|403"
$S mask rule m_customers.email --off >/dev/null 2>&1 || bad "taking the email rule off"
assert_eq "a rule taken off: its column is real again for the masked account, the others still masked" \
  "$(gwm "$MK" main "SELECT email, phone FROM m_customers WHERE id = 2")" "ravi.k@example.org|XXXXXX3211"
$S mask account mask-analyst@foxbyte.dev --off --yes >/dev/null 2>&1 || bad "unmasking the account"
assert_eq "unmasked: real values again, and writes as before" \
  "$(gwm "$MK" main "SELECT phone FROM m_customers WHERE id = 2")|$(gwm "$MK" main "UPDATE m_customers SET city = 'Panaji' WHERE id = 2; SELECT city FROM m_customers WHERE id = 2")" "9876543211|Panaji"
assert_eq "every setup, rule and account change is in the security log" \
  "$($S audit log --limit 300 | grep -c 'mask.setup')|$($S audit log --limit 300 | grep -c 'mask.rule')|$($S audit log --limit 300 | grep -c 'mask.account')" "1|7|2"
$S branch delete maskown >/dev/null 2>&1
for c in m_customers.phone m_customers.aadhaar_no m_orders.customer_email m_kyc.aadhaar_no; do $S mask rule "$c" --off >/dev/null 2>&1; done
$S mask rule m_customers.prefs --path '$.contact.mobile' --off >/dev/null 2>&1
assert_eq "with every rule taken off, no mask is left behind: no view, shadow, trigger or rule" \
  "$(pg pg-main "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'bb_mask' AND c.relkind IN ('r','v') AND c.relname <> 'lookups'), (SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'bb_mask%'), (SELECT count(*) FROM bb.mask_rules)")" "0|0|0"
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS m_customers, m_orders, m_kyc, m_plain CASCADE" >/dev/null
$S user delete mask-analyst@foxbyte.dev >/dev/null 2>&1

echo "### 11aj. masking keys: domains and rotation (F5 Gate 1, step 2)"
# Enterprise: a key domain hashes apart from the others; a table's masks are
# put under one and back; a key is rotated while the application writes and a
# masked account reads, the old key deleted; a branch stopped meanwhile is
# named and its masks made again; a domain in use is not deleted. On main,
# set up by §11ai. Its tables and rules are taken off at the end.
$S branch delete keystale >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS k_people, k_orders CASCADE" >/dev/null
pg pg-main "CREATE TABLE k_people (id bigint PRIMARY KEY, email text, phone text);
  INSERT INTO k_people SELECT g, 'person' || g || '@example.com', '98765' || lpad(g::text, 5, '0') FROM generate_series(1, 5000) g;
  CREATE TABLE k_orders (id bigint PRIMARY KEY, cust_email text);
  INSERT INTO k_orders VALUES (1, 'person1@example.com'), (2, 'person2@example.com')" >/dev/null
$S pii scan >/dev/null 2>&1
KJ="$($S pii --json 2>/dev/null)"
kfid() { hjson "print([f['id'] for f in d['findings'] if f['table']=='$1' and f['column']=='$2'][0])" <<<"$KJ"; }
for at in "k_people email" "k_people phone" "k_orders cust_email"; do $S pii mark "$(kfid $at)" confirm >/dev/null 2>&1; done
for c in k_people.email k_people.phone k_orders.cust_email; do $S mask rule "$c" --yes >/dev/null 2>&1 || bad "setting the rule on $c"; done
printf 'password123\n' | $S user create key-analyst@foxbyte.dev >/dev/null 2>&1
KK="$($S apikey create key-analyst@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
$S mask account key-analyst@foxbyte.dev --yes >/dev/null 2>&1 || bad "masking the key analyst"
KD="${HOME:?}/${BRAND_STATE_DIR:?}/mask"
keyhex() { sudo od -An -tx1 "$KD/$1.key" | tr -d ' \n'; }
JOIN="SELECT count(*) FROM k_people p JOIN k_orders o ON o.cust_email = p.email"
assert_eq "the default domain: key 1, made when setup wrote it, the key itself never shown; masks join within it" \
  "$($S mask key --json | hjson "k=[x for x in d['keys'] if x['domain']=='default'][0]; print(k['gen'], bool(k['made']), 'key' in k)")|$($S mask key | grep -c "$(keyhex default)")|$(gwm "$KK" main "$JOIN")" "1 True False|0|2"

assert_eq "a domain's name is checked: a capital, a dot or a dash is refused" \
  "$($S mask key create Tenant --yes 2>&1 | grep -c 'a key domain is a lowercase letter')|$($S mask key create a.b --yes 2>&1 | grep -c 'a key domain is')|$($S mask key create a-b --yes 2>&1 | grep -c 'a key domain is')" "1|1|1"
assert_eq "making a domain without --yes says what it is for, and makes nothing" \
  "$($S mask key create tenant_a 2>&1 | grep -c 'hash apart')|$(sudo test -e "$KD/tenant_a.key" && echo made || echo none)" "1|none"
$S mask key create tenant_a --yes >/dev/null 2>&1 || bad "making tenant_a"
assert_eq "with --yes: a key of its own, the server's alone, 32 bytes, unlike the default's" \
  "$(sudo stat -c '%u %a %s' "$KD/tenant_a.key")|$([ "$(keyhex tenant_a)" != "$(keyhex default)" ] && echo apart)|$($S mask key --json | hjson "print(sorted(k['domain'] for k in d['keys']))")" \
  "999 400 32|apart|['default', 'tenant_a']"
assert_eq "…a second domain of the same name is refused" "$($S mask key create tenant_a --yes 2>&1 | grep -c 'already has a key domain')" "1"
assert_eq "putting a table under a domain without --yes changes nothing" \
  "$($S mask key use tenant_a --table k_orders 2>&1 | grep -c 'Run again with --yes')|$(gwm "$KK" main "$JOIN")" "1|2"
$S mask key use tenant_a --table k_orders --yes >/dev/null 2>&1 || bad "putting k_orders under tenant_a"
assert_eq "under tenant_a, k_orders's masks are tenant_a's hashes and no longer join with the default domain's" \
  "$(gwm "$KK" main "$JOIN")|$(pg pg-main "SELECT count(*) FROM bb_mask.public__k_orders m JOIN k_orders o USING (id) WHERE m.cust_email = bb_f1.bbid_mask_hmac('tenant_a', o.cust_email)")|$($S mask key --json | hjson "print([t['table'] for k in d['keys'] if k['domain']=='tenant_a' for t in k['tables'] if t['branch']=='main'])")" \
  "0|2|['k_orders']"
DROPA="$($S mask key drop tenant_a --yes 2>&1)"
assert_eq "a domain a table uses is not deleted" \
  "$(grep -c 'main:public.k_orders uses tenant_a' <<<"$DROPA")|$(sudo test -e "$KD/tenant_a.key" && echo kept)" "1|kept"
grep -q 'main:public.k_orders uses tenant_a' <<<"$DROPA" || echo "    it said: $DROPA"

ROTD="$(mktemp -d)"
# A branch with masks, stopped through the rotation: named, then made again.
$S branch create keystale >/dev/null 2>&1
$S branch suspend keystale >/dev/null 2>&1
OLDKEY="$(keyhex default)"
OLDMASK="$(gwm "$KK" main "SELECT email FROM k_people WHERE id = 1")"
PRE="$($S mask key rotate default 2>&1)"
assert_eq "rotating without --yes says what it does and costs, names the tables and the stopped branch, and makes no key" \
  "$(grep -c 'There is no undo' <<<"$PRE")|$(grep -c '21 seconds a million rows' <<<"$PRE")|$(grep -c 'main: public.k_people' <<<"$PRE")|$(grep -c 'keystale' <<<"$PRE")|$(sudo test -e "$KD/default--next.key" && echo made || echo none)|$(keyhex default | grep -c "$OLDKEY")" \
  "1|1|1|1|none|1"
# The application writes and a masked account reads all through the rotation.
( for i in $(seq 1 60); do gwm "$KEY" main "UPDATE k_people SET email = 'w$i@example.com' WHERE id = $((i * 50)); INSERT INTO k_people VALUES ($((100000 + i)), 'n$i@example.com', '1')" | grep -E 'ERROR|FATAL|error'; done ) >"$ROTD/writer.log" 2>&1 &
RW=$!
( for _ in $(seq 1 40); do gwm "$KK" main "SELECT count(*) FROM k_people" | grep -vE '^[0-9]+$'; done ) >"$ROTD/reader.log" 2>&1 &
RR=$!
ROT="$($S mask key rotate default --yes 2>&1)"; rc=$?
wait "$RW" "$RR"
assert_eq "with --yes: every table in the domain is written again, and the old key's file now holds a new key" \
  "$rc|$(grep -c 'main: public.k_people written again under the new key' <<<"$ROT")|$(keyhex default | grep -c "$OLDKEY")|$(sudo stat -c '%u %a %s' "$KD/default.key")|$(sudo test -e "$KD/default--next.key" && echo left || echo gone)" \
  "0|1|0|999 400 32|gone"
[ "$rc" = 0 ] || { echo "--- what it said ---"; tail -8 <<<"$ROT"; echo "--- end ---"; }
assert_eq "…the writer was never refused, and the masked reader never failed, while it ran" \
  "$(grep -c . "$ROTD/writer.log")|$(grep -c . "$ROTD/reader.log")" "0|0"
cat "$ROTD/writer.log" "$ROTD/reader.log" | head -5
assert_eq "…every mask, the writer's included, is under the new key, nothing is left over, and only tenant_a's table is untouched" \
  "$(pg pg-main "SELECT (SELECT count(*) FROM bb_mask.public__k_people m JOIN k_people p USING (id) WHERE m.email IS DISTINCT FROM bb_f1.bbid_mask_hmac('default', p.email)), (SELECT count(*) FROM k_people) = (SELECT count(*) FROM bb_mask.public__k_people), (SELECT count(*) FROM pg_class WHERE relname LIKE '%\_\_next' OR relname LIKE '%\_\_old'), (SELECT count(*) FROM bb_mask.public__k_orders m JOIN k_orders o USING (id) WHERE m.cust_email = bb_f1.bbid_mask_hmac('tenant_a', o.cust_email))")" \
  "0|t|0|2"
assert_eq "…the masked account reads the new masks, every hash changed: masks copied out before do not match" \
  "$(NEW="$(gwm "$KK" main "SELECT email FROM k_people WHERE id = 1")"; [ "$NEW" != "$OLDMASK" ] && [ ${#NEW} = 64 ] && echo changed)|$(gwm "$KK" main "SELECT count(*) FROM k_people WHERE email = '$OLDMASK'")" "changed|0"
assert_eq "…the default key is key 2, rotated by who asked; the new key is in no log" \
  "$($S mask key --json | hjson "k=[x for x in d['keys'] if x['domain']=='default'][0]; print(k['gen'], k['rotatedBy'].startswith('cli:'), k['next'])")|$(sudo docker logs pg-main 2>&1 | grep -c "$(keyhex default)")" \
  "2 True False|0"
$S branch resume keystale >/dev/null 2>&1
assert_eq "the branch stopped through it is named as made under an older key (its tenant_a table is not), and set up again it is not" \
  "$($S mask key --json | hjson "print(sorted(t['branch']+':'+t['table'] for k in d['keys'] for t in k['stale']))")|$($S mask setup --branch keystale --yes >/dev/null 2>&1; $S mask key --json | hjson "print(sum(len(k['stale']) for k in d['keys']))")|$(pg pg-keystale "SELECT count(*) FROM bb_mask.public__k_people m JOIN k_people p USING (id) WHERE m.email IS DISTINCT FROM bb_f1.bbid_mask_hmac('default', p.email)")" \
  "['keystale:k_people']|0|0"
$S mask key use default --table k_orders --yes >/dev/null 2>&1 || bad "putting k_orders back under default"
assert_eq "back under the default domain, k_orders joins again, under the new key" "$(gwm "$KK" main "$JOIN")" "2"
assert_eq "the API: an admin reads the keys and a rotation's cost; a bad name is refused; the masked account is refused" \
  "$(curl -sk -H "$AUTH" https://localhost:8080/api/masking/keys | hjson "print(sorted(k['domain'] for k in d['keys']))")|$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -d '{"action":"rotate","domain":"tenant_a"}' https://localhost:8080/api/masking/key | hjson "print('There is no undo' in d['cost'])")|$(code "$KEY" -X POST -H 'Content-Type: application/json' -d '{"action":"create","domain":"Bad","apply":true}' https://localhost:8080/api/masking/key)|$(code "$KK" https://localhost:8080/api/masking/keys)|$(code "$KK" -X POST -H 'Content-Type: application/json' -d '{"action":"rotate","domain":"default","apply":true}' https://localhost:8080/api/masking/key)" \
  "['default', 'tenant_a']|True|400|403|403"
$S branch delete keystale >/dev/null 2>&1
DROPB="$($S mask key drop tenant_a --yes 2>&1)" || bad "deleting tenant_a once no table uses it: $DROPB"
assert_eq "a domain no table uses is deleted, its key with it; the default cannot be" \
  "$(sudo test -e "$KD/tenant_a.key" && echo kept || echo gone)|$($S mask key --json | hjson "print([k['domain'] for k in d['keys']])")|$($S mask key drop default --yes 2>&1 | grep -c 'default domain is the install')" \
  "gone|['default']|1"
assert_eq "every key change is in the security log" "$($S audit log --limit 300 | grep -c 'mask.key')" "5"
for c in k_people.email k_people.phone k_orders.cust_email; do $S mask rule "$c" --off >/dev/null 2>&1; done
$S mask account key-analyst@foxbyte.dev --off --yes >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS k_people, k_orders CASCADE" >/dev/null
$S user delete key-analyst@foxbyte.dev >/dev/null 2>&1
rm -rf "${ROTD:?}"

echo "### 11ak. masking: unmask, the lookup, the access review, reads audited (F5 Gate 1, step 3)"
# Enterprise: a masked account given unmask on a branch sees real values
# there, and its reads of marked tables are logged by the audit log, its only;
# it cannot undo that. The lookup finds a person by an exact value, masked, 30
# a minute, recorded without the value. The access review says who sees what.
# On main, set up by §11ai.
$S branch delete umother >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS u_people CASCADE" >/dev/null
pg pg-main "CREATE TABLE u_people (id bigint PRIMARY KEY, email text, phone text, aadhaar_no text);
  INSERT INTO u_people VALUES (1, 'asha.u@example.com', '+91 98765 43210', '234567890124'), (2, 'ravi.u@example.org', '9876543211', '456789012341')" >/dev/null
$S pii scan >/dev/null 2>&1
UJ="$($S pii --json 2>/dev/null)"
ufid() { hjson "print([f['id'] for f in d['findings'] if f['table']=='u_people' and f['column']=='$1'][0])" <<<"$UJ"; }
for c in email phone aadhaar_no; do $S pii mark "$(ufid $c)" confirm >/dev/null 2>&1; $S mask rule "u_people.$c" --yes >/dev/null 2>&1 || bad "setting the rule on u_people.$c"; done
for u in unmask-analyst plain-person; do printf 'password123\n' | $S user create "$u@foxbyte.dev" >/dev/null 2>&1; done
UM="$($S apikey create unmask-analyst@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
$S mask account unmask-analyst@foxbyte.dev --yes >/dev/null 2>&1 || bad "masking the analyst"
UROLE="SELECT coalesce(array_to_string(rolconfig, ' '), '') FROM pg_roles WHERE rolname = 'unmask-analyst@foxbyte.dev'"
unmasked() { $S access review --json 2>/dev/null | hjson "print([a['unmasked'] for a in d['accounts'] if a['email']=='$1'][0])"; }
assert_eq "the access review says who sees what: an admin real values, an account not masked everything, a masked one masks" \
  "$(unmasked test@foxbyte.dev | grep -c 'an admin always sees real values')|$(unmasked plain-person@foxbyte.dev | grep -c 'not masked')|$(unmasked unmask-analyst@foxbyte.dev | grep -c '^masks of marked tables$')" "1|1|1"
assert_eq "unmask is for a masked account: one that is not is refused, saying why; so is a branch that is not there" \
  "$($S mask unmask plain-person@foxbyte.dev --branch main --yes 2>&1 | grep -c 'is not masked, so it sees real values already')|$($S mask unmask unmask-analyst@foxbyte.dev --branch nosuchbranch --yes 2>&1 | grep -c 'there is no branch')" "1|1"
PRE="$($S mask unmask unmask-analyst@foxbyte.dev --branch main 2>&1)"
assert_eq "without --yes it says what changes, that reads are audited and the audit log is off, and changes nothing" \
  "$(grep -c 'Every read they make there of a marked table is audited' <<<"$PRE")|$(grep -c 'The audit log is off' <<<"$PRE")|$(gwm "$UM" main "SELECT length(email) FROM u_people WHERE id = 1")" "1|1|64"
$S audit-log setup --yes >/dev/null 2>&1; main_up
$S mask unmask unmask-analyst@foxbyte.dev --branch main --yes >/dev/null 2>&1 || bad "unmasking the analyst on main"
assert_eq "with unmask on main, the masked account reads real values there, and its role's audit role is bb_audit_read" \
  "$(gwm "$UM" main "SELECT email, phone FROM u_people WHERE id = 1")|$(pg pg-main "$UROLE" | grep -o 'pgaudit.role=bb_audit_read')" "asha.u@example.com|+91 98765 43210|pgaudit.role=bb_audit_read"
gwm "$UM" main "SELECT count(*) FROM u_people" >/dev/null; sleep 1.5
assert_eq "…its reads of a marked table are logged (both), under its login, with nothing the table holds" \
  "$(auditlog main | grep '"user":"unmask-analyst@foxbyte.dev"' | grep -c 'AUDIT: OBJECT,[0-9]*,[0-9]*,READ,SELECT,TABLE,public.u_people,')|$(auditlog main | grep -c 'asha.u@example.com')" "2|0"
assert_eq "…and it cannot undo that: the setting is a superuser's" \
  "$(gwm "$UM" main "SET pgaudit.role = 'nobody'" | grep -c 'permission denied')|$(gwm "$UM" main "ALTER ROLE SESSION_USER RESET pgaudit.role" | grep -c 'permission denied')" "1|1"
$S branch create umother >/dev/null 2>&1
# The Gateway lets a non-admin reach main and the branches it owns only, so
# another branch is read from the record, not by connecting.
assert_eq "unmask is on one branch: another branch lists nobody" \
  "$($S mask --branch umother --json | hjson "print(len(d['unmasks']))")|$($S mask --json | hjson "print(len(d['unmasks']))")" "0|1"
assert_eq "the access review lists the unmask, audited" \
  "$(unmasked unmask-analyst@foxbyte.dev)" "masks of marked tables; unmask on main, its reads of marked tables audited"
assert_eq "status lists it, and the API: an admin reads lookups; the masked account may not unmask itself" \
  "$($S mask --json | hjson "print([g['email'] for g in d['unmasks']], d['auditOn'])")|$(code "$KEY" https://localhost:8080/api/masking/lookups?branch=main)|$(code "$UM" -X POST -H 'Content-Type: application/json' -d '{"email":"unmask-analyst@foxbyte.dev","branch":"umother"}' https://localhost:8080/api/masking/unmask)" \
  "['unmask-analyst@foxbyte.dev'] True|200|403"
$S mask unmask unmask-analyst@foxbyte.dev --branch main --off --yes >/dev/null 2>&1 || bad "taking unmask off"
assert_eq "unmask taken off: masks again, and the audit role is gone from the role" \
  "$(gwm "$UM" main "SELECT length(email) FROM u_people WHERE id = 1")|$(pg pg-main "$UROLE" | grep -c 'pgaudit.role')" "64|0"

# The lookup: by an exact value, the rows masked; nothing outside a rule.
assert_eq "the lookup finds a person by an exact value and returns the row masked: by a hash, and by a partial mask" \
  "$(gwm "$UM" main "SELECT d->>'id', length(d->>'email'), d->>'phone' FROM bb_mask.find('u_people', 'email', 'asha.u@example.com') d")|$(gwm "$UM" main "SELECT d->>'id', d->>'aadhaar_no' FROM bb_mask.find('public.u_people', 'aadhaar_no', '456789012341') d")|$(gwm "$UM" main "SELECT count(*) FROM bb_mask.find('u_people', 'email', 'nobody@example.com')")" \
  "1|64|XXXXXXXXXXX3210|2|XXXXXXXX2341|0"
assert_eq "…only in a column with a rule of its own, and never a table without one" \
  "$(gwm "$UM" main "SELECT * FROM bb_mask.find('u_people', 'id', '1')" | grep -c 'has none')|$(gwm "$UM" main "SELECT * FROM bb_mask.find('pg_authid', 'rolpassword', 'x')" | grep -c 'has none')|$(gwm "$KEY" main "SELECT * FROM bb_mask.find('u_people', 'email', 'x')" | grep -c 'permission denied')" "1|1|1"
LK="$($S mask lookups --json)"
assert_eq "each lookup is recorded: who, which column, how many found; never the value; the masked account cannot read the record" \
  "$(hjson "print(len(d), sorted(set(l['who'] for l in d)), sorted(set(l['column'] for l in d)), sum(l['found'] for l in d))" <<<"$LK")|$(grep -cE 'asha|456789' <<<"$LK")|$(gwm "$UM" main "SELECT count(*) FROM bb_mask.lookups" | grep -c 'permission denied')" \
  "3 ['unmask-analyst@foxbyte.dev'] ['aadhaar_no', 'email'] 2|0|1"
for _ in $(seq 27); do gwm "$UM" main "SELECT count(*) FROM bb_mask.find('u_people', 'email', 'x@example.com')" >/dev/null; done
assert_eq "30 lookups a minute for each account, then refused" \
  "$(gwm "$UM" main "SELECT count(*) FROM bb_mask.find('u_people', 'email', 'asha.u@example.com')" | grep -c 'too many lookups')" "1"
assert_eq "no value looked up is in the database's log" "$(sudo docker logs pg-main 2>&1 | grep -cE 'asha.u@example.com|456789012341|x@example.com')" "0"

# A branch's unmask goes with it; an account unmasked keeps none.
$S mask unmask unmask-analyst@foxbyte.dev --branch umother --yes >/dev/null 2>&1 || bad "unmask on umother"
$S branch delete umother >/dev/null 2>&1
$S mask unmask unmask-analyst@foxbyte.dev --branch main --yes >/dev/null 2>&1
UG="${HOME:?}/${BRAND_STATE_DIR:?}/unmask-grants.json"
assert_eq "a deleted branch's unmask is gone with it, so a branch made later with its name has none" \
  "$(python3 -c 'import json,sys; print(sorted(g["branch"] for g in json.load(open(sys.argv[1]))))' "$UG")" "['main']"
$S mask account unmask-analyst@foxbyte.dev --off --yes >/dev/null 2>&1
assert_eq "an account unmasked keeps no unmask, and its audit role is gone" \
  "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$UG")|$(pg pg-main "$UROLE" | grep -c 'pgaudit.role')" "0|0"
assert_eq "every unmask given and taken is in the security log" "$($S audit log --limit 300 | grep -c 'mask.unmask')" "4"
$S audit-log off --yes >/dev/null 2>&1; main_up
for c in email phone aadhaar_no; do $S mask rule "u_people.$c" --off >/dev/null 2>&1; done
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS u_people CASCADE" >/dev/null
for u in unmask-analyst plain-person; do $S user delete "$u@foxbyte.dev" >/dev/null 2>&1; done

echo "### 11al. masking: every access path (F5 Gate 1, step 4)"
# Enterprise. The suite runs as a masked account and as its agent on each path
# the design names (section 11): each keeps the masks or is refused. The
# tables are made by an ordinary account through the Gateway, as an
# application's are, so what it makes later is granted as the defaults say.
# On main, set up by §11ai.
for b in pmown pmpit; do $S branch delete "$b" >/dev/null 2>&1; done
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS p_people, p_logins, p_notes, p_late CASCADE; DROP FUNCTION IF EXISTS p_phone_of(text)" >/dev/null
for u in path-dev path-analyst; do printf 'password123\n' | $S user create "$u@foxbyte.dev" >/dev/null 2>&1; done
PD="$($S apikey create path-dev@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
PM="$($S apikey create path-analyst@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
PA="$($S apikey create path-analyst@foxbyte.dev agent --agent 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
gwm "$PD" main "CREATE TABLE p_people (id bigint PRIMARY KEY, email text UNIQUE, phone text, city text);
  INSERT INTO p_people VALUES (1, 'asha.p@example.com', '+91 98765 43210', 'Pune'), (2, 'ravi.p@example.org', '9876543211', 'Goa');
  CREATE TABLE p_logins (id serial PRIMARY KEY, login text REFERENCES p_people(email), at timestamptz DEFAULT now());
  CREATE TABLE p_notes (id serial PRIMARY KEY, person bigint REFERENCES p_people(id), note text)" >/dev/null
$S pii scan >/dev/null 2>&1
PJ="$($S pii --json 2>/dev/null)"
pfid() { hjson "print([f['id'] for f in d['findings'] if f['table']=='p_people' and f['column']=='$1'][0])" <<<"$PJ"; }
for c in email phone; do $S pii mark "$(pfid $c)" confirm >/dev/null 2>&1; $S mask rule "p_people.$c" --yes >/dev/null 2>&1 || bad "setting the rule on p_people.$c"; done
$S mask account path-analyst@foxbyte.dev --yes >/dev/null 2>&1 || bad "masking the analyst"
PREAL="asha.p@example.com|98765 43210"
leaks() { grep -cE "$PREAL"; }
assert_eq "Gateway: masks; the real table refused" \
  "$(gwm "$PM" main "SELECT email ~ '^[0-9a-f]{64}\$', phone, city FROM p_people WHERE id = 1")|$(gwm "$PM" main "SELECT * FROM public.p_people" | grep -c 'permission denied')" "t|XXXXXXXXXXX3210|Pune|1"
pq() { as "$1" -H 'Content-Type: application/json' -X POST -d "$(python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1]}))' "$2")" https://localhost:8080/api/branches/main/query; }
assert_eq "console query, as the account's own role: masks; the real table refused" \
  "$(pq "$PM" "SELECT email, phone FROM p_people" | leaks)|$(pq "$PM" "SELECT phone FROM p_people WHERE id = 1" | grep -c 'XXXXXXXXXXX3210')|$(pq "$PM" "SELECT * FROM public.p_people" | grep -c 'permission denied')" "0|1|1"
assert_eq "the data grid: the marked table's real rows refused, its edit refused" \
  "$(pq "$PM" 'SELECT * FROM "public"."p_people" LIMIT 100' | grep -c 'permission denied')|$(code "$PM" -X POST -H 'Content-Type: application/json' -d '{"schema":"public","table":"p_people","changes":[{"op":"update","key":{"id":"1"},"values":{"city":"x"}}]}' https://localhost:8080/api/branches/main/rows | grep -vc '^200$')$(pg pg-main "SELECT city FROM p_people WHERE id = 1")" "1|1Pune"
assert_eq "exports, CSV and workbook: masks" \
  "$(as "$PM" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT * FROM p_people"}' https://localhost:8080/api/branches/main/export | leaks)|$(as "$PM" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT * FROM p_people"}' https://localhost:8080/api/branches/main/export | grep -c 'XXXXXX3211')|$(as "$PM" -H 'Content-Type: application/json' -X POST -d '{"sql":"SELECT * FROM p_people","format":"xlsx"}' https://localhost:8080/api/branches/main/export | python3 -c 'import sys,zipfile,io; z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())); print(sum(b"asha.p@" in z.read(n) for n in z.namelist()))')" "0|1|0"
assert_eq "the object browser: definitions, no values" \
  "$(as "$PM" 'https://localhost:8080/api/branches/main/schema' | leaks)" "0"
assert_eq "an agent key of the masked account: masks through the Gateway, as a masked agent role; db_client out of reach" \
  "$(gwm "$PA" main "SELECT current_user, session_user, phone FROM p_people WHERE id = 2")|$(gwm "$PA" main "SET ROLE db_client" | grep -c 'permission denied')|$(gwm "$PA" main "SELECT * FROM public.p_people" | grep -c 'permission denied')" \
  "db_masked|agent:path-analyst@foxbyte.dev|XXXXXX3211|1|1"
mcpm() { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
    | env FOX_API_KEY="$PA" "$S" mcp 2>/dev/null \
    | python3 -c 'import sys,json
for line in sys.stdin:
    m=json.loads(line)
    if m.get("id")==2:
        r=m.get("result") or {}; e=m.get("error") or {}
        print((r.get("content") or [{}])[0].get("text","") or e.get("message",""))'; }
assert_eq "MCP run_sql and execute_change, as the masked agent: masks; writing a marked table refused" \
  "$(mcpm run_sql '{"sql":"SELECT email, phone FROM p_people"}' | leaks)|$(mcpm run_sql '{"sql":"SELECT phone FROM p_people WHERE id = 1"}' | grep -c 'XXXXXXXXXXX3210')|$(mcpm execute_change '{"sql":"UPDATE p_people SET city = city","agent_id":"pm"}' | grep -cE 'permission denied|cannot update')" "0|1|1"
assert_eq "joins, views and functions it writes read masks only; it cannot make objects in public" \
  "$(gwm "$PM" main "CREATE TEMP VIEW tv AS SELECT p.phone FROM p_people p JOIN p_notes n ON n.person = p.id; SELECT count(*) FROM tv; SELECT phone FROM p_people")" \
  "0
XXXXXXXXXXX3210
XXXXXX3211"
assert_eq "…a temporary function sees masks too; CREATE in public refused" \
  "$(gwm "$PM" main "CREATE FUNCTION pg_temp.f(t text) RETURNS text LANGUAGE sql AS \$\$ SELECT t \$\$; SELECT pg_temp.f(phone) FROM p_people WHERE id = 1")|$(gwm "$PM" main "CREATE VIEW public.pv AS SELECT 1" | grep -c 'permission denied')" "XXXXXXXXXXX3210|1"
assert_eq "RETURNING, ON CONFLICT and MERGE: no write to a marked table" \
  "$(gwm "$PM" main "INSERT INTO p_people (id) VALUES (9) RETURNING *" | grep -cE 'permission denied|cannot insert')|$(gwm "$PM" main "INSERT INTO p_people (id) VALUES (1) ON CONFLICT (id) DO NOTHING" | grep -cE 'permission denied|cannot insert|no unique')|$(gwm "$PM" main "DELETE FROM p_people WHERE id = 1 RETURNING phone" | grep -cE 'permission denied|cannot delete')|$(gwm "$PM" main "MERGE INTO p_people t USING (SELECT 1 AS id) s ON t.id = s.id WHEN MATCHED THEN DELETE" | grep -cE 'permission denied|cannot')" "1|1|1|1"
assert_eq "errors show masks: a failed cast quotes the mask" \
  "$(gwm "$PM" main "SELECT phone::int FROM p_people WHERE id = 2" | grep -c 'XXXXXX3211')" "1"
assert_eq "pg_stats and extended statistics: nothing of the real table; EXPLAIN: no values" \
  "$(pg pg-main "ANALYZE p_people" >/dev/null; gwm "$PM" main "SELECT count(*) FROM pg_stats WHERE tablename IN ('p_people', 'public__p_people')")|$(gwm "$PM" main "SELECT count(*) FROM pg_stats_ext WHERE tablename = 'p_people'")|$(gwm "$PM" main "EXPLAIN (VERBOSE) SELECT * FROM p_people WHERE city = 'Pune'" | leaks)" "0|0|0"
assert_eq "COPY: masks from a query, the real table refused, the view refused" \
  "$(gwm "$PM" main "COPY (SELECT phone FROM p_people WHERE id = 2) TO STDOUT")|$(gwm "$PM" main "COPY public.p_people TO STDOUT" | grep -c 'permission denied')|$(gwm "$PM" main "COPY p_people TO STDOUT" | grep -c 'cannot copy from view')" "XXXXXX3211|1|1"
assert_eq "realtime: refused to the masked account, saying why, before anything else; an account not masked is not" \
  "$(code "$PM" https://localhost:8080/api/branches/main/realtime)|$(as "$PM" https://localhost:8080/api/branches/main/realtime | grep -c 'is masked, and the change feed would carry')|$(code "$PD" https://localhost:8080/api/branches/main/realtime | grep -vc '^403$')" "403|1|1"
# A continuous import copies an outside source into a branch of its own, and
# reads no marked table; its list is the imports' state, no rows.
assert_eq "logical replication: the cutover is an admin's; the imports' list carries no values" \
  "$(code "$PM" -X POST https://localhost:8080/api/branches/main/replication/cutover)|$(as "$PM" https://localhost:8080/api/replication | leaks)" "403|0"
# The Blackbox: a statement's text can hold real values.
gwm "$PD" main "UPDATE p_people SET city = 'Pune' WHERE email = 'asha.p@example.com'" >/dev/null
gwm "$PD" main "CREATE TABLE p_late (id int PRIMARY KEY)" >/dev/null
assert_eq "Blackbox: the masked account reads the entries without their text; an admin with it; its export refused" \
  "$(as "$PM" 'https://localhost:8080/api/branches/main/ledger?limit=200' | leaks)|$(as "$PM" 'https://localhost:8080/api/branches/main/ledger?limit=20' | grep -c 'hidden from masked accounts')|$(curl -sk -H "$AUTH" 'https://localhost:8080/api/branches/main/ledger?limit=20' | grep -c 'CREATE TABLE p_late')|$(code "$PM" https://localhost:8080/api/branches/main/ledger/export)" "0|1|1|403"
# Branches: owning one does not unmask, and the masks travel.
code "$PM" -X POST -H 'Content-Type: application/json' -d '{"name":"pmown","from":"main"}' https://localhost:8080/api/branches >/dev/null
LATE="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger WHERE object_identity = 'public.p_late' AND command_tag = 'CREATE TABLE'")"
code "$PM" -X POST -H 'Content-Type: application/json' -d '{"name":"pmpit"}' "https://localhost:8080/api/branches/main/ledger/$LATE/branch" >/dev/null
assert_eq "a branch it makes of main, and one made back in time, read masks: owning them does not unmask" \
  "$(gwm "$PM" pmown "SELECT phone FROM p_people WHERE id = 2")|$(gwm "$PM" pmown "SELECT * FROM public.p_people" | grep -c 'permission denied')|$(gwm "$PM" pmpit "SELECT phone FROM p_people WHERE id = 2")" "XXXXXX3211|1|XXXXXX3211"
assert_eq "…its agent key too, on its own branch" "$(gwm "$PA" pmown "SELECT phone FROM p_people WHERE id = 2")" "XXXXXX3211"
# Refused in step 4; since step 5 it is a masked branch of main (§11am).
assert_eq "an agent branch is never one whose role reads real values: it is made as a masked branch" \
  "$(code "$PM" -X POST https://localhost:8088/agents/pm1/branch)|$($S mask branches --json | hjson "print([b['state'] for b in d if b['name']=='agent-pm1'][0])")" "201|open"
curl -sk -o /dev/null -H "Authorization: Bearer $PM" -X DELETE https://localhost:8088/agents/pm1/branch
$S mask unmask path-analyst@foxbyte.dev --branch pmown --yes >/dev/null 2>&1 || bad "unmask on pmown"
assert_eq "unmask on its branch lifts it there only, its agent key's too" \
  "$(gwm "$PM" pmown "SELECT phone FROM p_people WHERE id = 2")|$(gwm "$PA" pmown "SELECT phone FROM p_people WHERE id = 2")|$(gwm "$PM" main "SELECT phone FROM p_people WHERE id = 2")" "9876543211|9876543211|XXXXXX3211"
# What others make: views over a marked column, grants, foreign keys.
gwm "$PD" main "CREATE VIEW p_summary AS SELECT email, city FROM p_people; CREATE VIEW p_cities AS SELECT id, city FROM p_people;
  CREATE VIEW p_summary2 AS SELECT * FROM p_summary; CREATE MATERIALIZED VIEW p_mv AS SELECT phone FROM p_people" >/dev/null
assert_eq "a view or materialized view over a marked column, made by an ordinary account, is closed to masked accounts; one over unmarked columns is not" \
  "$(gwm "$PM" main "SELECT * FROM p_summary" | grep -c 'permission denied')|$(gwm "$PM" main "SELECT * FROM p_summary2" | grep -c 'permission denied')|$(gwm "$PM" main "SELECT * FROM p_mv" | grep -c 'permission denied')|$(gwm "$PM" main "SELECT city FROM p_cities WHERE id = 1")|$(gwm "$PD" main "SELECT email FROM p_summary WHERE city = 'Pune'")" \
  "1|1|1|Pune|asha.p@example.com"
assert_eq "a grant on a marked table or such a view is taken back; to PUBLIC it is refused, saying why" \
  "$(gwm "$PD" main "GRANT SELECT ON p_people TO db_masked; GRANT SELECT ON p_summary TO \"path-analyst@foxbyte.dev\"" >/dev/null; gwm "$PM" main "SELECT * FROM public.p_people" | grep -c 'permission denied')$(gwm "$PM" main "SELECT * FROM p_summary" | grep -c 'permission denied')|$(gwm "$PD" main "GRANT SELECT ON p_summary TO PUBLIC" | grep -c 'to PUBLIC would give masked accounts')" "11|1"
assert_eq "a foreign key into a marked column: writing that table is refused, it would say which values exist; one into the key is not" \
  "$(gwm "$PM" main "INSERT INTO p_logins (login) VALUES ('guess@example.com')" | grep -c 'permission denied')|$(gwm "$PM" main "INSERT INTO p_notes (person, note) VALUES (1, 'n'); SELECT count(*) FROM p_notes")" "1|1"
assert_eq "mask status lists what it closed, and why" \
  "$($S mask --json | hjson "print(sorted(c['relation']+':'+c['kind'] for c in d['closed']))")|$($S mask | grep -c 'Closed to masked accounts on main')" \
  "['public.p_logins:refs', 'public.p_mv:reads', 'public.p_summary2:reads', 'public.p_summary:reads']|1"
gwm "$PD" main "CREATE FUNCTION p_phone_of(e text) RETURNS text LANGUAGE sql SECURITY DEFINER AS \$\$ SELECT phone FROM p_people WHERE email = e \$\$" >/dev/null
assert_eq "a SECURITY DEFINER function owned by a reader of real values is listed: it can return them" \
  "$($S mask --json | hjson "print([x['function']+'/'+x['owner']+'/'+','.join(x['tables']) for x in d['definers']])")|$($S mask | grep -c 'Definer functions a masked account can run')" \
  "['p_phone_of(text)/db_client/public.p_people']|1"
gwm "$PD" main "REVOKE EXECUTE ON FUNCTION p_phone_of(text) FROM PUBLIC" >/dev/null
assert_eq "…and once EXECUTE is taken from PUBLIC it is not" "$($S mask --json | hjson "print(len(d['definers']))")" "0"
$S mask rule p_people.email --off >/dev/null 2>&1 || bad "taking the email rule off"
assert_eq "a rule taken off opens what it alone closed: the email views and the foreign key, not the phone's" \
  "$(gwm "$PM" main "SELECT email FROM p_summary WHERE city = 'Goa'")|$(gwm "$PM" main "INSERT INTO p_logins (login) VALUES ('ravi.p@example.org'); SELECT count(*) FROM p_logins")|$(gwm "$PM" main "SELECT * FROM p_mv" | grep -c 'permission denied')" "ravi.p@example.org|1|1"
assert_eq "no path above gave the masked account a real phone number" "$(gwm "$PM" main "SELECT count(*) FROM p_people WHERE phone LIKE '%98765 43210'")" "0"
# The guard is the engine's: no definer function as a superuser outside bb.
assert_eq "the hardening report's definer check still passes with the guard in place" \
  "$($S hardening --json 2>/dev/null | hjson "print([c['status'] for c in d['checks'] if c['id']=='roles.definer'][0])")" "pass"
for b in pmown pmpit; do $S branch delete "$b" >/dev/null 2>&1; done
$S mask rule p_people.phone --off >/dev/null 2>&1
$S mask account path-analyst@foxbyte.dev --off --yes >/dev/null 2>&1
assert_eq "every rule off: nothing is left closed" "$($S mask --json | hjson "print(len(d['closed']))")" "0"
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS p_people, p_logins, p_notes, p_late CASCADE; DROP FUNCTION IF EXISTS p_phone_of(text)" >/dev/null
for u in path-dev path-analyst; do $S user delete "$u@foxbyte.dev" >/dev/null 2>&1; done

echo "### 11am. masking: masked branches (F5 Gate 1, step 5)"
# Enterprise: `fox branch create <name> --masked` makes a copy whose marked
# columns hold their masks, closed until it is masked and verified: no real
# value left in its tables, statistics, WAL or Blackbox, and the scan finding
# no masked category where no rule masked it. On an open one nobody is masked.
# On main, set up by §11ai.
for b in mb1c mb1 mb2 mbnone agent-mbag; do $S branch delete "$b" >/dev/null 2>&1; done
curl -sk -o /dev/null -H "$AUTH" -X DELETE https://localhost:8088/agents/mbag/branch
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS b_people, b_orders, b_logins, b_feature CASCADE" >/dev/null
pg pg-main "CREATE TABLE b_people (id bigint PRIMARY KEY, email text, phone text, aadhaar_no text, prefs jsonb, city text);
  INSERT INTO b_people SELECT g, CASE WHEN g = 1 THEN 'asha.b@example.com' ELSE 'person' || g || '@example.org' END,
    CASE WHEN g = 1 THEN '+91 98765 43210' ELSE '98' || lpad(g::text, 8, '0') END, CASE WHEN g = 1 THEN '234567890124' ELSE '456789012341' END,
    jsonb_build_object('contact', jsonb_build_object('mobile', '+91 98765 43210'), 'theme', 'dark'), 'Pune' FROM generate_series(1, 2000) g;
  CREATE TABLE b_orders (id bigint PRIMARY KEY, customer_email text, total int);
  INSERT INTO b_orders SELECT g, CASE WHEN g = 1 THEN 'asha.b@example.com' ELSE 'person' || g || '@example.org' END, g FROM generate_series(1, 2000) g;
  CREATE TABLE b_logins (id bigint PRIMARY KEY, login text);
  INSERT INTO b_logins SELECT g, 'person' || g || '@example.org' FROM generate_series(1, 200) g; ANALYZE" >/dev/null
# A statement whose text holds a real value, as the Blackbox records it.
gwm "$KEY" main "CREATE TABLE b_tmp AS SELECT 1 AS x WHERE 'asha.b@example.com' <> ''" >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS b_tmp" >/dev/null
$S pii scan >/dev/null 2>&1
BJ="$($S pii --json 2>/dev/null)"
bfid() { hjson "print([f['id'] for f in d['findings'] if f['table']=='$1' and f['column']=='$2' and f['path']=='$3'][0])" <<<"$BJ"; }
for at in "b_people email" "b_people phone" "b_people aadhaar_no" "b_orders customer_email"; do $S pii mark "$(bfid $at '')" confirm >/dev/null 2>&1; done
$S pii mark "$(bfid b_people prefs '$.contact.mobile')" confirm >/dev/null 2>&1
for c in b_people.email b_people.phone b_people.aadhaar_no b_orders.customer_email; do $S mask rule "$c" --yes >/dev/null 2>&1 || bad "setting the rule on $c"; done
$S mask rule b_people.prefs --path '$.contact.mobile' --yes >/dev/null 2>&1 || bad "the JSON path's rule"
printf 'password123\n' | $S user create mb-analyst@foxbyte.dev >/dev/null 2>&1
MB="$($S apikey create mb-analyst@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
MBA="$($S apikey create mb-analyst@foxbyte.dev agent --agent 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
$S mask account mb-analyst@foxbyte.dev --yes >/dev/null 2>&1 || bad "masking the analyst"
FORK="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger")"
assert_eq "main's Blackbox holds a statement with a real value in it, as a source's can" \
  "$(pg pg-main "SELECT count(*) > 0 FROM bb.schema_ledger WHERE statement LIKE '%asha.b@%'")" "t"

# The first run: b_logins holds emails no rule masks, so it stays closed.
OUT1="$($S branch create mb1 --masked 2>&1)"; rc=$?
assert_eq "a masked branch whose scan finds a masked category with no rule stays closed, saying where and what to do" \
  "$rc|$(grep -c 'public.b_logins.login holds email with no rule masking it' <<<"$OUT1")|$(grep -c 'reject the finding there as not personal data' <<<"$OUT1")|$($S mask branches --json | hjson "print([b['state'] for b in d if b['name']=='mb1'][0])")" "1|1|1|failed"
[ "$rc" = 1 ] || { echo "--- what it said ---"; tail -15 <<<"$OUT1"; echo "--- end ---"; }
assert_eq "…closed to the Gateway, even an admin, and to the API, which says why; it may be deleted" \
  "$(gwm "$KEY" mb1 "SELECT 1" | grep -c 'was not masked')|$(code "$KEY" https://localhost:8080/api/branches/mb1/schema)|$(as "$KEY" https://localhost:8080/api/branches/mb1/schema | grep -c 'stays closed')|$(curl -sk -H "$AUTH" https://localhost:8080/api/branches | hjson "print([b.get('masked') for b in d if b['name']=='mb1'][0])")" \
  "1|423|1|failed"
$S pii mark "$(bfid b_logins login '')" reject >/dev/null 2>&1
OUT2="$($S branch create mb1 --masked 2>&1)"; rc=$?
assert_eq "the finding rejected on the source, run again: it starts over from the source, is masked, verified and opened" \
  "$rc|$(grep -c 'did not finish: starting again from main' <<<"$OUT2")|$(grep -c 'is masked, verified and open' <<<"$OUT2")|$($S mask branches --json | hjson "b=[x for x in d if x['name']=='mb1'][0]; print(b['state'], b['tables'], b['rows'], b['fork']==$FORK)")" \
  "0|1|1|open 2 4000 True"
[ "$rc" = 0 ] || { echo "--- what it said ---"; tail -15 <<<"$OUT2"; echo "--- end ---"; }
assert_eq "its marked columns hold their masks, for anyone, the superuser included; the rest as it was" \
  "$(pg pg-mb1 "SELECT email ~ '^[0-9a-f]{64}\$', phone, aadhaar_no, prefs->'contact'->>'mobile', prefs->>'theme', city FROM b_people WHERE id = 1")|$(pg pg-mb1 "SELECT count(*) FROM b_people WHERE email = 'asha.b@example.com' OR phone LIKE '%98765 43210'")" \
  "t|XXXXXXXXXXX3210|XXXXXXXX0124|XXXXXXXXXXX3210|dark|Pune|0"
assert_eq "…and joins on the hash, as on main for a masked account" \
  "$(pg pg-mb1 "SELECT count(*) FROM b_people p JOIN b_orders o ON o.customer_email = p.email")" "2000"
MBDIR="$(sudo docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Source}}{{end}}{{end}}' pg-mb1)"
left_mb() { sudo grep -rlaE 'asha\.b@example\.com|98765 43210|234567890124' "$MBDIR/$1" 2>/dev/null | wc -l | tr -d ' '; }
assert_eq "no file of its tables, statistics or WAL holds a real value; its Blackbox none of main's entries" \
  "$(left_mb base)|$(left_mb pg_wal)|$(pg pg-mb1 "SELECT count(*) FROM bb.schema_ledger WHERE id <= $FORK")|$(pg pg-mb1 "SELECT count(*) FROM bb.schema_ledger WHERE statement LIKE '%asha.b@%'")" "0|0|0|0"
[ -n "$MBDIR" ] || bad "the masked branch's data folder was not found"
assert_eq "the masks' machinery is gone and the key never mounted: nothing there can make a mask" \
  "$(pg pg-mb1 "SELECT to_regnamespace('bb_mask') IS NULL, (SELECT count(*) FROM pg_event_trigger WHERE evtname = 'bb_mask_close'), to_regclass('bb.mask_rules') IS NULL")|$(sudo docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' pg-mb1 | grep -c '/run/bb-mask')" "t|0|t|0"
# Made through the API by the masked account itself: it owns it, and reads it.
assert_eq "the API makes one in the background, closed meanwhile: 202, then 423 until it opens" \
  "$(code "$MB" -X POST -H 'Content-Type: application/json' -d '{"name":"mb2","from":"main","masked":true}' https://localhost:8080/api/branches)|$(code "$MB" https://localhost:8080/api/branches/mb2/schema)" "202|423"
for _ in $(seq 1 120); do [ "$(as "$MB" https://localhost:8080/api/masking/branches | hjson "print([b['state'] for b in d if b['name']=='mb2'][0] if any(b['name']=='mb2' for b in d) else '')")" = making ] || break; sleep 2; done
assert_eq "…open: the masked account reads it as it is, masks in its data, not as a masked reader; so does its agent key" \
  "$(as "$MB" https://localhost:8080/api/masking/branches | hjson "print([b['state'] for b in d if b['name']=='mb2'][0])")|$(gwm "$MB" mb2 "SELECT current_user, phone FROM public.b_people WHERE id = 1")|$(gwm "$MBA" mb2 "SELECT phone FROM b_people WHERE id = 1")" \
  "open|db_client|XXXXXXXXXXX3210|XXXXXXXXXXX3210"
assert_eq "…and writes it as any account writes its own branch" \
  "$(gwm "$MB" mb2 "UPDATE b_people SET city = 'Goa' WHERE id = 2; SELECT city FROM b_people WHERE id = 2")" "Goa"
# A change request from it carries only what was done on it.
gwm "$MB" mb2 "CREATE TABLE b_feature (id int PRIMARY KEY)" >/dev/null
RQ="$(as "$MB" -X POST -H 'Content-Type: application/json' -d '{"target":"main"}' https://localhost:8080/api/branches/mb2/request)"
RID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$RQ" 2>/dev/null)"
assert_eq "a change request from a masked branch carries only its own change, nothing of its making" \
  "$(hjson "print([e['command'] for e in d], [e['object'] for e in d])" <<<"$RQ")" "['CREATE TABLE'] ['public.b_feature']"
APR="$(curl -sk -X POST -H "$AUTH" -H 'content-type: application/json' -d '{}' "https://localhost:8080/api/requests/$RID/approve")"
assert_eq "…approved, main has the change and keeps every mask: the masked account still reads masks there" \
  "$(pg pg-main "SELECT to_regclass('public.b_feature') IS NOT NULL")|$(gwm "$MB" main "SELECT phone FROM b_people WHERE id = 1")|$(pg pg-main "SELECT to_regclass('bb_mask.b_people') IS NOT NULL")" "t|XXXXXXXXXXX3210|t"
[ -n "$RID" ] && grep -q '"status":"approved"' <<<"$APR" || { echo "--- request $RID, approval ---"; head -c 600 <<<"$APR"; echo; echo "--- end ---"; }
# A masked account's agent is given a masked branch.
AGR="$(as "$MB" -X POST https://localhost:8088/agents/mbag/branch)"
assert_eq "a masked account's agent branch is made as a masked branch of main" \
  "$(hjson "print(d.get('branch'))" <<<"$AGR")|$($S mask branches --json | hjson "print([b['state'] for b in d if b['name']=='agent-mbag'][0])")|$(pg pg-agent-mbag "SELECT phone FROM b_people WHERE id = 1")" "agent-mbag|open|XXXXXXXXXXX3210"
curl -sk -o /dev/null -H "Authorization: Bearer $MB" -X DELETE https://localhost:8088/agents/mbag/branch
RS="$($S branch reset mb1 2>&1)"
assert_eq "reset makes it again as a masked branch of its source" \
  "$(grep -c 'is masked and verified, and open' <<<"$RS")|$(pg pg-mb1 "SELECT phone FROM b_people WHERE id = 1")" "1|XXXXXXXXXXX3210"
grep -q 'is masked and verified, and open' <<<"$RS" || { echo "--- what it said ---"; tail -8 <<<"$RS"; echo "--- end ---"; }
assert_eq "a copy of a masked branch is one too, at once" \
  "$($S branch create mb1c --from mb1 >/dev/null 2>&1; $S mask branches --json | hjson "b=[x for x in d if x['name']=='mb1c'][0]; print(b['state'], b.get('inherited'))")|$(pg pg-mb1c "SELECT phone FROM b_people WHERE id = 1")" "open True|XXXXXXXXXXX3210"
assert_eq "a masked branch asked of a branch that is not there is refused" \
  "$($S branch create mbnone --masked --from nosuchbranch 2>&1 | grep -ciE 'not found|no branch')|$($S mask branches --json | hjson "print(any(b['name']=='mbnone' for b in d))")" "1|False"
assert_eq "every masked branch made or refused is in the security log" \
  "$($S audit log --limit 400 | grep 'mask.branch' | grep -c 'refused')|$($S audit log --limit 400 | grep 'mask.branch' | grep -c 'opened')" "1|2"
for b in mb1c mb1 mb2; do $S branch delete "$b" >/dev/null 2>&1; done
assert_eq "a deleted masked branch's record goes with it" "$($S mask branches --json | hjson "print(len([b for b in d if b['name'].startswith('mb')]))")" "0"
$S mask account mb-analyst@foxbyte.dev --off --yes >/dev/null 2>&1
for c in b_people.email b_people.phone b_people.aadhaar_no b_orders.customer_email; do $S mask rule "$c" --off >/dev/null 2>&1; done
$S mask rule b_people.prefs --path '$.contact.mobile' --off >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS b_people, b_orders, b_logins, b_feature CASCADE" >/dev/null
$S user delete mb-analyst@foxbyte.dev >/dev/null 2>&1

echo "### 11an. sessions and upkeep (point 12.5)"
# Who is connected to a branch and what each runs; a query cancelled, a
# session ended; a table vacuumed and analysed. The branch's owner and an
# admin see and stop everyone's sessions, anyone else their own; FoxByte's own
# are not ended from here; upkeep is the owner's.
$S branch delete sesown >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS s_orders CASCADE" >/dev/null
pg pg-main "CREATE TABLE s_orders (id int PRIMARY KEY, total int); INSERT INTO s_orders SELECT g, g FROM generate_series(1, 5000) g; DELETE FROM s_orders WHERE id <= 2000" >/dev/null
for u in ses-dev ses-other; do printf 'password123\n' | $S user create "$u@foxbyte.dev" >/dev/null 2>&1; done
SD="$($S apikey create ses-dev@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
SO="$($S apikey create ses-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
spid() { as "$1" "https://localhost:8080/api/branches/${3:-main}/sessions" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(str(s["pid"]) for s in d["sessions"] if sys.argv[1] in s["query"]))' "$2"; }
gwm "$SD" main "SELECT pg_sleep(30) AS sd_sleep" > /tmp/ses-cancel.out 2>&1 & W1=$!
for _ in $(seq 1 40); do [ -n "$(spid "$KEY" sd_sleep)" ] && break; sleep 0.25; done
P1="$(spid "$KEY" sd_sleep)"
assert_eq "an admin sees every client session, with its login and statement; the account sees its own; another account does not see it" \
  "$([ -n "$P1" ] && echo found)|$(as "$KEY" https://localhost:8080/api/branches/main/sessions | hjson "print(d['all'], [s['user'] for s in d['sessions'] if 'sd_sleep' in s['query']])")|$(spid "$SD" sd_sleep)|$(as "$SO" https://localhost:8080/api/branches/main/sessions | hjson "print(d['all'], sum('sd_sleep' in s['query'] for s in d['sessions']))")" \
  "found|True ['ses-dev@foxbyte.dev']|$P1|False 0"
assert_eq "another account may not cancel it, and is not told whose it is" \
  "$(code "$SO" -X POST "https://localhost:8080/api/branches/main/sessions/$P1/cancel")|$(as "$SO" -X POST "https://localhost:8080/api/branches/main/sessions/$P1/cancel" | grep -c 'no session')" "404|1"
assert_eq "an admin cancels its query: the client is told, the session was not the admin's" \
  "$(code "$KEY" -X POST "https://localhost:8080/api/branches/main/sessions/$P1/cancel")" "200"
wait "$W1"
assert_eq "…and the client's statement ended, cancelled" "$(grep -c 'canceling statement due to user request' /tmp/ses-cancel.out)" "1"
gwm "$SD" main "SELECT pg_sleep(30) AS sd_own" > /tmp/ses-own.out 2>&1 & W2=$!
for _ in $(seq 1 40); do [ -n "$(spid "$SD" sd_own)" ] && break; sleep 0.25; done
assert_eq "the account cancels its own" \
  "$(code "$SD" -X POST "https://localhost:8080/api/branches/main/sessions/$(spid "$SD" sd_own)/cancel")" "200"
wait "$W2"
gwm "$SD" main "SELECT pg_sleep(30) AS sd_end" > /tmp/ses-end.out 2>&1 & W3=$!
for _ in $(seq 1 40); do [ -n "$(spid "$KEY" sd_end)" ] && break; sleep 0.25; done
P3="$(spid "$KEY" sd_end)"
PRE="$($S sessions end "$P3" 2>&1)"
assert_eq "fox sessions lists it; ending it without --yes says what it ends and ends nothing" \
  "$($S sessions | grep -c "^$P3 .*ses-dev@foxbyte.dev.*sd_end")|$(grep -c 'Run again with --yes' <<<"$PRE")|$(spid "$KEY" sd_end)" "1|1|$P3"
assert_eq "…with --yes the session is ended: the client sees its connection closed" \
  "$($S sessions end "$P3" --yes 2>&1 | grep -c "Ended session $P3")" "1"
wait "$W3"
assert_eq "…and was told by whom" "$(grep -cE 'terminating connection due to administrator command|server closed the connection' /tmp/ses-end.out)" "1"
sudo docker exec -e PGPASSWORD=foxbyte pg-main psql -U dbadmin -d appdb -c "SELECT pg_sleep(20) AS engine_own" >/dev/null 2>&1 & W4=$!
for _ in $(seq 1 40); do [ -n "$(spid "$KEY" engine_own)" ] && break; sleep 0.25; done
PE="$(spid "$KEY" engine_own)"
assert_eq "FoxByte's own session is listed as its own and not ended from here" \
  "$(as "$KEY" https://localhost:8080/api/branches/main/sessions | hjson "print([s['engine'] for s in d['sessions'] if 'engine_own' in s['query']])")|$(code "$KEY" -X POST "https://localhost:8080/api/branches/main/sessions/$PE/end")|$($S sessions end "$PE" --yes 2>&1 | grep -c "own, and is not ended from here")" "[True]|400|1"
sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "SELECT pg_cancel_backend($PE)" >/dev/null 2>&1; wait "$W4"
assert_eq "a session that is not there is 404; a pid that is not a number, 400" \
  "$(code "$KEY" -X POST https://localhost:8080/api/branches/main/sessions/999999/cancel)|$(code "$KEY" -X POST https://localhost:8080/api/branches/main/sessions/abc/cancel)" "404|400"
assert_eq "every cancel and end is in the security log, under who did it" \
  "$($S audit log --limit 300 | grep 'session.cancel' | grep -c 'ses-dev')|$($S audit log --limit 300 | grep 'session.end' | grep -c 'ses-dev')" "2|1"
# Upkeep.
MO="$($S maintain vacuum-analyze s_orders 2>&1)"
assert_eq "fox maintain vacuums and analyses a table, and says what it found" \
  "$(grep -c 'vacuum-analyze of public.s_orders on main done' <<<"$MO")|$($S maintain --table s_orders --json | hjson "t=d[0]; print(t['lastVacuum'] != '', t['lastAnalyze'] != '', t['vacuums'] >= 1, t['dead'])")" "1|True True True 0"
assert_eq "…its list shows every table's upkeep, the engine's own left out" \
  "$($S maintain | grep -c '^public.s_orders ')|$($S maintain --json | hjson "print(any(t['schema'] in ('bb', 'bb_mask') for t in d))")" "1|False"
assert_eq "upkeep is read by anyone who may use the branch; run by its owner or an admin" \
  "$(code "$SD" 'https://localhost:8080/api/branches/main/maintenance?table=s_orders')|$(code "$SD" -X POST -H 'Content-Type: application/json' -d '{"table":"s_orders","op":"analyze"}' https://localhost:8080/api/branches/main/maintenance)|$(as "$KEY" -X POST -H 'Content-Type: application/json' -d '{"table":"s_orders","op":"analyze"}' https://localhost:8080/api/branches/main/maintenance | hjson "print(d['op'], d['table']['table'], d['table']['lastAnalyze'] != '')")" \
  "200|403|analyze s_orders True"
assert_eq "VACUUM FULL is not offered; a table that is not there is 404" \
  "$(code "$KEY" -X POST -H 'Content-Type: application/json' -d '{"table":"s_orders","op":"vacuum full"}' https://localhost:8080/api/branches/main/maintenance)|$(code "$KEY" -X POST -H 'Content-Type: application/json' -d '{"table":"no_such","op":"vacuum"}' https://localhost:8080/api/branches/main/maintenance)" "400|404"
code "$SD" -X POST -H 'Content-Type: application/json' -d '{"name":"sesown","from":"main"}' https://localhost:8080/api/branches >/dev/null
gwm "$SO" main "SELECT 1" >/dev/null
assert_eq "on a branch it owns, the account runs upkeep and sees every session there" \
  "$(code "$SD" -X POST -H 'Content-Type: application/json' -d '{"table":"s_orders","op":"vacuum"}' https://localhost:8080/api/branches/sesown/maintenance)|$(as "$SD" https://localhost:8080/api/branches/sesown/sessions | hjson "print(d['all'])")" "200|True"
assert_eq "each upkeep run is in the security log" "$($S audit log --limit 300 | grep -cE '(vacuum|analyze|vacuum-analyze) of public.s_orders')" "3"
$S branch delete sesown >/dev/null 2>&1
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS s_orders CASCADE" >/dev/null
for u in ses-dev ses-other; do $S user delete "$u@foxbyte.dev" >/dev/null 2>&1; done
rm -f /tmp/ses-cancel.out /tmp/ses-own.out /tmp/ses-end.out

echo "### 11ao. run, toggle and plan (point 12.4)"
# The console's Run form, trigger switches and Explain are SQL the person
# runs, so what is checked here is what the engine gives the form (each
# argument of a function and a procedure) and that what the form writes runs
# as written; the console's own behaviour is runplan.spec.ts.
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS r_items CASCADE; DROP FUNCTION IF EXISTS r_add(integer, integer), r_series(integer), r_none(), r_sum(VARIADIC integer[]); DROP PROCEDURE IF EXISTS r_bump(integer, integer, text)" >/dev/null
pg pg-main "CREATE FUNCTION r_add(a integer, b integer DEFAULT 10) RETURNS integer LANGUAGE sql AS \$\$ SELECT a + b \$\$;
  CREATE FUNCTION r_series(n integer) RETURNS TABLE(i integer, sq integer) LANGUAGE sql AS \$\$ SELECT g, g * g FROM generate_series(1, n) g \$\$;
  CREATE FUNCTION r_none() RETURNS text LANGUAGE sql AS \$\$ SELECT 'none' \$\$;
  CREATE FUNCTION r_sum(VARIADIC xs integer[]) RETURNS integer LANGUAGE sql AS \$\$ SELECT sum(x)::int FROM unnest(xs) x \$\$;
  CREATE PROCEDURE r_bump(IN a integer, INOUT b integer, OUT note text) LANGUAGE plpgsql AS \$\$ BEGIN b := a + b; note := 'bumped'; END \$\$" >/dev/null
rq() { curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST -d "$(python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1]}))' "$1")" https://localhost:8080/api/branches/main/query; }
# Made through the console as the admin, so its role owns the table, as a
# person owns what they make: only an owner switches a table's triggers.
rq 'CREATE TABLE r_items (id int PRIMARY KEY, v text);
  CREATE FUNCTION r_upper() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.v := upper(NEW.v); RETURN NEW; END $$;
  CREATE TRIGGER r_items_up BEFORE INSERT ON r_items FOR EACH ROW EXECUTE FUNCTION r_upper()' >/dev/null
CAT="$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/main/schema)"
roid() { hjson "print([o['oid'] for o in d['objects'] if o['name']=='$1' and o['kind']=='$2'][0])" <<<"$CAT"; }
params() { curl -sk -H "$AUTH" "https://localhost:8080/api/branches/main/schema/$2/$(roid "$1" "$2")" | hjson "print([(p.get('name',''), p['type'], p['mode'], p.get('default', False)) for p in d.get('params', [])])"; }
assert_eq "a function's arguments, each with its name, type, mode and whether it has a default" \
  "$(params r_add function)" "[('a', 'integer', 'in', False), ('b', 'integer', 'in', True)]"
assert_eq "…a set-returning one's TABLE columns, one without arguments, a variadic one" \
  "$(params r_series function)|$(params r_none function)|$(params r_sum function)" \
  "[('n', 'integer', 'in', False), ('i', 'integer', 'table', False), ('sq', 'integer', 'table', False)]|[]|[('xs', 'integer[]', 'variadic', False)]"
assert_eq "…and a procedure's IN, INOUT and OUT" \
  "$(params r_bump procedure)" "[('a', 'integer', 'in', False), ('b', 'integer', 'inout', False), ('note', 'text', 'out', False)]"
rows() { python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("results",[d])[-1]; print(r.get("error") or ";".join(",".join(str(c) for c in row) for row in r.get("rows") or []))'; }
assert_eq "what the Run form writes runs: named, a default left out, a NULL of its type" \
  "$(rq "SELECT * FROM \"public\".\"r_add\"(\"a\" => CAST('5' AS integer))" | rows)|$(rq "SELECT * FROM \"public\".\"r_add\"(\"a\" => CAST('5' AS integer), \"b\" => NULL::integer)" | rows)" "15|None"
assert_eq "…a set-returning function's rows, a variadic one, and a procedure's INOUT and OUT values" \
  "$(rq "SELECT * FROM \"public\".\"r_series\"(\"n\" => CAST('3' AS integer))" | rows)|$(rq "SELECT * FROM \"public\".\"r_sum\"(VARIADIC \"xs\" => CAST('{1,2,3}' AS integer[]))" | rows)|$(rq "CALL \"public\".\"r_bump\"(\"a\" => CAST('2' AS integer), \"b\" => CAST('3' AS integer), \"note\" => NULL)" | rows)" \
  "1,1;2,4;3,9|6|5,bumped"
# A trigger switched off and on, as the Triggers tab does.
toid="$(roid r_items table)"
trg() { curl -sk -H "$AUTH" "https://localhost:8080/api/branches/main/schema/table/$toid" | hjson "print([(t['name'], t.get('disabled', False), t.get('system', False)) for t in d.get('triggers', []) if not t.get('system')])"; }
rq 'ALTER TABLE "public"."r_items" DISABLE TRIGGER "r_items_up"' >/dev/null
assert_eq "a trigger disabled as the Triggers tab disables it: the catalog says so, and it no longer fires" \
  "$(trg)|$(rq "INSERT INTO r_items VALUES (1, 'quiet'); SELECT v FROM r_items WHERE id = 1" | rows)" "[('r_items_up', True, False)]|quiet"
rq 'ALTER TABLE "public"."r_items" ENABLE TRIGGER "r_items_up"' >/dev/null
assert_eq "…enabled again, it fires; both changes are in the Blackbox" \
  "$(trg)|$(rq "INSERT INTO r_items VALUES (2, 'loud'); SELECT v FROM r_items WHERE id = 2" | rows)|$(pg pg-main "SELECT count(*) FROM bb.schema_ledger WHERE statement ~ 'r_items.*(DISABLE|ENABLE) TRIGGER'")" "[('r_items_up', False, False)]|LOUD|2"
$S track r_items >/dev/null 2>&1
assert_eq "FoxByte's own trigger on a tracked table is marked its own, which the tab does not switch" \
  "$(curl -sk -H "$AUTH" "https://localhost:8080/api/branches/main/schema/table/$toid" | hjson "print(any(t.get('system') for t in d.get('triggers', [])), [t['name'] for t in d.get('triggers', []) if not t.get('system')])")" "True ['r_items_up']"
$S track r_items --off >/dev/null 2>&1
# Explain, as the console sends it.
EX="$(rq 'EXPLAIN (FORMAT JSON) SELECT * FROM r_items WHERE id = 1')"
assert_eq "a jsonb array of objects comes back as JSON whole, not each object as text of its own" \
  "$(rq "SELECT '[{\"a\": 1}, {\"b\": [2]}]'::jsonb AS j" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("results",[d])[-1]; print(json.loads(r["rows"][0][0]))')" "[{'a': 1}, {'b': [2]}]"
assert_eq "Explain returns the plan as JSON, which the console reads into a table" \
  "$(python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("results",[d])[-1]; v=r["rows"][0][0]; doc=json.loads(v) if isinstance(v, str) else v; p=doc[0]["Plan"]; print(r["columns"], p["Node Type"] in ("Index Scan", "Seq Scan", "Bitmap Heap Scan"), p.get("Relation Name"))' <<<"$EX")" "['QUERY PLAN'] True r_items"
EXA="$(rq "BEGIN;
EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS) DELETE FROM r_items;
ROLLBACK;")"
assert_eq "…with Analyse it runs, measured, inside a transaction rolled back: nothing deleted" \
  "$(python3 -c 'import json,sys; d=json.load(sys.stdin); r=[x for x in d["results"] if x.get("columns")==["QUERY PLAN"]][0]; v=r["rows"][0][0]; doc=json.loads(v) if isinstance(v, str) else v; p=doc[0]; print(p["Plan"]["Node Type"], p["Plan"]["Actual Rows"], "Execution Time" in p)' <<<"$EXA")|$(pg pg-main "SELECT count(*) FROM r_items")" "ModifyTable 0 True|2"
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS r_items CASCADE; DROP FUNCTION IF EXISTS r_add(integer, integer), r_series(integer), r_none(), r_sum(VARIADIC integer[]), r_upper(); DROP PROCEDURE IF EXISTS r_bump(integer, integer, text)" >/dev/null

echo "### 11ap. create and edit dialogs for functions and triggers (point 12.3)"
# The dialogs write SQL the person runs, so what is checked here is what the
# engine gives an edit dialog, and that what the dialogs write runs and keeps
# what it was not asked to change; the dialogs themselves are routines.spec.ts.
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS rd_items CASCADE; DROP FUNCTION IF EXISTS rd_full(integer), rd_atomic(), rd_full2(integer), rd_tf(); DROP PROCEDURE IF EXISTS rd_proc(integer)" >/dev/null
printf 'password123\n' | $S user create dlg-other@foxbyte.dev >/dev/null 2>&1
DO="$($S apikey create dlg-other@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
rd() { curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST -d "$(python3 -c 'import json,sys; print(json.dumps({"sql": sys.argv[1]}))' "$1")" https://localhost:8080/api/branches/main/query; }
rderr() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("error") or next((r["error"] for r in d.get("results",[]) if r.get("error")), ""))'; }
assert_eq "what the New dialog writes makes the function, the procedure and the trigger function" \
  "$(rd 'CREATE FUNCTION "public"."rd_full"(a integer DEFAULT 1)
 RETURNS integer
 LANGUAGE sql
 STABLE
 STRICT
 SECURITY DEFINER
 COST 50
 SET search_path TO '"'"'public'"'"', '"'"'pg_temp'"'"'
AS $body$
SELECT a
$body$' | rderr)|$(rd 'CREATE PROCEDURE "public"."rd_proc"(a integer)
 LANGUAGE plpgsql
AS $body$
BEGIN NULL; END;
$body$' | rderr)|$(rd 'CREATE FUNCTION "public"."rd_tf"()
 RETURNS trigger
 LANGUAGE plpgsql
AS $body$
BEGIN RETURN NEW; END;
$body$' | rderr)" "||"
rd 'CREATE FUNCTION rd_atomic() RETURNS integer BEGIN ATOMIC SELECT 1; END' >/dev/null
RCAT="$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/main/schema)"
rdoid() { hjson "print([o['oid'] for o in d['objects'] if o['name']=='$1' and o['kind']=='$2'][0])" <<<"$RCAT"; }
rout() { curl -sk -H "$AUTH" "https://localhost:8080/api/branches/main/schema/$2/$(rdoid "$1" "$2")"; }
assert_eq "an edit dialog is given everything: arguments, identity, returns, language, body, and each attribute" \
  "$(rout rd_full function | hjson "r=d['routine']; print(r['arguments'], '/', r['identity'], '/', r['returns'], r['language'], r['body'].strip(), r['volatility'], r.get('strict'), r.get('definer'), r['cost'], r['set'])")" \
  "a integer DEFAULT 1 / a integer / integer sql SELECT a stable True True 50 [\"SET search_path TO 'public', 'pg_temp'\"]"
assert_eq "…a trigger function is told apart in the list; BEGIN ATOMIC is said to have no body to edit" \
  "$(hjson "print([o.get('sub') for o in d['objects'] if o['name']=='rd_tf'][0])" <<<"$RCAT")|$(rout rd_tf function | hjson "print(d['routine'].get('trigger'))")|$(rout rd_atomic function | hjson "print(d['routine'].get('atomic'))")" "trigger|True|True"
assert_eq "what the Edit dialog writes changes the body and keeps every attribute" \
  "$(rd 'CREATE OR REPLACE FUNCTION "public"."rd_full"(a integer DEFAULT 1)
 RETURNS integer
 LANGUAGE sql
 STABLE
 STRICT
 SECURITY DEFINER
 COST 50
 SET search_path TO '"'"'public'"'"', '"'"'pg_temp'"'"'
AS $body$
SELECT a + 1
$body$' | rderr)|$(rout rd_full function | hjson "r=d['routine']; print(r['body'].strip(), r.get('definer'), r['cost'], len(r['set']))")" "|SELECT a + 1 True 50 1"
# log_ddl_drop does not record a procedure's or a trigger's drop; the catalog
# scan does, as OBSERVED, so one is run before the drop and one after. It names
# what it drops as it last saw it, so a trigger renamed between scans keeps its old name.
$S ledger scan main >/dev/null 2>&1
assert_eq "rename and drop, as written; each in the Blackbox, the procedure's drop by the catalog scan" \
  "$(rd 'ALTER FUNCTION "public"."rd_full"(a integer) RENAME TO "rd_full2"' | rderr)|$(pg pg-main "SELECT to_regproc('rd_full2') IS NOT NULL, to_regproc('rd_full') IS NULL")|$(rd 'DROP PROCEDURE "public"."rd_proc"(a integer)' | rderr)|$($S ledger scan main >/dev/null 2>&1; pg pg-main "SELECT to_regproc('rd_proc') IS NULL, (SELECT count(*) FROM bb.schema_ledger WHERE object_identity LIKE '%rd_full%' AND command_tag = 'ALTER FUNCTION'), (SELECT count(*) FROM bb.schema_ledger WHERE object_identity = 'public.rd_proc(integer)' AND command_tag = 'DROP PROCEDURE' AND status = 'OBSERVED')")" \
  "|t|t||t|1|1"
# Accounts reach a branch through one database role, so what any of them made
# is that role's; what it does not own, Postgres refuses, from a dialog as anywhere.
pg pg-main "CREATE OR REPLACE FUNCTION rd_admin(a integer) RETURNS integer LANGUAGE sql AS 'SELECT a'" >/dev/null
assert_eq "a dialog cannot change what the account's database role does not own" \
  "$(curl -sk -H "Authorization: Bearer $DO" -H 'Content-Type: application/json' -X POST -d '{"sql":"DROP FUNCTION \"public\".\"rd_admin\"(a integer)"}' https://localhost:8080/api/branches/main/query | rderr | grep -c 'must be owner')|$(pg pg-main "SELECT to_regproc('rd_admin') IS NOT NULL")" "1|t"
# Triggers.
rd 'CREATE TABLE rd_items (id int PRIMARY KEY, v text, w int)' >/dev/null
assert_eq "what the New trigger dialog writes makes it, UPDATE OF, a condition and arguments included" \
  "$(rd 'CREATE TRIGGER "rd_t" BEFORE INSERT OR UPDATE OF "v", "w" ON "public"."rd_items"
 FOR EACH ROW
 WHEN (new.w > 0)
 EXECUTE FUNCTION "public"."rd_tf"('"'"'a'"'"', '"'"'b'"'"')' | rderr)" ""
RCAT="$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/main/schema)"
trinfo() { rout rd_items table | hjson "t=[x for x in d['triggers'] if not x.get('system')]; print([(x['name'], x['trigger']['timing'], x['trigger']['events'], x['trigger'].get('columns'), x['trigger']['forEach'], x['trigger'].get('when'), x['trigger']['function'], x['trigger'].get('args'), x.get('disabled', False)) for x in t])"; }
assert_eq "an edit dialog is given each part of a trigger" \
  "$(trinfo)" "[('rd_t', 'BEFORE', ['INSERT', 'UPDATE'], ['v', 'w'], 'ROW', 'new.w > 0', 'public.rd_tf', \"'a', 'b'\", False)]"
rd 'ALTER TABLE "public"."rd_items" DISABLE TRIGGER "rd_t"' >/dev/null
assert_eq "what the Edit dialog writes replaces it, and one that was disabled stays so" \
  "$(rd 'CREATE OR REPLACE TRIGGER "rd_t" AFTER UPDATE ON "public"."rd_items"
 FOR EACH ROW
 EXECUTE FUNCTION "public"."rd_tf"();
ALTER TABLE "public"."rd_items" DISABLE TRIGGER "rd_t"' | rderr)|$(trinfo)" "|[('rd_t', 'AFTER', ['UPDATE'], None, 'ROW', None, 'public.rd_tf', None, True)]"
$S ledger scan main >/dev/null 2>&1
assert_eq "a trigger renamed and dropped, as written; the drop in the Blackbox by the catalog scan" \
  "$(rd 'ALTER TRIGGER "rd_t" ON "public"."rd_items" RENAME TO "rd_t2"' | rderr)|$(trinfo | grep -c rd_t2)|$(rd 'DROP TRIGGER "rd_t2" ON "public"."rd_items"' | rderr)|$(trinfo)|$($S ledger scan main >/dev/null 2>&1; pg pg-main "SELECT count(*) FROM bb.schema_ledger WHERE object_identity LIKE 'rd_t% on public.rd_items' AND command_tag = 'DROP TRIGGER' AND status = 'OBSERVED'")" "|1||[]|1"
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS rd_items CASCADE; DROP FUNCTION IF EXISTS rd_full2(integer), rd_atomic(), rd_tf(), rd_admin(integer)" >/dev/null
$S user delete dlg-other@foxbyte.dev >/dev/null 2>&1

echo "### 11aq. create and edit dialogs for tables, columns and keys (point 12.3)"
# As in 11ap: what the dialogs write is run here and what the engine gives an
# edit dialog is checked; the dialogs themselves are tables.spec.ts.
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS kt_child, kt_parent, kt_ex, kt_renamed, kt_inc CASCADE" >/dev/null
assert_eq "what the New table dialog writes makes it: columns, not null, a default and a primary key of two" \
  "$(rd 'CREATE TABLE "public"."kt_parent" (
  "id" integer,
  "sub" integer,
  "label" text NOT NULL DEFAULT '"'"'x'"'"',
  PRIMARY KEY ("id", "sub")
)' | rderr)|$(pg pg-main "SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid = 'kt_parent'::regclass AND attnum > 0")|$(pg pg-main "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'kt_parent'::regclass AND contype = 'p'")" \
  "|id,sub,label|PRIMARY KEY (id, sub)"
rd 'CREATE TABLE "public"."kt_child" (id bigserial PRIMARY KEY, pid integer, psub integer, qty integer DEFAULT 1, note text)' >/dev/null
pg pg-main "INSERT INTO kt_parent VALUES (1, 1, 'a')" >/dev/null
pg pg-main "INSERT INTO kt_child (pid, psub, qty) VALUES (1, 1, 5)" >/dev/null
kcat() { RCAT="$(curl -sk -H "$AUTH" https://localhost:8080/api/branches/main/schema)"; }
kcat
assert_eq "what the Add column dialog writes adds it" \
  "$(rd 'ALTER TABLE "public"."kt_child" ADD COLUMN "extra" text NOT NULL DEFAULT '"'"'y'"'"'' | rderr)|$(pg pg-main "SELECT extra FROM kt_child")" "|y"
assert_eq "what the Edit column dialog writes changes the type with its conversion, not null, the default and the name, together" \
  "$(rd 'ALTER TABLE "public"."kt_child"
  ALTER COLUMN "qty" TYPE text USING qty::text || '"'"'!'"'"',
  ALTER COLUMN "qty" SET NOT NULL,
  ALTER COLUMN "qty" SET DEFAULT '"'"'0'"'"';
ALTER TABLE "public"."kt_child" RENAME COLUMN "qty" TO "amount"' | rderr)|$(pg pg-main "SELECT amount FROM kt_child")|$(rout kt_child table | hjson "c=[x for x in d['columns'] if x['name']=='amount'][0]; print(c['type'], c.get('not_null'), c['default'])")" \
  "|5!|text True '0'::text"
assert_contains "…and a rename that cannot be done leaves the rest undone" \
  "$(rd 'ALTER TABLE "public"."kt_child" ALTER COLUMN "note" SET DEFAULT '"'"'n'"'"';
ALTER TABLE "public"."kt_child" RENAME COLUMN "note" TO "amount"' | rderr)" "already exists"
assert_eq "…the column's default not applied" "$(pg pg-main "SELECT atthasdef FROM pg_attribute WHERE attrelid = 'kt_child'::regclass AND attname = 'note'")" "f"
assert_eq "a column dropped, as written, in the Blackbox as an ALTER TABLE" \
  "$(rd 'ALTER TABLE "public"."kt_child" DROP COLUMN "extra"' | rderr)|$(pg pg-main "SELECT count(*) FROM pg_attribute WHERE attrelid = 'kt_child'::regclass AND attname = 'extra' AND NOT attisdropped")|$(pg pg-main "SELECT count(*) > 0 FROM bb.schema_ledger WHERE command_tag = 'ALTER TABLE' AND statement LIKE '%kt_child%DROP COLUMN%'")" "|0|t"
assert_eq "what the Add key dialog writes: unique, named or left to Postgres, foreign and check" \
  "$(rd 'ALTER TABLE "public"."kt_child"
  ADD CONSTRAINT "kt_note_u" UNIQUE ("note") DEFERRABLE INITIALLY DEFERRED' | rderr)|$(rd 'ALTER TABLE "public"."kt_child"
  ADD UNIQUE ("psub", "pid")' | rderr)|$(rd 'ALTER TABLE "public"."kt_child"
  ADD CONSTRAINT "kt_fk" FOREIGN KEY ("pid", "psub") REFERENCES "public"."kt_parent" ("id", "sub") ON UPDATE RESTRICT ON DELETE CASCADE' | rderr)|$(rd 'ALTER TABLE "public"."kt_child"
  ADD CONSTRAINT "kt_ck" CHECK (id > 0)' | rderr)|$(pg pg-main "SELECT string_agg(conname, ',' ORDER BY conname) FROM pg_constraint WHERE conrelid = 'kt_child'::regclass AND contype <> 'n'")" \
  "||||kt_child_pkey,kt_child_psub_pid_key,kt_ck,kt_fk,kt_note_u"
kparts() { rout kt_child table | hjson "print({x['name']: (x['key']['type'], x['key'].get('columns'), x['key'].get('refSchema'), x['key'].get('refTable'), x['key'].get('refColumns'), x['key'].get('onDelete'), x['key'].get('onUpdate'), x['key'].get('deferrable'), x['key'].get('deferred'), x['key'].get('check'), x['key'].get('editable')) for x in d['constraints']}['$1'])"; }
assert_eq "an edit dialog is given a foreign key, part by part, its columns in the key's order" \
  "$(kparts kt_fk)" "('foreign', ['pid', 'psub'], 'public', 'kt_parent', ['id', 'sub'], 'CASCADE', 'RESTRICT', None, None, None, True)"
assert_eq "…a unique key, deferred, and in the order it was written" \
  "$(kparts kt_note_u)|$(kparts kt_child_psub_pid_key)" "('unique', ['note'], None, None, None, None, None, True, True, None, True)|('unique', ['psub', 'pid'], None, None, None, None, None, None, None, None, True)"
assert_eq "…a primary key and a check" \
  "$(kparts kt_child_pkey)|$(kparts kt_ck)" "('primary', ['id'], None, None, None, None, None, None, None, None, True)|('check', ['id'], None, None, None, None, None, None, None, 'id > 0', True)"
assert_eq "what the Edit key dialog writes replaces it in one statement, under its name" \
  "$(rd 'ALTER TABLE "public"."kt_child"
  DROP CONSTRAINT "kt_fk",
  ADD CONSTRAINT "kt_fk" FOREIGN KEY ("pid", "psub") REFERENCES "public"."kt_parent" ("id", "sub") ON DELETE SET NULL' | rderr)|$(kparts kt_fk)" \
  "|('foreign', ['pid', 'psub'], 'public', 'kt_parent', ['id', 'sub'], 'SET NULL', None, None, None, None, True)"
assert_contains "…one that fails keeps the key as it was" \
  "$(rd 'ALTER TABLE "public"."kt_child"
  DROP CONSTRAINT "kt_ck",
  ADD CONSTRAINT "kt_ck" CHECK (id < 0)' | rderr)" "violated by some row"
assert_eq "…the check still there" "$(kparts kt_ck)" "('check', ['id'], None, None, None, None, None, None, None, 'id > 0', True)"
assert_eq "a primary key replaced under its name, a new order of its columns" \
  "$(rd 'ALTER TABLE "public"."kt_child"
  DROP CONSTRAINT "kt_child_pkey",
  ADD CONSTRAINT "kt_child_pkey" PRIMARY KEY ("pid", "id")' | rderr)|$(pg pg-main "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'kt_child_pkey'")" "|PRIMARY KEY (pid, id)"
assert_contains "…one another table depends on is refused, and Postgres says why" \
  "$(rd 'ALTER TABLE "public"."kt_parent"
  DROP CONSTRAINT "kt_parent_pkey",
  ADD CONSTRAINT "kt_parent_pkey" PRIMARY KEY ("sub", "id")' | rderr)" "depend on it"
rd 'CREATE TABLE "public"."kt_ex" (id int, r int4range, b int, CONSTRAINT kt_ex_x EXCLUDE USING gist (r WITH &&), CONSTRAINT kt_ex_u UNIQUE (id) INCLUDE (b))' >/dev/null
kcat
assert_eq "what the key dialog cannot write again is not offered as an edit: an exclusion, and a key with INCLUDE" \
  "$(rout kt_ex table | hjson "print(sorted((x['name'], x['key']['type'], bool(x['key'].get('editable'))) for x in d['constraints']))")" "[('kt_ex_u', 'unique', False), ('kt_ex_x', 'exclusion', False)]"
assert_eq "a key renamed and dropped, as written" \
  "$(rd 'ALTER TABLE "public"."kt_child" RENAME CONSTRAINT "kt_ck" TO "kt_ck2"' | rderr)|$(rd 'ALTER TABLE "public"."kt_child" DROP CONSTRAINT "kt_ck2"' | rderr)|$(pg pg-main "SELECT count(*) FROM pg_constraint WHERE conrelid = 'kt_child'::regclass AND conname LIKE 'kt_ck%'")" "||0"
assert_eq "a table renamed, as written" \
  "$(rd 'ALTER TABLE "public"."kt_ex" RENAME TO "kt_renamed"' | rderr)|$(pg pg-main "SELECT to_regclass('kt_ex') IS NULL, to_regclass('kt_renamed') IS NOT NULL")" "|t|t"
assert_contains "DROP TABLE from its dialog meets the guardrail, as it does anywhere" \
  "$(rd 'DROP TABLE "public"."kt_renamed"' | rderr)" "guardrail: DROP TABLE is blocked by policy"
assert_eq "…and the table is still there; with the override, as the editor asks for it, it goes" \
  "$(pg pg-main "SELECT to_regclass('kt_renamed') IS NOT NULL")|$(curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST -d '{"sql":"DROP TABLE \"public\".\"kt_renamed\"","allow_destructive":true}' https://localhost:8080/api/branches/main/query | rderr)|$(pg pg-main "SELECT to_regclass('kt_renamed') IS NULL")" "t||t"
pg pg-main "SET bb.allow_destructive = on; DROP TABLE IF EXISTS kt_child, kt_parent, kt_ex, kt_renamed CASCADE" >/dev/null

echo "### 11ar. the Aadhaar exposure report: whose Aadhaar is exposed, where, and since when (point 4.5)"
# Synthetic numbers only, the same as 11r's: 234567890124, 345678901238 and
# 456789012341 pass Verhoeff. 4111 1111 1111 1111 is the usual test card, a
# sixteen-digit number that must not be read as an Aadhaar.
$S branch delete aadt >/dev/null 2>&1
$S branch create aadt >/dev/null 2>&1
pg pg-aadt "CREATE TABLE customers (id int PRIMARY KEY, name text, aadhaar text);
  INSERT INTO customers VALUES (1, 'A Person', '2345 6789 0124'), (2, 'B Person', '456789012341'), (3, 'C Person', NULL);
  -- created_at already there, so tracking it (below) keeps when each row was made.
  CREATE TABLE tickets (id int PRIMARY KEY, notes text, created_at timestamptz);
  INSERT INTO tickets VALUES
    (9, 'customer read out 234567890124 on the call', '2026-01-15 10:00+00'),
    (10, 'card 4111 1111 1111 1111, phone +91 98765 43210', '2026-01-16 10:00+00'),
    (12, 'again: 4567-8901-2341', '2026-02-01 10:00+00');
  CREATE TABLE orders (id bigint PRIMARY KEY, meta jsonb);
  INSERT INTO orders VALUES (1, '{\"kyc\": {\"uid\": 345678901238}, \"status\": \"open\"}'), (2, '{\"by\": {\"456789012341\": \"seen\"}}');
  CREATE TABLE nokey (note text);
  INSERT INTO nokey VALUES ('345678901238'), ('nothing here');" >/dev/null
$S track tickets --branch aadt >/dev/null 2>&1
LEDGER_BEFORE="$(pg pg-aadt "SELECT count(*) FROM bb.schema_ledger")"
RUNS_LOGGED="$($S audit --limit 1000 | grep -c 'personal-data.aadhaar')"
AR="$($S pii aadhaar run --branch aadt 2>&1)"; AR_RC=$?
assert_eq "fox pii aadhaar run reads every table and exits 0" \
  "$AR_RC|$(grep -c '^Aadhaar exposure on aadt: run [0-9]*' <<<"$AR")|$(grep -c '^[0-9]* table(s), [0-9]* column(s) read; [0-9]* row(s) held twelve digits in its shape. 7 number(s) found, 3 distinct; 7 place(s) kept.' <<<"$AR")" "0|1|1"
# The branch is made from main, so main's tables are read too: the counts of
# tables and rows are main's as well, and only what was found is pinned.
grep -q ' 7 number(s) found, 3 distinct; 7 place(s) kept.' <<<"$AR" || { echo "--- what it said ---"; head -12 <<<"$AR"; echo "--- end ---"; }
AJ="$($S pii aadhaar --branch aadt --json 2>/dev/null)"
assert_eq "…finds each number by column, inside JSON path by path, a key holding one hidden as *; not a card or a phone" \
  "$(hjson "print(' '.join(sorted(c['schema']+'.'+c['table']+'.'+c['column']+(' '+c['path'] if c['path'] else '')+':'+str(c['numbers']) for c in d['columns'])))" <<<"$AJ")" \
  "public.customers.aadhaar:2 public.nokey.note:1 public.orders.meta $.by.*:1 public.orders.meta $.kyc.uid:1 public.tickets.notes:2"
assert_eq "…groups the places of one number as one person, shown by its last four digits, the most places first" \
  "$(hjson "print([(p['masked'], p['places']) for p in d['people']])" <<<"$AJ")" \
  "[('XXXX XXXX 2341', 3), ('XXXX XXXX 0124', 2), ('XXXX XXXX 1238', 2)]"
P2341="$(hjson "print(d['people'][0]['person'])" <<<"$AJ")"
PJ2341="$($S pii aadhaar places --person "$P2341" --branch aadt --json 2>/dev/null)"
assert_eq "fox pii aadhaar places names a person's rows by their primary key" \
  "$(hjson "print(sorted(p['table']+(' '+p['path'] if p['path'] else '')+' '+p['row'] for p in d))" <<<"$PJ2341")" \
  "['customers id=2', 'orders $.by.* id=2', 'tickets id=12']"
P0124="$(hjson "print([p['person'] for p in d['people'] if p['masked'].endswith('0124')][0])" <<<"$AJ")"
assert_eq "…since when: a tracked row's created_at, when it is earlier than the first run" \
  "$(hjson "print([p['since'][:10] for p in d['people'] if p['masked'].endswith('0124')][0])" <<<"$AJ")|$($S pii aadhaar places --person "$P0124" --branch aadt --json | hjson "print(sorted((p['table'], p['rowCreated'] is not None) for p in d))")" \
  "2026-01-15|[('customers', False), ('tickets', True)]"
assert_eq "…a row of a table with no primary key named by its position, and the report says so" \
  "$($S pii aadhaar places --column public.nokey.note --branch aadt --json | hjson "print([p['row'][:6] for p in d])")|$(grep -c 'no primary key are named by their physical position (ctid).*public.nokey' <<<"$AR")" "['ctid=(']|1"
assert_eq "…and says what it cannot claim: the check digit, no vault yet, the logs not read" \
  "$(grep -c 'not that it was issued' <<<"$AR")|$(grep -c 'every number it finds is outside the vault' <<<"$AR")|$(grep -c 'Query history, the audit log' <<<"$AR")" "1|1|1"
# The point of the design: the report must not become one more copy of the
# numbers it finds, or a way to find them again.
assert_eq "no full number is stored, nor its first eight digits, in any of the report's tables" \
  "$(pg pg-aadt "SELECT count(*) FROM (SELECT r::text t FROM bb.aadhaar_runs r UNION ALL SELECT c::text FROM bb.aadhaar_columns c UNION ALL SELECT p::text FROM bb.aadhaar_places p) x
     WHERE regexp_replace(t, '[ -]', '', 'g') ~ '(23456789|45678901|34567890)'")" "0"
assert_eq "…and a client role cannot read it" \
  "$(sudo docker exec -e PGPASSWORD=foxbyte pg-aadt psql -U dbadmin -d appdb -tAc "SET ROLE db_client; SELECT count(*) FROM bb.aadhaar_places" 2>&1 | grep -c 'permission denied')" "1"
assert_eq "a run reads only: the Blackbox records nothing for it" "$(pg pg-aadt "SELECT count(*) FROM bb.schema_ledger")" "$LEDGER_BEFORE"
assert_eq "…and it is in the security log, with counts and no digit of a number" \
  "$($S audit --limit 1000 | grep -c 'personal-data.aadhaar')|$($S audit --limit 1000 | grep 'personal-data.aadhaar' | grep -cE '0124|2341|1238')" "$((RUNS_LOGGED+1))|0"

# A second run: a number removed is gone; a table it could not read is not.
# customers is held locked past the run's lock wait, so it is skipped, and its
# places are not looked for, which is not the same as not found.
RUN1="$(hjson "print(d['run']['id'])" <<<"$AJ")"
pg pg-aadt "UPDATE tickets SET notes = 'number removed' WHERE id = 9" >/dev/null
sudo docker exec -e PGPASSWORD=foxbyte pg-aadt psql -U dbadmin -d appdb -qc "BEGIN; LOCK TABLE customers IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(25); COMMIT;" >/dev/null 2>&1 &
LOCKER=$!
sleep 2
AR2="$($S pii aadhaar run --branch aadt 2>&1)"
wait "$LOCKER" 2>/dev/null
AJ2="$($S pii aadhaar --branch aadt --json 2>/dev/null)"
assert_eq "a table locked past the run's wait is skipped and said so" \
  "$(grep -c 'not read: public.customers (it was locked by another session for longer than 10s)' <<<"$AR2")" "1"
assert_eq "…a number no longer there is gone, and the skipped table's places are not" \
  "$(hjson "print(d['gone'])" <<<"$AJ2")|$($S pii aadhaar places --gone --branch aadt --json | hjson "print([(p['table'], p['row'], p['masked']) for p in d])")" \
  "1|[('tickets', 'id=9', 'XXXX XXXX 0124')]"
assert_eq "…and a place found again keeps when it was first found" \
  "$(pg pg-aadt "SELECT first_run = $RUN1 AND last_run > $RUN1 FROM bb.aadhaar_places WHERE table_name = 'tickets' AND row_key = 'id=12'")" "t"
assert_eq "a table's time limit outside 1s to 1h is refused" \
  "$($S pii aadhaar run --branch aadt --table-timeout 500ms >/dev/null 2>&1; echo $?)|$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"tableTimeout":4000}' https://localhost:8080/api/branches/aadt/personal-data/aadhaar/run)" "1|400"
AU=https://localhost:8080/api/branches/aadt/personal-data/aadhaar
assert_eq "the API runs and reads for the branch's owner or an admin, and no one else" \
  "$(code "$KEY" -X POST "$AU/run")|$(code "$KEY" "$AU")|$(code "$KEY" "$AU/places?person=$P2341")|$(code "$KA" "$AU")|$(code "$KA" -X POST "$AU/run")|$(code "$KA" https://localhost:8080/api/branches/main/personal-data/aadhaar)|$(code "$KA" -X POST https://localhost:8080/api/branches/main/personal-data/aadhaar/run)" \
  "200|200|200|404|404|403|403"
assert_eq "…refusing a person that is not a number, or a column not written schema.table.column" \
  "$(code "$KEY" "$AU/places?person=abc")|$(code "$KEY" "$AU/places?column=notes")|$(code "$KEY" "$AU/places?limit=20000")" "400|400|400"
assert_eq "…answering with the report, by person, last four digits only" \
  "$(as "$KEY" "$AU" | hjson "print(d['run']['actor'], d['people'][0]['masked'], len(d['columns']))")" "test@foxbyte.dev XXXX XXXX 2341 5"
$S branch delete aadt2 >/dev/null 2>&1
$S branch create aadt2 --from aadt >/dev/null 2>&1
assert_eq "the report travels with the branch: one made from it carries it" \
  "$($S pii aadhaar --branch aadt2 --json | hjson "print(d['run']['id'] == $(as "$KEY" "$AU" | hjson "print(d['run']['id'])"))")" "True"
$S branch delete aadt2 >/dev/null 2>&1
$S branch delete aadt >/dev/null 2>&1

echo "### 11as. the Aadhaar exposure report's logs part: query history, the audit log's text, the Blackbox (point 4.5b)"
# Synthetic numbers, each passing Verhoeff, used nowhere else in the suite:
# the branch is made from main, and main's Blackbox keeps other sections'
# statements, numbers and all. 298765432101 (A, in a table and in the logs),
# 387654321095 (B, a table only), 476543210985 (C, a query's error only),
# 565432109873 (D, the Blackbox only), 654321098763 (E, the audit log's text
# only). alice owns the branch and is not an admin; test@ is the admin.
$S audit-log setup --yes >/dev/null 2>&1; main_up
$S branch delete aadl >/dev/null 2>&1
$S branch create aadl >/dev/null 2>&1
$S branch owner aadl alice@foxbyte.dev >/dev/null 2>&1
# One statement a call: the Blackbox keeps a DDL statement's whole query
# string, and an INSERT run with the CREATE would put its numbers there too.
pg pg-aadl "CREATE TABLE uids (id int PRIMARY KEY, uid text UNIQUE)" >/dev/null
pg pg-aadl "INSERT INTO uids VALUES (1, '2987 6543 2101'), (2, '387654321095')" >/dev/null
pg pg-aadl "GRANT ALL ON uids TO db_client" >/dev/null
pg pg-aadl "ALTER TABLE uids ADD CONSTRAINT uid_not_test CHECK (uid <> '565432109873')" >/dev/null
AQ=https://localhost:8080/api/branches/aadl
as "$KA" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT id FROM uids WHERE uid = '2987 6543 2101'\"}" "$AQ/query" >/dev/null
as "$KEY" -H 'Content-Type: application/json' -X POST -d "{\"sql\":\"SELECT ('4765' || '43210985')::int\"}" "$AQ/query" >/dev/null
code "$KEY" -X PUT -H 'Content-Type: application/json' -d '{}' "$AQ/audit/tables/public/uids" >/dev/null
$S audit-log mode forensic --branch aadl --reason 'aadhaar logs test' --yes >/dev/null 2>&1
PGPASSWORD="$KEY" psql "$GATEWAY/aadl?sslmode=require" -X -q -tA -c "UPDATE uids SET uid = uid WHERE uid IN ('2987 6543 2101', '654321098763')" >/dev/null 2>&1
# The collector moves raw lines into the store once a minute; collect now.
for i in $(seq 1 30); do $S audit-log collect >/dev/null 2>&1; forensic_all | grep -q '654321098763' && break; sleep 1; done
assert_eq "(setup) the audit log kept the UPDATE's text" "$(forensic_all | grep -c '654321098763' | awk '{print ($1 >= 1)}')" "1"
LEDGER_BEFORE="$(pg pg-aadl "SELECT count(*) FROM bb.schema_ledger")"
LOGGED0="$($S audit --limit 1000 | grep -c 'personal-data.aadhaar')"
AL="$($S pii aadhaar run --branch aadl --logs 2>&1)"; AL_RC=$?
assert_eq "fox pii aadhaar run --logs reads the tables and the logs, and exits 0" \
  "$AL_RC|$(grep -c '^The logs (admins only), read with run [0-9]*: [0-9]* query history entr(ies), [0-9]* audit statement text(s), [0-9]* Blackbox entr(ies).' <<<"$AL")|$(grep -c 'what they hold is in the logs part, for admins only' <<<"$AL")" "0|1|1"
grep -q '^The logs (admins only)' <<<"$AL" || { echo "--- what it said ---"; tail -30 <<<"$AL"; echo "--- end ---"; }
ALJ="$($S pii aadhaar --branch aadl --json 2>/dev/null)"
who() { hjson "p=[p for p in d['people'] if p['masked'].endswith('$1')]; print(sorted(p[0]['where']) if p else None)" <<<"$ALJ"; }
assert_eq "a number in a table and in the logs is one person, with each place it is" \
  "$(who 2101)" "['audit log', 'public.uids.uid', 'query history']"
assert_eq "…a number in the logs only is a person of its own: an error, the Blackbox, the audit log's text" \
  "$(who 0985)|$(who 9873)|$(who 8763)" "['query history']|['Blackbox']|['audit log']"
assert_eq "…a number in the tables only is not in the logs" "$(who 1095)" "['public.uids.uid']"
assert_eq "…and the logs part is read with this run, so its people are the report's" \
  "$(hjson "print(d['logs']['linked'], d['logs']['run']['branchRun'] == d['run']['id'], d['logs']['run']['skipped'])" <<<"$ALJ")" "True True []"
PA="$(hjson "print([p['person'] for p in d['people'] if p['masked'].endswith('2101')][0])" <<<"$ALJ")"
assert_eq "fox pii aadhaar places --logs --person names the entries: which log, who made it" \
  "$($S pii aadhaar places --logs --person "$PA" --branch aadl --json | hjson "print(sorted((p['source'], p['field'], p['actor']) for p in d))")" \
  "[('audit', '', 'test@foxbyte.dev'), ('history', 'sql', 'alice@foxbyte.dev')]"
assert_eq "…a query's error is read too: it can quote a value the statement did not" \
  "$($S pii aadhaar places --logs --source history --branch aadl --json | hjson "print([(p['field'], p['actor']) for p in d if p['last4'] == '0985'])")" \
  "[('error', 'test@foxbyte.dev')]"
assert_eq "…and the Blackbox entry is the one that added the constraint" \
  "$($S pii aadhaar places --logs --source blackbox --branch aadl --json | hjson "print([p['entry'] for p in d if p['last4'] == '9873'])")" \
  "[$(pg pg-aadl "SELECT id FROM bb.schema_ledger WHERE statement LIKE '%uid_not_test%'")]"
assert_eq "…and prints them to read" \
  "$($S pii aadhaar places --logs --person "$PA" --branch aadl | grep -c 'XXXX XXXX 2101  *query history  *[0-9]* (sql)  *alice@foxbyte.dev')" "1"
assert_eq "no full number is kept in the install's store, nor its first eight digits" \
  "$(python3 - "$HOME/$BRAND_STATE_DIR/auth.db" <<'PYA'
import re,sqlite3,sys
c=sqlite3.connect(sys.argv[1])
rows=[str(r) for t in ('aadhaar_log_runs','aadhaar_log_places') for r in c.execute('SELECT * FROM '+t)]
print(sum(1 for r in rows if re.search('(29876543|38765432|47654321|56543210|65432109)', r.replace(' ','').replace('-',''))), len(rows) > 0)
PYA
)" "0 True"
assert_eq "…nor in the branch: the logs' places are not in its tables" \
  "$(pg pg-aadl "SELECT count(*) FROM bb.aadhaar_places WHERE row_key ~ 'history|audit|blackbox'")" "0"
assert_eq "a run reads only: the Blackbox records nothing for it" "$(pg pg-aadl "SELECT count(*) FROM bb.schema_ledger")" "$LEDGER_BEFORE"
assert_eq "…and the security log has it, with the logs' counts and no digit of a number" \
  "$(( $($S audit --limit 1000 | grep -c 'personal-data.aadhaar') - LOGGED0 ))|$($S audit --limit 1000 | grep 'personal-data.aadhaar' | grep -c '; logs: ')|$($S audit --limit 1000 | grep 'personal-data.aadhaar' | grep -cE 'XXXX|29876543|38765432|47654321|56543210|65432109')" "1|1|0"

# The branch's owner, not an admin: the tables' report, never the logs.
AU=https://localhost:8080/api/branches/aadl/personal-data/aadhaar
printf 'password123\n' | $S user create aad-none@foxbyte.dev >/dev/null 2>&1
KN="$($S apikey create aad-none@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
assert_eq "an owner who is not an admin may not read the logs, or run a read of them" \
  "$(code "$KA" -H 'Content-Type: application/json' -X POST -d '{"logs":true}' "$AU/run")|$(code "$KA" "$AU/log-places")|$(as "$KA" "$AU" | hjson "print('logs' in d, d['run'] is not None)")" "403|403|False True"
assert_eq "…their report has no log in it, though the tables' people are there" \
  "$(as "$KA" "$AU" | hjson "print(sorted(w for p in d['people'] for w in p['where'] if not w.startswith('public.')), [p['masked'] for p in d['people'] if p['masked'].endswith('0985')])")" "[] []"
assert_eq "…someone with no access to the branch gets nothing either" "$(code "$KN" "$AU/log-places")|$(code "$KN" "$AU")" "404|404"
assert_eq "an owner's run reads the tables only" \
  "$(code "$KA" -X POST "$AU/run")|$(as "$KA" "$AU" | hjson "print('logs' in d)")" "200|False"
assert_eq "…after which an admin's report lists the logs' people apart: they were read with an earlier run" \
  "$(as "$KEY" "$AU" | hjson "print(d['logs']['linked'], [p['masked'] for p in d['logs']['people'] if p['masked'].endswith('2101')], [w for p in d['people'] for w in p['where'] if not w.startswith('public.')])")" \
  "False ['XXXX XXXX 2101'] []"
assert_eq "…and fox pii aadhaar says so" \
  "$($S pii aadhaar --branch aadl | grep -c 'before the latest, so its people are numbered apart')" "1"

# Gone: alice deletes her history, and the next read with the logs no longer
# finds her entry there; the audit text and the Blackbox are still there.
as "$KA" -X DELETE "$HU/history" >/dev/null
assert_eq "an admin runs it with the logs through the API" \
  "$(code "$KEY" -H 'Content-Type: application/json' -X POST -d '{"logs":true}' "$AU/run")" "200"
ALG="$(as "$KEY" "$AU")"
assert_eq "…an entry deleted since is gone; the others are found again" \
  "$(hjson "print(d['logs']['gone'], d['logs']['linked'], sorted(s['source'] for s in d['logs']['sources']))" <<<"$ALG")|$(as "$KEY" "$AU/log-places?gone=1" | hjson "print([(p['source'], p['actor'], p['masked'], p['gone']) for p in d['places']])")" \
  "1 True ['audit', 'blackbox', 'history']|[('history', 'alice@foxbyte.dev', 'XXXX XXXX 2101', True)]"
assert_eq "…a log the API does not know is refused" \
  "$(code "$KEY" "$AU/log-places?source=gateway")|$(code "$KEY" "$AU/log-places?person=x")" "400|400"
assert_eq "a run without --logs still says the logs were not read" \
  "$($S pii aadhaar run --branch aadl 2>&1 | grep -c 'Query history, the audit log.s statement text and the Blackbox are not read by this run')" "1"
$S audit-log mode default --branch aadl >/dev/null 2>&1
$S branch delete aadl >/dev/null 2>&1
$S audit-log off --yes >/dev/null 2>&1; main_up

echo "### 11at. the vault: setup, the token and keys, tokenise, find, detokenise, its log anchored in the security log (point 13.1)"
# The install's vault: its own database on an internal network, and the
# service talking PKCS#11 to FoxByte's own software token. The image is built
# from this checkout, as the database image is when it cannot be pulled.
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VA=https://localhost:8080/api/vault
# A vault another suite set up on this VM (integration_ui.sh does) is taken
# away first: this section starts from an install with none.
sudo docker rm -fv fox-vault fox-vault-db >/dev/null 2>&1
sudo docker volume rm fox-vault-db >/dev/null 2>&1
sudo docker network rm fox-vault fox-vault-hsm >/dev/null 2>&1
case "$HOME/$BRAND_STATE_DIR/vault" in */"$BRAND_STATE_DIR"/vault) rm -rf "${HOME:?}/$BRAND_STATE_DIR/vault" ;; esac
printf 'password123\n' | $S user create vault-none@foxbyte.dev >/dev/null 2>&1
KV="$($S apikey create vault-none@foxbyte.dev t 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
OUT="$($S vault status 2>&1)"
assert_eq "before setup: not set up, and how to" "$(grep -c 'not set up' <<<"$OUT")|$(grep -c 'vault setup' <<<"$OUT")" "1|1"
assert_eq "GET /api/vault: an admin reads it; anyone else is refused" \
  "$(as "$KEY" "$VA" | jget set_up)|$(code "$KV" "$VA")|$(code "$KV" "$VA/kinds")" "False|403|403"
OUT="$($S vault setup 2>&1)"
assert_eq "setup without --yes says what it will do, and does nothing" \
  "$(grep -c 'UIDAI requires an HSM' <<<"$OUT")|$(sudo docker ps -aq --filter name=^fox-vault | wc -l | tr -d ' ')|$([ -e "$HOME/$BRAND_STATE_DIR/vault" ] && echo made || echo none)" "1|0|none"
SETUPS_BEFORE="$($S audit --limit 5000 | grep -c 'vault.setup')"
OUT="$(FOX_VAULT_IMAGE_CONTEXT="$REPO_DIR" $S vault setup --yes 2>&1)"; RC=$?
assert_eq "setup --yes: the image, the token, the networks, the database and the service" "$RC|$(grep -c 'Done: the vault is set up and running' <<<"$OUT")" "0|1"
[ "$RC" = 0 ] || echo "$OUT" | tail -15
assert_eq "both containers run, and carry the engine's label" \
  "$(sudo docker ps --filter "label=$DB_MANAGED_LABEL" --format '{{.Names}}' | grep -cx 'fox-vault\|fox-vault-db')" "2"
assert_eq "the vault's network is internal, and only the two are on it" \
  "$(sudo docker network inspect -f '{{.Internal}}' fox-vault)|$(sudo docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' fox-vault | tr ' ' '\n' | grep -c .)" "true|2"
VD="$HOME/$BRAND_STATE_DIR/vault"
assert_eq "the socket is the engine user's own, mode 600; the secrets 600, in a directory of 700" \
  "$(stat -c '%a %U' "$VD/run/vault.sock")|$(stat -c '%a' "$VD/secret/secret" "$VD/secret/pin" "$VD/secret/dsn" | sort -u | tr '\n' ' ')|$(stat -c '%a' "$VD/secret")" "600 $(id -un)|600 |700"
assert_eq "the service runs as the engine's user, not root" "$(sudo docker inspect -f '{{.Config.User}}' fox-vault)" "$(id -u):$(id -g)"
assert_eq "…and listens on no TCP port (Docker's DNS on 127.0.0.11 aside)" \
  "$(sudo docker exec fox-vault sh -c "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '\$4 == \"0A\" && \$2 !~ /^0B00007F:/' | wc -l")" "0"
assert_eq "the setup is in the security log" "$(( $($S audit --limit 5000 | grep -c 'vault.setup') - SETUPS_BEFORE ))" "1"
OUT="$($S vault setup --yes 2>&1)"; RC=$?
assert_eq "a second setup is refused" "$RC|$(grep -c 'set up already' <<<"$OUT")" "1|1"

OUT="$($S vault status 2>&1)"
assert_eq "status: the software token, said to be not compliant for Aadhaar" \
  "$(grep -c 'SoftHSM project' <<<"$OUT")|$(grep -c '^aadhaar .*no: software token (trials and testing only)' <<<"$OUT")|$(grep -c '^text .*no rules mapped' <<<"$OUT")" "1|1|1"
assert_eq "…four keys, each made in the token and never extractable" "$(grep -c 'made in the token, never extractable' <<<"$OUT")" "4"
OUT="$($S vault kinds 2>&1)"
assert_eq "kinds: Aadhaar under UIDAI's rules with its legacy format; text with none" \
  "$(grep -c 'Verhoeff' <<<"$OUT")|$(grep -c 'UIDAI Circular No. 14 of 2025 (an HSM is required)' <<<"$OUT")|$(grep -c 'legacy:   none' <<<"$OUT")" "1|1|1"

N1=298765432101; N2=387654321095
OUT="$($S vault tokenise --kind aadhaar "$N1" 2>&1)"; RC=$?
R1="$(awk '{print $1}' <<<"$OUT")"
assert_eq "tokenise: a new number gets an opaque Aadhaar reference key" "$RC|$(grep -cE '^AR[0-9A-Z]{26}	new$' <<<"$OUT")" "0|1"
assert_eq "…the same number with spaces gets the same key, not a new one" "$($S vault tokenise --kind aadhaar '2987 6543 2101' 2>&1)" "$R1"
assert_eq "find gives it" "$($S vault find --kind aadhaar "$N1" 2>&1)" "$R1"
OUT="$($S vault tokenise --kind aadhaar 123412341234 2>&1)"; RC=$?
assert_eq "a number failing the check is refused, and the command fails" "$RC|$(grep -c '^(refused)$' <<<"$OUT")" "1|1"
OUT="$($S vault tokenise --kind aadhaar --format legacy "$N2" 2>&1)"
assert_eq "the legacy format: 12 digits starting with 1" "$(grep -cE '^1[0-9]{11}	new$' <<<"$OUT")" "1"
OUT="$(printf '%s\n%s\n' "$N1" "$N2" | $S vault find --kind aadhaar - 2>&1)"
assert_eq "values may come on standard input, one a line, so none sits in the shell's history" "$(head -1 <<<"$OUT")|$(wc -l <<<"$OUT" | tr -d ' ')" "$R1|2"
OUT="$($S vault detokenise --kind aadhaar "$R1" 2>&1)"; RC=$?
assert_eq "detokenise needs a purpose" "$RC|$(grep -c 'purpose is needed' <<<"$OUT")" "2|1"
assert_eq "…and with one, gives the number back" "$($S vault detokenise --kind aadhaar --purpose 'integration: KYC check' "$R1" 2>&1)" "$N1"
TR="$($S vault tokenise --kind text 'Asha Rao, 12 MG Road' 2>&1 | awk '{print $1}')"
assert_eq "any text goes in under the text kind, and comes back as it was" \
  "$(grep -cE '^TX[0-9A-Z]{26}$' <<<"$TR")|$($S vault detokenise --kind text --purpose integration "$TR" 2>&1)" "1|Asha Rao, 12 MG Road"

H='Content-Type: application/json'
OUT="$(as "$KEY" -H "$H" -X POST -d "{\"kind\":\"aadhaar\",\"values\":[\"$N1\",\"$N2\"]}" "$VA/tokenise")"
assert_eq "POST /api/vault/tokenise: an admin gets the same keys" "$(hjson 'print(d["refs"][0], d["new"][0])' <<<"$OUT")" "$R1 False"
assert_eq "POST /api/vault/find: an admin finds them; anyone else is refused" \
  "$(as "$KEY" -H "$H" -X POST -d "{\"kind\":\"aadhaar\",\"values\":[\"$N1\"]}" "$VA/find" | hjson 'print(d["refs"][0])')|$(code "$KV" -H "$H" -X POST -d "{\"kind\":\"aadhaar\",\"values\":[\"$N1\"]}" "$VA/find")" "$R1|403"
OUT="$(as "$KEY" -H "$H" -X POST -d "{\"kind\":\"aadhaar\",\"refs\":[\"$R1\"],\"purpose\":\"x\"}" "$VA/detokenise")"
assert_eq "POST /api/vault/detokenise: refused even to an admin, until there are grants" \
  "$(code "$KEY" -H "$H" -X POST -d "{\"kind\":\"aadhaar\",\"refs\":[\"$R1\"],\"purpose\":\"x\"}" "$VA/detokenise")|$(grep -c 'only the operator can' <<<"$OUT")|$(grep -c "$N1" <<<"$OUT")" "403|1|0"
assert_eq "an unknown kind is a bad request" "$(code "$KEY" -H "$H" -X POST -d '{"kind":"pan","values":["x"]}' "$VA/tokenise")" "400"
OUT="$(as "$KEY" "$VA")"
assert_eq "GET /api/vault: running, the software token, 2 Aadhaar records (the API gave the same keys), 1 text" \
  "$(hjson 'print(d["database_running"], d["service_running"], d["status"]["token"]["software"], [k["records"] for k in d["status"]["kinds"]])' <<<"$OUT")" "True True True [2, 1]"

AUD="$($S audit --limit 3000)"
assert_eq "every call is in the security log, with the vault's log head" \
  "$(grep 'vault.call' <<<"$AUD" | grep -c '; head [0-9]*:[0-9a-f]\{64\}')" "$(grep -c 'vault.call' <<<"$AUD")"
assert_eq "…the detokenise with its purpose" "$(grep 'vault.call' <<<"$AUD" | grep -c 'detokenise, 1 reference key, purpose "integration: KYC check": done 1')" "1"
assert_eq "…and no number, no text value, anywhere in it" "$(grep -cE "$N1|$N2|2987 6543 2101|Asha Rao" <<<"$AUD")" "0"
assert_eq "the vault database holds no number in the clear" \
  "$(sudo docker exec fox-vault-db pg_dump -U postgres vault | grep -cE "$N1|$N2|Asha Rao")" "0"
OUT="$($S vault status 2>&1)"
assert_eq "the vault's log holds, and agrees with the head the security log saw" \
  "$(grep -c 'the chain holds' <<<"$OUT")|$(grep -c 'Against the security log: entry [0-9]* is as the security log saw it' <<<"$OUT")" "1|1"

# The host reaches an internal network through its bridge (design, section
# 20): the database admits only the service's address.
VPW="$(sed -n 's|^postgres://vault_svc:\([^@]*\)@.*|\1|p' "$VD/secret/dsn")"
DBIP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["db_addr"])' "$VD/vault.json")"
OUT="$(sudo docker run --rm --network host -e PGPASSWORD="$VPW" -e PGCONNECT_TIMEOUT=3 postgres:18-bookworm psql -X -h "$DBIP" -U vault_svc -d vault -tAc 'SELECT 1' 2>&1)"
assert_contains "the machine itself, with the service's password, is refused by the database" "$OUT" "pg_hba.conf"

# Entries cut off the end of the vault's log, and the service restarted so it
# forgets how long the log was: the chain still holds, and only the head kept
# in the security log shows the cut.
sudo docker exec fox-vault-db psql -X -q -U postgres -d vault -c "DELETE FROM vault.access_log WHERE seq > (SELECT max(seq) - 2 FROM vault.access_log)" >/dev/null
sudo docker restart fox-vault >/dev/null; sleep 3
for i in $(seq 1 30); do $S vault status >/dev/null 2>&1 && break; sleep 1; done
OUT="$($S vault status 2>&1)"
assert_eq "after a cut and a restart, the chain holds, but the security log's head does not" \
  "$(grep -c 'the chain holds' <<<"$OUT")|$(grep -c 'DOES NOT HOLD: the security log saw entry [0-9]*, which the vault.s access log no longer holds: entries were cut off its end' <<<"$OUT")" "1|1"
assert_eq "…and the console's API says so too" "$(as "$KEY" "$VA" | hjson 'print(d["anchor"]["holds"])')" "False"
# The next call writes a new head; the vault goes on.
$S vault find --kind aadhaar "$N1" >/dev/null 2>&1
assert_eq "the vault goes on, its new head recorded" "$($S vault status 2>&1 | grep -c 'is as the security log saw it')" "1"

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
assert_eq "…and keeps the vault's database, takes its networks" \
  "$(sudo docker volume ls --format '{{.Name}}' | grep -cx fox-vault-db)|$(sudo docker network ls --format '{{.Name}}' | grep -cx fox-vault)" "1|0"

$S uninstall --yes >/tmp/uninstall-all.log 2>&1
assert_eq "uninstall removes the storage pool" \
  "$(sudo zpool list -H -o name "$DB_POOL" 2>/dev/null | wc -l | tr -d ' ')" "0"
assert_eq "…and the archived WAL and base backups" \
  "$(sudo docker volume ls --format '{{.Name}}' | grep -cx "$DB_OBJECT_STORE-data")" "0"
assert_eq "…and the vault's database" "$(sudo docker volume ls --format '{{.Name}}' | grep -cx fox-vault-db)" "0"
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
sudo docker rm -fv mongo-src >/dev/null 2>&1
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
