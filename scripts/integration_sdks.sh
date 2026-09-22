#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Contract tests for the published clients (audit v2 G26): clients/python and
# clients/typescript are what other people's code calls, and nothing checked
# that they still match the API. Each one is driven against a live engine —
# branches, SQL, the Blackbox, suspend/resume, and the error a bad call gives.
#
#   make integration-sdks     # in the throwaway VM
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${FOX_BIN:-/tmp/fox}"
API="${FOX_API_URL:-https://localhost:8080}"
EMAIL="sdk@foxbyte.dev"
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

echo "### setup: a running stack, an account and a key"
"$S" start >/dev/null 2>&1
for _ in $(seq 60); do curl -sk "$API/api/status" >/dev/null 2>&1 && break; sleep 1; done
printf 'password123\n' | "$S" user create "$EMAIL" >/dev/null 2>&1
KEY="$("$S" apikey create "$EMAIL" sdk 2>/dev/null | grep -o "${DB_KEY_PREFIX}[A-Za-z0-9_-]*")"
assert_eq "an API key for the SDKs" "$([ -n "$KEY" ] && echo yes)" "yes"
for b in sdkpy sdkts; do "$S" branch delete "$b" >/dev/null 2>&1; done

echo "### 1. the Python client (clients/python)"
PY_OUT="$(FOX_KEY="$KEY" FOX_API="$API" python3 - "$ROOT/clients/python" <<'PY' 2>&1
import os, sys
sys.path.insert(0, sys.argv[1])
from foxbyte import FoxByte, FoxByteError

db = FoxByte(api_key=os.environ["FOX_KEY"], base_url=os.environ["FOX_API"], verify_tls=False)
say = lambda name, got, want: print(f"{'PASS' if got == want else 'FAIL'}|{name}|{got}|{want}")

say("status reports main ready", db.status()["mainReady"], True)
db.create_branch("sdkpy")
say("create_branch then branches lists it", any(b["name"] == "sdkpy" for b in db.branches()), True)
# One statement per call: the query endpoint runs a single statement (a
# multi-statement string is refused by the extended protocol).
db.query("sdkpy", "CREATE TABLE t (id int)")
db.query("sdkpy", "INSERT INTO t VALUES (1),(2)")
r = db.query("sdkpy", "SELECT count(*) AS n FROM t")
say("query returns columns and rows", (r.get("columns"), r.get("rows"), r.get("error")), (["n"], [[2]], None))
# ledger() and verify_ledger() answer with a result set: columns and rows.
entries = db.ledger("sdkpy")
tags = [row[entries["columns"].index("command_tag")] for row in entries["rows"]]
say("the Blackbox lists the CREATE TABLE", "CREATE TABLE" in tags, True)
say("blackbox() is the same call", db.blackbox("sdkpy")["columns"], entries["columns"])
v = db.verify_ledger("sdkpy")
say("verify_ledger reports an intact chain", v["rows"][0][v["columns"].index("broken")], 0)
db.suspend("sdkpy")
say("suspend stops the branch", next(b["state"] for b in db.branches() if b["name"] == "sdkpy"), "exited")
db.resume("sdkpy")
say("resume starts it again", next(b["state"] for b in db.branches() if b["name"] == "sdkpy"), "running")
try:
    db.query("nosuchbranch", "select 1")
    say("a call on a branch that is not there raises", "no error", "FoxByteError")
except FoxByteError as e:
    say("a call on a branch that is not there raises", "404" in str(e), True)
db.delete_branch("sdkpy")
say("delete_branch removes it", any(b["name"] == "sdkpy" for b in db.branches()), False)
PY
)"
while IFS='|' read -r st name got want; do
	case "$st" in
	PASS) ok "python: $name" ;;
	FAIL) bad "python: $name (got '$got', want '$want')" ;;
	esac
done <<<"$PY_OUT"
if grep -q 'Traceback\|^PASS|\|^FAIL|' <<<"$PY_OUT" && ! grep -q Traceback <<<"$PY_OUT"; then
	: # every check ran
else
	bad "python: the client stopped part way"
	sed 's/^/      /' <<<"$PY_OUT" | tail -6
fi

echo "### 2. the TypeScript client (clients/typescript)"
# Built in a copy: the repository is mounted read-only in the test VM, so
# npm cannot write node_modules beside the sources.
TS="${TMPDIR:-/tmp}/fox-sdk-ts"
rm -rf "$TS"; mkdir -p "$TS"; cp -r "$ROOT/clients/typescript/." "$TS/"
TS_OUT="$(cd "$TS" && npm install --silent --no-audit --no-fund 2>&1 && npx --yes tsc 2>&1)"
assert_eq "it compiles with its own tsconfig" "$([ -f "$TS/dist/index.js" ] && echo yes || echo "no: $(tail -2 <<<"$TS_OUT")")" "yes"
if [ -f "$TS/dist/index.js" ]; then
	TS_OUT="$(cd "$TS" && FOX_KEY="$KEY" FOX_API="$API" NODE_TLS_REJECT_UNAUTHORIZED=0 node --input-type=module -e '
import { FoxByte, FoxByteError } from "./dist/index.js"
const db = new FoxByte(process.env.FOX_KEY, process.env.FOX_API)
const say = (name, got, want) => console.log(`${JSON.stringify(got) === JSON.stringify(want) ? "PASS" : "FAIL"}|${name}|${JSON.stringify(got)}|${JSON.stringify(want)}`)

say("status reports main ready", (await db.status()).mainReady, true)
await db.createBranch("sdkts")
say("createBranch then branches lists it", (await db.branches()).some(b => b.name === "sdkts"), true)
await db.query("sdkts", "CREATE TABLE t (id int)")
await db.query("sdkts", "INSERT INTO t VALUES (1),(2)")
const r = await db.query("sdkts", "SELECT count(*) AS n FROM t")
say("query returns columns and rows", [r.columns, r.rows, r.error ?? null], [["n"], [[2]], null])
const entries = await db.ledger("sdkts")
const tags = entries.rows.map(r => r[entries.columns.indexOf("command_tag")])
say("the Blackbox lists the CREATE TABLE", tags.includes("CREATE TABLE"), true)
const v = await db.verifyLedger("sdkts")
say("verifyLedger reports an intact chain", v.rows[0][v.columns.indexOf("broken")], 0)
await db.suspend("sdkts")
say("suspend stops the branch", (await db.branches()).find(b => b.name === "sdkts").state, "exited")
await db.resume("sdkts")
say("resume starts it again", (await db.branches()).find(b => b.name === "sdkts").state, "running")
try {
  await db.query("nosuchbranch", "select 1")
  say("a call on a branch that is not there throws", "no error", "FoxByteError")
} catch (e) {
  say("a call on a branch that is not there throws", e instanceof FoxByteError && e.message.includes("404"), true)
}
await db.deleteBranch("sdkts")
say("deleteBranch removes it", (await db.branches()).some(b => b.name === "sdkts"), false)
' 2>&1)"
	while IFS='|' read -r st name got want; do
		case "$st" in
		PASS) ok "typescript: $name" ;;
		FAIL) bad "typescript: $name (got '$got', want '$want')" ;;
		esac
	done <<<"$TS_OUT"
	if grep -qE '^(node:|.*Error:)' <<<"$TS_OUT" || ! grep -q '^PASS|\|^FAIL|' <<<"$TS_OUT"; then
		bad "typescript: the client stopped part way"
		sed 's/^/      /' <<<"$TS_OUT" | tail -6
	fi
fi

echo "### cleanup"
for b in sdkpy sdkts; do "$S" branch delete "$b" >/dev/null 2>&1; done
rm -rf "$TS"

echo
echo "==== ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ]
