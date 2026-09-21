#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# `fox start`'s new-release notice and `fox update`, end to end, in the Linux dev
# VM (ZFS + Docker) against a local fake GitHub:
#   make integration-update
# Builds two test releases (0.98.0 installed, 0.99.0 published), updates, and
# checks the servers restarted on the new binary while containers, data,
# branches, Blackbox history and settings stayed exactly as they were. The
# stack is put back on /usr/local/bin/fox at the end.
set -uo pipefail

# Refuses to run anywhere but the throwaway test VM (see scripts/lib/test_guard.sh).
# A guard that can't be found must stop the suite, not let it carry on.
. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
# Names in one place (generated from brand.json by `make brand`).
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(go env GOARCH)"
T="$(mktemp -d /tmp/odbupd.XXXXXX)"
PORT=18931
export FOX_UPDATE_BASE_URL="http://127.0.0.1:$PORT"
V="$T/bin/fox"
ENGINE="fox-linux-$ARCH"
PASS=0
FAIL=0
HTTP_PID=""

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
contains() { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (no '$2' in output)"; tail -n 15 <<<"$3" | sed 's/^/      /'; fi; }
lacks()    { if grep -qF -- "$2" <<<"$3"; then bad "$1 ('$2' in output)"; else ok "$1"; fi; }
pg() { local c="$1"; shift; sudo docker exec "$c" psql -U dbadmin -d appdb -tAc "$*" 2>/dev/null; }
pid_of() { "$V" status 2>/dev/null | sed -n "s/^$1: running (pid \([0-9]*\)).*/\1/p"; }
# ledger_digest <container> <max id>  -> count and hash of the entries up to that id
ledger_digest() { pg "$1" "SELECT count(*) || ':' || coalesce(md5(string_agg(row_hash, ',' ORDER BY id)), '') FROM bb.schema_ledger WHERE id <= ${2:-0}"; }
EMAIL="updtest@foxbyte.dev"

cleanup() {
	[ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null
	for k in $("$V" apikey list "$EMAIL" 2>/dev/null | awk '$2 == "upd" { print $1 }'); do
		"$V" apikey revoke "$EMAIL" "$k" >/dev/null 2>&1
	done
	pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS updkeep" >/dev/null
	"$V" branch delete updb >/dev/null 2>&1
	rm -rf "$HOME/.fox/updates" "$HOME/.fox/update-check.json" "$HOME/.fox/update-notice.json"
	# Put the stack back on the installed binary.
	"$V" stop >/dev/null 2>&1
	/usr/local/bin/fox start >/dev/null 2>&1
	rm -rf "$T"
}
trap cleanup EXIT

echo "### setup: build test releases 0.98.0 and 0.99.0, serve a fake GitHub"
build() { (cd "$ROOT" && go build -ldflags "-X github.com/thefoxbyte/foxbyte/internal/version.Version=$1" -o "$2" ./cmd/fox); }
mkdir -p "$T/bin" "$T/www/dl/v0.98.0" "$T/www/dl/v0.99.0" "$T/www/dl/v0.99.5" "$T/www/dl/v1.0.0"
build 0.98.0 "$V" || { echo "build failed"; exit 1; }
build 0.99.0 "$T/www/dl/v0.99.0/$ENGINE" || { echo "build failed"; exit 1; }
cp "$V" "$T/www/dl/v0.98.0/$ENGINE"
cp "$T/www/dl/v0.99.0/$ENGINE" "$T/www/dl/v1.0.0/$ENGINE"
cp "$T/www/dl/v0.99.0/$ENGINE" "$T/good-engine"
# v1.0.0 is a prerelease and v0.99.5 has no engine yet: neither may be offered.
python3 - "$FOX_UPDATE_BASE_URL" "$T/www" "$ENGINE" <<'PY'
import hashlib, json, os, sys
base, www, engine = sys.argv[1:4]
def rel(tag, files, pre=False):
    d = os.path.join(www, "dl", tag)
    assets, sums = [], ""
    for name in files:
        p = os.path.join(d, name)
        sums += hashlib.sha256(open(p, "rb").read()).hexdigest() + "  " + name + "\n"
        assets.append({"name": name, "size": os.path.getsize(p), "browser_download_url": f"{base}/dl/{tag}/{name}"})
    open(os.path.join(d, "SHA256SUMS"), "w").write(sums)
    assets.append({"name": "SHA256SUMS", "size": len(sums), "browser_download_url": f"{base}/dl/{tag}/SHA256SUMS"})
    return {"tag_name": tag, "draft": False, "prerelease": pre, "html_url": f"{base}/releases/tag/{tag}", "assets": assets}
rels = [rel("v1.0.0", [engine], pre=True), rel("v0.99.5", []), rel("v0.99.0", [engine]), rel("v0.98.0", [engine])]
os.makedirs(os.path.join(www, "repos/thefoxbyte/foxbyte"), exist_ok=True)
json.dump(rels, open(os.path.join(www, "repos/thefoxbyte/foxbyte/releases"), "w"))
PY
start_fake_github() {
	python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$T/www" >/dev/null 2>&1 &
	HTTP_PID=$!
	for _ in $(seq 50); do curl -sf "$FOX_UPDATE_BASE_URL/repos/thefoxbyte/foxbyte/releases" >/dev/null && break; sleep 0.2; done
}
stop_fake_github() { [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null; HTTP_PID=""; }
start_fake_github
assert_eq "test binary is 0.98.0" "$("$V" version)" "fox 0.98.0"

# Stack on the 0.98.0 binary, with data on main and on a branch.
/usr/local/bin/fox stop >/dev/null 2>&1
"$V" stop >/dev/null 2>&1; sleep 1
FOX_NO_UPDATE_CHECK=1 "$V" start >/dev/null 2>&1; sleep 5
pg pg-main "SET bb.allow_destructive=on; DROP TABLE IF EXISTS updkeep; CREATE TABLE updkeep(id int); INSERT INTO updkeep SELECT generate_series(1,3);" >/dev/null
"$V" branch delete updb >/dev/null 2>&1
"$V" branch create updb >/dev/null 2>&1
pg pg-updb "CREATE TABLE onbranch(x int); INSERT INTO onbranch VALUES (7);" >/dev/null
MAIN_ID="$(sudo docker inspect -f '{{.Id}}' pg-main)"
BR_ID="$(sudo docker inspect -f '{{.Id}}' pg-updb)"
SECRETS="$(md5sum "$HOME/.fox/secrets.json" 2>/dev/null)"
TLS="$(cd "$HOME/.fox" && find tls -type f -exec md5sum {} + 2>/dev/null | sort)"
MAIN_MAX="$(pg pg-main "SELECT max(id) FROM bb.schema_ledger")"
BR_MAX="$(pg pg-updb "SELECT max(id) FROM bb.schema_ledger")"
MAIN_HIST="$(ledger_digest pg-main "$MAIN_MAX")"
BR_HIST="$(ledger_digest pg-updb "$BR_MAX")"
printf 'password123\n' | "$V" user create "$EMAIL" >/dev/null 2>&1 || true
KEY="$("$V" apikey create "$EMAIL" upd 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
CP_PID="$(pid_of 'control API')"
assert_eq "secrets.json and TLS certificates exist" "$([ -n "$SECRETS" ] && [ -n "$TLS" ] && echo yes)" "yes"
assert_eq "Blackbox has entries on main and the branch" "$([ -n "$MAIN_MAX" ] && [ -n "$BR_MAX" ] && echo yes)" "yes"
assert_eq "test API key minted" "$([ -n "$KEY" ] && echo yes)" "yes"
assert_eq "branch has its data" "$(pg pg-updb 'SELECT x FROM onbranch')" "7"
assert_eq "control API runs on 0.98.0" "$(readlink "/proc/$CP_PID/exe")" "$V"

echo "### 1. fox start prints the notice, last"
OUT="$("$V" start 2>&1)"
assert_eq "notice is the last line" "$(tail -n 1 <<<"$OUT")" \
	'FoxByte v0.99.0 is available (you have 0.98.0). Run `fox update` to get the new capabilities.'
assert_eq "notice printed once" "$(grep -c 'is available' <<<"$OUT")" "1"
contains "banner still printed" "FoxByte is up (background)" "$OUT"

echo "### 1b. a found release is remembered between starts"
# GitHub throttles repeated downloads of a release asset, so the check asks only
# for the releases list, and remembers a found release (default 6h) — never
# "up to date", which would hide a release published inside that window.
stop_fake_github
lacks "a forced check with GitHub unreachable prints nothing" "is available" "$(FOX_UPDATE_CHECK_INTERVAL=0 "$V" start 2>&1)"
assert_eq "the remembered notice still prints with GitHub unreachable" "$(tail -n 1 <<<"$("$V" start 2>&1)")" \
	'FoxByte v0.99.0 is available (you have 0.98.0). Run `fox update` to get the new capabilities.'
start_fake_github

echo "### 2. FOX_NO_UPDATE_CHECK=1 turns it off"
lacks "no notice when turned off" "is available" "$(FOX_NO_UPDATE_CHECK=1 FOX_UPDATE_CHECK_INTERVAL=0 "$V" start 2>&1)"

echo "### 3. offline: nothing printed, no noticeable delay"
S=$(date +%s)
OUT="$(FOX_UPDATE_BASE_URL=http://127.0.0.1:9 FOX_UPDATE_CHECK_INTERVAL=0 "$V" start 2>&1)"
lacks "no notice offline" "is available" "$OUT"
lacks "no error offline" "error" "$OUT"
assert_eq "offline start not slowed (<15s)" "$([ $(( $(date +%s) - S )) -lt 15 ] && echo yes)" "yes"

echo "### 4-5. fox update --check picks the newest complete, non-prerelease release"
OUT="$("$V" update --check 2>&1)"; CODE=$?
assert_eq "--check exits 0" "$CODE" "0"
contains "--check reports v0.99.0" "FoxByte v0.99.0 is available (you have 0.98.0)." "$OUT"
lacks "prerelease v1.0.0 not offered" "v1.0.0" "$OUT"
lacks "incomplete v0.99.5 not offered" "v0.99.5" "$OUT"
assert_eq "--check changes nothing" "$("$V" version)" "fox 0.98.0"
OUT="$("$V" update </dev/null 2>&1)"; CODE=$?
assert_eq "without a terminal, update needs --yes" "$CODE:$(grep -c -- '--yes' <<<"$OUT")" "1:1"

echo "### 6. a tampered download is refused and nothing changes"
printf 'X' | dd of="$T/www/dl/v0.99.0/$ENGINE" bs=1 seek=4096 conv=notrunc 2>/dev/null
OUT="$("$V" update --yes 2>&1)"; CODE=$?
assert_eq "tampered update fails" "$CODE" "1"
contains "reports the checksum mismatch" "checksum mismatch" "$OUT"
contains "says nothing changed" "Nothing was changed" "$OUT"
assert_eq "still 0.98.0" "$("$V" version)" "fox 0.98.0"
assert_eq "servers untouched" "$(pid_of 'control API')" "$CP_PID"
assert_eq "no partial download left" "$(ls "$HOME/.fox/updates/v0.99.0" 2>/dev/null | wc -l | tr -d ' ')" "0"
cp "$T/good-engine" "$T/www/dl/v0.99.0/$ENGINE"

echo "### 7. fox update --yes"
OUT="$("$V" update --yes 2>&1)"; CODE=$?
assert_eq "update exits 0" "$CODE" "0"
[ "$CODE" = 0 ] || tail -n 30 <<<"$OUT" | sed 's/^/      /'
contains "says done" "Done — FoxByte is now v0.99.0. Your data was not touched." "$OUT"
contains "upgraded Blackbox on the branch" "updb: ledger up to date" "$OUT"
assert_eq "fox is 0.99.0" "$("$V" version)" "fox 0.99.0"
NEW_CP="$(pid_of 'control API')"
assert_eq "control API restarted" "$([ -n "$NEW_CP" ] && [ "$NEW_CP" != "$CP_PID" ] && echo yes)" "yes"
for svc in "control API" "gateway" "agent API"; do
	assert_eq "$svc runs the new binary" "$(readlink "/proc/$(pid_of "$svc")/exe")" "$V"
done
assert_eq "main container not recreated" "$(sudo docker inspect -f '{{.Id}}' pg-main)" "$MAIN_ID"
assert_eq "branch container not recreated" "$(sudo docker inspect -f '{{.Id}}' pg-updb)" "$BR_ID"
assert_eq "main data intact" "$(pg pg-main 'SELECT count(*) FROM updkeep')" "3"
assert_eq "branch data intact" "$(pg pg-updb 'SELECT x FROM onbranch')" "7"
# Starting and upgrading add entries; every entry from before must be untouched.
assert_eq "main Blackbox history unchanged" "$(ledger_digest pg-main "$MAIN_MAX")" "$MAIN_HIST"
assert_eq "branch Blackbox history unchanged" "$(ledger_digest pg-updb "$BR_MAX")" "$BR_HIST"
contains "main Blackbox chain intact" "ledger intact" "$("$V" ledger verify main 2>&1)"
contains "branch Blackbox chain intact" "ledger intact" "$("$V" ledger verify updb 2>&1)"
assert_eq "blast radius present on the branch" "$(pg pg-updb "SELECT count(*) > 0 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'bb' AND p.proname = 'blast_radius'")" "t"
assert_eq "secrets.json unchanged" "$(md5sum "$HOME/.fox/secrets.json" 2>/dev/null)" "$SECRETS"
assert_eq "TLS certificates unchanged" "$(cd "$HOME/.fox" && find tls -type f -exec md5sum {} + 2>/dev/null | sort)" "$TLS"
assert_eq "previous engine kept" "$("$HOME/.fox/updates/prev/fox" version)" "fox 0.98.0"
assert_eq "gateway serves main with a key made before the update" "$(PGPASSWORD="$KEY" psql "postgresql://dbadmin@127.0.0.1:6432/main?sslmode=require" -tAc 'SELECT count(*) FROM updkeep' 2>&1)" "3"
assert_eq "control plane answers" "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8080/api/status | grep -vc '^000$')" "1"

echo "### 8. up to date afterwards"
contains "--check says up to date" "FoxByte 0.99.0 is up to date." "$("$V" update --check 2>&1)"
lacks "start shows no notice" "is available" "$(FOX_UPDATE_CHECK_INTERVAL=0 "$V" start 2>&1)"

echo
echo "integration-update: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
