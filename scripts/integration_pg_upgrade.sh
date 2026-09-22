#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# `fox backup export`, `fox backup restore` and `fox pg upgrade`, end to end, in
# the throwaway test VM:
#   make integration-pg-upgrade
#
# Builds a real PostgreSQL 16 install (the image its data runs on is chosen by
# the data, so after one start pinned to 16 it stays on 16 by itself), fills it
# the way a user would -- an account, an API key, writes through the Gateway, a
# second branch left suspended, an expression index, two base backups -- and
# then exports it, restores from the export, shows the upgrade plan and its
# refusals, upgrades it to the major this fox ships, rolls back, upgrades
# again and finalizes. It starts and ends by uninstalling everything.
set -uo pipefail

# Refuses to run anywhere but the throwaway test VM (see scripts/lib/test_guard.sh).
. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

S="${FOX_BIN:-/tmp/fox}"
GATEWAY="postgresql://$DB_SUPERUSER@127.0.0.1:6432"
IMG16="ghcr.io/${BRAND_REPO%%/*}/postgres-walg:16"
T="$(mktemp -d /tmp/pgup.XXXXXX)"
EMAIL="upgrade@$BRAND_SLUG.dev"
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
contains() { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (no '$2' in output)"; tail -n 12 <<<"$3" | sed 's/^/      /'; fi; }
lacks()    { if grep -qF -- "$2" <<<"$3"; then bad "$1 ('$2' in output)"; else ok "$1"; fi; }
pg() { local c="$1"; shift; sudo docker exec "$c" psql -U "$DB_SUPERUSER" -d "$DB_DATABASE" -tAc "$*" 2>/dev/null; }
major() { pg "$1" "SHOW server_version_num" | cut -c1-2; }
state() { local v; v="$(sudo docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null | tr -d '[:space:]')"; echo "${v:-absent}"; }
# ledger_digest <container> <max id> -> count:md5 of the entries up to that id.
# With maxid it states "every entry that was there is still there, unchanged";
# the checks below also require that nothing was added.
ledger_digest() { pg "$1" "SELECT count(*) || ':' || coalesce(md5(string_agg(row_hash, ',' ORDER BY id)), '') FROM bb.schema_ledger WHERE id <= ${2:-0}"; }
maxid() { pg "$1" 'SELECT coalesce(max(id), 0) FROM bb.schema_ledger'; }
gw() { PGPASSWORD="$KEY" psql "$GATEWAY/$1" -tAc "$2" 2>&1; }
backups() { $S backup list 2>/dev/null | grep -c 'base_'; }
held() { sudo zfs list -H -o name "$DB_POOL/pre-upgrade-pg16" >/dev/null 2>&1 && echo held || echo gone; }

cleanup() {
	unset FOX_PG_IMAGE
	$S uninstall --yes >/dev/null 2>&1
	rm -rf "$T"
}
trap cleanup EXIT

echo "### 0. a PostgreSQL 16 install, filled the way a user would"
$S uninstall --yes >/dev/null 2>&1
FOX_PG_IMAGE="$IMG16" $S start >"$T/start16.log" 2>&1
assert_eq "an install pinned to 16 starts on PostgreSQL 16" "$(major pg-main)" "16"
# From here nothing pins it: the data decides.
$S stop >/dev/null 2>&1
$S start >"$T/start.log" 2>&1
assert_eq "…and restarts on 16 with no override: the image follows the data" "$(major pg-main)" "16"
contains "fox pg status names the install's major" "This install: PostgreSQL 16" "$($S pg status 2>&1)"
contains "…and says a newer one is available" "pg upgrade --dry-run" "$($S pg status 2>&1)"

printf 'password123\n' | $S user create "$EMAIL" >/dev/null 2>&1
KEY="$($S apikey create "$EMAIL" ci 2>/dev/null | grep -o "${DB_KEY_PREFIX:-key_}[A-Za-z0-9_-]*")"
gw main "CREATE TABLE people (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL);
         INSERT INTO people (name) SELECT 'p' || g FROM generate_series(1, 100) g;
         CREATE INDEX people_lower ON people (lower(name));" >/dev/null
assert_eq "writes through the Gateway as the account" "$(gw main 'SELECT count(*) FROM people')" "100"
$S branch create qa >/dev/null 2>&1
gw qa "CREATE TABLE qa_only (x int); INSERT INTO qa_only SELECT generate_series(1, 5);" >/dev/null
QA_MAX="$(maxid pg-qa)"; QA_DIGEST="$(ledger_digest pg-qa "$QA_MAX")"
$S branch suspend qa >/dev/null 2>&1
assert_eq "qa is left suspended" "$(state pg-qa)" "exited"
$S backup create >/dev/null 2>&1
$S backup create >/dev/null 2>&1
BK16="$(backups)"
# Three: the one `fox start` takes on a new install (audit v2 G19), and two more.
assert_eq "three base backups on 16 (the first taken at install)" "$BK16" "3"
MAIN_MAX="$(maxid pg-main)"; MAIN_DIGEST="$(ledger_digest pg-main "$MAIN_MAX")"

echo "### 1. export and restore"
OUT="$($S backup export --out "$T/e16.tar" 2>&1)"
assert_eq "backup export succeeds" "$?" "0"
contains "…and says it verified the file" "verified" "$OUT"
LIST="$(tar tf "$T/e16.tar" 2>/dev/null)"
for member in manifest.json SHA256SUMS branches/main/data.dump branches/main/roles.sql branches/qa/data.dump; do
	contains "…the export holds $member" "$member" "$LIST"
done
lacks "…and not the disposable standby" "branches/standby" "$LIST"
assert_eq "…and qa is suspended again afterwards" "$(state pg-qa)" "exited"

python3 - "$T/e16.tar" "$T/bad.tar" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read())
b[len(b) // 2] ^= 0xFF
open(sys.argv[2], "wb").write(b)
PY
OUT="$($S backup restore "$T/bad.tar" --branch qa --as badcopy 2>&1)"
contains "a damaged export is refused" "export" "$OUT"
assert_eq "…and restores nothing" "$(state pg-badcopy)" "absent"

OUT="$($S backup restore "$T/e16.tar" --branch qa --as qacopy 2>&1)"
contains "restore into a new branch succeeds" "Restored qa" "$OUT"
assert_eq "…with qa's data" "$(pg pg-qacopy 'SELECT count(*) FROM qa_only')" "5"
assert_eq "…its Blackbox, every entry unchanged" "$(ledger_digest pg-qacopy "$QA_MAX")" "$QA_DIGEST"
assert_eq "…and nothing added by the restore" "$(maxid pg-qacopy)" "$QA_MAX"
assert_eq "…which verifies" "$($S blackbox verify qacopy >/dev/null 2>&1; echo $?)" "0"
assert_eq "…and its roles: the account can log in there" "$(gw qacopy 'SELECT count(*) FROM qa_only')" "5"
$S branch delete qacopy >/dev/null 2>&1

echo "### 2. the plan, and its refusals"
OUT="$($S pg upgrade --dry-run 2>&1)"
assert_eq "a dry run succeeds" "$?" "0"
contains "…names the move" "PostgreSQL 16 → 18" "$OUT"
contains "…warns that point-in-time restore starts again" "Point-in-time restore cannot reach a moment before the upgrade" "$OUT"
contains "…finds the expression index in main" "[found in main]" "$OUT"
contains "…and says nothing changed" "Dry run: nothing was changed" "$OUT"
assert_eq "…and nothing did" "$(major pg-main)" "16"

$S ha enable >/dev/null 2>&1; sleep 2
OUT="$($S pg upgrade --dry-run 2>&1)"
assert_eq "with HA on, the plan is refused" "$?" "1"
contains "…and says what to do" "ha disable" "$OUT"
$S ha disable >/dev/null 2>&1

OUT="$(echo no | $S pg upgrade 2>&1)"
contains "answering anything but the command's name stops it" "not confirmed" "$OUT"
assert_eq "…and changes nothing" "$(major pg-main)" "16"

echo "### 3. the upgrade"
OUT="$($S pg upgrade --yes --export "$T/before.tar" 2>&1)"
RC=$?
assert_eq "pg upgrade succeeds" "$RC" "0"
[ "$RC" = 0 ] || tail -n 25 <<<"$OUT" | sed 's/^/      /'
assert_eq "…after taking the export it was given" "$(tar tf "$T/before.tar" 2>/dev/null | grep -c manifest.json)" "1"
assert_eq "main runs PostgreSQL 18" "$(major pg-main)" "18"
assert_eq "…with its data" "$(pg pg-main 'SELECT count(*) FROM people')" "100"
assert_eq "…and its expression index" "$(pg pg-main "SELECT count(*) FROM pg_indexes WHERE indexname = 'people_lower'")" "1"
assert_eq "the Blackbox came across: every entry, unchanged" "$(ledger_digest pg-main "$MAIN_MAX")" "$MAIN_DIGEST"
assert_eq "…and nothing added by the upgrade" "$(maxid pg-main)" "$MAIN_MAX"
assert_eq "…and it verifies" "$($S blackbox verify >/dev/null 2>&1; echo $?)" "0"
assert_eq "the account's API key still works through the Gateway" "$(gw main 'SELECT count(*) FROM people')" "100"
assert_eq "qa is suspended, as it was" "$(state pg-qa)" "exited"
$S branch resume qa >/dev/null 2>&1
assert_eq "…and wakes on 18 with its data" "$(major pg-qa)|$(pg pg-qa 'SELECT count(*) FROM qa_only')" "18|5"
assert_eq "the new cluster has its own base backup, and none of 16's" "$(backups)" "1"
contains "…archived under its own prefix" "pg18-" "$(sudo cat "/$DB_POOL/branches/main/wal-archive-prefix" 2>/dev/null)"
assert_eq "the 16 databases are kept aside" "$(held)" "held"
lacks "…where the branch list cannot see them" "pre-upgrade" "$($S branch list 2>&1)"
contains "fox pg status reports what is kept" "Kept by an upgrade" "$($S pg status 2>&1)"

$S stop >/dev/null 2>&1
OUT="$(FOX_PG_IMAGE="$IMG16" $S start 2>&1)"
contains "starting 18 data on the 16 image is refused before Postgres sees it" "holds PostgreSQL 18 data" "$OUT"
$S start >/dev/null 2>&1

echo "### 4. rollback"
$S branch create after >/dev/null 2>&1
OUT="$($S pg upgrade --rollback --yes 2>&1)"
assert_eq "rollback succeeds" "$?" "0"
contains "…after saying what it deletes" "Deletes after" "$OUT"
assert_eq "main is back on 16" "$(major pg-main)" "16"
assert_eq "…with its data" "$(pg pg-main 'SELECT count(*) FROM people')" "100"
assert_eq "…and its Blackbox, unchanged" "$(ledger_digest pg-main "$MAIN_MAX")" "$MAIN_DIGEST"
assert_eq "…with nothing added" "$(maxid pg-main)" "$MAIN_MAX"
assert_eq "…which verifies" "$($S blackbox verify >/dev/null 2>&1; echo $?)" "0"
assert_eq "the branch made after the upgrade is gone" "$(state pg-after)|$($S branch list 2>&1 | grep -cw after)" "absent|0"
$S branch resume qa >/dev/null 2>&1
assert_eq "qa is back on 16" "$(major pg-qa)" "16"
assert_eq "16's base backups are visible again" "$(backups)" "$BK16"
assert_eq "…because main archives to the bucket's root again" "$(sudo test -f "/$DB_POOL/branches/main/wal-archive-prefix" && echo file || echo none)" "none"
assert_eq "nothing is held any more" "$(held)" "gone"

echo "### 5. upgrade again, then finalize"
OUT="$($S pg upgrade --yes --i-have-a-backup 2>&1)"
assert_eq "a second upgrade succeeds" "$?" "0"
lacks "…and takes no export when told there is a backup" "Taking an export" "$OUT"
assert_eq "main runs 18 again" "$(major pg-main)" "18"
OUT="$($S pg upgrade --finalize --yes 2>&1)"
assert_eq "finalize succeeds" "$?" "0"
assert_eq "…and deletes what was kept" "$(held)" "gone"
lacks "…so pg status reports nothing kept" "Kept by an upgrade" "$($S pg status 2>&1)"
contains "rollback now says there is nothing to go back to" "no earlier upgrade" "$($S pg upgrade --rollback --yes 2>&1)"
contains "an install on 18 has nothing to upgrade" "Nothing to do" "$($S pg upgrade --dry-run 2>&1)"
assert_eq "…and the data is still there" "$(gw main 'SELECT count(*) FROM people')" "100"

echo
echo "integration-pg-upgrade: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
