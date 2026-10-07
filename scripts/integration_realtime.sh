#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Realtime change-feed integration checks. Run inside the Linux dev VM:
#   make integration-realtime
#
# This is the suite that exercises a real decoder against a real write-ahead
# log. Everything up to here was unit-tested; none of it had decoded an actual
# WAL record. The assertions that matter most are the ones only a live database
# can make: that a refusal prevents the breakage it exists for, that an
# unchanged TOASTed column really does arrive unsent, and that replay resumes
# where a subscriber left off.
#
# Exits non-zero if any assertion fails.
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
S=/tmp/fox-rt            # the Enterprise build, with a throwaway licence key
STD=/tmp/fox-rt-standard # the Standard build, for the boundary checks
API="https://localhost:8080"
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq()       { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (got '$2', want something containing '$3')";; esac; }
assert_missing()  { case "$2" in *"$3"*) bad "$1 (got '$2', which must not contain '$3')";; *) ok "$1";; esac; }

pg() { local c="$1"; shift; sudo docker exec "$c" psql -U dbadmin -d appdb -tAc "$*" 2>/dev/null; }
# pgx keeps stderr. Setup steps use it: the first version hid a DROP that the
# engine's own guardrail was refusing, so the tables survived between runs and
# three assertions failed for reasons that had nothing to do with them.
pgx() { local c="$1"; shift; sudo docker exec "$c" psql -U dbadmin -d appdb -tAc "$*" 2>&1; }
# ddl runs a destructive statement the Blackbox guardrail would otherwise
# refuse. That refusal is a feature of the product -- blocking DROP TABLE is one
# of the two guardrails that stay free in every edition -- so the suite has to
# ask for the override the same way a person would, rather than pretend it is
# not there.
ddl() { pgx "$1" "SET bb.allow_destructive=on; $2"; }

main_ready() {
  local i
  for i in $(seq 1 90); do
    [ "$(sudo docker exec -e PGPASSWORD=foxbyte pg-main psql -h localhost -U dbadmin -d appdb -tAc 'SELECT 1' 2>/dev/null)" = "1" ] && return 0
    sleep 1
  done
  echo "  (main did not become ready)" >&2
  return 1
}

# ── A licence this build will accept ────────────────────────────────────────
#
# The signing key is deliberately not in the repository or in CI, so the suite
# makes a throwaway one and pins its public half into the binary under test with
# -ldflags -X -- exactly how the release key is given to a test build. The key
# lives and dies with this run.
echo
echo "0. a build and a licence to test with"
cd "$REPO" || exit 2
KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT
# Built once and then run from the key's own directory: `go run` needs the
# module, and `generate` writes license-signing.key relative to where it runs.
go build -o "$KEYDIR/licensesign" ./cmd/licensesign || { echo "  (could not build licensesign)"; exit 2; }
PUB="$(cd "$KEYDIR" && ./licensesign generate 2>/dev/null | awk '/public key/{print $3}')"
if [ -z "$PUB" ]; then echo "  (could not mint a test signing key)"; exit 2; fi
LD="-X github.com/thefoxbyte/foxbyte/internal/license.licensePublicKey=$PUB"

go build -tags enterprise -ldflags "$LD" -o "$S" ./cmd/fox || { bad "the Enterprise build"; exit 1; }
go build -ldflags "$LD" -o "$STD" ./cmd/fox || { bad "the Standard build"; exit 1; }
ok "both editions built with a throwaway licence key"

go build -ldflags "$LD" -o "$KEYDIR/licensesign-trusting" ./cmd/licensesign
FOX_LICENSE_SIGNING_KEY="$(cat "$KEYDIR/license-signing.key")" \
  "$KEYDIR/licensesign-trusting" issue \
    --customer "integration" --features all --months 1 --id FB-IT > "$KEYDIR/lic.json" 2>/dev/null
"$S" license activate "$KEYDIR/lic.json" >/dev/null 2>&1
assert_contains "the licence unlocks this build" "$("$S" version)" "features licensed"

# Start from a known state. The suite has to be re-runnable: the first version
# assumed a clean install, so a second run found the feed already set up, the
# tables already published, and reported six failures that were its own doing.
#
# Forcefully, because a run killed mid-stream leaves an active replication slot
# and `realtime teardown` rightly refuses to pull one out from under a live
# subscriber. That refusal is correct for a person and wrong for a suite, so the
# suite clears them itself rather than inheriting the last run's state.
sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "
  SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots
   WHERE slot_name LIKE 'fox_rt_%' AND active_pid IS NOT NULL" >/dev/null 2>&1
sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "
  SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots
   WHERE slot_name LIKE 'fox_rt_%'" >/dev/null 2>&1
TEARDOWN="$("$S" realtime teardown --yes 2>&1)"
case "$TEARDOWN" in *rror*) echo "  (teardown on entry: $TEARDOWN)";; esac
"$S" stop >/dev/null 2>&1; sleep 1
"$S" start >/dev/null 2>&1; sleep 5; main_ready
USER_EMAIL="rt@foxbyte.dev"
printf 'password123\n' | "$S" user create "$USER_EMAIL" >/dev/null 2>&1 || true
KEY="$("$S" apikey create "$USER_EMAIL" rt 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
[ -n "$KEY" ] && ok "an API key for the feed" || bad "could not mint an API key"

# ── 1. The Standard boundary ────────────────────────────────────────────────
echo
echo "1. the Standard build has none of it"
assert_eq "no pglogrepl symbols in the Standard binary" \
  "$(go tool nm "$STD" 2>/dev/null | grep -c pglogrepl)" "0"
assert_contains "\`realtime enable\` is not a command there" \
  "$("$STD" realtime enable orders 2>&1 | head -1)" "unknown"
# setup, teardown, status and slots stay, so somebody who goes back to Standard
# can still see and undo what they turned on.
assert_contains "but \`realtime status\` is" "$("$STD" realtime status 2>&1 | head -1)" "change feed"

# ── 2. Setup says what it will do ───────────────────────────────────────────
echo
echo "2. setup is an opt-in, and says so first"
BEFORE_WAL="$(pg pg-main 'SHOW wal_level')"
assert_eq "main starts at wal_level=replica" "$BEFORE_WAL" "replica"
OUT="$("$S" realtime setup 2>&1)"
assert_contains "setup without --yes explains" "$OUT" "--yes"
assert_eq "and changes nothing" "$(pg pg-main 'SHOW wal_level')" "replica"

"$S" realtime setup --yes >/dev/null 2>&1
main_ready
assert_eq "with --yes, main is logical" "$(pg pg-main 'SHOW wal_level')" "logical"
assert_contains "and holds a bounded amount of WAL" "$(pg pg-main 'SHOW max_slot_wal_keep_size')" "GB"

# ── 3. The refusals, and the breakage they prevent ──────────────────────────
echo
echo "3. enable refuses what a feed cannot carry safely"
ddl pg-main 'DROP TABLE IF EXISTS public.nokey, public.rls_t, public.ok_t CASCADE' >/dev/null
pg pg-main 'CREATE TABLE public.ok_t (id bigint PRIMARY KEY, note text, body text)'
# STORAGE EXTERNAL so `body` is stored out-of-line and uncompressed. Without it
# the unchanged-TOAST case cannot be tested at all: a 12 kB run of one character
# compresses to 147 bytes and is kept inline, Postgres sends it with the update
# like any ordinary column, and the assertion fails against a decoder that was
# right all along.
pg pg-main 'ALTER TABLE public.ok_t ALTER COLUMN body SET STORAGE EXTERNAL'
pg pg-main 'CREATE TABLE public.nokey (a int, b text)'
pg pg-main 'CREATE TABLE public.rls_t (id int PRIMARY KEY, who text)'
pg pg-main 'ALTER TABLE public.rls_t ENABLE ROW LEVEL SECURITY'
pg pg-main 'GRANT SELECT ON public.ok_t, public.nokey, public.rls_t TO db_client'
assert_eq "the test tables start empty" "$(pg pg-main 'SELECT count(*) FROM public.nokey')" "0"
assert_eq "and nokey starts at the default replica identity" \
  "$(pg pg-main "SELECT relreplident FROM pg_class WHERE relname='nokey'")" "d"

assert_contains "an RLS table is refused" "$("$S" realtime enable rls_t 2>&1)" "row-level security"
assert_missing  "and offers no override"  "$("$S" realtime enable rls_t 2>&1)" "--replica-identity"
# Refused for one of two reasons depending on what db_client may read, and
# which one is not this suite's business: that it is never streamed is.
"$S" realtime enable bb.schema_ledger >/dev/null 2>&1
assert_missing "the Blackbox is never streamed" "$("$S" realtime tables 2>&1)" "schema_ledger"

# The regression the no-primary-key refusal exists for: adding such a table to a
# publication that publishes updates makes every later UPDATE on it fail. So the
# refusal has to hold, and UPDATE has to still work afterwards.
pg pg-main "INSERT INTO public.nokey VALUES (1,'x')"
assert_contains "a table with no primary key is refused" "$("$S" realtime enable nokey 2>&1)" "no primary key"
pg pg-main "UPDATE public.nokey SET b='y' WHERE a=1" >/dev/null
assert_eq "and UPDATE on it still works" "$(pg pg-main "SELECT b FROM public.nokey WHERE a=1")" "y"

assert_contains "--events=insert is accepted" "$("$S" realtime enable nokey --events insert 2>&1)" "Streaming"
"$S" realtime disable nokey >/dev/null 2>&1
assert_contains "--replica-identity=full is accepted" "$("$S" realtime enable nokey --replica-identity=full 2>&1)" "Streaming"
assert_eq "and the table really is FULL now" "$(pg pg-main "SELECT relreplident FROM pg_class WHERE relname='nokey'")" "f"

# ── 4. The feed itself ──────────────────────────────────────────────────────
echo
echo "4. a feed carries what the wire format promises"
"$S" realtime enable ok_t >/dev/null 2>&1
CAP=/tmp/rt-capture.ndjson
: > "$CAP"
# --max-time, not kill: the server holds a stream open for an hour by design, so
# killing the pipeline left `wait` blocked on it. Letting curl end itself is
# both simpler and what a client would actually do.
( curl -skN --max-time 12 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/main/realtime" | sed -u -n 's/^data: //p' >> "$CAP" ) &
STREAM=$!
sleep 3

# Big *and* incompressible, so it really is stored out-of-line: that is the only
# case in which Postgres omits an untouched column from an update.
pg pg-main "INSERT INTO public.ok_t VALUES (1, '', repeat(md5(random()::text), 400))"
# Asserted, so a future failure says which of the two things went wrong.
TOASTED="$(pg pg-main "SELECT pg_column_size(body) > 2000 FROM public.ok_t WHERE id=1")"
assert_eq "the test value really is stored out-of-line" "$TOASTED" "t"
pg pg-main "UPDATE public.ok_t SET note = 'changed' WHERE id = 1"
pg pg-main "INSERT INTO public.ok_t VALUES (2, NULL, 'small')"
pg pg-main "DELETE FROM public.ok_t WHERE id = 2"
wait "$STREAM" 2>/dev/null

have() { python3 - "$CAP" "$1" <<'PY' 2>/dev/null
import json,sys
want=sys.argv[2]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    try: e=json.loads(line)
    except Exception: continue
    if eval(want, {"e": e}): print("yes"); break
PY
}

assert_eq "an insert arrives" "$(have "e.get('type')=='change' and e.get('action')=='insert'")" "yes"
# This is what the first run got wrong. --events was publication-wide in
# Postgres but per-table in the API, so a table enabled earlier with
# --events=insert silently decided that updates would never arrive for any
# later table. One publication per event set is the fix; this is the assertion
# that would have caught it.
assert_eq "an update arrives" "$(have "e.get('type')=='change' and e.get('action')=='update'")" "yes"
assert_eq "a delete arrives"  "$(have "e.get('type')=='change' and e.get('action')=='delete'")" "yes"
assert_eq "no change arrives without an identity" \
  "$(have "e.get('type')=='change' and not e.get('identity')")" ""
CHANGES="$(grep -c '"type":"change"' "$CAP" 2>/dev/null || echo 0)"
if [ "$CHANGES" -gt 0 ]; then ok "the feed delivered $CHANGES changes"; else bad "the feed delivered nothing at all"; fi
# The one that silently corrupts a subscriber's copy if it is got wrong.
assert_eq "an unchanged TOASTed column is named, not nulled" \
  "$(have "e.get('action')=='update' and 'body' in (e.get('unchanged') or []) and 'body' not in (e.get('new') or {})")" "yes"
# An empty string and a NULL have to stay different things.
assert_eq "an empty string arrives as \"\"" \
  "$(have "e.get('action')=='insert' and (e.get('new') or {}).get('note')==''")" "yes"
assert_eq "a NULL arrives as null" \
  "$(have "e.get('action')=='insert' and 'note' in (e.get('new') or {}) and (e.get('new') or {}).get('note') is None")" "yes"
# Values are text, so a bigint survives.
assert_eq "values are strings, not numbers" \
  "$(have "e.get('action')=='insert' and isinstance((e.get('identity') or {}).get('id'), str)")" "yes"

# ── 5. The scoped key reaches its branch and nothing else ───────────────────
echo
echo "5. a branch-scoped key is narrow"
# A branch-scoped key is minted by the Agent API for its own branch, but is not
# returned over HTTP -- so there is no way to get one from a shell, which is
# itself the point: it is a credential a program is handed, not one a person
# copies. That it reaches only its own branch is covered by
# TestUserForBranchStream in internal/auth.
#
# What this suite can prove is the route's own half of the same rule: a caller
# who may not reach a branch is told it does not exist rather than that they
# may not have it.
CODE="$(curl -sk -o /dev/null -w '%{http_code}' "$API/api/branches/main/realtime")"
assert_eq "no credentials at all: refused" "$CODE" "401"

OTHER="other@foxbyte.dev"
printf 'password123\n' | "$S" user create "$OTHER" >/dev/null 2>&1 || true
OKEY="$("$S" apikey create "$OTHER" rt 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
"$S" branch create rtprivate >/dev/null 2>&1
if [ -n "$OKEY" ]; then
  CODE="$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $OKEY" \
    "$API/api/branches/rtprivate/realtime")"
  # 404 rather than 403, so a branch's name is not confirmed to somebody who
  # cannot use it -- the same answer `allowed` gives everywhere else.
  assert_eq "somebody else's branch is 404, not 403" "$CODE" "404"
else
  bad "could not mint a second account's key"
fi

# ── 6. Slots are accounted for ──────────────────────────────────────────────
echo
echo "6. slots are found, listed and swept"
assert_contains "the feed's slot is listed" "$("$S" realtime slots main 2>&1)" "fox_rt_"
"$S" up >/dev/null 2>&1
sleep 2
LEFT="$(pg pg-main "SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%' AND NOT active")"
assert_eq "an idle slot is swept by \`fox up\`" "$LEFT" "0"

# ── 7. Teardown leaves the database working ─────────────────────────────────
echo
echo "7. teardown undoes it, and breaks nothing"
"$S" realtime teardown --yes >/dev/null 2>&1
main_ready
assert_eq "main is back to replica" "$(pg pg-main 'SHOW wal_level')" "replica"
assert_eq "no publications are left" \
  "$(pg pg-main "SELECT count(*) FROM pg_publication WHERE pubname LIKE 'fox_rt_%'")" "0"
# The point of the whole exercise: nothing it touched is worse off.
pg pg-main "UPDATE public.ok_t SET note='after' WHERE id=1" >/dev/null
assert_eq "UPDATE on a formerly-streamed table still works" \
  "$(pg pg-main "SELECT note FROM public.ok_t WHERE id=1")" "after"
pg pg-main "UPDATE public.nokey SET b='z' WHERE a=1" >/dev/null
assert_eq "and on the one that was set to FULL" \
  "$(pg pg-main "SELECT b FROM public.nokey WHERE a=1")" "z"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
