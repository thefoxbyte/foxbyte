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

# The Enterprise build and its throwaway licence come from the same helper every
# other suite uses (scripts/build_test_fox.sh): it mints a signing key, pins the
# public half in with -ldflags -X, issues a licence and activates it. This suite
# had its own copy of that first; one place is better, and it is the place the
# nightly fix put it.
scripts/build_test_fox.sh "$S" >/dev/null || { bad "the Enterprise build"; exit 1; }

# And a Standard build that trusts the *same* key, for the boundary checks
# below. Deliberately given the licence rather than withheld from it: "a
# Standard build with a valid licence activated still contains none of this" is
# the property worth proving, and a build that was never offered one proves
# less.
PUB="$(cat "$S.licence.pub")"
go build -ldflags "-X github.com/thefoxbyte/foxbyte/internal/license.licensePublicKey=$PUB" \
  -o "$STD" ./cmd/fox || { bad "the Standard build"; exit 1; }
"$STD" license activate "$S.licence.json" >/dev/null 2>&1
ok "both editions built, and both given the same licence"

assert_contains "the licence unlocks this build" "$("$S" version)" "features licensed"

# Start from a known state. The suite has to be re-runnable: the first version
# assumed a clean install, so a second run found the feed already set up, the
# tables already published, and reported six failures that were its own doing.
#
# The stack has to be up before anything can be cleaned: slots live in Postgres,
# and a stopped branch cannot be asked to drop one. The first version reset
# before starting, so on a run that followed a failed one it found the stack
# down, could clean nothing, and then reported five failures in later sections
# that were all the same inherited state.
"$S" stop >/dev/null 2>&1; sleep 1
"$S" start >/dev/null 2>&1; sleep 5; main_ready

# Now that Postgres is running, clear anything the last run left behind. A run
# killed mid-stream leaves an active slot, and `realtime teardown` rightly
# refuses to pull one out from under a live subscriber -- correct for a person,
# wrong for a suite.
sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "
  SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots
   WHERE slot_name LIKE 'fox_rt_%' AND active_pid IS NOT NULL" >/dev/null 2>&1
sudo docker exec pg-main psql -U dbadmin -d appdb -tAc "
  SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots
   WHERE slot_name LIKE 'fox_rt_%'" >/dev/null 2>&1
TEARDOWN="$("$S" realtime teardown --yes 2>&1)"
case "$TEARDOWN" in *"left on"*) echo "  (could not reset the feed on entry: $TEARDOWN)";; esac
main_ready
USER_EMAIL="rt@foxbyte.dev"
printf 'password123\n' | "$S" user create "$USER_EMAIL" >/dev/null 2>&1 || true
KEY="$("$S" apikey create "$USER_EMAIL" rt 2>/dev/null | grep -o 'key_[A-Za-z0-9_-]*')"
[ -n "$KEY" ] && ok "an API key for the feed" || bad "could not mint an API key"
# Branch feeds, from section 9 on. A plain account reaches `main` and the
# branches it owns and nothing else (access.Checker.Level), and a branch made
# from the CLI has no owner -- so without this the stream route would answer
# 404 to the very key these sections subscribe with, and for the right reason.
# Granted here rather than later because the answer is cached for 30 seconds,
# and a suite that depended on that window elapsing would pass or fail by how
# fast the sections before it ran.
"$S" admin grant --branch main "$USER_EMAIL" >/dev/null 2>&1

# ── 1. The Standard boundary ────────────────────────────────────────────────
echo
echo "1. the Standard build has none of it, licence or no licence"
assert_eq "no pglogrepl symbols in the Standard binary" \
  "$(go tool nm "$STD" 2>/dev/null | grep -c pglogrepl)" "0"
# The licence above was activated against this binary too, and it unlocks
# nothing: the code is not in it. That is the property the edition split exists
# for, and it is worth asserting against a build that was *offered* a licence
# rather than one that never saw one.
assert_missing "and a valid licence unlocks nothing in it" \
  "$("$STD" version)" "features licensed"
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

have_in() { python3 - "$1" "$2" <<'PY' 2>/dev/null
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
# The capture section 4 is reading. Later sections watch their own branches, so
# they name the file; this keeps the ones here short.
have() { have_in "$CAP" "$1"; }

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
# An idle slot survives, because it is exactly what a reconnecting subscriber
# resumes from and max_slot_wal_keep_size already bounds what it can cost. Only
# a *lost* one is swept -- see SweepRealtimeSlots, and section 8.
BEFORE="$(pg pg-main "SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%'")"
"$S" up >/dev/null 2>&1
sleep 2
AFTER="$(pg pg-main "SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%'")"
assert_eq "an idle slot survives \`fox up\`, so a subscriber can still resume" "$AFTER" "$BEFORE"

# ── 7. Replay: a subscriber resumes where it left off ───────────────────────
echo
echo "7. replay, and the budget that bounds it"

# stream_for <seconds> <file> [since]  -- capture the feed for a while.
stream_for() {
  local secs="$1" out="$2" since="${3:-}" url="$API/api/branches/main/realtime"
  [ -n "$since" ] && url="$url?since=$since"
  : > "$out"
  curl -skN --max-time "$secs" -H "Authorization: Bearer $KEY" "$url" \
    | sed -u -n 's/^data: //p' >> "$out"
}
# last_lsn <file> -- the commit_lsn of the last change in a capture.
last_lsn() { python3 -c '
import json,sys
lsn=""
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    try: e=json.loads(line)
    except Exception: continue
    if e.get("type")=="change" and e.get("commit_lsn"): lsn=e["commit_lsn"]
print(lsn)' "$1" 2>/dev/null; }
# ids_in <file> -- the identity ids of every change, in order.
ids_in() { python3 -c '
import json,sys
out=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    try: e=json.loads(line)
    except Exception: continue
    if e.get("type")=="change":
        v=(e.get("identity") or {}).get("id")
        if v is not None: out.append(str(v))
print(",".join(out))' "$1" 2>/dev/null; }

pg pg-main "DELETE FROM public.ok_t" >/dev/null
A=/tmp/rt-before.ndjson
B=/tmp/rt-after.ndjson

# Watch, write one row, and note where we got to.
( stream_for 8 "$A" ) &
W=$!
sleep 3
pg pg-main "INSERT INTO public.ok_t VALUES (100, 'first', 'x')" >/dev/null
wait "$W" 2>/dev/null
MARK="$(last_lsn "$A")"
# The DELETE above is itself a change, so the capture legitimately opens with
# those deletes. What matters is that the insert arrived and is last.
case "$(ids_in "$A")" in
  *100) ok "the first change arrives and carries a position" ;;
  *) bad "the first change did not arrive (got '$(ids_in "$A")')" ;;
esac
if [ -n "$MARK" ]; then ok "and the position is usable ($MARK)"; else bad "no commit_lsn to resume from"; fi

# Now nobody is listening. These are the changes a subscriber must not lose.
pg pg-main "INSERT INTO public.ok_t VALUES (101, 'missed one', 'x')" >/dev/null
pg pg-main "INSERT INTO public.ok_t VALUES (102, 'missed two', 'x')" >/dev/null
pg pg-main "INSERT INTO public.ok_t VALUES (103, 'missed three', 'x')" >/dev/null

# Reconnect from the mark. This is the promise durable replay was chosen for:
# changes made while disconnected arrive, in order, rather than silently never
# arriving at all.
stream_for 8 "$B" "$MARK"
GOT="$(ids_in "$B")"
case "$GOT" in
  *101*102*103*) ok "every change made while disconnected is replayed, in order" ;;
  *) bad "replay lost changes (got '$GOT', want 101,102,103 in order)" ;;
esac

# ── 8. The budget: a slot past saving says so ───────────────────────────────
echo
echo "8. exceeding the WAL budget costs a resync, not a full disk"

# A tiny budget. It has to be set the way an operator would -- the environment
# variable, then `realtime setup` -- because Postgres gives a setting from the
# command line precedence over ALTER SYSTEM, and the engine passes this one on
# the command line. An ALTER SYSTEM here is accepted and silently ignored, which
# is how the first version of this test "proved" the budget does not work.
"$S" realtime teardown --yes >/dev/null 2>&1
FOX_REALTIME_WAL_KEEP=0 "$S" realtime setup --yes >/dev/null 2>&1
main_ready
assert_eq "the budget really is what we asked for" \
  "$(pg pg-main "SELECT setting FROM pg_settings WHERE name='max_slot_wal_keep_size'")" "0"
"$S" realtime enable ok_t >/dev/null 2>&1

# A brief connection, to leave a slot behind for the WAL to outrun.
stream_for 4 /tmp/rt-seed.ndjson
SEED="$(last_lsn /tmp/rt-seed.ndjson)"
[ -z "$SEED" ] && SEED="$MARK"

for i in 1 2 3 4 5 6; do
  pg pg-main "INSERT INTO public.ok_t SELECT 200+$i*1000+g, 'bulk', repeat(md5(random()::text), 50) FROM generate_series(1,2000) g" >/dev/null
  pg pg-main "SELECT pg_switch_wal()" >/dev/null
  pg pg-main "CHECKPOINT" >/dev/null
done
sleep 2
STATUS="$(pg pg-main "SELECT wal_status FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%' LIMIT 1")"
assert_eq "Postgres invalidated the slot rather than hold more WAL" "$STATUS" "lost"

# A lost slot can never be resumed from, and the subscriber has to be told --
# silence is a gap in its copy that nothing downstream could detect.
C=/tmp/rt-lost.ndjson
stream_for 12 "$C" "$SEED"
assert_contains "the subscriber is told to resync, not left waiting" \
  "$(cat "$C" 2>/dev/null)" "resync"

# And the lost slot is cleaned up: it holds a catalog entry and can do nothing
# else for anyone.
"$S" up >/dev/null 2>&1
sleep 2
assert_eq "a lost slot is swept by \`fox up\`" \
  "$(pg pg-main "SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%' AND wal_status='lost'")" "0"

# ── 9. The reaper, and a branch somebody is listening to ────────────────────
echo
echo "9. a subscribed branch is not suspended out from under its subscribers"

# Back to a usable budget: section 8 deliberately left it at 0 so a slot would
# be invalidated, and every assertion from here on wants a slot that survives.
"$S" up >/dev/null 2>&1
"$S" realtime teardown --yes >/dev/null 2>&1
"$S" realtime setup --yes >/dev/null 2>&1
main_ready
assert_eq "the budget is back to its default" \
  "$(pg pg-main 'SHOW max_slot_wal_keep_size')" "1GB"

"$S" branch delete rtfeed >/dev/null 2>&1
"$S" branch delete rtidle >/dev/null 2>&1
"$S" branch create rtfeed >/dev/null 2>&1
# The control. Without an ordinary branch beside the subscribed one, a reaper
# that suspended nothing at all would look exactly like one that spared the
# right branch -- which is the shape of mistake this suite has made before.
"$S" branch create rtidle >/dev/null 2>&1
# A branch container has never been given a command line before this feature, so
# this is the assertion that the new one is right rather than merely accepted.
assert_eq "a branch starts with logical decoding available" \
  "$(pg pg-rtfeed 'SHOW wal_level')" "logical"
pg pg-rtfeed 'CREATE TABLE public.feed (id bigint PRIMARY KEY, v text)'
pg pg-rtfeed 'GRANT SELECT ON public.feed TO db_client'
assert_contains "and a table on it can be streamed" \
  "$("$S" realtime enable feed --branch rtfeed 2>&1)" "Streaming"

# A gateway of its own with a short idle window. The reaper reaches the same
# decision at 8 seconds as at two minutes -- canSuspend asks Postgres what is
# attached, not the clock -- and the alternative is two and a half minutes of
# waiting in every run. This is the pattern the continuous-import test in
# integration_test.sh already uses, for the same reason.
F=/tmp/rt-feed-branch.ndjson
: > "$F"
( curl -skN --max-time 40 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/rtfeed/realtime" | sed -u -n 's/^data: //p' >> "$F" ) &
STREAM=$!
sleep 5
nohup "$S" gateway --addr :6503 --idle 8s >/tmp/rt-gateway.log 2>&1 &
GWPID=$!
sleep 25
assert_eq "a subscribed branch survives the reaper" \
  "$(sudo docker inspect -f '{{.State.Status}}' pg-rtfeed 2>/dev/null)" "running"
assert_eq "…while an idle one beside it is suspended" \
  "$(sudo docker inspect -f '{{.State.Status}}' pg-rtidle 2>/dev/null)" "exited"
# Still running is not the same as still working: a branch can be left up by a
# probe that failed rather than by one that answered.
pg pg-rtfeed "INSERT INTO public.feed VALUES (1,'alive')"
wait "$STREAM" 2>/dev/null
assert_eq "…and the feed was still delivering 25 seconds in" \
  "$(have_in "$F" "e.get('type')=='change' and (e.get('identity') or {}).get('id')=='1'")" "yes"

# Nobody is listening now. The slot stays -- it is what a reconnecting
# subscriber resumes from, and the budget bounds what it can cost -- but an idle
# slot must not pin a branch awake for ever.
sleep 20
assert_eq "once the last subscriber leaves, the branch suspends" \
  "$(sudo docker inspect -f '{{.State.Status}}' pg-rtfeed 2>/dev/null)" "exited"

# And a subscriber arriving at a suspended branch is served rather than told
# that nothing is there.
G=/tmp/rt-resumed.ndjson
: > "$G"
( curl -skN --max-time 30 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/rtfeed/realtime" | sed -u -n 's/^data: //p' >> "$G" ) &
STREAM=$!
sleep 12
assert_eq "a new subscriber resumes a suspended branch" \
  "$(sudo docker inspect -f '{{.State.Status}}' pg-rtfeed 2>/dev/null)" "running"
pg pg-rtfeed "INSERT INTO public.feed VALUES (2,'resumed')"
wait "$STREAM" 2>/dev/null
assert_eq "…and the feed it resumed for delivers" \
  "$(have_in "$G" "e.get('type')=='change' and (e.get('identity') or {}).get('id')=='2'")" "yes"
kill "$GWPID" 2>/dev/null

# `fox check` is where somebody looks when a slot is holding WAL and nothing is
# draining it. The slot on rtfeed is idle now, which is the case worth a word.
"$S" up >/dev/null 2>&1
CHECK="$("$S" check 2>&1 | grep 'change feed')"
assert_contains "\`check\` reports the feed" "$CHECK" "change feed"
assert_contains "…and names the idle slot it found" "$CHECK" "idle"

"$S" realtime disable feed --branch rtfeed >/dev/null 2>&1
"$S" branch delete rtfeed >/dev/null 2>&1
"$S" branch delete rtidle >/dev/null 2>&1

# ── 10. The control plane dying mid-stream ──────────────────────────────────
echo
echo "10. a crashed control plane leaves a slot, not an unbounded one"

# A small budget, so "bounded" can be shown in a minute rather than an hour.
# Set the way an operator would -- the variable, then `realtime setup` -- for
# the reason section 8 records: a command-line setting beats ALTER SYSTEM.
"$S" realtime teardown --yes >/dev/null 2>&1
FOX_REALTIME_WAL_KEEP=32MB "$S" realtime setup --yes >/dev/null 2>&1
main_ready
assert_eq "the budget is 32MB for this section" \
  "$(pg pg-main "SELECT setting FROM pg_settings WHERE name='max_slot_wal_keep_size'")" "32"
"$S" realtime enable ok_t >/dev/null 2>&1

# A subscriber, and then the process it lives in is killed outright: no
# shutdown, no deferred close, nothing released. The slot is left behind
# holding a position in the WAL, which is what makes replay work and what would
# fill a disk if nothing bounded it.
( curl -skN --max-time 90 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/main/realtime" >/dev/null 2>&1 ) &
sleep 6
CPPID="$(cat "$HOME/.fox/controlplane.pid" 2>/dev/null)"
if [ -n "$CPPID" ] && { kill -9 "$CPPID" 2>/dev/null || sudo kill -9 "$CPPID" 2>/dev/null; }; then
  ok "the control plane was killed outright (pid $CPPID)"
else
  bad "could not kill the control plane (pid '$CPPID')"
fi
sleep 2
assert_eq "it really is gone" "$(kill -0 "$CPPID" 2>/dev/null; echo $?)" "1"
assert_eq "the slot it was reading is still there, to resume from" \
  "$(pg pg-main "SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%'")" "1"

# Now write far more WAL than the budget allows, with nothing draining the slot.
LSN0="$(pg pg-main 'SELECT pg_current_wal_lsn()')"
for i in 1 2 3 4 5 6 7 8 9 10; do
  pg pg-main "INSERT INTO public.ok_t SELECT 900000+$i*5000+g, 'crashfill', repeat(md5(random()::text), 60) FROM generate_series(1,4000) g" >/dev/null
  pg pg-main "SELECT pg_switch_wal()" >/dev/null
  pg pg-main "CHECKPOINT" >/dev/null
done
sleep 2
WROTE="$(pg pg-main "SELECT (pg_wal_lsn_diff(pg_current_wal_lsn(), '$LSN0')/1024/1024)::bigint")"
HELD="$(pg pg-main "SELECT (coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0)/1024/1024)::bigint
  FROM pg_replication_slots WHERE slot_name LIKE 'fox_rt_%' LIMIT 1")"
# Asserted, so a pass cannot come from a test that wrote nothing -- the way the
# first version of section 4 "passed" with no events at all.
if [ "${WROTE:-0}" -gt 64 ]; then ok "the test generated ${WROTE}MB of WAL, well past the budget"
else bad "the test only generated ${WROTE:-0}MB of WAL, so it proves nothing"; fi
if [ "${HELD:-0}" -lt 64 ]; then ok "the abandoned slot holds ${HELD}MB, not the ${WROTE}MB written"
else bad "the abandoned slot is holding ${HELD}MB of WAL after a crash"; fi

# Nothing restarts a crashed daemon on this install -- there is no supervisor,
# which is written down as a gap rather than papered over -- so it comes back
# the way a person would bring it back, and the stale pidfile must not stop it.
"$S" start >/dev/null 2>&1
sleep 4
NEWPID="$(cat "$HOME/.fox/controlplane.pid" 2>/dev/null)"
if [ -n "$NEWPID" ] && [ "$NEWPID" != "$CPPID" ]; then ok "it starts again over the stale pidfile"
else bad "the control plane did not come back (pid '$NEWPID', was '$CPPID')"; fi

H=/tmp/rt-aftercrash.ndjson
: > "$H"
( curl -skN --max-time 12 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/main/realtime" | sed -u -n 's/^data: //p' >> "$H" ) &
STREAM=$!
sleep 4
pg pg-main "INSERT INTO public.ok_t VALUES (990001, 'after the crash', 'x')"
wait "$STREAM" 2>/dev/null
assert_eq "and a subscriber after the crash gets a working feed" \
  "$(have_in "$H" "e.get('type')=='change' and (e.get('identity') or {}).get('id')=='990001'")" "yes"

# ── 11. The neighbours: a continuous import under logical decoding ──────────
echo
echo "11. a continuous import still works, and is decodable"

# Branch containers are started with a command line for the first time by this
# feature, and a continuous import is the one thing that uses a branch for
# something other than queries: its apply worker has no client connection of
# its own, which is the reason canSuspend asks about replication at all.
IMG="$(sudo docker inspect -f '{{.Config.Image}}' pg-main)"
sudo docker rm -f rtsrc >/dev/null 2>&1
"$S" branch delete rtimp >/dev/null 2>&1
sudo docker run -d --name rtsrc --network "$DB_NETWORK" -e POSTGRES_PASSWORD=srcpw \
  "$IMG" postgres -c wal_level=logical >/dev/null
for i in $(seq 1 60); do sudo docker exec rtsrc pg_isready -U postgres -q && break; sleep 1; done
sudo docker exec rtsrc psql -U postgres -q -c \
  "CREATE TABLE items(id int PRIMARY KEY, v text); INSERT INTO items VALUES (1,'a'),(2,'b'),(3,'c');" >/dev/null
"$S" import --from "postgresql://postgres:srcpw@rtsrc:5432/postgres" --continuous --as rtimp >/tmp/rt-import.log 2>&1
assert_eq "the initial copy lands" "$(pg pg-rtimp 'SELECT count(*) FROM items')" "3"
assert_eq "…on a branch running logical" "$(pg pg-rtimp 'SHOW wal_level')" "logical"
assert_eq "…with its subscription in place" "$(pg pg-rtimp 'SELECT count(*) FROM pg_subscription')" "1"
sudo docker exec rtsrc psql -U postgres -q -c "INSERT INTO items VALUES (4,'d')" >/dev/null
for i in $(seq 1 30); do [ "$(pg pg-rtimp 'SELECT count(*) FROM items')" = 4 ] && break; sleep 1; done
assert_eq "a later source change streams across" "$(pg pg-rtimp 'SELECT count(*) FROM items')" "4"

# And the imported table is readable by the role every gateway client is logged
# in as. This is why the cross-feature assertion below failed the first time:
# `prepareTarget` drops and recreates the target's public schema, which took
# the grants ledger.sql had made with it -- so an imported instance could be
# read by the superuser the import itself uses and by nobody else. Every test
# of the import had used that superuser, which is how it survived this long.
assert_eq "db_client can read what was imported" \
  "$(pg pg-rtimp "SELECT has_table_privilege('db_client','public.items','SELECT')")" "t"
assert_eq "…and reach the schema it is in" \
  "$(pg pg-rtimp "SELECT has_schema_privilege('db_client','public','USAGE')")" "t"

# `fox up` sweeps the feed's lost slots, and the import's subscription is not
# one of them: the sweep matches on the feed's own prefix, and this is the
# assertion that keeps it that way.
"$S" up >/dev/null 2>&1; sleep 2
assert_eq "\`up\` leaves the import's subscription alone" \
  "$(pg pg-rtimp 'SELECT count(*) FROM pg_subscription')" "1"

# Two logical features on one branch: rows arriving over replication are written
# to WAL by the apply worker like any other write, so they decode like any other
# change. Nothing about that is obvious from either feature on its own.
"$S" realtime enable items --branch rtimp >/dev/null 2>&1
I=/tmp/rt-imported.ndjson
: > "$I"
( curl -skN --max-time 20 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/rtimp/realtime" | sed -u -n 's/^data: //p' >> "$I" ) &
STREAM=$!
sleep 6
sudo docker exec rtsrc psql -U postgres -q -c "INSERT INTO items VALUES (5,'e')" >/dev/null
for i in $(seq 1 20); do [ "$(pg pg-rtimp 'SELECT count(*) FROM items')" = 5 ] && break; sleep 1; done
wait "$STREAM" 2>/dev/null
assert_eq "a replicated-in row arrives on the change feed" \
  "$(have_in "$I" "e.get('type')=='change' and (e.get('identity') or {}).get('id')=='5'")" "yes"

"$S" realtime disable items --branch rtimp >/dev/null 2>&1
"$S" branch delete rtimp >/dev/null 2>&1
sudo docker rm -f rtsrc >/dev/null 2>&1

# ── 12. The neighbours: backups, and a failover that keeps the feed ─────────
echo
echo "12. backups and HA under logical decoding"

BEFORE_B="$("$S" backup list 2>/dev/null | grep -c 'base_')"
"$S" backup create >/dev/null 2>&1
assert_eq "a base backup is taken with the feed on" \
  "$("$S" backup list 2>/dev/null | grep -c 'base_')" "$((BEFORE_B + 1))"
VERIFY="$("$S" backup verify 2>&1)"; VRC=$?
assert_eq "…and a restore from it is proved to work" "$VRC" "0"
sudo docker rm -f pg-restore >/dev/null 2>&1

"$S" ha enable >/dev/null 2>&1; sleep 3
assert_eq "a standby streams from a logical primary" \
  "$(pg pg-main "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'")" "1"
# A standby is a primary in waiting, and its command line is fixed when its
# container is made. One built before `realtime setup` would come up after a
# failover unable to decode at all -- and RealtimeHAGuard then refuses the
# setup that would fix it until a failback, so the feed would be stuck off.
"$S" realtime teardown --yes >/dev/null 2>&1
"$S" realtime setup --yes >/dev/null 2>&1
main_ready
assert_eq "the standby picks up a setup that happened after it" \
  "$(pg pg-standby 'SHOW wal_level')" "logical"

"$S" realtime enable ok_t >/dev/null 2>&1
"$S" ha failover >/dev/null 2>&1; sleep 4
assert_eq "the promoted standby is the primary" "$(pg pg-standby 'SELECT pg_is_in_recovery()')" "f"
assert_eq "…and it is realtime-capable" "$(pg pg-standby 'SHOW wal_level')" "logical"
# Refused rather than attempted: teardown restarts the container now serving
# main, and would lower wal_level under a live feed. (`setup` is already on at
# this point and says "already set up" before it reaches the guard, which is
# right -- it changes nothing, so there is nothing to refuse. The guard itself
# is covered by TestRealtimeHAGuard.)
assert_contains "teardown is refused while failed over, and says what to run" \
  "$("$S" realtime teardown --yes 2>&1)" "ha failback"

# The feed on `main` now means the feed on the promoted standby, which is the
# situation RealtimeDSN resolves by address rather than by container name. A
# slot made on the old primary did not come across -- slots are not replicated
# -- so this also proves the decoder makes its own.
J=/tmp/rt-failover.ndjson
: > "$J"
( curl -skN --max-time 25 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/main/realtime" | sed -u -n 's/^data: //p' >> "$J" ) &
STREAM=$!
sleep 8
pg pg-standby "INSERT INTO public.ok_t VALUES (990002, 'after the failover', 'x')"
wait "$STREAM" 2>/dev/null
assert_eq "the feed follows main onto the promoted standby" \
  "$(have_in "$J" "e.get('type')=='change' and (e.get('identity') or {}).get('id')=='990002'")" "yes"

"$S" ha failback >/tmp/rt-failback.log 2>&1
assert_eq "failback puts main back" "$(pg pg-main 'SELECT pg_is_in_recovery()')" "f"
assert_eq "…still logical" "$(pg pg-main 'SHOW wal_level')" "logical"
assert_eq "…and keeps the write made on the standby" \
  "$(pg pg-main "SELECT count(*) FROM public.ok_t WHERE id=990002")" "1"
K=/tmp/rt-failedback.ndjson
: > "$K"
( curl -skN --max-time 20 -H "Authorization: Bearer $KEY" \
    "$API/api/branches/main/realtime" | sed -u -n 's/^data: //p' >> "$K" ) &
STREAM=$!
sleep 6
pg pg-main "INSERT INTO public.ok_t VALUES (990003, 'after the failback', 'x')"
wait "$STREAM" 2>/dev/null
assert_eq "and the feed comes back with it" \
  "$(have_in "$K" "e.get('type')=='change' and (e.get('identity') or {}).get('id')=='990003'")" "yes"
"$S" ha disable >/dev/null 2>&1


# ── 13. Teardown leaves the database working ─────────────────────────────────
echo
echo "13. teardown undoes it, and breaks nothing"
"$S" realtime teardown --yes >/dev/null 2>&1
main_ready
assert_eq "main is back to replica" "$(pg pg-main 'SHOW wal_level')" "replica"
assert_eq "no publications are left" \
  "$(pg pg-main "SELECT count(*) FROM pg_publication WHERE pubname LIKE 'fox_rt_%'")" "0"
# The point of the whole exercise: nothing it touched is worse off.
# A row of its own: section 7 empties this table, so reading one written in
# section 4 found nothing and the assertion failed for a reason that had no
# bearing on what it was testing.
pg pg-main "INSERT INTO public.ok_t VALUES (900, 'before', 'x') ON CONFLICT (id) DO NOTHING" >/dev/null
pg pg-main "UPDATE public.ok_t SET note='after' WHERE id=900" >/dev/null
assert_eq "UPDATE on a formerly-streamed table still works" \
  "$(pg pg-main "SELECT note FROM public.ok_t WHERE id=900")" "after"
pg pg-main "UPDATE public.nokey SET b='z' WHERE a=1" >/dev/null
assert_eq "and on the one that was set to FULL" \
  "$(pg pg-main "SELECT b FROM public.nokey WHERE a=1")" "z"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
