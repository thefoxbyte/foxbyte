#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The release workflow's nightly gate (audit v2 G24). A gate that is wrong in
# either direction is worse than none: too strict and no release can be cut, too
# loose and a tag ships past a red suite. So the step's own shell is lifted out of
# release.yml and run here against fabricated API answers.
#
#   bash scripts/test_nightly_gate.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows/release.yml"
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# GNU date is what the runner has; without it the age arithmetic cannot be
# exercised here (macOS date takes different flags).
if ! date -u -d "2026-01-01T00:00:00Z" +%s >/dev/null 2>&1; then
	echo "skipping: this machine's date(1) is not GNU date, which the gate uses (it runs on ubuntu-latest)"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Lift the step's script out of the workflow, so the test cannot drift from
#    what actually runs.
python3 - "$WF" > "$TMP/gate.sh" <<'PY'
import re, sys
y = open(sys.argv[1]).read()
m = re.search(r'name: The newest nightly must be green, and recent.*?run: \|\n(.*?)\n\n', y, re.S)
if not m:
    sys.exit("could not find the gate step in release.yml")
indent = ' ' * 10
print('\n'.join(l[len(indent):] if l.startswith(indent) else l for l in m.group(1).split('\n')))
PY
[ -s "$TMP/gate.sh" ] || { echo "FAIL: the gate step could not be extracted from release.yml"; exit 1; }
bash -n "$TMP/gate.sh" || { echo "FAIL: the gate step is not valid shell"; exit 1; }

# 2. A stub `gh` that answers with whatever the case under test wants, and a git
#    repository with two commits so the ancestry check has something real to read.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Two calls now: the newest run, then that run's jobs. Routed on the path so the
# jobs check can be given a full matrix or a partial one independently.
#
# --jq is applied with real jq rather than ignored, so the filter in the gate is
# what gets exercised. Ignoring it made a full matrix look like a list of skipped
# suites — the fixture came back whole and every name was "missing".
fixture="$GATE_TEST_RUN_JSON"
case "$*" in */jobs*) fixture="${GATE_TEST_JOBS_JSON:-/dev/null}" ;; esac
filter=""
prev=""
for arg in "$@"; do
	[ "$prev" = "--jq" ] && filter="$arg"
	prev="$arg"
done
if [ -n "$filter" ]; then
	jq -r "$filter" < "$fixture"
else
	cat "$fixture"
fi
STUB
chmod +x "$TMP/bin/gh"

git init -q "$TMP/repo"
cd "$TMP/repo" || exit 1
git config user.email t@example.com; git config user.name t
echo one > a; git add a; git commit -qm one
OLD_SHA="$(git rev-parse HEAD)"
echo two > b; git add b; git commit -qm two
NEW_SHA="$(git rev-parse HEAD)"

# Every suite the nightly runs. A full run reports all of them; a run given a
# `suite` input skips the rest, which is what the gate must now refuse.
SUITES="integration ledger-v2 update pg-upgrade sdks ui"

jobs_json() { # <ran suite, or "all"> -> the jobs API's answer for that run
	local only="$1" name c first=1
	printf '{"jobs":['
	for name in $SUITES; do
		c=success
		[ "$only" = all ] || [ "$only" = "$name" ] || c=skipped
		[ "$first" = 1 ] || printf ','
		first=0
		printf '{"name":"suite (%s)","conclusion":"%s"}' "$name" "$c"
	done
	printf ']}\n'
}

run_gate() { # <json file> <allow_red> [jobs file] -> prints output, returns the exit status
	GATE_TEST_RUN_JSON="$1" ALLOW_RED="$2" GATE_TEST_JOBS_JSON="${3:-$TMP/jobs-all.json}" \
		MAX_AGE_HOURS=48 \
		GITHUB_REPOSITORY=thefoxbyte/foxbyte GH_TOKEN=x \
		PATH="$TMP/bin:$PATH" bash "$TMP/gate.sh" 2>&1
}
# Shaped like the real endpoint's answer, because the stub now applies the gate's
# own --jq filter: a bare run object would be filtered away by
# `.workflow_runs[0]` and read as "no nightly at all".
nightly_json() { # <conclusion> <hours ago> <head_sha>
	printf '{"workflow_runs":[{"id":4242,"conclusion":"%s","created_at":"%s","html_url":"https://example.invalid/run","head_sha":"%s"}]}\n' \
		"$1" "$(date -u -d "-$2 hours" +%Y-%m-%dT%H:%M:%SZ)" "$3"
}

jobs_json all > "$TMP/jobs-all.json"
jobs_json ui  > "$TMP/jobs-ui-only.json"

echo "### a green, recent nightly lets the release through"
nightly_json success 2 "$NEW_SHA" > "$TMP/green.json"
OUT="$(run_gate "$TMP/green.json" false)"; RC=$?
[ "$RC" = 0 ] && ok "exit 0 for a green nightly" || { bad "a green nightly was refused (exit $RC)"; echo "$OUT" | sed 's/^/      /'; }
grep -q "covered by that nightly run" <<<"$OUT" && ok "…and it says the tag is covered" || bad "…but it did not confirm coverage"

echo "### a red nightly stops it"
nightly_json failure 2 "$NEW_SHA" > "$TMP/red.json"
OUT="$(run_gate "$TMP/red.json" false)"; RC=$?
[ "$RC" != 0 ] && ok "exit non-zero for a red nightly" || bad "a red nightly was allowed through"
grep -q "concluded 'failure'" <<<"$OUT" && ok "…and says which conclusion" || bad "…but did not say why"

echo "### a stale nightly stops it, even when green"
nightly_json success 120 "$NEW_SHA" > "$TMP/stale.json"
OUT="$(run_gate "$TMP/stale.json" false)"; RC=$?
[ "$RC" != 0 ] && ok "exit non-zero for a nightly older than the limit" || bad "a five-day-old nightly was accepted"
grep -q "says little about this tag" <<<"$OUT" && ok "…and says it is too old" || bad "…but did not say it was stale"

echo "### no nightly at all stops it"
printf '{"workflow_runs":[]}\n' > "$TMP/none.json"
OUT="$(run_gate "$TMP/none.json" false)"; RC=$?
[ "$RC" != 0 ] && ok "exit non-zero when there is no nightly run" || bad "a release was allowed with no nightly run at all"
grep -q "no completed nightly run" <<<"$OUT" && ok "…and says how to get one" || bad "…but did not explain"

echo "### the manual override works, and is loud about it"
OUT="$(run_gate "$TMP/red.json" true)"; RC=$?
[ "$RC" = 0 ] && ok "allow_red_nightly releases past a red suite" || bad "the override did not work (exit $RC)"
grep -q "::warning::releasing past the nightly gate" <<<"$OUT" && ok "…and warns in the log" || bad "…silently"

echo "### a tag ahead of the nightly warns, but is not blocked"
# The nightly ran on the older commit; HEAD is the newer one.
nightly_json success 2 "$OLD_SHA" > "$TMP/ahead.json"
OUT="$(run_gate "$TMP/ahead.json" false)"; RC=$?
[ "$RC" = 0 ] && ok "a release cut after a merge is not blocked" || bad "being ahead of the nightly blocked the release"
grep -q "::warning::this tag has commits the newest nightly never ran" <<<"$OUT" && ok "…and says so" || bad "…without saying so"

echo "### a nightly that ran one suite is not evidence, however green"
# `nightly.yml` takes a `suite` input. A run of one suite skips the other five
# and still concludes 'success' — it would pass every other check here while
# having tested almost nothing, which is worse than a red gate because it looks
# like evidence. This is not hypothetical: it is how the ui suite was rerun on
# 29 Sep 2026, and that run became the newest nightly.
OUT="$(run_gate "$TMP/green.json" false "$TMP/jobs-ui-only.json")"; RC=$?
[ "$RC" != 0 ] && ok "a partial nightly is refused" || bad "a nightly that skipped five suites was accepted"
grep -q "ran only part of the matrix" <<<"$OUT" && ok "…and names the skipped suites" || bad "…without saying which"
grep -q "integration" <<<"$OUT" && ok "…listing integration among them" || bad "…but did not list them"

echo "### a full nightly still passes that check"
OUT="$(run_gate "$TMP/green.json" false "$TMP/jobs-all.json")"; RC=$?
[ "$RC" = 0 ] && ok "a full nightly is accepted" || { bad "a full nightly was refused (exit $RC)"; echo "$OUT" | sed 's/^/      /'; }
grep -q "every suite in that run reported" <<<"$OUT" && ok "…and says so" || bad "…without confirming it"

echo "### the override covers a partial run too, since it covers a red one"
OUT="$(run_gate "$TMP/green.json" true "$TMP/jobs-ui-only.json")"; RC=$?
[ "$RC" = 0 ] && ok "allow_red_nightly releases past a partial run" || bad "the override did not cover a partial run (exit $RC)"

echo
echo "nightly gate: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
