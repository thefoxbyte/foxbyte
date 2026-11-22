#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Release candidates in the release workflow. A tag like v2.3.0-rc.1 is built
# and published so it can be tested, but must never reach a user: it is not
# promoted to Latest, and it moves no image tag an install pulls. Wrong in one
# direction, a test build ships to everybody; in the other, a real release is
# never offered. So the steps' own shell is lifted out of release.yml and run
# here, and the conditions that guard promotion are checked as written.
#
#   bash scripts/test_release_candidate.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows/release.yml"
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# lift <step name> <job> <out>: the run: block of that step in that job.
lift() {
	python3 - "$WF" "$1" "$2" > "$3" <<'PY'
import re, sys
y = open(sys.argv[1]).read()
job = re.search(r'\n  ' + re.escape(sys.argv[3]) + r':\n(.*?)(?=\n  [a-z][a-z-]*:\n|\Z)', y, re.S)
if not job:
    sys.exit("no job " + sys.argv[3])
m = re.search(r'name: ' + re.escape(sys.argv[2]) + r'\n.*?run: \|\n(.*?)(?=\n\n|\n      - |\Z)', job.group(1), re.S)
if not m:
    sys.exit("no step '" + sys.argv[2] + "' in job " + sys.argv[3])
indent = ' ' * 10
print('\n'.join(l[len(indent):] if l.startswith(indent) else l for l in m.group(1).split('\n')))
PY
}

# 1. Which tags are candidates.
lift "Is this a release candidate" nightly-gate "$TMP/kind.sh" || { echo "FAIL: could not lift the candidate step"; exit 1; }
kind() {
	: > "$TMP/out"
	TAG="$1" GITHUB_OUTPUT="$TMP/out" bash "$TMP/kind.sh" >/dev/null
	sed -n 's/^candidate=//p' "$TMP/out"
}
for t in v2.3.0-rc.1 v2.3-rc.1 v3.0.0-beta.2 v2.3.0-rc1; do
	[ "$(kind "$t")" = true ] && ok "$t is a release candidate" || bad "$t should be a release candidate, got '$(kind "$t")'"
done
for t in v2.3.0 v2.3 v2.2.1 v10.0.0; do
	[ "$(kind "$t")" = false ] && ok "$t is a release" || bad "$t should be a release, got '$(kind "$t")'"
done

# 2. The image tags each one pushes.
tags() { # job step-env... -> the tag list, one per line
	local job="$1"; shift
	: > "$TMP/out"
	env "$@" GITHUB_OUTPUT="$TMP/out" bash "$TMP/$job.sh" >/dev/null
	sed -n '/^list<<EOF$/,/^EOF$/p' "$TMP/out" | sed '1d;$d'
}
lift "Choose the image's tags" image "$TMP/image.sh" || { echo "FAIL: could not lift the postgres tag step"; exit 1; }
lift "Choose the image's tags" vault-image "$TMP/vault.sh" || { echo "FAIL: could not lift the vault tag step"; exit 1; }

got="$(tags image PG=18 TAG=v2.3.0 CANDIDATE=false | tr '\n' ' ')"
[ "$got" = "ghcr.io/thefoxbyte/postgres-walg:18 ghcr.io/thefoxbyte/postgres-walg:18-v2.3.0 " ] \
	&& ok "a release moves postgres-walg:18 and adds its own tag" || bad "a release pushed: $got"
got="$(tags image PG=18 TAG=v2.3.0-rc.1 CANDIDATE=true | tr '\n' ' ')"
[ "$got" = "ghcr.io/thefoxbyte/postgres-walg:18-v2.3.0-rc.1 " ] \
	&& ok "a candidate pushes only postgres-walg:18-v2.3.0-rc.1" || bad "a candidate pushed: $got"
got="$(tags vault REV=3 TAG=v2.3.0 CANDIDATE=false | tr '\n' ' ')"
[ "$got" = "ghcr.io/thefoxbyte/fox-vault:3 ghcr.io/thefoxbyte/fox-vault:3-v2.3.0 " ] \
	&& ok "a release moves fox-vault:<rev> and adds its own tag" || bad "a release pushed: $got"
got="$(tags vault REV=3 TAG=v2.3.0-rc.1 CANDIDATE=true | tr '\n' ' ')"
[ "$got" = "ghcr.io/thefoxbyte/fox-vault:3-v2.3.0-rc.1 " ] \
	&& ok "a candidate pushes only fox-vault:<rev>-v2.3.0-rc.1" || bad "a candidate pushed: $got"

# 3. The guards, as written. Each image job must use the list it chose, and
#    promotion must be skipped for a candidate.
python3 - "$WF" > "$TMP/guards" <<'PY'
import re, sys
y = open(sys.argv[1]).read()
def job(name):
    m = re.search(r'\n  ' + re.escape(name) + r':\n(.*?)(?=\n  [a-z][a-z-]*:\n|\Z)', y, re.S)
    return m.group(1) if m else ''
gate = job('nightly-gate')
print('gate-output', 'candidate: ${{ steps.kind.outputs.candidate }}' in gate)
rv = job('release-verify')
print('verify-needs-gate', bool(re.search(r'needs: \[nightly-gate,', rv)))
promote = re.search(r'- name: Promote the release\n(.*?)run:', rv, re.S)
print('promote-guarded', bool(promote) and "if: needs.nightly-gate.outputs.candidate != 'true'" in promote.group(1))
print('promote-once', y.count('--prerelease=false') == 1)
for j in ('image', 'vault-image'):
    body = job(j)
    print(j + '-uses-list', 'tags: ${{ steps.tags.outputs.list }}' in body and 'CANDIDATE: ${{ needs.nightly-gate.outputs.candidate }}' in body)
PY
while read -r what result; do
	[ "$result" = True ] && ok "release.yml: $what" || bad "release.yml: $what"
done < "$TMP/guards"

# 4. The version release-verify looks for in `fox update`'s output.
python3 - "$WF" > "$TMP/want.sh" <<'PY'
import re, sys
y = open(sys.argv[1]).read()
m = re.search(r'\n(\s*)want="\$\{TAG#v\}"\n(.*?)\n\s*want="\$base\$pre"\n', y, re.S)
if not m:
    sys.exit("no want block")
print('want="${TAG#v}"')
print('\n'.join(l.strip() for l in m.group(2).split('\n') if not l.strip().startswith('#')))
print('want="$base$pre"')
print('echo "$want"')
PY
for pair in v2.3.0-rc.1=2.3.0-rc.1 v2.3-rc.1=2.3.0-rc.1 v2-rc.1=2.0.0-rc.1 v2.3.0=2.3.0 v2.0=2.0.0 v3=3.0.0; do
	t="${pair%%=*}"; want="${pair#*=}"
	got="$(TAG="$t" bash "$TMP/want.sh")"
	[ "$got" = "$want" ] && ok "$t is looked for as $want" || bad "$t is looked for as '$got', want $want"
done

echo
echo "release candidates: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
