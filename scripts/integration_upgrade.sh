#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The upgrade matrix: can a PREVIOUSLY RELEASED fox update to this build?
#
#   make integration-upgrade
#
# Every other suite has the current build do the updating, which is the wrong
# way round. `fox update` validates the engine it has staged by running its
# `version` and parsing what comes back, and the binary doing that parsing is
# the one ALREADY INSTALLED. v1.0 shipped a version line its predecessors could
# not parse, so no existing install could take it — and nothing noticed,
# because no suite ever let an old binary drive.
#
# So this builds each recent tag FROM ITS OWN SOURCE, which is where its own
# parser lives, points it at a fake release serving this build, and checks it
# gets past the staged-engine check.
#
# It stops there on purpose. On Linux that step needs no stack at all —
# stage() is a copy and output() just runs the file (internal/host/
# host_update_other.go) — so the whole suite is non-destructive: each version
# runs with a throwaway HOME, touches no install, and takes seconds.
#
# Published binaries cannot be used for this: they carry the real release
# public key and would refuse a fake release, and the private half exists only
# as a release secret. Their source is the next best thing, and is in fact the
# thing under test. The published artifacts are covered on the other side, by
# release.yml's release-verify job, which runs before a release is promoted.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(go env GOARCH)"
T="$(mktemp -d /tmp/foxupgrade.XXXXXX)"
PORT=18947
export FOX_UPDATE_BASE_URL="http://127.0.0.1:$PORT"
ENGINE="fox-linux-$ARCH"
MODULE="$(awk 'NR==1 {print $2}' "$ROOT/go.mod")"
# Newer than every real tag, so every old binary sees it as an upgrade. It is
# also the version line under test: "fox 9.99.0" and nothing after it.
CANDIDATE="9.99.0"
HOW_MANY="${FOX_UPGRADE_COUNT:-5}"
PASS=0
FAIL=0
SKIP=0
HTTP_PID=""
WORKTREES=()

ok()   { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

cleanup() {
	[ -n "$HTTP_PID" ] && { kill "$HTTP_PID" 2>/dev/null; wait "$HTTP_PID" 2>/dev/null; }
	for w in ${WORKTREES+"${WORKTREES[@]}"}; do
		git -C "$ROOT" worktree remove --force "$w" >/dev/null 2>&1
	done
	rm -rf "$T"
}
trap cleanup EXIT

echo "### the upgrade matrix: older releases updating to this build"
# Linux only, and loudly rather than silently. The step under test is the
# Linux engine host (the engine IS the host binary there, so staging is a copy);
# on macOS and Windows it goes through Lima or WSL and needs one running. A pass
# on the wrong platform would be worse than no suite at all.
if [ "$(uname -s)" != "Linux" ]; then
	echo "  this suite tests the Linux engine-host path and must run on Linux"
	echo "  (it runs in the nightly, and in the test VM via: make integration-upgrade)"
	exit 2
fi
command -v go >/dev/null 2>&1 || { echo "need go"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "need python3"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "need openssl"; exit 1; }

# Tags before the FoxByte rename are a different Go module, so their source
# cannot be built with this one's ldflags paths and their binaries are not this
# product's lineage. Comparing go.mod is how that is decided, rather than a
# hand-kept list that would quietly go stale.
echo
echo "1. which released versions are in this module's lineage"
# One pipeline, newline-separated. Accumulating into a space-joined string and
# splitting it again leans on unquoted word splitting, which bash does and zsh
# does not — run that way it quietly tested one version fewer than it reported.
TAGS="$(
	for t in $(git -C "$ROOT" for-each-ref --sort=-creatordate --format='%(refname:short)' 'refs/tags/v*' 2>/dev/null); do
		mod="$(git -C "$ROOT" show "$t:go.mod" 2>/dev/null | awk 'NR==1 {print $2}')"
		[ "$mod" = "$MODULE" ] && echo "$t"
	done | head -n "$HOW_MANY"
)"
if [ -z "$TAGS" ]; then
	echo "  FAIL: no tag shares this module path ($MODULE) — is this a shallow clone with no tags?"
	echo "        a nightly must fetch tags (actions/checkout fetch-depth: 0) or this suite tests nothing."
	exit 1
fi
ok "testing updates from: $(printf '%s' "$TAGS" | tr '\n' ' ')"

echo
echo "2. build this tree as the release they will update to"
openssl genpkey -algorithm ed25519 -out "$T/release.key" 2>/dev/null
RELEASE_PUB="$(openssl pkey -in "$T/release.key" -pubout -outform DER 2>/dev/null | tail -c 32 | base64)"
mkdir -p "$T/www/dl/v$CANDIDATE"
if (cd "$ROOT" && go build \
	-ldflags "-X $MODULE/internal/version.Version=$CANDIDATE -X $MODULE/internal/update.releasePublicKey=$RELEASE_PUB" \
	-o "$T/www/dl/v$CANDIDATE/$ENGINE" ./cmd/fox); then
	ok "built the candidate engine ($ENGINE at $CANDIDATE)"
else
	bad "could not build this tree"; exit 1
fi
# The line every old parser has to read. Printed because when this suite fails,
# this is the thing to look at first.
echo "     its version line: '$("$T/www/dl/v$CANDIDATE/$ENGINE" version)'"

python3 - "$FOX_UPDATE_BASE_URL" "$T/www" "$ENGINE" "$T/release.key" "v$CANDIDATE" <<'PY'
import hashlib, json, os, subprocess, sys
base, www, engine, key, tag = sys.argv[1:6]
d = os.path.join(www, "dl", tag)
sums = hashlib.sha256(open(os.path.join(d, engine), "rb").read()).hexdigest() + "  " + engine + "\n"
open(os.path.join(d, "SHA256SUMS"), "w").write(sums)
subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin",
                "-in", os.path.join(d, "SHA256SUMS"), "-out", os.path.join(d, "SHA256SUMS.sig")], check=True)
assets = [{"name": n, "size": os.path.getsize(os.path.join(d, n)),
           "browser_download_url": f"{base}/dl/{tag}/{n}"}
          for n in (engine, "SHA256SUMS", "SHA256SUMS.sig")]
rel = {"tag_name": tag, "draft": False, "prerelease": False,
       "html_url": f"{base}/releases/tag/{tag}", "assets": assets}
os.makedirs(os.path.join(www, "repos/thefoxbyte/foxbyte"), exist_ok=True)
json.dump([rel], open(os.path.join(www, "repos/thefoxbyte/foxbyte/releases"), "w"))
PY

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$T/www" >/dev/null 2>&1 &
HTTP_PID=$!
for _ in $(seq 50); do
	curl -sf "$FOX_UPDATE_BASE_URL/repos/thefoxbyte/foxbyte/releases" >/dev/null && break
	sleep 0.2
done

echo
echo "3. each released version updates to it"
# read rather than `for tag in $TAGS`, for the same reason as the selection
# above: splitting an unquoted variable is bash behaviour and not every
# shell's, and the cost of getting it wrong is a suite that silently tests
# fewer versions than it says it did.
while IFS= read -r tag; do
	[ -n "$tag" ] || continue
	src="$T/src/$tag"
	if ! git -C "$ROOT" worktree add --detach -q "$src" "$tag" 2>"$T/wt-$tag.log"; then
		skip "$tag — could not check out its source ($(tail -n1 "$T/wt-$tag.log"))"
		continue
	fi
	WORKTREES+=("$src")
	old="$T/fox-$tag"
	if ! (cd "$src" && go build \
		-ldflags "-X $MODULE/internal/version.Version=${tag#v} -X $MODULE/internal/update.releasePublicKey=$RELEASE_PUB" \
		-o "$old" ./cmd/fox) 2>"$T/build-$tag.log"; then
		# A tag that no longer builds must not block every future release, so
		# this is a visible skip rather than a failure. If they all skip, the
		# count at the end fails the suite.
		skip "$tag — its source no longer builds ($(tail -n1 "$T/build-$tag.log"))"
		continue
	fi
	# A throwaway HOME per version, so an update touches no real install: `fox`
	# keeps its state in ~/.fox and stages downloads under it. Set per command,
	# never exported — Go resolves its module cache from HOME too, so exporting
	# it here broke every build after the first.
	fhome="$T/home-$tag"
	mkdir -p "$fhome"

	# Self-check first: if this build does not honour FOX_UPDATE_BASE_URL it
	# would quietly ask the real GitHub instead, and a pass would mean nothing.
	check="$(HOME="$fhome" "$old" update --check 2>&1)"
	if ! grep -qF "$CANDIDATE" <<<"$check"; then
		skip "$tag — does not see the fake release, so it would have asked the real GitHub: $(head -n2 <<<"$check" | tr '\n' ' ')"
		continue
	fi

	out="$(HOME="$fhome" "$old" update --yes 2>&1)"
	if grep -qF "engine $CANDIDATE runs" <<<"$out"; then
		ok "$tag → $CANDIDATE: the staged engine is accepted"
	elif grep -qF "doesn't run" <<<"$out"; then
		bad "$tag → $CANDIDATE: REFUSED the new engine — an install on $tag cannot update to this build"
		grep -F "doesn't run" <<<"$out" | sed 's/^/      /'
	else
		bad "$tag → $CANDIDATE: never reached the staged-engine check"
		tail -n 8 <<<"$out" | sed 's/^/      /'
	fi
done <<<"$TAGS"

echo
echo "### $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$PASS" = 0 ]; then
	echo "no version was actually exercised — treating that as a failure, because a"
	echo "suite that skips everything looks like evidence and is not."
	exit 1
fi
[ "$FAIL" = 0 ] || exit 1
