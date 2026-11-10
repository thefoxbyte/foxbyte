#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests scripts/release-checksums.sh against a fake `gh` that keeps the release's
# assets in a temporary directory. Runs anywhere (no GitHub access):
#   bash scripts/test_release_checksums.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-checksums.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1"; printf '    got:\n%s\n    want:\n%s\n' "$2" "$3"; fi; }

# --- fake gh --------------------------------------------------------------
# Supports exactly what the script uses:
#   gh release download <tag> -p <name> -O <dest> --clobber
#   gh release upload   <tag> <file>... --clobber
# STUB_RELEASE    directory holding the release's assets
# STUB_LOG        every call is appended here
# STUB_OVERWRITE  if set to a file, each upload is immediately replaced by that
#                 file's content, as if somebody else wrote the asset
# STUB_FAIL_UPLOAD  make every upload fail
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -eu
echo "gh $*" >> "$STUB_LOG"
[ "$1" = release ] || { echo "fake gh: unsupported: $*" >&2; exit 2; }
case "$2" in
download)
	dest="" name=""
	while [ $# -gt 0 ]; do [ "$1" = -O ] && dest="$2"; [ "$1" = -p ] && name="$2"; shift; done
	[ -f "$STUB_RELEASE/$name" ] || { echo "release has no $name" >&2; exit 1; }
	cp "$STUB_RELEASE/$name" "$dest"
	;;
upload)
	[ -z "${STUB_FAIL_UPLOAD:-}" ] || { echo "upload failed" >&2; exit 1; }
	shift 3
	first=""
	for f in "$@"; do
		[ "$f" = --clobber ] && continue
		cp "$f" "$STUB_RELEASE/$(basename "$f")"
		[ -n "$first" ] || first="$(basename "$f")"
	done
	[ -z "${STUB_OVERWRITE:-}" ] || cp "$STUB_OVERWRITE" "$STUB_RELEASE/$first"
	;;
*) echo "fake gh: unsupported: $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/gh"

# A stand-in for cmd/releasesign: the "signature" is the file's SHA-256, so the
# test can see exactly which bytes were signed. Every signed file is kept.
cat > "$tmp/bin/fakesign" <<'SIGNER'
#!/usr/bin/env bash
set -eu
h() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
case "$1" in
sign) h "$2" > "$3"; cat "$2" >> "$STUB_SIGNED"; echo "signed" >> "$STUB_LOG" ;;
verify) [ "$(h "$2")" = "$(cat "$3")" ] ;;
esac
SIGNER
chmod +x "$tmp/bin/fakesign"
export PATH="$tmp/bin:$PATH" CHECKSUM_SETTLE_SECONDS=0 RELEASE_SIGN="$tmp/bin/fakesign"

if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | awk '{print $1}'; }; else sum() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

# Assets of the two jobs, in their own dist directories.
mkdir -p "$tmp/rel" "$tmp/distro"
for f in fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz; do echo "content of $f" > "$tmp/rel/$f"; done
echo "content of the distro image" > "$tmp/distro/foxbyte-distro.tar.zst"

publish_release() { (cd "$tmp/rel" && bash "$script" v9.9.9 SHA256SUMS fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz) >/dev/null; }
publish_distro()  { (cd "$tmp/distro" && bash "$script" v9.9.9 SHA256SUMS.distro foxbyte-distro.tar.zst) >/dev/null; }
names() { awk '{print $2}' "$STUB_RELEASE/$1" | tr '\n' ' ' | sed 's/ $//'; }
new_release() {
	export STUB_RELEASE="$tmp/release-$1" STUB_LOG="$tmp/log-$1" STUB_SIGNED="$tmp/signed-$1"
	rm -rf "$STUB_RELEASE" "$STUB_LOG" "$STUB_SIGNED"
	mkdir -p "$STUB_RELEASE"
	: > "$STUB_LOG"
	: > "$STUB_SIGNED"
	unset STUB_OVERWRITE STUB_FAIL_UPLOAD
}
sig_matches() { [ -f "$STUB_RELEASE/$1.sig" ] && [ "$(sum "$STUB_RELEASE/$1")" = "$(cat "$STUB_RELEASE/$1.sig")" ] && echo yes || echo no; }

evil="$(printf 'e%.0s' $(seq 1 64))"

echo "### release-checksums.sh"

new_release first
publish_release
assert_eq "the release job's file lists exactly what it built" "$(names SHA256SUMS)" \
  "fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz"
assert_eq "…and it is signed" "$(sig_matches SHA256SUMS)" "yes"

publish_distro
assert_eq "the distro job writes its own file" "$(names SHA256SUMS.distro)" "foxbyte-distro.tar.zst"
assert_eq "…signed on its own" "$(sig_matches SHA256SUMS.distro)" "yes"
assert_eq "…and leaves SHA256SUMS and its signature alone" "$(names SHA256SUMS)|$(sig_matches SHA256SUMS)" \
  "fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz|yes"
release_then_distro="$(cat "$STUB_RELEASE/SHA256SUMS" "$STUB_RELEASE/SHA256SUMS.distro")"

new_release reversed
publish_distro
publish_release
assert_eq "the result doesn't depend on which job finishes first" \
  "$(cat "$STUB_RELEASE/SHA256SUMS" "$STUB_RELEASE/SHA256SUMS.distro")" "$release_then_distro"

# The finding itself: whatever is already on the release must never be signed.
new_release oracle
printf '%s  %s\n' "$evil" "fox-backdoor" > "$STUB_RELEASE/SHA256SUMS"
printf '%s  %s\n' "$evil" "fox-linux-amd64" >> "$STUB_RELEASE/SHA256SUMS"
publish_release
assert_eq "a line planted on the release is not signed" "$(grep -c "$evil" "$STUB_SIGNED")" "0"
assert_eq "…nor published" "$(grep -c "$evil" "$STUB_RELEASE/SHA256SUMS")" "0"
assert_eq "…and the planted file is replaced by the signed one" "$(names SHA256SUMS)|$(sig_matches SHA256SUMS)" \
  "fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz|yes"
assert_eq "signing happens before anything is read from the release" \
  "$(grep -n 'download\|signed' "$STUB_LOG" | head -1 | sed 's/^[0-9]*://')" "signed"

new_release rerun
publish_release
echo "changed binary" > "$tmp/rel/fox-linux-amd64"
publish_release
assert_eq "a re-run replaces its own entries" \
  "$(grep -c ' fox-linux-amd64$' "$STUB_RELEASE/SHA256SUMS")|$(grep ' fox-linux-amd64$' "$STUB_RELEASE/SHA256SUMS" | awk '{print $1}')|$(sig_matches SHA256SUMS)" \
  "1|$(sum "$tmp/rel/fox-linux-amd64")|yes"

new_release overwritten
printf '%s  %s\n' "$evil" "fox-linux-amd64" > "$tmp/other-writer.txt"
export STUB_OVERWRITE="$tmp/other-writer.txt"
(cd "$tmp/rel" && CHECKSUM_ATTEMPTS=2 bash "$script" v9.9.9 SHA256SUMS fox-linux-amd64) >/dev/null 2>&1
assert_eq "somebody else's file in its place fails the job" "$?" "1"
assert_eq "…and is still not signed" "$(grep -c "$evil" "$STUB_SIGNED")" "0"
unset STUB_OVERWRITE

new_release failing
export STUB_FAIL_UPLOAD=1
(cd "$tmp/rel" && bash "$script" v9.9.9 SHA256SUMS fox-linux-amd64) >/dev/null 2>&1
assert_eq "a failed upload fails the job" "$?" "1"
unset STUB_FAIL_UPLOAD

new_release nofile
(cd "$tmp/rel" && bash "$script" v9.9.9 SHA256SUMS no-such-file) >/dev/null 2>&1
assert_eq "a file this job did not build fails the job" "$?:$(ls "$STUB_RELEASE" | wc -l | tr -d ' ')" "1:0"

assert_eq "missing arguments are a usage error" "$(bash "$script" v9.9.9 SHA256SUMS >/dev/null 2>&1; echo $?)" "2"
assert_eq "no signer is an error, not an unsigned release" \
  "$(cd "$tmp/rel" && RELEASE_SIGN='' bash "$script" v9.9.9 SHA256SUMS fox-linux-amd64 >/dev/null 2>&1; echo $?)" "2"

echo
# The workflows must stay on this path: nothing may read a release's checksums
# back in order to rewrite them.
wf="$here/../.github/workflows"
assert_eq "no workflow reads SHA256SUMS back from a release" \
  "$(grep -lE 'gh release download.*SHA256SUMS' "$wf"/*.yml | wc -l | tr -d ' ')" "0"
assert_eq "only release.yml publishes SHA256SUMS" \
  "$(grep -lE 'release-checksums\.sh "\$TAG" SHA256SUMS |gh release upload.* SHA256SUMS' "$wf"/*.yml | xargs -n1 basename | tr '\n' ' ' | sed 's/ $//')" "release.yml"
assert_eq "wsl-distro.yml publishes its own file" \
  "$(grep -c 'release-checksums\.sh "\$TAG" SHA256SUMS\.distro ' "$wf/wsl-distro.yml")" "1"

echo "==== ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ]
