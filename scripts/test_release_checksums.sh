#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests scripts/release-checksums.sh against a fake `gh` that keeps the release's
# SHA256SUMS in a temporary directory. Runs anywhere (no GitHub access):
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
#   gh release download <tag> -p SHA256SUMS -O <dest> --clobber
#   gh release upload   <tag> <file> --clobber
# STUB_RELEASE    directory holding the release's SHA256SUMS
# STUB_OVERWRITE  if set to a file, the first upload is immediately replaced by
#                 that file's content, as if another job uploaded at that moment
# STUB_FAIL_UPLOAD  make every upload fail
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -eu
[ "$1" = release ] || { echo "fake gh: unsupported: $*" >&2; exit 2; }
case "$2" in
download)
	dest=""
	while [ $# -gt 0 ]; do [ "$1" = -O ] && dest="$2"; shift; done
	[ -f "$STUB_RELEASE/SHA256SUMS" ] || { echo "release has no SHA256SUMS" >&2; exit 1; }
	cp "$STUB_RELEASE/SHA256SUMS" "$dest"
	;;
upload)
	[ -z "${STUB_FAIL_UPLOAD:-}" ] || { echo "upload failed" >&2; exit 1; }
	cp "$4" "$STUB_RELEASE/SHA256SUMS"
	if [ -n "${STUB_OVERWRITE:-}" ] && [ ! -f "$STUB_RELEASE/.overwritten" ]; then
		cp "$STUB_OVERWRITE" "$STUB_RELEASE/SHA256SUMS"
		touch "$STUB_RELEASE/.overwritten"
	fi
	;;
*) echo "fake gh: unsupported: $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" CHECKSUM_SETTLE_SECONDS=0

if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | awk '{print $1}'; }; else sum() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

# Assets of the two jobs, in their own dist directories.
mkdir -p "$tmp/rel" "$tmp/distro"
for f in fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz; do echo "content of $f" > "$tmp/rel/$f"; done
echo "content of the distro image" > "$tmp/distro/foxbyte-distro.tar.gz"

publish_release() { (cd "$tmp/rel" && bash "$script" v9.9.9 fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz) >/dev/null; }
publish_distro()  { (cd "$tmp/distro" && bash "$script" v9.9.9 foxbyte-distro.tar.gz) >/dev/null; }
names() { awk '{print $2}' "$STUB_RELEASE/SHA256SUMS" | tr '\n' ' ' | sed 's/ $//'; }
new_release() { export STUB_RELEASE="$tmp/release-$1"; rm -rf "$STUB_RELEASE"; mkdir -p "$STUB_RELEASE"; unset STUB_OVERWRITE STUB_FAIL_UPLOAD; }

echo "### release-checksums.sh"

new_release first
publish_release
assert_eq "a release without SHA256SUMS gets this job's entries" "$(names)" \
  "fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz"

publish_distro
assert_eq "the second job adds its entry and keeps the first job's" "$(names)" \
  "fox-linux-amd64 fox-verify-linux-amd64 foxbyte-distro.tar.gz foxbyte-docker-context.tar.gz"
release_then_distro="$(cat "$STUB_RELEASE/SHA256SUMS")"

new_release reversed
publish_distro
publish_release
assert_eq "the result doesn't depend on which job finishes first" "$(cat "$STUB_RELEASE/SHA256SUMS")" "$release_then_distro"

echo "changed binary" > "$tmp/rel/fox-linux-amd64"
publish_release
assert_eq "a re-run replaces its own entry without duplicating it" \
  "$(grep -c ' fox-linux-amd64$' "$STUB_RELEASE/SHA256SUMS")|$(grep ' fox-linux-amd64$' "$STUB_RELEASE/SHA256SUMS" | awk '{print $1}')|$(wc -l < "$STUB_RELEASE/SHA256SUMS" | tr -d ' ')" \
  "1|$(sum "$tmp/rel/fox-linux-amd64")|4"
assert_eq "…and leaves the other job's entry untouched" \
  "$(grep ' foxbyte-distro.tar.gz$' "$STUB_RELEASE/SHA256SUMS" | awk '{print $1}')" "$(sum "$tmp/distro/foxbyte-distro.tar.gz")"

new_release exact
printf '%s  %s\n' "$(printf 'a%.0s' $(seq 1 64))" "fox-linux-amd64.sig" > "$STUB_RELEASE/SHA256SUMS"
publish_release
assert_eq "entries are matched by exact name (fox-linux-amd64.sig survives)" "$(names)" \
  "fox-linux-amd64 fox-linux-amd64.sig fox-verify-linux-amd64 foxbyte-docker-context.tar.gz"

new_release race
printf '%s  %s\n' "$(printf 'b%.0s' $(seq 1 64))" "foxbyte-distro.tar.gz" > "$tmp/other-job.txt"
export STUB_OVERWRITE="$tmp/other-job.txt"
out="$( (cd "$tmp/rel" && bash "$script" v9.9.9 fox-linux-amd64 fox-verify-linux-amd64 foxbyte-docker-context.tar.gz) 2>&1 >/dev/null)"
assert_eq "another job uploading at the same moment is detected and merged again" \
  "$(echo "$out" | grep -c 'merging again')|$(names)" \
  "1|fox-linux-amd64 fox-verify-linux-amd64 foxbyte-distro.tar.gz foxbyte-docker-context.tar.gz"

new_release failing
export STUB_FAIL_UPLOAD=1
(cd "$tmp/rel" && bash "$script" v9.9.9 fox-linux-amd64) >/dev/null 2>&1
assert_eq "a failed upload fails the job" "$?" "1"
unset STUB_FAIL_UPLOAD

assert_eq "missing arguments are a usage error" "$(bash "$script" v9.9.9 >/dev/null 2>&1; echo $?)" "2"

echo
echo "==== ${PASS} passed, ${FAIL} failed ===="
[ "$FAIL" -eq 0 ]
