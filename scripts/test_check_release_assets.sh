#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests scripts/check-release-assets.sh against a fake `gh`. Runs anywhere:
#   bash scripts/test_check_release_assets.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-release-assets.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# fake gh: STUB_RELEASE holds `assets` (one attached name per line) and SHA256SUMS.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -eu
case "$1 $2" in
"release view") cat "$STUB_RELEASE/assets" ;;
"release download")
	dest=""
	while [ $# -gt 0 ]; do [ "$1" = -O ] && dest="$2"; shift; done
	cp "$STUB_RELEASE/SHA256SUMS" "$dest"
	;;
*) echo "fake gh: unsupported: $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" STUB_RELEASE="$tmp/rel" CHECK_RETRY_SLEEP=0
mkdir -p "$tmp/rel"

all="fox-darwin-arm64 fox-darwin-amd64 fox-linux-arm64 fox-linux-amd64 fox-windows-amd64.exe foxbyte-docker-context.tar.gz"
sum="$(printf 'a%.0s' $(seq 64))"
publish() { # publish "<attached names>" "<listed names>"
	printf '%s\n' $1 SHA256SUMS fox-verify-linux-amd64 > "$tmp/rel/assets"
	: > "$tmp/rel/SHA256SUMS"
	for n in $2; do printf '%s  %s\n' "$sum" "$n" >> "$tmp/rel/SHA256SUMS"; done
}
expect() { # expect <description> <exit code> [text in output]
	local out code
	out="$(bash "$script" v9.9.9 2>&1)"; code=$?
	if [ "$code" = "$2" ] && { [ -z "${3:-}" ] || grep -qF "$3" <<<"$out"; }; then ok "$1"; else bad "$1 (exit $code)"; echo "$out"; fi
}

publish "$all" "$all"
expect "a complete release passes" 0 "every file fox update needs"

publish "${all/fox-linux-arm64 /}" "$all"
expect "a missing attachment fails" 1 "missing fox-linux-arm64"

publish "$all" "${all/fox-windows-amd64.exe /}"
expect "an unlisted checksum fails" 1 "doesn't list fox-windows-amd64.exe"

publish "$all" "$all"
sed -i.bak 's/  fox-darwin-arm64$/ *fox-darwin-arm64/' "$tmp/rel/SHA256SUMS"
printf '%s  fox-linux-amd64\r\n' "$sum" >> "$tmp/rel/SHA256SUMS"
expect "binary-mode and CRLF lines count as listed" 0

publish "$all" "$all"
grep -vx SHA256SUMS "$tmp/rel/assets" > "$tmp/rel/a" && mv "$tmp/rel/a" "$tmp/rel/assets"
expect "a release without SHA256SUMS fails" 1 "has no SHA256SUMS"

echo "check-release-assets: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
