#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests deploy/install.sh against a fake release directory: the installer must
# verify every download against SHA256SUMS and install nothing it cannot check.
# Runs anywhere (no network, no GitHub):
#   bash scripts/test_install_sh.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
installer="$here/../deploy/install.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

os="$(uname -s)"; case "$os" in Darwin) os=darwin ;; Linux) os=linux ;; esac
arch="$(uname -m)"; case "$arch" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; esac
asset="fox-$os-$arch"
linux_asset="fox-linux-$arch"

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# A fake release: a "binary" that prints a version, plus its checksums.
rel="$tmp/release"
mkdir -p "$rel"
printf '#!/bin/sh\necho "fox 9.9.9"\n' > "$rel/$asset"
chmod +x "$rel/$asset"
cp "$rel/$asset" "$rel/$linux_asset"
{ printf '%s  %s\n' "$(sha "$rel/$asset")" "$asset"
  printf '%s  %s\n' "$(sha "$rel/$linux_asset")" "$linux_asset"; } > "$rel/SHA256SUMS"

run() { # run <prefix-dir> [env...]  -> installer output, exit code in $?
	local prefix="$1"; shift
	env FOX_BASE_URL="file://$rel" FOX_PREFIX="$prefix" "$@" sh "$installer" 2>&1
}

# 1. A good release installs and reports each file as verified.
p="$tmp/p1"; out="$(run "$p")"; code=$?
if [ "$code" = 0 ] && [ -x "$p/bin/fox" ] && grep -q "verified $asset" <<<"$out"; then
	ok "a verified release installs"
else
	bad "a verified release installs (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'
fi

# 2. A tampered binary must not be installed.
bad_rel="$tmp/tampered"; cp -r "$rel" "$bad_rel"
printf '#!/bin/sh\necho "evil"\n' > "$bad_rel/$asset"
p="$tmp/p2"; out="$(env FOX_BASE_URL="file://$bad_rel" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "checksum mismatch" <<<"$out"; then
	ok "a tampered download is refused and nothing is installed"
else
	bad "a tampered download is refused (exit $code, fox present: $([ -e "$p/bin/fox" ] && echo yes || echo no))"
fi

# 3. A release without SHA256SUMS must not install.
no_sums="$tmp/nosums"; cp -r "$rel" "$no_sums"; rm -f "$no_sums/SHA256SUMS"
p="$tmp/p3"; out="$(env FOX_BASE_URL="file://$no_sums" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "could not fetch SHA256SUMS" <<<"$out"; then
	ok "a release without SHA256SUMS is refused"
else
	bad "a release without SHA256SUMS is refused (exit $code)"
fi

# 4. An asset missing from the listing must not install.
gap="$tmp/gap"; cp -r "$rel" "$gap"
grep -v "  $asset\$" "$rel/SHA256SUMS" > "$gap/SHA256SUMS"
p="$tmp/p4"; out="$(env FOX_BASE_URL="file://$gap" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "not listed in SHA256SUMS" <<<"$out"; then
	ok "an asset missing from SHA256SUMS is refused"
else
	bad "an asset missing from SHA256SUMS is refused (exit $code)"
fi

# 5. FOX_NO_VERIFY=1 installs the tampered build deliberately.
p="$tmp/p5"; out="$(env FOX_BASE_URL="file://$bad_rel" FOX_PREFIX="$p" FOX_NO_VERIFY=1 sh "$installer" 2>&1)"; code=$?
if [ "$code" = 0 ] && [ -x "$p/bin/fox" ]; then
	ok "FOX_NO_VERIFY=1 installs without checking"
else
	bad "FOX_NO_VERIFY=1 installs without checking (exit $code)"
fi

# 6. A local build (FOX_DIST) still installs — there is no release to check.
p="$tmp/p6"; out="$(env FOX_DIST="$rel" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
if [ "$code" = 0 ] && [ -x "$p/bin/fox" ]; then
	ok "a local FOX_DIST build still installs"
else
	bad "a local FOX_DIST build still installs (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'
fi

echo
echo "install.sh: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
