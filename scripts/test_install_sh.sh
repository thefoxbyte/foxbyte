#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests deploy/install.sh against a fake release directory: the installer must
# verify every download against SHA256SUMS and install nothing it cannot check.
# Runs anywhere (no network, no GitHub):
#   bash scripts/test_install_sh.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
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
# On Linux amd64 the host asset and the VM's engine are the same file.
[ "$asset" = "$linux_asset" ] || cp "$rel/$asset" "$rel/$linux_asset"
zeros="$(printf '0%.0s' $(seq 1 64))"
# The first line names the release (SUP-4), as scripts/release-checksums.sh writes it.
{ printf '%s  VERSION=v9.9.9\n' "$zeros"
  { printf '%s  %s\n' "$(sha "$rel/$asset")" "$asset"
    printf '%s  %s\n' "$(sha "$rel/$linux_asset")" "$linux_asset"; } | sort -u; } > "$rel/SHA256SUMS"

# Signatures (audit v2 G22). A test release key, and a copy of the installer
# that trusts it instead of the real one. Where openssl cannot do Ed25519
# (macOS's LibreSSL), the installer can only warn, and that is what is tested.
if command -v openssl >/dev/null 2>&1 && openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519; then
	CAN_SIGN=1
else
	CAN_SIGN=0
fi
installer="$tmp/install.sh"
if [ "$CAN_SIGN" = 1 ]; then
	openssl genpkey -algorithm ed25519 -out "$tmp/key.pem" 2>/dev/null
	openssl pkey -in "$tmp/key.pem" -pubout -out "$tmp/pub.pem" 2>/dev/null
	openssl genpkey -algorithm ed25519 -out "$tmp/other.pem" 2>/dev/null
	sign() { openssl pkeyutl -sign -inkey "${2:-$tmp/key.pem}" -rawin -in "$1/SHA256SUMS" -out "$1/SHA256SUMS.sig"; }
	sign "$rel"
	PUB="$(cat "$tmp/pub.pem")"
else
	sign() { head -c 64 /dev/zero > "$1/SHA256SUMS.sig"; }
	sign "$rel"
	PUB='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END PUBLIC KEY-----'
fi
PUB="$PUB" python3 - "$here/../deploy/install.sh" "$installer" <<'PY'
import os, re, sys
s = open(sys.argv[1]).read()
s = re.sub(r"RELEASE_PUBLIC_KEY='[^']*'", "RELEASE_PUBLIC_KEY='" + os.environ["PUB"] + "'", s, count=1)
open(sys.argv[2], "w").write(s)
PY

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
# (the binary changes, SHA256SUMS and its signature do not)
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
# Without the host asset — but not empty: openssl cannot sign an empty file,
# and on Linux amd64 the two assets are one name, so removing it removes all.
{ grep -v "  $asset\$" "$rel/SHA256SUMS"; printf '%s  %s\n' "$(sha "$rel/SHA256SUMS")" other-file; } > "$gap/SHA256SUMS"
sign "$gap"   # a properly signed listing that simply leaves the file out
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

# 7–10. Who published it: the signature over SHA256SUMS.
if [ "$CAN_SIGN" = 1 ]; then
	if grep -q "signed with the FoxByte release key" <<<"$(run "$tmp/p7")"; then
		ok "a release signed with the release key says so"
	else
		bad "a release signed with the release key says so"
	fi
	forged="$tmp/forged"; cp -r "$rel" "$forged"; sign "$forged" "$tmp/other.pem"
	p="$tmp/p8"; out="$(env FOX_BASE_URL="file://$forged" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
	if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "not signed with the FoxByte release key" <<<"$out"; then
		ok "a release signed with another key is refused"
	else
		bad "a release signed with another key is refused (exit $code)"
	fi
	# A whole release replaced, checksums included, still fails: it cannot be re-signed.
	swapped="$tmp/swapped"; cp -r "$bad_rel" "$swapped"
	{ printf '%s  %s\n' "$(sha "$swapped/$asset")" "$asset"; printf '%s  %s\n' "$(sha "$swapped/$linux_asset")" "$linux_asset"; } > "$swapped/SHA256SUMS"
	p="$tmp/p9"; out="$(env FOX_BASE_URL="file://$swapped" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
	if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ]; then
		ok "a binary replaced together with its checksum is refused"
	else
		bad "a binary replaced together with its checksum is refused (exit $code)"
	fi
else
	out="$(run "$tmp/p7")"; code=$?
	if [ "$code" = 0 ] && grep -q "signature of .* was not checked" <<<"$out"; then
		ok "where openssl cannot check Ed25519, the install warns"
	else
		bad "where openssl cannot check Ed25519, the install warns (exit $code)"
	fi
	p="$tmp/p8"; out="$(run "$p" FOX_REQUIRE_SIGNATURE=1)"; code=$?
	if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ]; then
		ok "…and FOX_REQUIRE_SIGNATURE=1 refuses"
	else
		bad "…and FOX_REQUIRE_SIGNATURE=1 refuses (exit $code)"
	fi
fi
unsigned="$tmp/unsigned"; cp -r "$rel" "$unsigned"; rm -f "$unsigned/SHA256SUMS.sig"
p="$tmp/p10"; out="$(env FOX_BASE_URL="file://$unsigned" FOX_PREFIX="$p" sh "$installer" 2>&1)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "has no SHA256SUMS.sig" <<<"$out"; then
	ok "an unsigned release is refused"
else
	bad "an unsigned release is refused (exit $code)"
fi
p="$tmp/p11"; out="$(env FOX_BASE_URL="file://$unsigned" FOX_PREFIX="$p" FOX_ALLOW_UNSIGNED=1 sh "$installer" 2>&1)"; code=$?
if [ "$code" = 0 ] && [ -x "$p/bin/fox" ]; then
	ok "FOX_ALLOW_UNSIGNED=1 installs it on checksums alone"
else
	bad "FOX_ALLOW_UNSIGNED=1 installs it on checksums alone (exit $code)"
fi

# 26–31. The signed version line (SUP-4), held to the tag being installed.
# FOX_VERSION names the tag; FOX_BASE_URL still points at the fake release.
# Each variant is re-signed, so only the version check can refuse it.
relver() { # relver <dir> <version line or "">: a copy of the release, re-signed
	cp -r "$rel" "$1"
	grep -v 'VERSION=' "$rel/SHA256SUMS" > "$1/SHA256SUMS"
	if [ -n "$2" ]; then { printf '%s  VERSION=%s\n' "$zeros" "$2"; cat "$1/SHA256SUMS"; } > "$1/s" && mv "$1/s" "$1/SHA256SUMS"; fi
	sign "$1"
}
vrun() { local dir="$1" p="$2"; shift 2; env FOX_BASE_URL="file://$dir" FOX_PREFIX="$p" "$@" sh "$installer" 2>&1; }
p="$tmp/p26"; out="$(vrun "$rel" "$p" FOX_VERSION=v9.9.9)"; code=$?
if [ "$code" = 0 ] && [ -x "$p/bin/fox" ]; then ok "a release whose signed version is its tag installs"; else bad "a release whose signed version is its tag installs (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'; fi
relver "$tmp/retag" v2.0.1
p="$tmp/p27"; out="$(vrun "$tmp/retag" "$p" FOX_VERSION=v99.0.0)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "is signed for v2.0.1" <<<"$out"; then ok "an old release under a newer tag is refused"; else bad "an old release under a newer tag is refused (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'; fi
relver "$tmp/unversioned" ""
p="$tmp/p28"; out="$(vrun "$tmp/unversioned" "$p" FOX_VERSION=v2.3.0)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "does not say which version" <<<"$out"; then ok "a release from the cutoff on without the line is refused"; else bad "a release from the cutoff on without the line is refused (exit $code)"; fi
p="$tmp/p29"; out="$(vrun "$tmp/unversioned" "$p" FOX_VERSION=v2.2.1)"; code=$?
if [ "$code" = 0 ] && [ -x "$p/bin/fox" ]; then ok "an older release, which never had the line, installs by FOX_VERSION"; else bad "an older release installs by FOX_VERSION (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'; fi
cp -r "$rel" "$tmp/twover"; printf '%s  VERSION=v2.0.1\n' "$zeros" >> "$tmp/twover/SHA256SUMS"; sign "$tmp/twover"
p="$tmp/p30"; out="$(vrun "$tmp/twover" "$p" FOX_VERSION=v9.9.9)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "more than one version" <<<"$out"; then ok "a listing naming two versions is refused"; else bad "a listing naming two versions is refused (exit $code)"; fi
if grep -q 'FIRST_VERSIONED_RELEASE="2.3.0"' "$installer" && grep -q 'const FirstVersionedRelease = "2.3.0"' "$here/../internal/update/select.go" \
	&& grep -q "\$FirstVersionedRelease = '2.3.0'" "$here/../deploy/install.ps1"; then
	ok "install.sh, install.ps1 and fox agree on the first versioned release"
else
	bad "install.sh, install.ps1 and fox agree on the first versioned release"
fi

# 32–37. The P-256 signature (SUP-5), where openssl cannot do Ed25519. The
# stand-in openssl below behaves as macOS's LibreSSL does here: it has no
# Ed25519, and checks ECDSA with `dgst -verify`. Every key is a throwaway.
if command -v openssl >/dev/null 2>&1 && openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/p256.pem" 2>/dev/null; then
	real_openssl="$(command -v openssl)"
	openssl ec -in "$tmp/p256.pem" -pubout -out "$tmp/p256pub.pem" 2>/dev/null
	openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/p256other.pem" 2>/dev/null
	sign_p256() { openssl dgst -sha256 -sign "${2:-$tmp/p256.pem}" -out "$1/SHA256SUMS.p256.sig" "$1/SHA256SUMS"; }
	mkdir -p "$tmp/libressl"
	cat > "$tmp/libressl/openssl" <<EOF
#!/bin/sh
case "\$1" in
	list|pkeyutl) echo "openssl: no Ed25519 here" >&2; exit 1 ;;
esac
exec "$real_openssl" "\$@"
EOF
	chmod +x "$tmp/libressl/openssl"
	P256PUB="$(cat "$tmp/p256pub.pem")" python3 - "$installer" "$tmp/install-p256.sh" <<'PY'
import os, re, sys
s = open(sys.argv[1]).read()
s, n = re.subn(r"RELEASE_P256_PUBLIC_KEY='[^']*'", "RELEASE_P256_PUBLIC_KEY='" + os.environ["P256PUB"] + "'", s, count=1)
assert n == 1, "no RELEASE_P256_PUBLIC_KEY in install.sh"
open(sys.argv[2], "w").write(s)
PY
	lrun() { local inst="$1" dir="$2" p="$3"; shift 3; env PATH="$tmp/libressl:$PATH" FOX_BASE_URL="file://$dir" FOX_PREFIX="$p" "$@" sh "$inst" 2>&1; }
	p256rel="$tmp/p256rel"; cp -r "$rel" "$p256rel"; sign_p256 "$p256rel"

	p="$tmp/p32"; out="$(lrun "$installer" "$p256rel" "$p")"; code=$?
	if [ "$code" = 0 ] && [ -x "$p/bin/fox" ] && grep -q "signature of .* was not checked" <<<"$out"; then
		ok "with no P-256 key pinned yet, a LibreSSL machine still installs with a warning"
	else
		bad "with no P-256 key pinned yet, a LibreSSL machine installs with a warning (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'
	fi
	p="$tmp/p33"; out="$(lrun "$tmp/install-p256.sh" "$p256rel" "$p")"; code=$?
	if [ "$code" = 0 ] && [ -x "$p/bin/fox" ] && grep -q "signed with the FoxByte release key (P-256)" <<<"$out"; then
		ok "once the P-256 key is pinned, a LibreSSL machine checks it and installs"
	else
		bad "a LibreSSL machine checks the P-256 signature (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'
	fi
	forged256="$tmp/forged256"; cp -r "$rel" "$forged256"; sign_p256 "$forged256" "$tmp/p256other.pem"
	p="$tmp/p34"; out="$(lrun "$tmp/install-p256.sh" "$forged256" "$p")"; code=$?
	if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "not signed with the FoxByte P-256 release key" <<<"$out"; then
		ok "a P-256 signature by another key is refused"
	else
		bad "a P-256 signature by another key is refused (exit $code)"
	fi
	p="$tmp/p35"; out="$(lrun "$tmp/install-p256.sh" "$rel" "$p")"; code=$?
	if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "has no SHA256SUMS.p256.sig" <<<"$out"; then
		ok "once the key is pinned, a release this machine cannot check is refused (fails closed)"
	else
		bad "a release with no P-256 signature fails closed (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'
	fi
	p="$tmp/p36"; out="$(lrun "$tmp/install-p256.sh" "$rel" "$p" FOX_ALLOW_UNSIGNED=1)"; code=$?
	if [ "$code" = 0 ] && [ -x "$p/bin/fox" ]; then
		ok "…unless FOX_ALLOW_UNSIGNED=1"
	else
		bad "…unless FOX_ALLOW_UNSIGNED=1 (exit $code)"
	fi
	if [ "$CAN_SIGN" = 1 ]; then
		# With OpenSSL 3, Ed25519 is checked first, and a release without the
		# P-256 signature still installs.
		p="$tmp/p37"; out="$(env FOX_BASE_URL="file://$rel" FOX_PREFIX="$p" sh "$tmp/install-p256.sh" 2>&1)"; code=$?
		if [ "$code" = 0 ] && [ -x "$p/bin/fox" ] && grep -q "signed with the FoxByte release key$" <<<"$out"; then
			ok "where Ed25519 can be checked, it is checked first"
		else
			bad "where Ed25519 can be checked, it is checked first (exit $code)"; tail -n 5 <<<"$out" | sed 's/^/      /'
		fi
	fi
else
	echo "  SKIP: no openssl with P-256 here"
fi

# 12–19, 21–25. macOS: Lima, then `fox setup`. Run on any machine as an Apple Silicon
# Mac: uname, sw_vers and brew are stand-ins on PATH, the release has the
# darwin assets, and Lima's archive is a fake whose checksum replaces the
# pinned one in a copy of the installer.
mac="$tmp/mac"; mkdir -p "$mac/rel" "$mac/lima/bin"
setup_log="$mac/setup.log"
# The fake fox logs each `setup` it is asked for, and what Lima it could see.
# `setup --which` names the VM setup would use: FOX_TEST_VM (fox), and
# FOX_TEST_VM_STATE (new), as the real one reads them from Lima.
cat > "$mac/rel/fox-darwin-arm64" <<'EOF'
#!/bin/sh
if [ "${1:-}" = setup ] && [ "${2:-}" = --which ]; then echo "${FOX_TEST_VM:-fox} ${FOX_TEST_VM_STATE:-new}"; exit 0; fi
if [ "${1:-}" = setup ]; then echo "setup limactl=$(command -v limactl || echo none)" >> "$FOX_TEST_SETUP_LOG"; exit "${FOX_TEST_SETUP_EXIT:-0}"; fi
echo "fox 9.9.9"
EOF
chmod +x "$mac/rel/fox-darwin-arm64"
cp "$mac/rel/fox-darwin-arm64" "$mac/rel/fox-linux-arm64"
{ printf '%s  %s\n' "$(sha "$mac/rel/fox-darwin-arm64")" fox-darwin-arm64
  printf '%s  %s\n' "$(sha "$mac/rel/fox-linux-arm64")" fox-linux-arm64; } > "$mac/rel/SHA256SUMS"
sign "$mac/rel"
printf '#!/bin/sh\necho "limactl version 2.2.1"\n' > "$mac/lima/bin/limactl"; chmod +x "$mac/lima/bin/limactl"
mkdir -p "$mac/lima/share/lima"; echo template > "$mac/lima/share/lima/ubuntu.yaml"
mkdir -p "$mac/limarel" "$mac/badlima"
tar -czf "$mac/limarel/lima-2.2.1-Darwin-arm64.tar.gz" -C "$mac/lima" .
cp "$mac/limarel/lima-2.2.1-Darwin-arm64.tar.gz" "$mac/badlima/"; echo junk >> "$mac/badlima/lima-2.2.1-Darwin-arm64.tar.gz"
macinstaller="$mac/install.sh"
LIMASUM="$(sha "$mac/limarel/lima-2.2.1-Darwin-arm64.tar.gz")" python3 - "$installer" "$macinstaller" <<'PY'
import os, re, sys
s = open(sys.argv[1]).read()
s, n = re.subn(r'LIMA_SHA256_ARM64="[0-9a-f]*"', 'LIMA_SHA256_ARM64="' + os.environ["LIMASUM"] + '"', s, count=1)
assert n == 1, "no LIMA_SHA256_ARM64 in install.sh"
open(sys.argv[2], "w").write(s)
PY
grep -q 'LIMA_VERSION="2.2.1"' "$macinstaller" || bad "install.sh pins Lima 2.2.1 (the fake archive's name assumes it; update both together)"

# macrun <case> [env...]: a fresh prefix and stand-in dir for each case. Extra
# stand-ins (brew, limactl, sw_vers) are made by the caller in $shims first.
# Each case runs as if from a terminal (FOX_TTY=/dev/null opens); a case
# without one passes FOX_TTY naming nothing.
macrun() {
	local c="$1"; shift
	local prefix="$mac/$c/prefix"
	mkdir -p "$prefix/bin" "$mac/$c/shims"
	cat > "$mac/$c/shims/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in -m) echo arm64 ;; *) echo Darwin ;; esac
EOF
	chmod +x "$mac/$c/shims/uname"
	[ -e "$mac/$c/shims/sw_vers" ] || { printf '#!/bin/sh\necho 14.5\n' > "$mac/$c/shims/sw_vers"; chmod +x "$mac/$c/shims/sw_vers"; }
	: > "$setup_log"
	env PATH="$mac/$c/shims:$prefix/bin:/usr/bin:/bin" FOX_BASE_URL="file://$mac/rel" FOX_PREFIX="$prefix" \
		FOX_LIMA_BASE_URL="file://$mac/limarel" FOX_TEST_SETUP_LOG="$setup_log" FOX_TTY=/dev/null "$@" sh "$macinstaller" </dev/null 2>&1
}
shims_for() { mkdir -p "$mac/$1/shims"; echo "$mac/$1/shims"; }

# 12. No Lima, no Homebrew: Lima's release is installed, then setup runs and finds it.
out="$(macrun m12)"; code=$?
if [ "$code" = 0 ] && [ -x "$mac/m12/prefix/bin/limactl" ] && [ -f "$mac/m12/prefix/share/lima/ubuntu.yaml" ] \
	&& grep -q "setup limactl=$mac/m12/prefix/bin/limactl" "$setup_log" && grep -q "verified lima-2.2.1-Darwin-arm64.tar.gz" <<<"$out"; then
	ok "macOS without Lima or Homebrew: Lima's release is installed, then fox setup runs"
else
	bad "macOS without Lima or Homebrew (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 13. A Lima archive that does not match the pinned checksum is not installed, and setup does not run.
out="$(macrun m13 FOX_LIMA_BASE_URL="file://$mac/badlima")"; code=$?
if [ "$code" != 0 ] && [ ! -e "$mac/m13/prefix/bin/limactl" ] && [ ! -s "$setup_log" ] \
	&& grep -q "checksum mismatch for lima-2.2.1-Darwin-arm64.tar.gz" <<<"$out" && [ -x "$mac/m13/prefix/bin/fox" ]; then
	ok "a Lima archive that does not match the pinned checksum is refused, and setup does not run"
else
	bad "a tampered Lima archive is refused (exit $code, limactl: $([ -e "$mac/m13/prefix/bin/limactl" ] && echo yes || echo no))"
fi

# 14. With Homebrew, Lima comes from brew.
s="$(shims_for m14)"
cat > "$s/brew" <<EOF
#!/bin/sh
echo "brew \$*" >> "$mac/m14/brew.log"
printf '#!/bin/sh\necho limactl version 9\n' > "$s/limactl"; chmod +x "$s/limactl"
EOF
chmod +x "$s/brew"
out="$(macrun m14)"; code=$?
if [ "$code" = 0 ] && grep -qx "brew install lima" "$mac/m14/brew.log" && [ ! -e "$mac/m14/prefix/bin/limactl" ] \
	&& grep -q "setup limactl=$s/limactl" "$setup_log"; then
	ok "with Homebrew, Lima is installed with brew, then fox setup runs"
else
	bad "with Homebrew, Lima comes from brew (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 15. Lima already there: nothing is installed, setup runs.
s="$(shims_for m15)"; printf '#!/bin/sh\necho limactl version 1\n' > "$s/limactl"; chmod +x "$s/limactl"
printf '#!/bin/sh\necho "brew $*" >> "%s"\n' "$mac/m15/brew.log" > "$s/brew"; chmod +x "$s/brew"
out="$(macrun m15)"; code=$?
if [ "$code" = 0 ] && [ ! -e "$mac/m15/brew.log" ] && [ ! -e "$mac/m15/prefix/bin/limactl" ] && grep -q "setup limactl=$s/limactl" "$setup_log"; then
	ok "with Lima already installed, nothing is added and fox setup runs"
else
	bad "with Lima already installed (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 16. FOX_NO_SETUP=1 installs Lima but does not run setup.
out="$(macrun m16 FOX_NO_SETUP=1)"; code=$?
if [ "$code" = 0 ] && [ -x "$mac/m16/prefix/bin/limactl" ] && [ ! -s "$setup_log" ] && grep -q "fox setup" <<<"$out"; then
	ok "FOX_NO_SETUP=1 installs Lima and leaves fox setup to the user"
else
	bad "FOX_NO_SETUP=1 (exit $code)"
fi

# 17. FOX_LIMA=skip installs neither Lima nor runs setup, and says what to do.
out="$(macrun m17 FOX_LIMA=skip)"; code=$?
if [ "$code" = 0 ] && [ ! -e "$mac/m17/prefix/bin/limactl" ] && [ ! -s "$setup_log" ] && grep -q "brew install lima" <<<"$out"; then
	ok "FOX_LIMA=skip leaves Lima and setup to the user"
else
	bad "FOX_LIMA=skip (exit $code)"
fi

# 18. macOS 12: no Lima is installed and the install says so.
s="$(shims_for m18)"; printf '#!/bin/sh\necho 12.7.4\n' > "$s/sw_vers"; chmod +x "$s/sw_vers"
out="$(macrun m18)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$mac/m18/prefix/bin/limactl" ] && [ ! -s "$setup_log" ] && grep -q "macOS 13 or later" <<<"$out"; then
	ok "on macOS 12 Lima is not installed, and the install says why"
else
	bad "macOS 12 (exit $code)"
fi

# 19. A setup that fails fails the install, and says how to pick up again.
out="$(macrun m19 FOX_TEST_SETUP_EXIT=1)"; code=$?
if [ "$code" != 0 ] && grep -q "setup did not finish" <<<"$out" && [ -x "$mac/m19/prefix/bin/limactl" ]; then
	ok "a failed fox setup fails the install and says to run it again"
else
	bad "a failed fox setup (exit $code)"
fi

# 21. No terminal (a CI job, a provisioning tool): Lima is installed, setup is
# not started unasked, and the install succeeds and says what to run.
out="$(macrun m21 FOX_TTY="$mac/m21/no-such-tty")"; code=$?
if [ "$code" = 0 ] && [ -x "$mac/m21/prefix/bin/limactl" ] && [ ! -s "$setup_log" ] \
	&& grep -q "No terminal here" <<<"$out" && grep -q "fox setup" <<<"$out"; then
	ok "with no terminal, Lima is installed and fox setup is left to the user, and the install succeeds"
else
	bad "with no terminal (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 22. No terminal, but FOX_SETUP=1: unattended provisioning runs setup.
out="$(macrun m22 FOX_TTY="$mac/m22/no-such-tty" FOX_SETUP=1)"; code=$?
if [ "$code" = 0 ] && grep -q "setup limactl=$mac/m22/prefix/bin/limactl" "$setup_log"; then
	ok "with no terminal, FOX_SETUP=1 runs fox setup unattended"
else
	bad "FOX_SETUP=1 with no terminal (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 23. Re-run on an install that is there: the VM is left as it is.
s="$(shims_for m23)"; printf '#!/bin/sh
echo limactl version 1
' > "$s/limactl"; chmod +x "$s/limactl"
out="$(macrun m23 FOX_TEST_VM_STATE=existing)"; code=$?
if [ "$code" = 0 ] && [ ! -s "$setup_log" ] && grep -q 'VM "fox" is already set up, so the installer left it as it is' <<<"$out"; then
	ok "on a machine whose FoxByte VM is there, the installer leaves the VM as it is"
else
	bad "an existing FoxByte VM (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 24. …unless FOX_SETUP=1 asks for setup.
s="$(shims_for m24)"; printf '#!/bin/sh
echo limactl version 1
' > "$s/limactl"; chmod +x "$s/limactl"
out="$(macrun m24 FOX_TEST_VM_STATE=existing FOX_SETUP=1)"; code=$?
if [ "$code" = 0 ] && grep -q "setup limactl=$s/limactl" "$setup_log"; then
	ok "FOX_SETUP=1 runs fox setup on an existing FoxByte VM"
else
	bad "FOX_SETUP=1 on an existing VM (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# 25. A plain "default" Lima VM, which setup would take over: never used
# without the person choosing, FOX_SETUP=1 or not.
s="$(shims_for m25)"; printf '#!/bin/sh
echo limactl version 1
' > "$s/limactl"; chmod +x "$s/limactl"
out="$(macrun m25 FOX_TEST_VM=default FOX_TEST_VM_STATE=existing FOX_SETUP=1)"; code=$?
if [ "$code" = 0 ] && [ ! -s "$setup_log" ] && grep -q 'Lima VM named "default"' <<<"$out" \
	&& grep -q "FOX_LIMA_INSTANCE=fox fox setup" <<<"$out" && grep -q "FOX_LIMA_INSTANCE=default fox setup" <<<"$out"; then
	ok "a Lima VM named default is never set up unasked: the installer asks the person to choose"
else
	bad "a default Lima VM (exit $code)"; tail -n 8 <<<"$out" | sed 's/^/      /'
fi

# An unknown FOX_LIMA is refused before anything is installed.
p="$tmp/p20"; out="$(run "$p" FOX_LIMA=maybe)"; code=$?
if [ "$code" != 0 ] && [ ! -e "$p/bin/fox" ] && grep -q "unknown FOX_LIMA" <<<"$out"; then
	ok "an unknown FOX_LIMA is refused before anything is installed"
else
	bad "an unknown FOX_LIMA is refused (exit $code)"
fi

# Linux: `fox start` checks for ZFS and Docker but does not install them, so the
# installer says so, and names what is missing on this machine. (The docs used
# to say start provisioned them.)
if [ "$os" = linux ]; then
	stubs="$tmp/stubs"; mkdir -p "$stubs"
	printf '#!/bin/sh\nexit 0\n' > "$stubs/zpool"; cp "$stubs/zpool" "$stubs/docker"; chmod +x "$stubs/zpool" "$stubs/docker"
	p="$tmp/p26"; out="$(run "$p" PATH="$stubs:$PATH")"; code=$?
	if [ "$code" = 0 ] && grep -q "needs ZFS and Docker" <<<"$out" && ! grep -q "Missing here" <<<"$out"; then
		ok "on Linux with ZFS and Docker present, the next step is just sudo fox start"
	else
		bad "on Linux with ZFS and Docker present (exit $code): $(tail -8 <<<"$out")"
	fi
	if ! command -v zpool >/dev/null 2>&1; then
		p="$tmp/p27"; out="$(run "$p")"; code=$?
		if [ "$code" = 0 ] && grep -q "Missing here: zfsutils-linux" <<<"$out" && grep -q "apt-get install -y zfsutils-linux" <<<"$out"; then
			ok "on Linux without ZFS, the installer names the package to install"
		else
			bad "on Linux without ZFS (exit $code): $(tail -8 <<<"$out")"
		fi
	fi
fi

echo
echo "install.sh: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
