#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FoxByte installer. Installs the `fox` command, then you run one more command:
#
#   macOS:  fox setup      # creates a local Linux VM and brings everything up
#   Linux:  sudo fox start # provisions ZFS/Docker/image and brings everything up
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.sh | sh
#
# The Enterprise edition (paid) is a different binary from the same release. It
# needs a licence to unlock its features, and behaves exactly like Standard
# without one:
#
#   curl -fsSL .../install.sh | FOX_EDITION=enterprise sh
#   sh install.sh --edition enterprise        # when the script is downloaded first
#
# Every download is checked against the release's SHA256SUMS before it is
# installed: these binaries are run as root, and a truncated or altered download
# must never reach $PREFIX/bin. Anything that cannot be verified stops the
# install (FOX_NO_VERIFY=1 deliberately skips the check).
#
# Env overrides:
#   FOX_EDITION   standard | enterprise          (default: standard)
#   FOX_VERSION   release tag to install         (default: latest)
#   FOX_REPO      GitHub owner/repo              (default: thefoxbyte/foxbyte)
#   FOX_DIST      install from a local dir of prebuilt binaries instead of downloading
#   FOX_PREFIX    install prefix                 (default: /usr/local)
#   FOX_BASE_URL  release download base URL      (default: GitHub releases)
#   FOX_NO_VERIFY set to 1 to skip checksum verification
#   FOX_REQUIRE_SIGNATURE  set to 1 to refuse to install when the signature cannot be checked here
#   FOX_ALLOW_UNSIGNED     set to 1 to install a release that is not signed (checksums are still checked)
set -eu

# generated from brand.json -- do not edit by hand, run `make brand`
PRODUCT="FoxByte"
CLI="fox"
SLUG="foxbyte"
ENV_PREFIX="FOX_"
STATE_DIR=".fox"
DEFAULT_REPO="thefoxbyte/foxbyte"
# end generated

EDITION="${FOX_EDITION:-standard}"
# --edition too, for a downloaded copy run directly. A piped install has no
# arguments, so the environment variable is the one that matters there.
while [ $# -gt 0 ]; do
	case "$1" in
		--edition)   EDITION="${2:-}"; shift 2 ;;
		--edition=*) EDITION="${1#*=}"; shift ;;
		-h|--help)
			printf 'usage: install.sh [--edition standard|enterprise]\n'
			exit 0 ;;
		*) printf 'error: unknown argument: %s\n' "$1" >&2; exit 2 ;;
	esac
done

REPO="${FOX_REPO:-$DEFAULT_REPO}"
VERSION="${FOX_VERSION:-latest}"
PREFIX="${FOX_PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
SHAREDIR="$PREFIX/share/$SLUG"

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# sudo helper: use sudo only if we can't create/write the install dir ourselves.
SUDO=""
if [ "$(id -u)" -ne 0 ] && ! ( install -d "$BINDIR" >/dev/null 2>&1 && [ -w "$BINDIR" ] ); then
	command -v sudo >/dev/null 2>&1 && SUDO="sudo" || err "need root or sudo to install into $BINDIR"
fi

# Detect OS + arch and map to our release-asset naming.
os="$(uname -s)"
case "$os" in
	Darwin) os="darwin" ;;
	Linux)  os="linux" ;;
	*)      err "unsupported OS: $os (macOS and Linux are supported)" ;;
esac
arch="$(uname -m)"
case "$arch" in
	arm64|aarch64) arch="arm64" ;;
	x86_64|amd64)  arch="amd64" ;;
	*)             err "unsupported architecture: $arch" ;;
esac

# The download's name carries the edition; the installed command is `fox` either
# way, so nothing downstream has to care which one is on the machine.
case "$EDITION" in
	standard)   BIN="$CLI" ;;
	enterprise) BIN="$CLI-enterprise" ;;
	*) err "unknown edition: $EDITION (expected 'standard' or 'enterprise')" ;;
esac

asset="$BIN-$os-$arch"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# fetch <url> <dest>
#
# The timeouts are the point of this function, not decoration. curl's default
# connect timeout is 300 seconds per address, and the release asset host
# resolves to three of them — so a network fault that lets connections stall
# instead of refusing them leaves this waiting for up to a quarter of an hour.
# With the metadata downloads below hiding curl's stderr, that looked exactly
# like a hang with no output at all, and was reported as one.
#
# --speed-limit catches the other shape: a transfer that opens and then stalls
# part-way. There is deliberately no --max-time — the largest asset is several
# hundred megabytes, and a slow but working connection has to be allowed to
# finish.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fSL --connect-timeout 15 --retry 2 --retry-delay 2 \
			--speed-limit 1024 --speed-time 60 "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" --connect-timeout=15 --tries=3 --read-timeout=60 "$1"
	else
		err "need curl or wget"
	fi
}

# Resolve the download URL for a release asset.
asset_url() { # asset_url <asset-name>
	if [ -n "${FOX_BASE_URL:-}" ]; then
		echo "$FOX_BASE_URL/$1"
	elif [ "$VERSION" = "latest" ]; then
		echo "https://github.com/$REPO/releases/latest/download/$1"
	else
		echo "https://github.com/$REPO/releases/download/$VERSION/$1"
	fi
}

# --- integrity -------------------------------------------------------------
# The release publishes SHA256SUMS next to its binaries. It travels over the
# same TLS connection as the files, so it proves integrity (a complete,
# unaltered download), not authorship. SHA256SUMS.sig proves authorship: an
# Ed25519 signature by the FoxByte release key, whose public half is below —
# in this script, which comes from the repository, not from the release.

VERIFY=1
[ "${FOX_NO_VERIFY:-}" = "1" ] && VERIFY=0
# A local dir is the user's own build; there is no release to check it against.
[ -n "${FOX_DIST:-}" ] && VERIFY=0

sha256_of() { # sha256_of <file>
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo ""
	fi
}

SUMS=""
if [ "$VERIFY" = "1" ]; then
	# Before this, the checksums and the signature were both fetched with curl's
	# stderr discarded and nothing printed beforehand, so the script's first
	# visible output came only once both had arrived. On a bad connection that is
	# minutes of apparent silence, which is indistinguishable from a hang.
	say "Checking the $VERSION release (checksums, then signature)…"
	SUMS="$tmp/SHA256SUMS"
	fetch "$(asset_url SHA256SUMS)" "$SUMS" 2>/dev/null || err "could not fetch SHA256SUMS for $VERSION.
Nothing was installed. Retry, or set FOX_NO_VERIFY=1 to install without checking (not recommended)."
fi

# The release key's public half. Written by `go run ./cmd/releasesign generate
# --write`, with fox's own copy (internal/update/signing.go).
RELEASE_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAaTn8b2xj53r7QjOK+K2//RBU+4OBHoxzuclxGK04WZc=
-----END PUBLIC KEY-----'

can_check_signatures() {
	command -v openssl >/dev/null 2>&1 && openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519
}

check_signature() {
	[ "$VERIFY" = "1" ] || return 0
	if [ "${FOX_ALLOW_UNSIGNED:-}" = "1" ]; then
		warn "FOX_ALLOW_UNSIGNED=1: not checking who published $VERSION (every file is still checked against SHA256SUMS)"
		return 0
	fi
	[ -n "$RELEASE_PUBLIC_KEY" ] || err "this installer carries no release public key, so it cannot check who published $VERSION.
Nothing was installed. Set FOX_ALLOW_UNSIGNED=1 to install on checksums alone."
	fetch "$(asset_url SHA256SUMS.sig)" "$tmp/SHA256SUMS.sig" 2>/dev/null || err "$VERSION has no SHA256SUMS.sig: it was not signed with the $PRODUCT release key.
Nothing was installed. (Releases published before signing began have none: set FOX_ALLOW_UNSIGNED=1 to install one on checksums alone.)"
	if ! can_check_signatures; then
		[ "${FOX_REQUIRE_SIGNATURE:-}" = "1" ] && err "this machine's openssl cannot check Ed25519 signatures (FOX_REQUIRE_SIGNATURE=1).
Nothing was installed. Install OpenSSL 3 (macOS: brew install openssl, then put it first on PATH) and re-run."
		warn "the signature of $VERSION was not checked: this machine's openssl cannot check Ed25519 signatures (macOS ships LibreSSL).
  Every file is still checked against SHA256SUMS, and $CLI checks signatures on every update.
  To check this install too: install OpenSSL 3 and re-run, or set FOX_REQUIRE_SIGNATURE=1 to refuse."
		return 0
	fi
	printf '%s\n' "$RELEASE_PUBLIC_KEY" > "$tmp/release.pub"
	if openssl pkeyutl -verify -pubin -inkey "$tmp/release.pub" -rawin -in "$SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1; then
		say "SHA256SUMS is signed with the $PRODUCT release key"
	else
		err "SHA256SUMS of $VERSION is not signed with the $PRODUCT release key — it was not published by $PRODUCT, or it was altered.
Nothing was installed."
	fi
}
check_signature

verify_file() { # verify_file <asset-name> <path>
	[ "$VERIFY" = "1" ] || return 0
	want="$(awk -v n="$1" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1; exit }' "$SUMS")"
	[ -n "$want" ] || { rm -f "$2"; err "$1 is not listed in SHA256SUMS for $VERSION.
Nothing was installed. Set FOX_NO_VERIFY=1 to install without checking (not recommended)."; }
	got="$(sha256_of "$2")"
	[ -n "$got" ] || { rm -f "$2"; err "need sha256sum or shasum to verify downloads.
Nothing was installed. Set FOX_NO_VERIFY=1 to install without checking (not recommended)."; }
	if [ "$got" != "$want" ]; then
		rm -f "$2"
		err "checksum mismatch for $1 — the download does not match the release.
  expected $want
  got      $got
Nothing was installed."
	fi
	say "verified $1"
}

# Get the host binary (from a local dist dir, or a GitHub release).
if [ -n "${FOX_DIST:-}" ]; then
	say "Installing from local dir $FOX_DIST"
	[ -f "$FOX_DIST/$asset" ] || err "missing $FOX_DIST/$asset"
	cp "$FOX_DIST/$asset" "$tmp/$CLI"
else
	say "Downloading $asset ($VERSION)…"
	fetch "$(asset_url "$asset")" "$tmp/$CLI" || err "download failed — check the release exists for $os/$arch"
	verify_file "$asset" "$tmp/$CLI"
fi
chmod +x "$tmp/$CLI"

say "Installing $CLI to $BINDIR"
$SUDO install -d "$BINDIR"
$SUDO install -m 0755 "$tmp/$CLI" "$BINDIR/$CLI"

# On macOS the engine runs in a Linux VM; stash the matching Linux binary so
# `fox setup` can install it into the VM without another download.
if [ "$os" = "darwin" ]; then
	# Same edition as the launcher above. A Standard engine under an Enterprise
	# launcher would offer commands the engine does not have, and the mismatch
	# would read as a bug rather than a mixed install.
	linux_asset="$BIN-linux-$arch"
	say "Fetching the Linux engine binary ($linux_asset) for the VM…"
	if [ -n "${FOX_DIST:-}" ] && [ -f "$FOX_DIST/$linux_asset" ]; then
		cp "$FOX_DIST/$linux_asset" "$tmp/$linux_asset"
	elif fetch "$(asset_url "$linux_asset")" "$tmp/$linux_asset"; then
		# It runs as root inside the VM, so it is held to the same standard as
		# the launcher: verified, or not installed at all.
		verify_file "$linux_asset" "$tmp/$linux_asset"
	else
		rm -f "$tmp/$linux_asset"
		warn "could not download $linux_asset; \`fox setup\` will fetch it instead"
	fi
	if [ -f "$tmp/$linux_asset" ]; then
		$SUDO install -d "$SHAREDIR"
		$SUDO install -m 0755 "$tmp/$linux_asset" "$SHAREDIR/$linux_asset"
	fi
fi

echo
say "Installed $CLI $("$BINDIR/$CLI" version 2>/dev/null | awk '{print $2}') ($EDITION edition)"
if [ "$os" = "darwin" ]; then
	cat <<EOF

Next step (one time):
  fox setup      # creates a local Linux VM, provisions it, and starts FoxByte

Then day-to-day:
  fox status · fox branch create qa · fox stop
EOF
	command -v limactl >/dev/null 2>&1 || cat <<EOF

Note: macOS needs Lima (the VM runner). Install it first:
  brew install lima
EOF
else
	cat <<EOF

Next step:
  sudo fox start   # provisions ZFS + Docker + image, then brings everything up

Then day-to-day:
  fox status · fox branch create qa · fox stop
EOF
fi
