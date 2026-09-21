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
# Every download is checked against the release's SHA256SUMS before it is
# installed: these binaries are run as root, and a truncated or altered download
# must never reach $PREFIX/bin. Anything that cannot be verified stops the
# install (FOX_NO_VERIFY=1 deliberately skips the check).
#
# Env overrides:
#   FOX_VERSION   release tag to install         (default: latest)
#   FOX_REPO      GitHub owner/repo              (default: thefoxbyte/foxbyte)
#   FOX_DIST      install from a local dir of prebuilt binaries instead of downloading
#   FOX_PREFIX    install prefix                 (default: /usr/local)
#   FOX_BASE_URL  release download base URL      (default: GitHub releases)
#   FOX_NO_VERIFY set to 1 to skip checksum verification
set -eu

# generated from brand.json -- do not edit by hand, run `make brand`
PRODUCT="FoxByte"
CLI="fox"
SLUG="foxbyte"
ENV_PREFIX="FOX_"
STATE_DIR=".fox"
DEFAULT_REPO="thefoxbyte/foxbyte"
# end generated

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

asset="$CLI-$os-$arch"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # fetch <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
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
# unaltered download), not authorship — signatures would be needed for that.

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
	SUMS="$tmp/SHA256SUMS"
	fetch "$(asset_url SHA256SUMS)" "$SUMS" 2>/dev/null || err "could not fetch SHA256SUMS for $VERSION.
Nothing was installed. Retry, or set FOX_NO_VERIFY=1 to install without checking (not recommended)."
fi

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
	linux_asset="$CLI-linux-$arch"
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
say "Installed $CLI $("$BINDIR/$CLI" version 2>/dev/null | awk '{print $2}')"
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
