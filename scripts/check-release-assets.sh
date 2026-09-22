#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fails unless a release has every file `fox update` needs, attached AND listed
# in SHA256SUMS. The updater never offers a release that lacks one of its
# platform's files, so a gap here would silently stop updates for that platform.
# Keep the list in step with update.RequiredAssets (a Go test checks it).
#   bash scripts/check-release-assets.sh <tag>
set -uo pipefail

tag="${1:?usage: check-release-assets.sh <tag>}"
required=(
	fox-darwin-arm64
	fox-darwin-amd64
	fox-linux-arm64
	fox-linux-amd64
	fox-windows-amd64.exe
	foxbyte-docker-context.tar.gz
)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
	local attached missing=0 name
	attached="$(gh release view "$tag" --json assets --jq '.assets[].name')" || return 1
	if ! grep -qxF SHA256SUMS <<<"$attached"; then
		echo "::error::$tag has no SHA256SUMS"
		return 1
	fi
	# fox update installs nothing whose SHA256SUMS is not signed (G22).
	if ! grep -qxF SHA256SUMS.sig <<<"$attached"; then
		echo "::error::$tag has no SHA256SUMS.sig (fox update refuses an unsigned release)"
		return 1
	fi
	gh release download "$tag" -p SHA256SUMS -O "$tmp/SHA256SUMS" --clobber || return 1
	for name in "${required[@]}"; do
		if ! grep -qxF "$name" <<<"$attached"; then
			echo "::error::$tag is missing $name (fox update needs it)"
			missing=1
		fi
		if ! awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); sub(/\r$/, "", f) } f == n { found = 1 } END { exit !found }' "$tmp/SHA256SUMS"; then
			echo "::error::SHA256SUMS of $tag doesn't list $name (fox update needs it)"
			missing=1
		fi
	done
	return "$missing"
}

# Retried briefly: the release API can lag just behind an upload.
for attempt in 1 2 3; do
	if check; then
		echo "$tag has every file fox update needs"
		exit 0
	fi
	[ "$attempt" -lt 3 ] && sleep "${CHECK_RETRY_SLEEP:-10}"
done
exit 1
