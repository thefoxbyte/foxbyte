#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Sign and publish the checksums of the files this job built, under a name only
# this job writes.
#
#   release-checksums.sh <tag> <asset> <file>...
#
# Two workflows attach assets to the same release, on their own schedules:
# release.yml (the fox and fox-verify binaries, the Docker context) publishes
# SHA256SUMS, and wsl-distro.yml (the Windows distro image) publishes
# SHA256SUMS.distro. Each file has its own signature, <asset>.sig.
#
# This used to merge every job's entries into one SHA256SUMS: download the
# published file, add this job's lines, sign the result. That made the job a
# signing oracle, because anyone able to upload a release asset could put a line
# in the published file and have the release key sign it. So nothing read back
# from a release is ever signed here: the entries are hashed from the local
# files, which are this job's own build outputs, and a re-run simply replaces
# them.
#
# The read-back afterwards only confirms what was uploaded is what is published
# (the release API can lag just behind an upload); it feeds nothing back in.
#
# RELEASE_SIGN is the releasesign tool (cmd/releasesign, which reads
# FOX_RELEASE_SIGNING_KEY). It is required: clients refuse an unsigned
# SHA256SUMS, so publishing one would only break the release.
#
# Needs gh (GH_TOKEN set) and sha256sum or shasum. Files may be given with a
# directory; entries use the base name, as the installers expect.
set -euo pipefail

tag="${1:-}"
asset="${2:-}"
[ -n "$tag" ] && [ -n "$asset" ] && [ "$#" -ge 3 ] || { echo "usage: $0 <tag> <asset> <file>..." >&2; exit 2; }
shift 2

sign="${RELEASE_SIGN:-}"
[ -n "$sign" ] || { echo "error: RELEASE_SIGN is not set; a release's checksums must be signed" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then
	checksum() { sha256sum "$@"; }
else
	checksum() { shasum -a 256 "$@"; }
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Our entries, and nothing else: "<hash>  <basename>".
checksum "$@" | awk '{ name = $2; sub(/^\*/, "", name); sub(/.*\//, "", name); print $1 "  " name }' | sort -k2 > "$work/$asset"

"$sign" sign "$work/$asset" "$work/$asset.sig"
gh release upload "$tag" "$work/$asset" "$work/$asset.sig" --clobber

attempts="${CHECKSUM_ATTEMPTS:-3}"
settle="${CHECKSUM_SETTLE_SECONDS:-10}"
mkdir "$work/published"
for attempt in $(seq 1 "$attempts"); do
	sleep "$settle"
	if gh release download "$tag" -p "$asset" -O "$work/published/$asset" --clobber >/dev/null 2>&1 &&
		gh release download "$tag" -p "$asset.sig" -O "$work/published/$asset.sig" --clobber >/dev/null 2>&1 &&
		cmp -s "$work/$asset" "$work/published/$asset" &&
		cmp -s "$work/$asset.sig" "$work/published/$asset.sig"; then
		cat "$work/$asset"
		exit 0
	fi
	echo "$asset of $tag is not what was uploaded yet ($attempt/$attempts)" >&2
done

echo "error: $asset of $tag does not match what this job uploaded: another writer, or the upload failed" >&2
exit 1
