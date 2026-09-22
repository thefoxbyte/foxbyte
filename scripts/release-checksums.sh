#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Publish this job's checksums into a GitHub release's SHA256SUMS without dropping
# anyone else's.
#
#   release-checksums.sh <tag> <file>...
#
# Two workflows attach assets to the same release: release.yml (the fox and
# fox-verify binaries, the Docker context) and wsl-distro.yml (the Windows distro
# image). Both start from the same tag push and either can finish first. The
# installers verify every download against SHA256SUMS and silently skip any file
# that isn't listed, so a job that replaces the whole file with only its own
# entries quietly turns verification off for the other job's assets. That
# happened with v0.8.1.
#
# So each job:
#   1. downloads the published SHA256SUMS (if any),
#   2. keeps every entry except those for the files it is publishing (matched by
#      exact file name, not substring),
#   3. adds its own entries and uploads the result,
#   4. waits a moment, downloads again and checks its entries are still there —
#      if the other job uploaded in between, it merges again (up to 3 times).
#
# Signing (audit v2 G22): with RELEASE_SIGN set to the releasesign tool
# (cmd/releasesign, which reads FOX_RELEASE_SIGNING_KEY), each upload of the
# merged SHA256SUMS goes with its signature, SHA256SUMS.sig, and step 4 also
# checks the published signature matches the published file. The two jobs can
# interleave (A's file, B's file, B's signature, A's signature), so a mismatch
# there is merged and signed again like any other race.
#
# Needs gh (GH_TOKEN set) and sha256sum or shasum. Files may be given with a
# directory; entries use the base name, as the installers expect.
set -euo pipefail

tag="${1:-}"
[ -n "$tag" ] && [ "$#" -ge 2 ] || { echo "usage: $0 <tag> <file>..." >&2; exit 2; }
shift

if command -v sha256sum >/dev/null 2>&1; then
	checksum() { sha256sum "$@"; }
else
	checksum() { shasum -a 256 "$@"; }
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Our entries: "<hash>  <basename>".
checksum "$@" | awk '{ name = $2; sub(/.*\//, "", name); print $1 "  " name }' > "$work/mine"

sign="${RELEASE_SIGN:-}"
attempts="${CHECKSUM_ATTEMPTS:-3}"
settle="${CHECKSUM_SETTLE_SECONDS:-10}"

for attempt in $(seq 1 "$attempts"); do
	# A release without SHA256SUMS yet starts from empty.
	if ! gh release download "$tag" -p SHA256SUMS -O "$work/existing" --clobber >/dev/null 2>&1; then
		: > "$work/existing"
	fi
	# Every published entry whose file we aren't publishing, then ours.
	awk 'NR == FNR { mine[$2] = 1; next } NF >= 2 && !($2 in mine)' "$work/mine" "$work/existing" > "$work/SHA256SUMS"
	cat "$work/mine" >> "$work/SHA256SUMS"
	sort -k2 -o "$work/SHA256SUMS" "$work/SHA256SUMS"

	if [ -n "$sign" ]; then
		"$sign" sign "$work/SHA256SUMS" "$work/SHA256SUMS.sig"
		gh release upload "$tag" "$work/SHA256SUMS" "$work/SHA256SUMS.sig" --clobber
	else
		gh release upload "$tag" "$work/SHA256SUMS" --clobber
	fi

	sleep "$settle"
	gh release download "$tag" -p SHA256SUMS -O "$work/published" --clobber
	signed_ok=1
	if [ -n "$sign" ]; then
		signed_ok=0
		if gh release download "$tag" -p SHA256SUMS.sig -O "$work/published.sig" --clobber >/dev/null 2>&1 &&
			"$sign" verify "$work/published" "$work/published.sig" >/dev/null 2>&1; then
			signed_ok=1
		fi
	fi
	if [ "$signed_ok" = 1 ] && awk 'NR == FNR { want[$1 "  " $2] = 1; total++; next }
	        (($1 "  " $2) in want) && !seen[$1 "  " $2]++ { found++ }
	        END { exit (found == total) ? 0 : 1 }' "$work/mine" "$work/published"; then
		cat "$work/published"
		exit 0
	fi
	echo "SHA256SUMS changed while publishing (another job uploaded at the same time); merging again ($attempt/$attempts)" >&2
done

echo "error: could not publish checksums for: $*" >&2
exit 1
