#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build the `fox` the integration suites run against, and give it a licence.
#
#   scripts/build_test_fox.sh <out> [extra build tags]
#
# Why this exists: the suites test features, and seven of those features now
# need a licence. Running them against a Standard build does not test the
# feature, it tests the refusal -- and the refusal already has tests of its own
# (scripts/test_editions.sh, and section 1 of integration_realtime.sh). So the
# suites get an Enterprise build with a licence, and go on asserting what the
# features actually do.
#
# The licence is a throwaway. The real signing key is deliberately not in the
# repository or in CI, so this generates one, pins its public half into the
# binary with -ldflags -X -- exactly how a test build is given the release key
# -- issues a licence against it, and activates it. The key lives and dies with
# the run.
set -euo pipefail

OUT="${1:?usage: build_test_fox.sh <out> [extra build tags]}"
shift || true
TAGS="enterprise"
[ "$#" -gt 0 ] && [ -n "$1" ] && TAGS="enterprise,$1"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT

# Built and run from the key's own directory: `go run` needs the module, and
# `generate` writes license-signing.key relative to where it runs.
go build -o "$KEYDIR/licensesign" ./cmd/licensesign
PUB="$(cd "$KEYDIR" && ./licensesign generate | awk '/public key/{print $3}')"
[ -n "$PUB" ] || { echo "build_test_fox: could not mint a test signing key" >&2; exit 1; }
LD="-X github.com/thefoxbyte/foxbyte/internal/license.licensePublicKey=$PUB"

go build -tags "$TAGS" -ldflags "$LD" -o "$OUT" ./cmd/fox

# A licence the build above will accept. Site-wide (no fingerprint) because a
# CI runner's machine id is not worth binding to, and short because this is not
# a licence anybody should be able to reuse.
go build -ldflags "$LD" -o "$KEYDIR/issue" ./cmd/licensesign
FOX_LICENSE_SIGNING_KEY="$(cat "$KEYDIR/license-signing.key")" \
  "$KEYDIR/issue" issue --customer "integration" --features all --months 1 --id FB-CI \
  > "$OUT.licence.json"

# The public half, next to the binary, so a suite that builds another fox --
# the update suite builds the "release" it updates to -- can make one that
# accepts the same licence. Public by design: it is compiled into every binary.
printf '%s\n' "$PUB" > "$OUT.licence.pub"

"$OUT" license activate "$OUT.licence.json" >/dev/null
echo "build_test_fox: $OUT is the Enterprise edition with a throwaway licence ($TAGS)"
