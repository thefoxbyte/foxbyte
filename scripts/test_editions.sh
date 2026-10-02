#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The edition boundary, checked against the built binaries rather than the source.
#
# The claim this protects is legal, not cosmetic: the Standard binary must contain
# no code from enterprise/, because that is what keeps it purely AGPL and freely
# redistributable. A source-level test can say the imports are tagged; only the
# linked binary can say the code is absent. So this builds both editions and
# looks inside them.
#
# Runs on the host — no VM, no Docker, no install.
#
#   bash scripts/test_editions.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Building both editions…"
go build -o "$TMP/fox" ./cmd/fox || { echo "the Standard build failed"; exit 1; }
go build -tags enterprise -o "$TMP/fox-enterprise" ./cmd/fox || { echo "the Enterprise build failed"; exit 1; }

# 1. No paid code in the free binary.
#
# `go tool nm` lists the symbols the linker kept. A package whose code was
# compiled in leaves its import path in those symbol names, so an empty result is
# the evidence. Counted rather than grepped so an empty enterprise/ cannot make
# this pass by accident — see the vacuity check below.
echo
echo "1. the Standard binary contains no enterprise code"
std_syms="$(go tool nm "$TMP/fox" 2>/dev/null | grep -c 'foxbyte/enterprise' || true)"
ent_syms="$(go tool nm "$TMP/fox-enterprise" 2>/dev/null | grep -c 'foxbyte/enterprise' || true)"
if [ "$std_syms" = "0" ]; then
	ok "no enterprise symbols in the Standard binary"
else
	bad "the Standard binary carries $std_syms enterprise symbol(s) — it is no longer purely AGPL"
fi

# Vacuity: while enterprise/ holds only its untagged placeholder there is nothing
# to link, so both binaries legitimately report zero and the check above proves
# nothing yet. Say so rather than reporting a pass that means nothing.
if [ "$ent_syms" = "0" ]; then
	echo "  note: the Enterprise binary has no enterprise symbols either, so check 1 is"
	echo "        not yet meaningful — enterprise/ has no compiled code. It becomes"
	echo "        meaningful with the first real feature, and must not be removed."
else
	ok "the Enterprise binary does carry them ($ent_syms), so check 1 is meaningful"
fi

# 2. Each binary says which edition it is. A user reporting a problem should
#    never have to guess, and a mixed install is diagnosed from this line.
echo
echo "2. each binary reports its own edition"
std_ver="$("$TMP/fox" version 2>&1)"
ent_ver="$("$TMP/fox-enterprise" version 2>&1)"
# Standard says only "fox <version>", and the version has to be the last field.
# `fox update` validates a staged engine by running this and parsing it — in the
# ALREADY INSTALLED binary, which up to v1.0 took the last whitespace field. A
# suffix here made every one of those installs refuse to update. The edition of
# a Standard build is reported by `fox check`, in a row of its own, and by the
# absence of a suffix here. cmd/fox holds the unit test for the invariant.
# The shape, not the digits: a dev build reports "0.1.0-dev", which no release
# ever does, so counting fields is the check that holds for both.
std_nf="$(printf '%s' "$std_ver" | awk '{print NF}')"
if [ "$std_nf" = 2 ]; then
	ok "Standard: $std_ver (nothing follows the version, so a pre-v1.0.1 install can read it)"
else
	bad "Standard's version line must be '<cli> <version>' and nothing more: $std_ver"
fi
case "$ent_ver" in
	*"enterprise edition"*) ok "Enterprise: $ent_ver" ;;
	*) bad "Enterprise build reports: $ent_ver" ;;
esac

# 3. An Enterprise binary with no licence behaves exactly like Standard. This is
#    the property that stops a build unlocking itself.
echo
echo "3. Enterprise without a licence unlocks nothing"
case "$ent_ver" in
	*"no licence active"*) ok "it says so on the version line" ;;
	*) bad "an unlicensed Enterprise build should say so: $ent_ver" ;;
esac

# 4. The licence boundary and both editions' unit tests.
echo
echo "4. the licence boundary and both test suites"
go test ./internal/edition/ >/dev/null 2>&1 \
	&& ok "boundary tests pass (Standard)" || bad "boundary tests fail (Standard)"
go test -tags enterprise ./internal/edition/ >/dev/null 2>&1 \
	&& ok "boundary tests pass (Enterprise)" || bad "boundary tests fail (Enterprise)"

# 5. The installers can fetch the edition they were asked for, and refuse one
#    that does not exist. A typo must not silently install the free edition.
echo
echo "5. the installers accept an edition and refuse a bad one"
sh -n deploy/install.sh && ok "install.sh parses" || bad "install.sh has a syntax error"
# Captured first, not piped: `set -o pipefail` above would take the installer's
# own non-zero exit as the pipeline's, and a refusal is exactly what we want here.
bad_edition="$(sh deploy/install.sh --edition nonesuch 2>&1 || true)"
case "$bad_edition" in
	*"unknown edition"*) ok "install.sh refuses an unknown edition" ;;
	*) bad "install.sh accepted an unknown edition: $bad_edition" ;;
esac
# The name is built from $Cli rather than spelled out, so that is what to look for.
for want in 'FOX_EDITION' '$Cli-enterprise' 'EngineAsset'; do
	grep -qF "$want" deploy/install.ps1 \
		&& ok "install.ps1 knows about $want" || bad "install.ps1 does not mention $want"
done

# 6. The release publishes the Enterprise set. An Enterprise install updates
#    itself from these, so a release missing one hands that platform the Standard
#    binary — which a user reads as their licence having stopped working.
echo
echo "6. the release publishes and checks the Enterprise assets"
for a in windows-amd64.exe linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
	grep -q "fox-enterprise-$a" .github/workflows/release.yml \
		&& ok "release.yml builds fox-enterprise-$a" \
		|| bad "release.yml does not build fox-enterprise-$a"
done
for a in windows-amd64.exe linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
	grep -q "fox-enterprise-$a" scripts/check-release-assets.sh \
		|| bad "check-release-assets.sh does not check fox-enterprise-$a"
done

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
