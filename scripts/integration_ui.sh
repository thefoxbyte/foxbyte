#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The web console's end-to-end tests (audit v2 G26): Playwright drives a real
# browser against a real engine — sign-in, the dashboard, a branch, SQL, the
# Blackbox and an API key — so a console regression fails here instead of
# reaching a user. Nothing is mocked: what the console shows has to be what
# the engine wrote.
#
#   make integration-ui      # in the throwaway VM
#
# The first run downloads Chromium (~150 MB) into the VM.
set -uo pipefail

. "$(cd "$(dirname "$0")" && pwd)/lib/test_guard.sh" || exit 2
. "$(cd "$(dirname "$0")" && pwd)/lib/brand.sh"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${FOX_BIN:-/tmp/fox}"
API="${FOX_API_URL:-https://localhost:8080}"
EMAIL="e2e@foxbyte.dev"
PASSWORD="password123"
BRANCH="e2eui"
NEW_BRANCH="e2eui2"
TABLE="e2e_notes"

echo "### setup: a running stack, an account, a clean branch"
# Restarted with this binary: another suite may have left services running from
# a build without the console (`-tags embedui`), and those would serve the API
# with no UI behind it.
"$S" stop >/dev/null 2>&1
"$S" start >/dev/null 2>&1
for _ in $(seq 60); do curl -sk "$API/api/status" >/dev/null 2>&1 && break; sleep 1; done
printf '%s\n' "$PASSWORD" | "$S" user create "$EMAIL" >/dev/null 2>&1
# The console and Blackbox tests need a branch of their own, and a branch made
# here belongs to no account until it is handed over (audit v2 G02).
for b in "$BRANCH" "$NEW_BRANCH"; do "$S" branch delete "$b" >/dev/null 2>&1; done
"$S" branch create "$BRANCH" >/dev/null 2>&1
"$S" branch owner "$BRANCH" "$EMAIL" >/dev/null 2>&1

# The console has to be there: a binary built without `-tags embedui` serves
# the API but no UI, and every test below would fail on a blank page.
if ! curl -sk "$API/login" | grep -qi '<div id="root"\|<title'; then
	echo "the engine at $API is not serving the web console."
	echo "Build it with the UI embedded:  make web-build && go build -tags embedui -o $S ./cmd/fox"
	exit 2
fi

# The console is served by the engine, but node_modules cannot be written on
# the read-only mount, so the tests run from a copy.
UI="${TMPDIR:-/tmp}/fox-ui-e2e"
rm -rf "$UI"; mkdir -p "$UI"
cp -r "$ROOT/web/tests" "$ROOT/web/playwright.config.ts" "$ROOT/web/package.json" "$ROOT/web/package-lock.json" "$UI/"
cd "$UI" || exit 1
echo "### installing @playwright/test and Chromium (first run downloads it)"
npm install --silent --no-audit --no-fund >/dev/null 2>&1 || { echo "npm install failed"; exit 1; }
npx --yes playwright install --with-deps chromium >/dev/null 2>&1 || {
	echo "could not install Chromium"; exit 1; }

echo "### the console's smoke tests"
FOX_E2E_URL="$API" FOX_E2E_EMAIL="$EMAIL" FOX_E2E_PASSWORD="$PASSWORD" \
	FOX_E2E_BRANCH="$BRANCH" FOX_E2E_NEW_BRANCH="$NEW_BRANCH" FOX_E2E_TABLE="$TABLE" npx playwright test
rc=$?

echo "### cleanup"
for b in "$BRANCH" "$NEW_BRANCH"; do "$S" branch delete "$b" >/dev/null 2>&1; done
cd "$ROOT" || exit 1
# A failure leaves the screenshots and traces where CI can collect them.
if [ "$rc" = 0 ]; then
	rm -rf "$UI"
else
	echo "the screenshots and traces of the failures are in $UI/test-results"
fi
exit "$rc"
