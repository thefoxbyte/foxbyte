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
# The promotion test's target. Made here rather than by the test, because making
# a branch starts a container, and starting a container changes the host's
# network interfaces — which makes Chromium abort every request in flight
# (net::ERR_NETWORK_CHANGED). A test that did that to itself moments before the
# interaction it measures failed for reasons that had nothing to do with the
# console, and failed differently on each retry.
TARGET_BRANCH="e2eui3"
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
for b in "$BRANCH" "$NEW_BRANCH" "$TARGET_BRANCH"; do "$S" branch delete "$b" >/dev/null 2>&1; done
for b in "$BRANCH" "$TARGET_BRANCH"; do
	"$S" branch create "$b" >/dev/null 2>&1
	"$S" branch owner "$b" "$EMAIL" >/dev/null 2>&1
done
# main is left alone by these tests, deliberately: a change applied to main would
# be inherited by every branch made afterwards, and the next run's `CREATE TABLE`
# would fail as a duplicate. The promotion test's target is $TARGET_BRANCH, above.
# Any table an earlier version of these tests did leave on main is removed here.
sudo docker exec -e PGPASSWORD=foxbyte "pg-main" psql -U dbadmin -d appdb -q -c \
	"SET bb.allow_destructive=on; DROP TABLE IF EXISTS $TABLE" >/dev/null 2>&1

# ── Realtime, set up before Chromium exists ─────────────────────────────────
#
# `realtime setup` turns on logical decoding and restarts main, and a container
# coming up changes the host's network interfaces — which makes Chromium abort
# every request in flight. So it happens here, for the same reason
# $TARGET_BRANCH is made here rather than by a test.
#
# The branch's own tables are made here too, in the three states the page has a
# different answer for: ready, fixable for free, and fixable only at a cost.
# A test that created them would be creating them through SQL it also has to
# wait for, and would still be measuring the console afterwards.
"$S" realtime setup --yes >/dev/null 2>&1
RT_BRANCH_PG="pg-$BRANCH"
rtsql() { sudo docker exec -e PGPASSWORD=foxbyte "$RT_BRANCH_PG" psql -U dbadmin -d appdb -q -c "$1" >/dev/null 2>&1; }
rtsql "SET bb.allow_destructive=on; DROP TABLE IF EXISTS public.rt_ready, public.rt_grant, public.rt_keyless CASCADE"
# Ready: a primary key, and the role a subscriber reads as can already see it.
rtsql "CREATE TABLE public.rt_ready (id bigint PRIMARY KEY, note text)"
rtsql "GRANT SELECT ON public.rt_ready TO db_client"
# Needs one free change: the grant is missing, and nothing else is.
rtsql "CREATE TABLE public.rt_grant (id bigint PRIMARY KEY, note text)"
rtsql "REVOKE SELECT ON public.rt_grant FROM db_client"
# Needs a change with a price: nothing unique identifies a row, so the only way
# is REPLICA IDENTITY FULL. This is the row whose button must ask first.
#
# With rows and updates behind it, deliberately. The cost is measured from
# pg_stat_user_tables, and a table created seconds ago has no statistics — so
# the dialog can only say what FULL does rather than what it would cost here,
# which is the engine being honest and a weaker thing to put in front of a
# person. 200 updates over 200 rows gives it something real to quote.
rtsql "CREATE TABLE public.rt_keyless (a text, b text)"
rtsql "GRANT SELECT ON public.rt_keyless TO db_client"
rtsql "INSERT INTO public.rt_keyless SELECT 'row-'||g, repeat('x', 200) FROM generate_series(1, 200) g"
rtsql "UPDATE public.rt_keyless SET b = repeat('y', 200)"
rtsql "ANALYZE public.rt_keyless"

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
	# A retry in the log is expected in CI and is not the console misbehaving: the
	# engine's short-lived containers change the host's network interfaces, and
	# Chromium aborts requests in flight when they do. web/playwright.config.ts
	# has the detail. A test that fails twice running is a real failure.
	FOX_E2E_BRANCH="$BRANCH" FOX_E2E_NEW_BRANCH="$NEW_BRANCH" FOX_E2E_TABLE="$TABLE" \
	FOX_E2E_TARGET_BRANCH="$TARGET_BRANCH" FOX_E2E_RT_BRANCH="$BRANCH" npx playwright test
rc=$?

echo "### cleanup"
# Realtime is an engine-wide setting, so it is turned off again: a later suite
# that asserts main's container arguments are byte-identical to a build with
# the feed off would otherwise fail for a reason this suite caused.
"$S" realtime teardown --yes >/dev/null 2>&1
for b in "$BRANCH" "$NEW_BRANCH" e2eui3; do "$S" branch delete "$b" >/dev/null 2>&1; done
cd "$ROOT" || exit 1
# A failure leaves the screenshots and traces where CI can collect them.
if [ "$rc" = 0 ]; then
	rm -rf "$UI"
else
	echo "the screenshots and traces of the failures are in $UI/test-results"
fi
exit "$rc"
