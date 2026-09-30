// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from '@playwright/test'

// The web console's smoke tests (audit v2 G26). They drive a real engine —
// scripts/integration_ui.sh starts one, makes the account and passes it here —
// so nothing is mocked: a change made in the console must appear in the
// Blackbox the engine actually wrote.
export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  // Retried in CI, for one specific and well-understood reason: the browser runs
  // on the same host as Docker, and the engine spawns short-lived containers on
  // its bridge network — the backup health check behind /api/status is one
  // (`docker run --rm --network dbnet … mc …`, internal/branch/backups.go). Each
  // one creates and destroys a veth interface, and Chromium treats that as the
  // machine's network changing and aborts every request in flight with
  // net::ERR_NETWORK_CHANGED. The page then shows "Failed to fetch" for a call
  // the engine completed perfectly well: on 29 Sep 2026 the promotion test failed
  // this way while the control plane logged
  // `POST /api/branches/e2eui/request (693ms)` — a success.
  //
  // This is the environment being non-deterministic, not the console being
  // flaky, and no assertion is weakened by retrying. A test that fails twice in a
  // row is a real failure. None locally, where a rerun should be deliberate.
  retries: process.env.CI ? 2 : 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.FOX_E2E_URL ?? 'https://localhost:8080',
    ignoreHTTPSErrors: true, // the engine serves its own certificate
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
})
