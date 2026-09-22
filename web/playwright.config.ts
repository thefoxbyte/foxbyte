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
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.FOX_E2E_URL ?? 'https://localhost:8080',
    ignoreHTTPSErrors: true, // the engine serves its own certificate
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
})
