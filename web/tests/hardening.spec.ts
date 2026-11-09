// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The hardening report (point 3.2) in a browser, against a real engine: the
// page is reachable from the menu, reads the engine's own checks, and filters.
// integration §11ag checks what the checks find.
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'

async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

test('the Hardening page checks main, by section, and shows only what did not pass when asked', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Hardening' }).click()
  await expect(page.getByRole('heading', { name: 'Hardening', exact: true })).toBeVisible()
  await expect(page.getByTestId('hardening-summary')).toContainText('main, PostgreSQL', { timeout: 30_000 })
  await expect(page.getByTestId('check-roles.scram')).toContainText('pass')
  await expect(page.getByTestId('check-set.durability')).toContainText('pass')
  await expect(page.getByRole('table', { name: 'Hardening: connections' })).toBeVisible()
  await expect(page.getByText('Not the CIS Benchmark')).toBeVisible()
  await page.getByLabel('Only what did not pass').check()
  await expect(page.getByTestId('check-roles.scram')).toHaveCount(0)
  await expect(page.getByTestId('check-set.fips')).toContainText('manual')
})

// Points 3.3 and 3.4: a fix made from the page after its confirmation, and a
// profile's preview. On the suite's own branch, so main keeps its settings.
test('a failing check is fixed from the page after showing what changes, and a profile previews its fixes', async ({ page }) => {
  const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'
  await signIn(page)
  await page.getByRole('link', { name: 'Hardening' }).click()
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  await page.getByRole('button', { name: 'Check' }).click()
  await expect(page.getByTestId('hardening-summary')).toContainText(`${branch}, PostgreSQL`, { timeout: 30_000 })
  const row = page.getByTestId('check-log.disconnections')
  await expect(row).toContainText('fail')
  await row.getByRole('button', { name: 'Fix…' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByTestId('plan-log.disconnections')).toContainText('log_disconnections: off → on')
  await dlg.getByRole('button', { name: 'Make this change' }).click()
  await expect(page.getByTestId('hardening-msg')).toHaveText('log.disconnections: fail → pass.', { timeout: 30_000 })
  await expect(page.getByTestId('check-log.disconnections')).toContainText('pass')

  const profiles = page.getByTestId('hardening-profiles')
  await profiles.getByLabel('Profile').selectOption('strict')
  await profiles.getByRole('button', { name: 'Preview' }).click()
  await expect(page.getByTestId('profile-preview')).toContainText('idle_in_transaction_session_timeout')
})
