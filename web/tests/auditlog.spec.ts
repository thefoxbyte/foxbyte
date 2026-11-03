// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The audit log (F6) in a browser, against a real engine. The component tests
// prove the page against mocks for both states; this proves the page is
// reachable from the menu, reads the engine's own answer, and says how to turn
// it on. The UI suite's install has it off, as every install does until an
// admin runs `fox audit-log setup`; integration §11y turns it on and off.
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

test('the Audit log page says audit is off, what it costs, and the command that turns it on', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Audit log' }).click()
  await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible()
  await expect(page.getByTestId('audit-off')).toContainText('No database runs pgAudit')
  await expect(page.getByTestId('audit-off')).toContainText('It costs capacity')
  await expect(page.getByTestId('audit-setup')).toHaveText(/audit-log setup$/)
})

// Step 2: a table marked from the console's view of it, seen on the Audit log
// page, and taken off there. Audit is off on this install, so the mark waits
// for it, and the console says so.
test('a table is marked for the audit log from the console, listed on the Audit log page, and unmarked there', async ({ page }) => {
  const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_aud_${Date.now().toString().slice(-6)}`
  await page.locator('textarea.editor').fill(`CREATE TABLE ${t} (id int PRIMARY KEY, v text)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()

  await page.getByRole('button', { name: 'Audit…' }).click()
  const dlg = page.getByRole('dialog', { name: `Audit ${t}` })
  await dlg.getByLabel('Writes and reads').check()
  await dlg.getByRole('button', { name: 'Audit', exact: true }).click()
  await expect(page.getByTestId('audit-mark')).toContainText('Audited: writes and reads', { timeout: 30_000 })
  await expect(page.getByTestId('audit-mark')).toContainText('the audit log is off')

  await page.getByRole('link', { name: 'Audit log' }).click()
  await page.getByLabel('Branch').selectOption(branch)
  const marked = page.getByRole('table', { name: `Marked tables on ${branch}` })
  const row = marked.locator('tr', { hasText: `public.${t}` })
  await expect(row).toContainText('writes and reads', { timeout: 30_000 })
  await row.getByRole('button', { name: 'Stop auditing' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Stop auditing' }).click()
  await expect(page.getByText(`public.${t}`)).toHaveCount(0, { timeout: 30_000 })
})
