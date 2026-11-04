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

// Step 3: the records, read from the engine. Audit is off on this install, so
// none match; integration §11aa reads real ones.
test('the Audit log page reads the records from the engine', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Audit log' }).click()
  await page.getByLabel('Records since').selectOption('all')
  await page.getByRole('button', { name: 'Show' }).click()
  await expect(page.getByTestId('no-records')).toHaveText('No record matches.', { timeout: 30_000 })
})

// Step 5b: forwarding to a SIEM, set and stopped from the console. Nothing is
// collected on this install, so nothing goes; integration §11ad forwards real
// records to real receivers.
test('forwarding to a SIEM is refused over plain http, set after saying what goes, and stopped', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Audit log' }).click()
  const fwd = page.getByTestId('audit-forward')
  await expect(fwd).toContainText('Not forwarded.')

  await page.getByLabel('Forward URL').fill('http://127.0.0.1:9/ingest')
  await page.getByRole('button', { name: 'Forward', exact: true }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Forward', exact: true }).click()
  await expect(page.getByText(/unencrypted/)).toBeVisible({ timeout: 30_000 })

  await page.getByLabel('Forward URL').fill('https://127.0.0.1:9/ingest')
  await page.getByLabel('Forward token').fill('e2e-token')
  await page.getByRole('button', { name: 'Forward', exact: true }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg).toContainText('Statement text is not sent.')
  await dlg.getByRole('button', { name: 'Forward', exact: true }).click()
  await expect(fwd).toContainText('forwarding to https://127.0.0.1:9/ingest', { timeout: 30_000 })
  await expect(page.getByTestId('forward-position')).toContainText('Delivered up to record')
  await expect(fwd).not.toContainText('e2e-token')

  await page.getByRole('button', { name: 'Send now' }).click()
  await expect(page.getByText(/0 record\(s\) sent; 0 waiting\./)).toBeVisible({ timeout: 30_000 })

  await page.getByRole('button', { name: 'Stop forwarding' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Stop forwarding' }).click()
  await expect(fwd).toContainText('Not forwarded.', { timeout: 30_000 })
})

// Step 6: a SECURITY DEFINER function naming a marked table is named on the
// Audit log page, because pgAudit does not see the statements inside it.
// Integration §11ae shows a write through one missing from the log.
test('a SECURITY DEFINER function naming a marked table is named as not audited', async ({ page }) => {
  const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_def_${Date.now().toString().slice(-6)}`
  // One statement a run: the Blackbox keeps a run's whole text with each of
  // its changes, and the change-request test replays this branch's entries.
  await page.locator('textarea.editor').fill(`CREATE TABLE ${t} (id int PRIMARY KEY)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await page.locator('.obj-filter').fill(t)
  await expect(page.locator('.obj-item', { hasText: t }).first()).toBeVisible({ timeout: 30_000 })
  await page.locator('textarea.editor').fill(`CREATE FUNCTION ${t}_add(i int) RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ INSERT INTO ${t} VALUES (i) $$`)
  await page.getByRole('button', { name: /^run/i }).click()
  await page.locator('.obj-filter').fill(t)
  // The table, not its function, whose name starts the same.
  await page.locator('.obj-item').filter({ hasText: new RegExp(`${t}(\\s|$)`) }).first().click()
  await page.getByRole('button', { name: 'Audit…' }).click()
  await page.getByRole('dialog', { name: `Audit ${t}` }).getByRole('button', { name: 'Audit', exact: true }).click()
  await expect(page.getByTestId('audit-mark')).toContainText('Audited: writes', { timeout: 30_000 })

  await page.getByRole('link', { name: 'Audit log' }).click()
  await page.getByLabel('Branch').selectOption(branch)
  const definers = page.getByTestId('audit-definers')
  await expect(definers).toContainText(`${t}_add(integer)`, { timeout: 30_000 })
  await expect(definers).toContainText(`public.${t}`)
  await expect(definers).toContainText('SECURITY INVOKER')
  const row = page.getByRole('table', { name: `Marked tables on ${branch}` }).locator('tr', { hasText: `public.${t}` })
  await row.getByRole('button', { name: 'Stop auditing' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Stop auditing' }).click()
  await expect(page.getByTestId('audit-definers')).toHaveCount(0, { timeout: 30_000 })
})
