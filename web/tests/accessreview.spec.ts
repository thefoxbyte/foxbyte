// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Access review page, in a browser, against a real engine (point 4.8). The
// component tests prove the page against mocks; this proves the report a real
// install produces lands in its tables, follows a new window, and downloads.
// The account is an install admin (scripts/integration_ui.sh), as the report
// requires, and owns the branch the suite made for it.
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'
const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'

async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

test('the access review lists accounts, keys and branches, follows a new window, and downloads as CSV', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Access review' }).click()
  await expect(page.getByRole('heading', { name: 'Access review', exact: true })).toBeVisible()

  const accounts = page.getByRole('table', { name: 'Accounts' })
  // hasText, not an exact cell: an admin's cell reads "<email> admin".
  const me = accounts.locator('tr', { hasText: email })
  await expect(me).toContainText('every branch (an install admin)', { timeout: 30_000 })
  await expect(me).toContainText('admin')
  await expect(page.getByRole('table', { name: 'Keys' })).toBeVisible()
  const branches = page.getByRole('table', { name: 'Branches' })
  await expect(branches.locator('tr', { has: page.getByText(branch, { exact: true }) })).toContainText(email)
  await expect(page.getByRole('heading', { name: 'What this report cannot claim' })).toBeVisible()
  await expect(page.getByText(/No masking is in place yet/)).toBeVisible()

  await page.getByLabel('Dormant after (days)').fill('30')
  await page.getByRole('button', { name: 'Produce report' }).click()
  await expect(page.getByTestId('ar-generated')).toContainText('dormant after 30 days')

  // The download is the engine's own CSV, for the window on screen.
  const href = await page.getByRole('link', { name: 'Keys', exact: true }).getAttribute('href')
  expect(href).toMatch(/dormant=30&format=csv&section=keys$/)
  const csv = await page.request.get(href!)
  expect(csv.ok()).toBeTruthy()
  expect(csv.headers()['content-type']).toContain('text/csv')
  expect((await csv.text()).split('\n')[0]).toBe('id,name,prefix,owner,kind,identity,reach,created,last_used,age_days,stale,why')
})

// The Applications table (F1): integration_ui.sh registered uishop for this
// account and asserted alice in a change on the suite's branch, so the report
// shows the key, what it asserted there, and why a reviewer should look: the
// account signs in here and is an install admin, which an application's
// account should be neither.
test('the access review lists the applications, what each key asserted, and what to question', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Access review' }).click()
  const apps = page.getByRole('table', { name: 'Applications' })
  const row = apps.locator('tr', { hasText: 'uishop' })
  await expect(row).toContainText(email, { timeout: 30_000 })
  await expect(row).toContainText('ui')
  await expect(row).toContainText('active')
  await expect(row).toContainText(branch)
  const findings = page.getByRole('list', { name: 'Application findings' })
  await expect(findings).toContainText('uishop: Its account signs in to the console')
  await expect(findings).toContainText('install admin')
  // The sidebar has an Applications link too: the CSV one is the report's.
  const csv = page.locator('.access-review a.btn', { hasText: 'Applications' })
  await expect(csv).toHaveAttribute('href', /section=applications$/)
})
