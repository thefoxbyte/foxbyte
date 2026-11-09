// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Sessions and upkeep (point 12.5) in a browser, against a real engine: a
// query of the signed-in account's own seen running on the Sessions page and
// cancelled there; a table analysed from the Console's Upkeep tab.
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

test('a running query is seen on the Sessions page and cancelled there', async ({ page }) => {
  await signIn(page)
  const tag = `e2e_sleep_${Date.now().toString().slice(-6)}`
  // Not awaited: it runs until it is cancelled.
  const running = page.request.post(`/api/branches/${branch}/query`, { data: { sql: `SELECT pg_sleep(60) AS ${tag}` }, timeout: 90_000 })
  await page.getByRole('link', { name: 'Sessions' }).click()
  await expect(page.getByRole('heading', { name: 'Sessions', exact: true })).toBeVisible()
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  const row = page.getByRole('row').filter({ hasText: tag })
  await expect(row).toContainText('active', { timeout: 30_000 })
  await expect(row).toContainText(email)
  await row.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByTestId('sessions-msg')).toContainText("query cancelled")
  const res = await running
  expect(await res.text()).toContain('canceling statement due to user request')
  await expect(row).toHaveCount(0, { timeout: 15_000 })
})

test("a table is analysed from the Console's Upkeep tab, and its last analyse shown", async ({ page }) => {
  await signIn(page)
  const t = `e2e_upk_${Date.now().toString().slice(-6)}`
  const made = await page.request.post(`/api/branches/${branch}/query`, {
    data: { sql: `CREATE TABLE ${t} (id int PRIMARY KEY); INSERT INTO ${t} SELECT generate_series(1, 100)` } })
  expect(made.ok()).toBeTruthy()
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()
  await page.getByRole('button', { name: 'Upkeep', exact: true }).click()
  await expect(page.getByTestId('upkeep-analyze')).toContainText('never', { timeout: 30_000 })
  await page.getByRole('button', { name: 'Analyse', exact: true }).click()
  await expect(page.getByTestId('upkeep-msg')).toContainText('Analyse: done', { timeout: 30_000 })
  await expect(page.getByTestId('upkeep-analyze')).not.toContainText('never')
})
