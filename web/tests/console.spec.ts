// SPDX-License-Identifier: AGPL-3.0-or-later
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'
const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'      // made by the harness, owned by this account
const newBranch = process.env.FOX_E2E_NEW_BRANCH ?? 'e2eui2' // made here, through the dashboard
const table = process.env.FOX_E2E_TABLE ?? 'e2e_notes'

// Each test signs in and works on its own: the branch the console and Blackbox
// tests use is made by scripts/integration_ui.sh, so no test depends on
// another having run first.
async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

test('signing in reaches the dashboard, which lists main', async ({ page }) => {
  await signIn(page)
  await expect(page.getByRole('cell', { name: 'main', exact: true })).toBeVisible()
})

test('the wrong password is refused', async ({ page }) => {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill('not-the-password')
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.locator('.err')).toContainText(/invalid credentials/i)
  await expect(page).toHaveURL(/\/login$/)
})

test('a branch made in the dashboard appears in the list', async ({ page }) => {
  await signIn(page)
  await page.getByPlaceholder(/new branch name/i).fill(newBranch)
  await page.getByRole('button', { name: /create branch/i }).click()
  await expect(page.getByRole('cell', { name: newBranch, exact: true })).toBeVisible({ timeout: 60_000 })
})

test('the console runs SQL on that branch, and the Blackbox shows the change', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'SQL Console' })).toBeVisible()
  // The branch picker is a select of the branches this account can reach.
  // The branch picker lists what this account may reach.
  const picker = page.locator('select').first()
  await expect(picker.locator(`option[value="${branch}"]`)).toHaveCount(1)
  await picker.selectOption(branch)
  await page.locator('textarea.editor').fill(`CREATE TABLE ${table} (id int)`)
  await page.getByRole('button', { name: /run query/i }).click()
  await expect(page.locator('.grid-wrap, .result, table').first()).toBeVisible()

  await page.goto('/blackbox', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'Blackbox' })).toBeVisible()
  const bbPicker = page.locator('select').first()
  await expect(bbPicker.locator(`option[value="${branch}"]`)).toHaveCount(1)
  await bbPicker.selectOption(branch)
  await expect(page.getByText(`public.${table}`).first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(email).first()).toBeVisible()
})

test('an API key is shown once, and the account page offers a password change', async ({ page }) => {
  await signIn(page)
  await page.goto('/keys', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'API keys' })).toBeVisible()
  await page.getByPlaceholder(/key name/i).fill('e2e')
  await page.getByRole('button', { name: /create key/i }).click()
  await expect(page.getByText(/copy it now/i)).toBeVisible()
  await expect(page.locator('pre code').first()).toContainText(/^key_/)
  await expect(page.getByRole('heading', { name: 'Your password' })).toBeVisible()
})
