// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Create and edit dialogs (point 12.3) in a browser, against a real engine: a
// function made, edited, renamed and dropped; a trigger function and a
// trigger on a table made, edited, renamed and dropped.
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

async function console_(page: Page) {
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  await expect(page.getByRole('button', { name: '+ New function…' })).toBeVisible({ timeout: 30_000 })
}

async function openRoutine(page: Page, name: string) {
  await page.locator('.obj-filter').fill(name)
  await page.locator('.obj-item', { hasText: name }).first().click({ timeout: 30_000 })
  await expect(page.getByRole('region', { name: new RegExp(`function ${name}`) })).toBeVisible()
}

test('a function is made, edited, renamed and dropped from its dialogs', async ({ page }) => {
  await signIn(page)
  const f = `e2e_dlg_${Date.now().toString().slice(-6)}`
  await console_(page)

  await page.getByRole('button', { name: '+ New function…' }).click()
  let dlg = page.getByRole('dialog')
  await dlg.getByLabel('Name', { exact: true }).fill(f)
  await dlg.getByLabel('Arguments', { exact: true }).fill('a integer')
  await dlg.getByLabel('Returns', { exact: true }).fill('integer')
  await dlg.getByLabel('Language', { exact: true }).selectOption('sql')
  await dlg.getByLabel('Body', { exact: true }).fill('SELECT a + 1')
  await expect(dlg.getByTestId('ddl-sql')).toContainText(`CREATE FUNCTION "public"."${f}"(a integer)`)
  await dlg.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(dlg).toHaveCount(0, { timeout: 30_000 })

  await openRoutine(page, f)
  await page.getByRole('button', { name: 'Edit…' }).click()
  dlg = page.getByRole('dialog')
  await expect(dlg.getByLabel('Name', { exact: true })).toBeDisabled()
  await dlg.getByLabel('Body', { exact: true }).fill('SELECT a + 100')
  await dlg.getByLabel('Security definer').check()
  await expect(dlg.getByTestId('ddl-sql')).toContainText('CREATE OR REPLACE FUNCTION')
  await dlg.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(dlg).toHaveCount(0, { timeout: 30_000 })
  await expect(page.getByLabel('CREATE script')).toContainText('SELECT a + 100', { timeout: 30_000 })
  await expect(page.getByLabel('CREATE script')).toContainText('SECURITY DEFINER')

  await page.getByRole('button', { name: 'Rename…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('New name').fill(`${f}_r`)
  await dlg.getByRole('button', { name: 'Rename', exact: true }).click()
  await expect(dlg).toHaveCount(0, { timeout: 30_000 })

  await openRoutine(page, `${f}_r`)
  await page.getByRole('button', { name: 'Drop…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Drop it' }).click()
  await page.locator('.obj-filter').fill(`${f}_r`)
  await expect(page.locator('.obj-item', { hasText: `${f}_r` })).toHaveCount(0, { timeout: 30_000 })
})

test('a trigger function and a trigger are made, edited, renamed and dropped', async ({ page }) => {
  await signIn(page)
  const t = `e2e_tdl_${Date.now().toString().slice(-6)}`
  const made = await page.request.post(`/api/branches/${branch}/query`, { data: { sql: `CREATE TABLE ${t} (id int PRIMARY KEY, v text)` } })
  expect(await made.text()).not.toContain('"error"')
  await console_(page)

  await page.getByRole('button', { name: '+ New function…' }).click()
  let dlg = page.getByRole('dialog')
  await dlg.getByLabel('Kind', { exact: true }).selectOption('trigger')
  await dlg.getByLabel('Name', { exact: true }).fill(`${t}_fn`)
  await expect(dlg.getByLabel('Body', { exact: true })).toHaveValue(/RETURN NEW;/)
  await expect(dlg.getByTestId('ddl-sql')).toContainText('RETURNS trigger')
  await dlg.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(dlg).toHaveCount(0, { timeout: 30_000 })

  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: new RegExp(`${t}$`) }).first().click()
  await page.getByRole('button', { name: 'Triggers', exact: true }).click()
  await page.getByRole('button', { name: '+ New trigger…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('Name', { exact: true }).fill(`${t}_tr`)
  await dlg.getByRole('group', { name: 'Events' }).getByLabel('UPDATE').check()
  await dlg.getByLabel('Trigger function').selectOption(`"public"."${t}_fn"`)
  await expect(dlg.getByTestId('ddl-sql')).toContainText(`CREATE TRIGGER "${t}_tr" BEFORE INSERT OR UPDATE`)
  await dlg.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(page.getByTestId('trigger-note')).toHaveText('Trigger created.', { timeout: 30_000 })

  let row = page.getByTestId(`part-${t}_tr`)
  await row.getByRole('button', { name: 'Edit…' }).click()
  dlg = page.getByRole('dialog')
  await expect(dlg.getByLabel('When it fires')).toHaveValue('BEFORE')
  await dlg.getByLabel('Condition').fill('new.v IS NOT NULL')
  await expect(dlg.getByTestId('ddl-sql')).toContainText('CREATE OR REPLACE TRIGGER')
  await dlg.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByTestId('trigger-note')).toHaveText(`${t}_tr saved.`, { timeout: 30_000 })
  await expect(row).toContainText('new.v IS NOT NULL')

  await row.getByRole('button', { name: 'Rename…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('New name').fill(`${t}_t2`)
  await dlg.getByRole('button', { name: 'Rename', exact: true }).click()
  await expect(page.getByTestId('trigger-note')).toHaveText('Trigger renamed.', { timeout: 30_000 })

  row = page.getByTestId(`part-${t}_t2`)
  await row.getByRole('button', { name: 'Drop…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Drop it' }).click()
  await expect(page.getByTestId('trigger-note')).toHaveText(`${t}_t2 dropped.`, { timeout: 30_000 })
  await expect(row).toHaveCount(0)
})

test("a slow reply about the branch just left does not replace this branch's catalog", async ({ page }) => {
  await signIn(page)
  const t = `e2e_race_${Date.now().toString().slice(-6)}`
  const made = await page.request.post(`/api/branches/${branch}/query`, { data: { sql: `CREATE TABLE ${t} (id int PRIMARY KEY)` } })
  expect(await made.text()).not.toContain('"error"')
  await page.route('**/api/branches/main/schema', async route => {
    await new Promise(r => setTimeout(r, 2500))
    await route.continue()
  })
  await console_(page)
  await page.waitForTimeout(3000) // main's reply has come, late
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Triggers', exact: true }).click()
  await expect(page.getByTestId('part-bb_guard_dml')).toBeVisible({ timeout: 30_000 })
})
