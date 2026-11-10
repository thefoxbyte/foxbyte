// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Run, toggle and plan (point 12.4) in a browser, against a real engine: a
// function run from its form; a table's own trigger disabled and enabled; a
// statement explained, and explained with ANALYZE, which is rolled back.
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

async function sql(page: Page, text: string) {
  const r = await page.request.post(`/api/branches/${branch}/query`, { data: { sql: text } })
  expect(r.ok()).toBeTruthy()
  const body = await r.text()
  expect(body).not.toContain('"error"')
}

async function console_(page: Page) {
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
}

test('a function is run from its form, with a default left to itself', async ({ page }) => {
  await signIn(page)
  const f = `e2e_add_${Date.now().toString().slice(-6)}`
  await sql(page, `CREATE FUNCTION ${f}(a integer, b integer DEFAULT 10) RETURNS integer LANGUAGE sql AS $$ SELECT a + b $$`)
  await console_(page)
  await page.locator('.obj-filter').fill(f)
  const group = page.getByRole('button', { name: /Functions/ })
  if ((await group.getAttribute('aria-expanded')) === 'false') await group.click()
  await page.locator('.obj-item', { hasText: f }).first().click()
  const form = page.getByRole('form', { name: `Run ${f}` })
  await form.getByLabel('Value of a').fill('5')
  await expect(form.getByTestId('run-sql')).toHaveText(`SELECT * FROM "public"."${f}"("a" => CAST('5' AS integer))`)
  await form.getByRole('button', { name: 'Run', exact: true }).click()
  await expect(page.getByRole('cell', { name: '15', exact: true })).toBeVisible({ timeout: 30_000 })
})

test("a table's own trigger is disabled and enabled from its Triggers tab", async ({ page }) => {
  await signIn(page)
  const t = `e2e_trg_${Date.now().toString().slice(-6)}`
  await sql(page, `CREATE TABLE ${t} (id int PRIMARY KEY, v text);
    CREATE FUNCTION ${t}_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.v := upper(NEW.v); RETURN NEW; END $$;
    CREATE TRIGGER ${t}_up BEFORE INSERT ON ${t} FOR EACH ROW EXECUTE FUNCTION ${t}_fn()`)
  await console_(page)
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()
  await page.getByRole('button', { name: 'Triggers', exact: true }).click()
  const row = page.getByTestId(`part-${t}_up`)
  await row.getByRole('button', { name: 'Disable…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Disable', exact: true }).click()
  await expect(page.getByTestId('trigger-note')).toHaveText(`${t}_up disabled.`)
  await expect(row).toContainText('disabled')
  await row.getByRole('button', { name: 'Enable' }).click()
  await expect(page.getByTestId('trigger-note')).toHaveText(`${t}_up enabled.`)
  await expect(row.getByRole('button', { name: 'Disable…' })).toBeVisible()
})

test('a statement is explained as a plan table, and with Analyse measured and rolled back', async ({ page }) => {
  await signIn(page)
  const t = `e2e_pln_${Date.now().toString().slice(-6)}`
  await sql(page, `CREATE TABLE ${t} (id int PRIMARY KEY, v int); INSERT INTO ${t} SELECT g, g FROM generate_series(1, 2000) g; ANALYZE ${t}`)
  await console_(page)
  await page.locator('textarea.editor').fill(`DELETE FROM ${t} WHERE v > 1000`)
  await page.getByRole('button', { name: 'Explain', exact: true }).click()
  const plan = page.getByTestId('plan')
  await expect(plan).toContainText('Plan, as estimated', { timeout: 30_000 })
  await expect(page.getByTestId('plan-row').first()).toContainText('Delete')
  await expect(plan).toContainText(t)
  await page.getByLabel('Analyse', { exact: true }).check()
  await page.getByRole('button', { name: 'Explain', exact: true }).click()
  await expect(page.getByTestId('plan-times')).toContainText('rolled back', { timeout: 30_000 })
  // Measured, and nothing deleted.
  await page.locator('textarea.editor').fill(`SELECT count(*) FROM ${t}`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.getByRole('cell', { name: '2000', exact: true })).toBeVisible({ timeout: 30_000 })
})
