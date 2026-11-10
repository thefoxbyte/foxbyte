// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The table dialogs (point 12.3) in a browser, against a real engine: a table
// made, its columns added, edited and dropped, renamed and dropped; its primary,
// unique, foreign and check keys added, edited, renamed and dropped.
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
  expect(await r.text()).not.toContain('"error"')
}

async function console_(page: Page) {
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  await expect(page.getByRole('button', { name: '+ New table…' })).toBeVisible({ timeout: 30_000 })
}

async function openTable(page: Page, t: string, tab: string) {
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click({ timeout: 30_000 })
  await page.getByRole('button', { name: tab, exact: true }).click()
}

test('a table is made, its columns added, edited and dropped, then renamed and dropped', async ({ page }) => {
  await signIn(page)
  const t = `e2e_tbl_${Date.now().toString().slice(-6)}`
  await console_(page)

  await page.getByRole('button', { name: '+ New table…' }).click()
  let dlg = page.getByRole('dialog')
  await dlg.getByLabel('Name', { exact: true }).fill(t)
  await dlg.getByRole('button', { name: '+ Add a column' }).click()
  await dlg.getByLabel('Column 2 name', { exact: true }).fill('label')
  await dlg.getByLabel('Column 2 type', { exact: true }).fill('text')
  await dlg.getByLabel('Column 2 not null', { exact: true }).check()
  await expect(dlg.getByTestId('ddl-sql')).toContainText(`CREATE TABLE "public"."${t}"`)
  await expect(dlg.getByTestId('ddl-sql')).toContainText('PRIMARY KEY ("id")')
  await dlg.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(dlg).toHaveCount(0, { timeout: 30_000 })

  // It opens on its columns.
  await expect(page.getByTestId('col-label')).toContainText('not null', { timeout: 30_000 })

  await page.getByRole('button', { name: '+ Add column…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('Name', { exact: true }).fill('qty')
  await dlg.getByLabel('Type', { exact: true }).fill('integer')
  await dlg.getByLabel('Default', { exact: true }).fill('1')
  await dlg.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(page.getByTestId('table-note')).toHaveText('Column added.', { timeout: 30_000 })
  await expect(page.getByTestId('col-qty')).toContainText('integer')

  await page.getByTestId('col-qty').getByRole('button', { name: 'Edit…' }).click()
  dlg = page.getByRole('dialog')
  await expect(dlg.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()
  await dlg.getByLabel('Name', { exact: true }).fill('amount')
  await dlg.getByLabel('Type', { exact: true }).fill('bigint')
  await dlg.getByLabel('Not null', { exact: true }).check()
  await expect(dlg.getByLabel('Using', { exact: true })).toBeVisible()
  await expect(dlg.getByTestId('ddl-sql')).toContainText('ALTER COLUMN "qty" TYPE bigint')
  await expect(dlg.getByTestId('ddl-sql')).toContainText('RENAME COLUMN "qty" TO "amount"')
  await dlg.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByTestId('table-note')).toHaveText('qty saved.', { timeout: 30_000 })
  await expect(page.getByTestId('col-amount')).toContainText('bigint')
  await expect(page.getByTestId('col-amount')).toContainText('not null')

  await page.getByTestId('col-amount').getByRole('button', { name: 'Drop…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByRole('button', { name: 'Drop it', exact: true }).click()
  await expect(page.getByTestId('table-note')).toHaveText('amount dropped.', { timeout: 30_000 })
  await expect(page.getByTestId('col-amount')).toHaveCount(0)

  const to = `${t}_r`
  await page.getByRole('button', { name: 'Rename table…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('New name', { exact: true }).fill(to)
  await dlg.getByRole('button', { name: 'Rename', exact: true }).click()
  await expect(dlg).toHaveCount(0, { timeout: 30_000 })
  await expect(page.getByRole('heading', { name: to, level: 2 })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByTestId('col-label')).toBeVisible({ timeout: 30_000 })

  // The guardrail answers a drop as it does anywhere; the editor is the way on.
  await page.getByRole('button', { name: 'Drop table…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByRole('button', { name: 'Drop it', exact: true }).click()
  await expect(dlg.getByTestId('ddl-err')).toContainText('DROP TABLE is blocked by policy', { timeout: 30_000 })
  await dlg.getByRole('button', { name: 'Put it in the editor' }).click()
  await expect(page.locator('textarea.editor')).toHaveValue(`DROP TABLE "public"."${to}"`)
  await sql(page, `SET bb.allow_destructive = on; DROP TABLE "public"."${to}"`)
})

test('a table\'s keys are added, edited, renamed and dropped', async ({ page }) => {
  await signIn(page)
  const n = Date.now().toString().slice(-6)
  const p = `e2e_kp_${n}`, c = `e2e_kc_${n}`
  await sql(page, `CREATE TABLE ${p} (id int PRIMARY KEY, code text); CREATE TABLE ${c} (cid int, pid int, code text, qty int)`)
  await console_(page)
  await openTable(page, c, 'Constraints')

  const add = async () => {
    await page.getByRole('button', { name: '+ Add key…' }).click({ timeout: 30_000 })
    return page.getByRole('dialog')
  }
  // A table with none is offered a primary key first.
  let dlg = await add()
  await expect(dlg.getByLabel('Kind', { exact: true })).toHaveValue('primary')
  await dlg.getByLabel('Columns: cid', { exact: true }).check()
  await expect(dlg.getByTestId('ddl-sql')).toContainText('ADD PRIMARY KEY ("cid")')
  await dlg.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(page.getByTestId('key-note')).toHaveText('Key added.', { timeout: 30_000 })
  await expect(page.getByTestId(`part-${c}_pkey`)).toContainText('PRIMARY KEY')

  dlg = await add()
  await expect(dlg.getByLabel('Kind', { exact: true })).toHaveValue('unique')
  await dlg.getByLabel('Name', { exact: true }).fill(`${c}_u`)
  await dlg.getByLabel('Columns: qty', { exact: true }).check()
  await dlg.getByLabel('Columns: code', { exact: true }).check()
  await expect(dlg.getByTestId('ddl-sql')).toContainText('UNIQUE ("qty", "code")')
  await dlg.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(page.getByTestId(`part-${c}_u`)).toBeVisible({ timeout: 30_000 })

  dlg = await add()
  await dlg.getByLabel('Kind', { exact: true }).selectOption('check')
  await dlg.getByLabel('Name', { exact: true }).fill(`${c}_ck`)
  await dlg.getByLabel('Condition', { exact: true }).fill('qty > 0')
  await dlg.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(page.getByTestId(`part-${c}_ck`)).toContainText('qty > 0', { timeout: 30_000 })

  // A foreign key takes the other table's primary key as what it references.
  dlg = await add()
  await dlg.getByLabel('Kind', { exact: true }).selectOption('foreign')
  await dlg.getByLabel('Name', { exact: true }).fill(`${c}_fk`)
  await dlg.getByLabel('Columns: pid', { exact: true }).check()
  await dlg.getByLabel('References', { exact: true }).selectOption(`public.${p}`)
  await expect(dlg.getByLabel('Its columns: id', { exact: true })).toBeChecked({ timeout: 30_000 })
  await dlg.getByLabel('On delete', { exact: true }).selectOption('CASCADE')
  await expect(dlg.getByTestId('ddl-sql')).toContainText(`REFERENCES "public"."${p}" ("id") ON DELETE CASCADE`)
  await dlg.getByRole('button', { name: 'Add', exact: true }).click()
  const fk = page.getByTestId(`part-${c}_fk`)
  await expect(fk).toContainText('ON DELETE CASCADE', { timeout: 30_000 })

  await fk.getByRole('button', { name: 'Edit…' }).click()
  dlg = page.getByRole('dialog')
  await expect(dlg.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()
  await expect(dlg.getByLabel('On delete', { exact: true })).toHaveValue('CASCADE')
  await dlg.getByLabel('On delete', { exact: true }).selectOption('SET NULL')
  await expect(dlg.getByTestId('ddl-sql')).toContainText(`DROP CONSTRAINT "${c}_fk"`)
  await dlg.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(fk).toContainText('ON DELETE SET NULL', { timeout: 30_000 })

  await page.getByTestId(`part-${c}_ck`).getByRole('button', { name: 'Rename…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('New name', { exact: true }).fill(`${c}_ck2`)
  await dlg.getByRole('button', { name: 'Rename', exact: true }).click()
  const ck2 = page.getByTestId(`part-${c}_ck2`)
  await expect(ck2).toBeVisible({ timeout: 30_000 })

  await ck2.getByRole('button', { name: 'Drop…' }).click()
  dlg = page.getByRole('dialog')
  await dlg.getByRole('button', { name: 'Drop it', exact: true }).click()
  await expect(page.getByTestId('key-note')).toHaveText(`${c}_ck2 dropped.`, { timeout: 30_000 })
  await expect(ck2).toHaveCount(0)

  // Postgres's refusal is shown in the dialog.
  await page.getByRole('button', { name: 'Structure', exact: true }).click()
  await page.getByTestId('col-cid').getByRole('button', { name: 'Edit…' }).click({ timeout: 30_000 })
  dlg = page.getByRole('dialog')
  await dlg.getByLabel('Name', { exact: true }).fill('pid')
  await dlg.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(dlg.getByTestId('ddl-err')).toContainText('already exists', { timeout: 30_000 })
  await dlg.getByRole('button', { name: 'Cancel', exact: true }).click()
})
