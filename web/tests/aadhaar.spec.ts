// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Aadhaar exposure page, in a browser, against a real engine (point 4.5).
//
// The component tests prove the page's logic against mocks. This proves a run
// started from the page reads every row of a real branch, groups one number's
// places as one person shown by its last four digits, opens that person's rows,
// keeps the report for the next visit, says when a number has gone, and puts
// no whole number on the screen. public.pii_people (synthetic values) is made
// by scripts/integration_ui.sh; the notes table here, through the API the SQL
// console uses, with this browser's own session.
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

test('a run from the page finds whose Aadhaar is where, by its last four digits, and shows no number', async ({ page }) => {
  await signIn(page)
  // Synthetic: 234567890124 passes Verhoeff; pii_people holds it as row 1.
  const notes = `aad_notes_${Date.now().toString().slice(-6)}`
  const sql = async (q: string) => {
    const r = await page.request.post(`/api/branches/${branch}/query`, { data: { sql: q } })
    expect(r.ok(), await r.text()).toBeTruthy()
  }
  await sql(`CREATE TABLE public.${notes} (id int PRIMARY KEY, note text)`)
  await sql(`INSERT INTO public.${notes} VALUES (7, 'caller read out 2345 6789 0124'), (8, 'card 4111 1111 1111 1111')`)

  await page.getByRole('link', { name: 'Aadhaar exposure' }).click()
  await expect(page.getByRole('heading', { name: 'Aadhaar exposure', exact: true })).toBeVisible()
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  await page.getByRole('button', { name: 'Run the report' }).click()

  const cols = page.getByRole('table', { name: 'Aadhaar by column' })
  const col = (where: string) => cols.locator('tr', { has: page.getByText(where, { exact: true }) })
  await expect(col('public.pii_people.aadhaar_no')).toContainText('2', { timeout: 120_000 })
  await expect(col(`public.${notes}.note`)).toBeVisible()
  // A card's sixteen digits are not an Aadhaar.
  await expect(cols.getByText('public.pii_people.card_no', { exact: true })).toHaveCount(0)

  // One number in two tables is one person, shown as UIDAI masks it.
  const people = page.getByRole('table', { name: 'Aadhaar by person' })
  const person = people.locator('tr', { has: page.getByText('XXXX XXXX 0124', { exact: true }) })
  await expect(person).toContainText('public.pii_people.aadhaar_no')
  await expect(person).toContainText(`public.${notes}.note`)
  await person.getByRole('button', { name: /^Rows of person \d+$/ }).click()
  const places = page.getByRole('table', { name: 'Aadhaar places' })
  await expect(places.locator('tr', { has: page.getByText(`public.${notes}.note`, { exact: true }) })).toContainText('id=7')
  await expect(places.locator('tr', { has: page.getByText('public.pii_people.aadhaar_no', { exact: true }) })).toContainText('id=1')
  await expect(page.getByRole('heading', { name: 'What this cannot claim' })).toBeVisible()
  await expect(page.getByTestId('aadhaar-summary')).toContainText('number(s) found')

  // Where, never what: no whole number reaches the screen.
  const text = (await page.locator('main').innerText()).replace(/[ -]/g, '')
  for (const v of ['234567890124', '456789012341', '4111111111111111']) {
    expect(text).not.toContain(v)
  }

  // Kept, not recomputed: the report is there on the next visit.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  await expect(col(`public.${notes}.note`)).toBeVisible({ timeout: 30_000 })

  // A number taken out is gone on the next run, with when it was last seen.
  await sql(`UPDATE public.${notes} SET note = 'number removed' WHERE id = 7`)
  await page.getByRole('button', { name: 'Run the report' }).click()
  await expect(cols.getByText(`public.${notes}.note`, { exact: true })).toHaveCount(0, { timeout: 120_000 })
  await page.getByRole('button', { name: /^\d+ place\(s\) earlier runs found are no longer there$/ }).click()
  const gone = page.getByRole('table', { name: 'Aadhaar places' })
  await expect(gone.locator('tr', { has: page.getByText(`public.${notes}.note`, { exact: true }) })).toContainText('XXXX XXXX 0124')
  await expect(gone).toContainText('Last seen')
  // No clean-up: a DROP here would be one of the branch's changes, which a
  // later spec applies to another branch, where the guardrail refuses it. The
  // harness remakes the branch, as personaldata.spec.ts leaves its table too.
})

test("an admin's run reads the branch's logs too: a number someone typed is the same person as the row's", async ({ page }) => {
  await signIn(page)
  // Synthetic: 298765432101 passes Verhoeff, and is used nowhere else here.
  const t = `aad_logs_${Date.now().toString().slice(-6)}`
  const sql = async (q: string) => {
    const r = await page.request.post(`/api/branches/${branch}/query`, { data: { sql: q } })
    expect(r.ok(), await r.text()).toBeTruthy()
  }
  await sql(`CREATE TABLE public.${t} (id int PRIMARY KEY, note text)`)
  await sql(`INSERT INTO public.${t} VALUES (3, 'uid 2987 6543 2101')`)
  // Kept in this account's query history, number and all.
  await sql(`SELECT id FROM public.${t} WHERE note LIKE '%2987 6543 2101%'`)

  await page.getByRole('link', { name: 'Aadhaar exposure' }).click()
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  await page.getByLabel(/Read the logs too/).check()
  await page.getByRole('button', { name: 'Run the report' }).click()

  const logs = page.getByRole('table', { name: 'Aadhaar in the logs' })
  await expect(logs).toContainText('query history', { timeout: 120_000 })
  await expect(page.getByTestId('aadhaar-logs-summary')).toContainText('also in the tables')
  const person = page.getByRole('table', { name: 'Aadhaar by person' })
    .locator('tr', { has: page.getByText('XXXX XXXX 2101', { exact: true }) })
  await expect(person).toContainText(`public.${t}.note`)
  await expect(person).toContainText('query history')
  await person.getByRole('button', { name: /^Rows of person \d+$/ }).click()
  await expect(page.getByRole('table', { name: 'Aadhaar places' })).toContainText('id=3')
  const entries = page.getByRole('table', { name: 'Aadhaar log entries' })
  await expect(entries).toContainText(email)
  await expect(entries).toContainText('(sql)')
  await expect(page.getByRole('heading', { name: 'What the logs part cannot claim' })).toBeVisible()

  const text = (await page.locator('main').innerText()).replace(/[ -]/g, '')
  expect(text).not.toContain('298765432101')
  // No clean-up, as above.
})
