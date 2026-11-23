// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The DPDP inventory page, in a browser, against a real engine (point 11.1).
//
// The component tests prove the page's logic against mocks. This proves the
// page lists a real branch's confirmed personal data as a gap until an entry
// is set from it, that the entry is kept in the branch (still there on the
// next visit), that a column's own entry replaces the table's, that the
// history and the export carry what was set, and that removing an entry
// leaves the column to the table's again. The table is made here, through the
// API the SQL console uses, with this browser's own session; the scan and the
// decisions are made through the API the Personal data page uses, whose own
// test drives them from the page.
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

test('a gap until an entry is set from the page; a column of its own; kept, exported and removed', async ({ page }) => {
  test.setTimeout(180_000)
  await signIn(page)
  const t = `dpdp_${Date.now().toString().slice(-6)}`
  const where = `public.${t}`
  const api = async (method: 'get' | 'post', url: string, data?: unknown) => {
    const r = method === 'get' ? await page.request.get(url) : await page.request.post(url, { data })
    expect(r.ok(), `${method} ${url}: ${await r.text()}`).toBeTruthy()
    return r.json()
  }
  await api('post', `/api/branches/${branch}/query`, { sql: `CREATE TABLE ${where} (id int PRIMARY KEY, email text, phone text, note text)` })
  await api('post', `/api/branches/${branch}/query`, {
    sql: `INSERT INTO ${where} VALUES (1, 'asha@example.com', '9876543210', 'x'), (2, 'ravi@example.org', '9123456780', 'y'), (3, 'meena@example.net', '8765432109', 'z')`,
  })
  // A full scan, as the Personal data page's first one is, then each of this
  // table's findings confirmed.
  const rep = await api('post', `/api/branches/${branch}/personal-data/scan`, {})
  const mine = (rep.findings ?? []).filter((f: { table: string }) => f.table === t)
  expect([...new Set(mine.map((f: { column: string }) => f.column))].sort()).toEqual(['email', 'phone'])
  for (const f of mine) {
    await api('post', `/api/branches/${branch}/personal-data/findings/${f.id}/mark`, { state: 'confirmed', note: 'dpdp e2e' })
  }

  // Exact: the dashboard's gaps warning links here too, as "Open the DPDP inventory".
  await page.getByRole('link', { name: 'DPDP inventory', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'DPDP inventory', exact: true })).toBeVisible()
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  const card = page.getByTestId(`dpdp-table-${where}`)
  await expect(card).toContainText('2 gap(s)', { timeout: 30_000 })
  await expect(card).toContainText('No entry for the table.')
  const cols = card.getByRole('table', { name: `Columns of ${where}`, exact: true })
  const row = (c: string) => cols.locator('tr', { has: page.getByText(c, { exact: true }) })
  await expect(row('email')).toContainText('no entry')
  await expect(row('phone')).toContainText('mobile')
  await expect(cols.getByText('note', { exact: true })).toHaveCount(0) // nothing found there

  // The table's entry, from the page.
  await card.getByRole('button', { name: 'Set entry…' }).click()
  const form = page.getByTestId('dpdp-form')
  await form.getByLabel('Purpose').fill('Delivering orders and sending receipts')
  await form.getByLabel('Keep for').fill('3')
  await form.getByLabel('Unit').selectOption('years')
  await form.getByLabel('After').selectOption('last_contact')
  await form.getByLabel('Because').selectOption('purpose')
  await form.getByRole('button', { name: 'Save entry' }).click()
  await expect(form).toHaveCount(0)
  await expect(card).not.toContainText('gap(s)')
  await expect(card).toContainText('Consent (s.6)')
  await expect(card).toContainText("kept 3 years after the person's last contact (s.8(8))")
  await expect(row('email')).toContainText("the table's entry")

  // The phone column's own entry: a law sets its period, so the page asks which.
  await row('phone').getByRole('button', { name: 'Own entry…' }).click()
  await expect(form).toContainText("it replaces the table's for this column")
  await expect(form.getByLabel('Purpose')).toHaveValue('Delivering orders and sending receipts')
  await form.getByLabel('Basis (s.4)').selectOption('7d')
  await form.getByLabel('Keep for').fill('8')
  await form.getByLabel('After').selectOption('account_closed')
  await form.getByLabel('Because').selectOption('law')
  await expect(form.getByRole('button', { name: 'Save entry' })).toBeDisabled()
  await form.getByLabel('Citation').fill('Prevention of Money-laundering Act, 2002, s.12')
  await form.getByRole('button', { name: 'Save entry' }).click()
  await expect(row('phone')).toContainText('its own entry')
  await expect(row('phone')).toContainText('8 years after the account is closed; a law requires it: Prevention of Money-laundering Act, 2002, s.12')

  // Kept in the branch: there on the next visit.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByLabel('Branch', { exact: true }).selectOption(branch)
  await expect(row('phone')).toContainText('its own entry', { timeout: 30_000 })

  // The history, and the export, carry what was set.
  await card.getByRole('button', { name: 'History' }).click()
  const hist = page.getByTestId('dpdp-history')
  await expect(hist).toContainText(email)
  await expect(hist.getByRole('row')).toHaveCount(3) // header, the table's, the column's
  const csv = await page.request.get(`/api/branches/${branch}/dpdp/inventory?format=csv`)
  expect(csv.ok()).toBeTruthy()
  const lines = (await csv.text()).split('\n').filter(l => l.startsWith(`public,${t},`))
  expect(lines).toHaveLength(2)
  expect(lines.find(l => l.includes(',email,'))).toContain(',table,consent,')
  expect(lines.find(l => l.includes(',phone,'))).toContain(',column,7d,')

  // Removing the column's entry leaves it to the table's.
  await row('phone').getByRole('button', { name: 'Edit its entry…' }).click()
  await form.getByRole('button', { name: 'Remove entry…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(row('phone')).toContainText("the table's entry")
  await expect(card).not.toContainText('gap(s)')
})
