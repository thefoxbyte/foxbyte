// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Erasure requests page, in a browser, against a real engine (point 11.2,
// F4, Gate 1 step 1).
//
// The component tests prove the page's logic against mocks. This proves a
// request made from the page finds a real person's row on main through a
// confirmed column, shows what it will do, and, applied from the page with
// the values typed again, erases that row and no other. The table is made on
// main, through the API the SQL console uses, and dropped at the end: an
// erasure request is for main alone in this step, and the harness does not
// remake main between runs. The scan, the decisions and the inventory entry go
// through the APIs their own pages use; their own tests drive them.
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

test('a request made from the page finds the person on main, and applied with the values again erases only them', async ({ page }) => {
  test.setTimeout(240_000)
  await signIn(page)
  const n = Date.now().toString().slice(-6)
  const t = `er_e2e_${n}`
  const where = `public.${t}`
  const person = `asha.${n}@example.in`
  const other = `ravi.${n}@example.org`
  const api = async (method: 'get' | 'post' | 'put', url: string, data?: unknown) => {
    const r = method === 'get' ? await page.request.get(url) : method === 'put' ? await page.request.put(url, { data }) : await page.request.post(url, { data })
    expect(r.ok(), `${method} ${url}: ${await r.text()}`).toBeTruthy()
    return r.json()
  }
  const sql = (q: string, destructive = false) => api('post', '/api/branches/main/query', { sql: q, allow_destructive: destructive })
  try {
    await sql(`CREATE TABLE ${where} (id int PRIMARY KEY, email text, note text)`)
    await sql(`INSERT INTO ${where} VALUES (1, '${person}', 'keep me'), (2, '${other}', 'and me')`)
    const rep = await api('post', '/api/branches/main/personal-data/scan', {})
    const mine = (rep.findings ?? []).filter((f: { table: string }) => f.table === t)
    expect(mine.map((f: { column: string }) => f.column)).toEqual(['email'])
    for (const f of mine) {
      await api('post', `/api/branches/main/personal-data/findings/${f.id}/mark`, { state: 'confirmed', note: 'erasure e2e' })
    }
    await api('put', '/api/branches/main/dpdp/entries', {
      schema: 'public', table: t, basis: 'consent', purpose: 'Receipts', principals: ['customer'],
      keep: { count: 1, unit: 'years', from: 'last_contact', reason: 'purpose', citation: '' }, onErasure: 'clear',
    })

    await page.getByRole('link', { name: 'Erasure requests', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Erasure requests', exact: true })).toBeVisible()
    await expect(page.getByTestId('erasure-review')).toContainText('not yet been reviewed by a privacy lawyer')

    // Made from the page: the plan, and nothing changed.
    await page.getByRole('button', { name: 'New request…' }).click()
    const form = page.getByTestId('erasure-new')
    await form.getByLabel('Values').fill(`email:${person}`)
    await form.getByLabel('Note').fill(`e2e ${n}`)
    await form.getByRole('button', { name: 'Plan the erasure' }).click()
    await expect(page.locator('.okmsg')).toContainText('Nothing has been changed', { timeout: 60_000 })
    const detail = page.getByTestId('erasure-detail')
    const plan = detail.getByTestId(`erasure-table-${where}-clear`)
    await expect(plan).toContainText('Cleared, 1 row(s)')
    await expect(plan).toContainText('email (email) → NULL')
    await expect(detail).toContainText(`email ending ${person.slice(-4)}`)
    await expect(detail).not.toContainText(person) // the request keeps four characters of it
    expect(String((await sql(`SELECT email FROM ${where} WHERE id = 1`)).rows?.[0]?.[0])).toBe(person)

    // Applied with the values again and the number typed.
    await detail.getByRole('button', { name: 'Apply to main…' }).click()
    const ask = page.getByTestId('erasure-values')
    await ask.getByLabel('Values').fill(person)
    const id = (await detail.getByRole('heading', { level: 2 }).innerText()).match(/#(\d+)/)?.[1] ?? ''
    await expect(ask.getByRole('button', { name: 'Apply' })).toBeDisabled()
    await ask.getByLabel('Request number').fill(id)
    await ask.getByRole('button', { name: 'Apply' }).click()
    await expect(page.locator('.okmsg')).toContainText(`Request #${id} applied to main: 1 row(s) changed`, { timeout: 120_000 })
    await expect(page.getByTestId('erasure-result')).toContainText('a search afterwards found none of the values')
    await expect(page.getByTestId('erasure-result')).toContainText('removed from live queries')
    await expect(page.getByRole('table', { name: 'Rewrites' })).toContainText(where)

    const after = (await sql(`SELECT id, coalesce(email, 'NULL'), note FROM ${where} ORDER BY id`)).rows as unknown[][]
    expect(after.map(r => r.map(String))).toEqual([['1', 'NULL', 'keep me'], ['2', other, 'and me']])
    await expect(page.getByRole('table', { name: 'Erasure requests' })).toContainText('applied')
  } finally {
    await page.request.delete(`/api/branches/main/dpdp/entries?schema=public&table=${t}`)
    await page.request.post('/api/branches/main/query', { data: { sql: `DROP TABLE IF EXISTS ${where}`, allow_destructive: true } })
  }
})
