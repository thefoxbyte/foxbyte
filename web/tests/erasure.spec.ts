// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Erasure requests page, in a browser, against a real engine (point 11.2,
// F4, Gate 1 steps 1 and 2).
//
// The component tests prove the page's logic against mocks. This proves a
// request, made on main, finds a real person's row on a branch
// through a confirmed column there, shows that branch's plan, and, applied
// from the page with the values typed again, erases that row and no other;
// then lists a branch made from that branch before its erasure, and deletes
// it from the request. The person is put on a branch of their own rather than on main:
// a scan of main would hand its baseline to every branch made from it later,
// and the harness, and the suites after it, keep main between runs. The scan,
// the decisions and the inventory entry go through the APIs their own pages
// use; their own tests drive them.
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

test('a request made on main finds the person on a branch, erases them there only, and the branch is deleted from it', async ({ page }) => {
  test.setTimeout(600_000)
  await signIn(page)
  const n = Date.now().toString().slice(-6)
  const t = `er_e2e_${n}`
  const where = `public.${t}`
  const person = `asha.${n}@example.in`
  const other = `ravi.${n}@example.org`
  const copy = `er-e2e-${n}` // a branch of main, where the person is
  const kid = `er-e2e-${n}-k` // a branch of that one, made before the erasure
  const api = async (method: 'get' | 'post' | 'put', url: string, data?: unknown) => {
    const r = method === 'get' ? await page.request.get(url) : method === 'put' ? await page.request.put(url, { data }) : await page.request.post(url, { data })
    expect(r.ok(), `${method} ${url}: ${await r.text()}`).toBeTruthy()
    return r.json()
  }
  const sql = (q: string) => api('post', `/api/branches/${copy}/query`, { sql: q })
  try {
    await api('post', '/api/branches', { name: copy })
    await sql(`CREATE TABLE ${where} (id int PRIMARY KEY, email text, note text)`)
    await sql(`INSERT INTO ${where} VALUES (1, '${person}', 'keep me'), (2, '${other}', 'and me')`)
    const rep = await api('post', `/api/branches/${copy}/personal-data/scan`, {})
    const mine = (rep.findings ?? []).filter((f: { table: string }) => f.table === t)
    expect(mine.map((f: { column: string }) => f.column)).toEqual(['email'])
    for (const f of mine) {
      await api('post', `/api/branches/${copy}/personal-data/findings/${f.id}/mark`, { state: 'confirmed', note: 'erasure e2e' })
    }
    await api('put', `/api/branches/${copy}/dpdp/entries`, {
      schema: 'public', table: t, basis: 'consent', purpose: 'Receipts', principals: ['customer'],
      keep: { count: 1, unit: 'years', from: 'last_contact', reason: 'purpose', citation: '' }, onErasure: 'clear',
    })
    await api('post', '/api/branches', { name: kid, from: copy })

    // Made and applied through the API, the browser only reading the page:
    // starting a branch's container (planning wakes a suspended one) changes
    // the test VM's network, and Chromium, running in that VM, drops a request
    // in flight when it does (net::ERR_NETWORK_CHANGED). The page's own forms
    // are proven by ErasureRequests.test.tsx.
    const made = await api('post', '/api/dpdp/erasures', { values: [{ category: 'email', value: person }], note: `e2e ${n}` })
    const id = String(made.id)
    const openIt = async () => {
      await page.goto('/erasure-requests', { waitUntil: 'domcontentloaded' })
      const list = page.getByRole('table', { name: 'Erasure requests' })
      await list.locator('tr').filter({ has: page.locator('td', { hasText: new RegExp(`^${id}$`) }) }).getByRole('button', { name: 'Open' }).click()
      return page.getByTestId('erasure-detail')
    }
    let detail = await openIt()
    await expect(page.getByTestId('erasure-review')).toContainText('not yet been reviewed by a privacy lawyer')
    await expect(detail).toContainText(`email ending ${person.slice(-4)}`)
    await expect(detail).not.toContainText(person) // the request keeps four characters of it
    const row = detail.getByRole('table', { name: 'Branches' }).getByTestId(`erasure-branch-${copy}`)
    await expect(row).toContainText('Planned')
    await expect(row).toContainText('1 row(s) hold a value')
    await row.getByRole('button', { name: 'Plan' }).click()
    const plan = detail.getByTestId(`erasure-branch-plan-${copy}`).getByTestId(`erasure-table-${where}-clear`)
    await expect(plan).toContainText('Cleared, 1 row(s)')
    await expect(plan).toContainText('email (email) → NULL')
    await expect(detail.getByRole('button', { name: /^Apply to main and every branch/ })).toBeEnabled()
    // Beside the branches: the INSERT above, in the query history, holds the person.
    await expect(page.getByTestId('erasure-copies-plan')).toContainText(/[1-9]\d* query history entr\(ies\) to delete/)
    expect(String((await sql(`SELECT email FROM ${where} WHERE id = 1`)).rows?.[0]?.[0])).toBe(person)

    // Applied with the values again: erased on the branches, the other person kept.
    const applied = await api('post', `/api/dpdp/erasures/${id}/apply`, { values: [{ value: person }] })
    expect(applied.state).toBe('applied')
    detail = await openIt()
    await expect(page.getByTestId('erasure-result')).toContainText('a search afterwards found none of the values')
    const erased = detail.getByRole('table', { name: 'Branches' }).getByTestId(`erasure-branch-${copy}`)
    await expect(erased).toContainText('Erased')
    await expect(erased).toContainText('1 row(s) changed')
    await expect(page.getByTestId('erasure-copies-result')).toContainText(/[1-9]\d* query history entr\(ies\) deleted/)
    expect((await api('get', `/api/history?q=${encodeURIComponent(person)}`)).entries).toEqual([])
    const after = (await sql(`SELECT id, coalesce(email, 'NULL'), note FROM ${where} ORDER BY id`)).rows as unknown[][]
    expect(after.map(r => r.map(String))).toEqual([['1', 'NULL', 'keep me'], ['2', other, 'and me']])

    // The branch made from the person's branch before its erasure is listed:
    // its origin snapshot keeps the old blocks. The person's own branch is not,
    // nor any branch of main, whose erasure changed nothing.
    const before = page.getByTestId('erasure-made-before')
    const item = before.locator('li', { hasText: kid })
    await expect(item).toContainText(`before ${copy}'s erasure finished`)
    await expect(before.locator('li').filter({ hasText: new RegExp(`^${copy} from`) })).toHaveCount(0)
    // Deleted from the request. Removing a branch's container changes the
    // test VM's network, which Chromium, running in that VM, answers by
    // dropping the request in flight (net::ERR_NETWORK_CHANGED); so the
    // outcome is read again after a reload rather than from that reply.
    await item.getByRole('button', { name: 'Delete…' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect.poll(async () => (await page.request.get(`/api/dpdp/erasures/${id}`)).json()
      .then(r => (r.madeBefore ?? []).some((m: { branch: string }) => m.branch === kid)), { timeout: 60_000 }).toBe(false)
    detail = await openIt()
    await expect(detail.getByTestId(`erasure-branch-${kid}`)).toContainText('deleted by')
    await expect(page.getByTestId('erasure-made-before').locator('li', { hasText: kid })).toHaveCount(0)
    await expect(page.getByRole('table', { name: 'Erasure requests' })).toContainText('applied')

    // The outcomes (step 5): with the branch made before it deleted, the
    // dependent branches are cleared; the one date is given, or why not; the
    // branches searched again by row key find no one; the evidence downloads.
    const outcomes = page.getByTestId('erasure-outcomes')
    await expect(outcomes.getByTestId('erasure-outcome-live')).toContainText('Met')
    await expect(outcomes.getByTestId('erasure-outcome-branches')).toContainText('Met')
    await expect(outcomes.getByTestId('erasure-clears-on')).toContainText('Clears on:')
    await expect(outcomes.getByTestId('erasure-outside-disk')).toContainText('freed disk blocks')
    await outcomes.getByTestId('erasure-check').click()
    await expect(outcomes.getByTestId('erasure-rechecked')).toBeVisible({ timeout: 60_000 })
    await expect(outcomes.getByTestId('erasure-outcome-live')).toContainText('none holds the person')
    const ev = await page.request.get(await outcomes.getByTestId('erasure-evidence').getAttribute('href') ?? '')
    expect(ev.ok()).toBeTruthy()
    const doc = await ev.json()
    expect(doc.format).toBe('erasure-evidence/1')
    expect(doc.keys).toBe(false)
    expect(JSON.stringify(doc)).not.toContain(person)
  } finally {
    await page.request.delete(`/api/branches/${kid}`)
    await page.request.delete(`/api/branches/${copy}`)
  }
})
