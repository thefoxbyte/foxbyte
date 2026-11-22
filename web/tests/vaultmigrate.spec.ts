// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Moving a branch's Aadhaar numbers into the vault from the Aadhaar exposure
// page, in a browser, against a real engine and a real vault (point 13, step
// 13.3). scripts/integration_ui.sh sets the vault up. The component tests prove
// the panel's logic against mocks; this proves a preview changes nothing, a
// move puts each number in the vault and leaves its key where it stood (a
// legacy key in a bigint, the same key for the same number everywhere, the rest
// of a note kept), the report then finds no number in those columns, and that
// once the branch is deleted the Vault page lists its keys as orphans and
// deletes them. The branch and its numbers are this test's own, made new each
// run; the numbers are synthetic, nobody's.
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

const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
  [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
  [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
const INV = [0,4,3,2,1,5,6,7,8,9]
function synthetic(): string {
  let d = String(2 + Math.floor(Math.random() * 8))
  for (let i = 0; i < 10; i++) d += String(Math.floor(Math.random() * 10))
  let c = 0
  for (let i = 0; i < d.length; i++) c = D[c][P[(i + 1) % 8][Number(d[d.length - 1 - i])]]
  return d + String(INV[c])
}
const spaced = (n: string) => `${n.slice(0, 4)} ${n.slice(4, 8)} ${n.slice(8)}`

test('a branch moved into the vault from the page keeps keys where its numbers stood; its keys are orphans once it is deleted', async ({ page }) => {
  test.setTimeout(240_000)
  await signIn(page)
  const branch = `vmig${Date.now().toString().slice(-7)}`
  const made = await page.request.post('/api/branches', { data: { name: branch, from: 'main' } })
  expect(made.ok(), await made.text()).toBeTruthy()
  const sql = async (q: string) => {
    const r = await page.request.post(`/api/branches/${branch}/query`, { data: { sql: q } })
    expect(r.ok(), await r.text()).toBeTruthy()
    return (await r.json()).rows as (string | null)[][]
  }
  const n1 = synthetic()
  let n2 = synthetic()
  while (n2 === n1) n2 = synthetic()
  await sql('CREATE TABLE public.vm_people (id int PRIMARY KEY, aadhaar text, legacy_id bigint, note text)')
  await sql(`INSERT INTO public.vm_people VALUES (1, '${spaced(n1)}', ${n2}, 'caller read out ${n1}, verified'), (2, '${n2}', NULL, NULL)`)

  try {
    await page.getByRole('link', { name: 'Aadhaar exposure' }).click()
    await page.getByLabel('Branch', { exact: true }).selectOption(branch)
    await page.getByRole('button', { name: 'Run the report' }).click()
    const cols = page.getByRole('table', { name: 'Aadhaar by column' })
    await expect(cols.getByText('public.vm_people.legacy_id', { exact: true })).toBeVisible({ timeout: 120_000 })

    // A preview says what would move, and moves nothing.
    const panel = page.getByTestId('vault-migrate')
    await panel.getByRole('button', { name: 'Preview' }).click()
    await expect(panel.getByTestId('vault-migration-summary')).toContainText('Preview', { timeout: 60_000 })
    const plan = panel.getByRole('table', { name: 'Columns moved' })
    await expect(plan.locator('tr', { hasText: 'public.vm_people.legacy_id' })).toContainText('legacy')
    await expect(plan.locator('tr', { hasText: 'public.vm_people.aadhaar' })).toContainText('opaque')
    await expect(plan.locator('tr', { hasText: 'public.vm_people.note' })).toContainText('opaque')
    expect((await sql('SELECT aadhaar FROM public.vm_people WHERE id = 1'))[0][0]).toBe(spaced(n1))
    // Only this test's table moves: anything else the branch copied from main
    // is left unticked.
    for (const box of await plan.getByRole('checkbox').all()) {
      const label = (await box.getAttribute('aria-label')) ?? ''
      if (!label.startsWith('Move public.vm_people.')) await box.uncheck()
    }
    await expect(panel.getByText('3 column(s) ticked in the preview')).toBeVisible()

    // The move, after confirming.
    await panel.getByRole('button', { name: 'Move into the vault' }).click()
    await page.getByRole('button', { name: 'Move', exact: true }).click()
    await expect(panel.getByTestId('vault-migration-summary')).toContainText('2 distinct number(s) in 3 column(s)', { timeout: 120_000 })
    await expect(panel.getByTestId('vault-migration-summary')).toContainText('Every column is moved, with no number left.')
    await expect(panel.getByRole('table', { name: 'Vault migrations' })).toContainText('done, clean')

    const rows = await sql('SELECT aadhaar, legacy_id::text, note FROM public.vm_people ORDER BY id')
    const [k1, k2, note] = rows[0]
    expect(k1).toMatch(/^AR[0-9A-Z]{26}$/)
    expect(k2).toMatch(/^1[0-9]{11}$/) // a bigint takes a legacy key
    expect(note).toBe(`caller read out ${k1}, verified`)
    expect(rows[1][0]).toBe(k2) // one number, one key, wherever it stood
    expect(JSON.stringify(rows)).not.toContain(n1)
    expect(JSON.stringify(rows)).not.toContain(n2)

    // The report finds no number in those columns any more.
    await page.getByRole('button', { name: 'Run the report' }).click()
    await expect(page.getByRole('button', { name: 'Run the report' })).toBeEnabled({ timeout: 120_000 })
    for (const c of ['aadhaar', 'legacy_id', 'note']) {
      await expect(page.getByRole('table', { name: 'Aadhaar by column' }).getByText(`public.vm_people.${c}`, { exact: true })).toHaveCount(0)
    }
  } finally {
    const del = await page.request.delete(`/api/branches/${branch}`)
    expect(del.ok(), await del.text()).toBeTruthy()
  }

  // Its branch gone, the run's keys are orphans; the Vault page deletes them.
  await page.getByRole('link', { name: 'Vault', exact: true }).click()
  const orphans = page.getByRole('table', { name: 'Orphaned keys' })
  const row = orphans.locator('tr', { hasText: branch })
  await expect(row).toContainText('the branch was deleted')
  // Run, branch, ran, by, why, then the keys made and still to delete.
  await expect(row.locator('td').nth(5)).toHaveText('2')
  await expect(row.locator('td').nth(6)).toHaveText('2')
  await row.getByRole('button', { name: /orphaned keys/ }).click()
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByTestId('orphans-note')).toHaveText('2 key(s) deleted; 0 kept, because someone else was handed them.')
  await expect(row.getByRole('button')).toHaveCount(0)
})
