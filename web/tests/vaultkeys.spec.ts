// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Rotating the vault's keys, and updating and deleting a value, from the Vault
// page, in a browser, against a real engine and a real vault (point 13, step
// 13.4). scripts/integration_ui.sh sets the vault up. The component tests prove
// the page's logic against mocks; this proves a rotation from the page makes a
// new key and destroys the old one while the value under a reference key still
// reads back, that an update keeps the key and changes what it holds, and that
// a delete leaves the key with nothing behind it. The numbers are synthetic,
// new each run; nobody's.
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

test('the vault: keys rotated from the page, a value updated under its key and then deleted', async ({ page }) => {
  test.setTimeout(120_000)
  await signIn(page)
  const n1 = synthetic()
  let n2 = synthetic()
  while (n2 === n1) n2 = synthetic()
  const put = await page.request.post('/api/vault/tokenise', { data: { kind: 'aadhaar', values: [n1] } })
  expect(put.ok(), await put.text()).toBeTruthy()
  const ref = (await put.json()).refs[0] as string
  expect(ref).toMatch(/^AR[0-9A-Z]{26}$/)
  const why = `e2e: corrected by the customer, run ${Date.now().toString().slice(-7)}`
  const find = async (n: string) => (await (await page.request.post('/api/vault/find', { data: { kind: 'aadhaar', values: [n] } })).json()) as { refs: string[]; results: string[] }

  await page.getByRole('link', { name: 'Vault', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Vault', exact: true })).toBeVisible()
  const keys = page.getByRole('table', { name: 'Vault keys' })
  await expect(keys.locator('tr', { hasText: 'index (current)' }).first()).toBeVisible()

  // The index key, then the data key: each made anew, the old one destroyed,
  // and the value under the reference key found and kept throughout.
  for (const key of ['index', 'data'] as const) {
    const oldLabel = (await keys.locator('tr', { hasText: `vault-aadhaar-${key}-` }).filter({ hasText: '(current)' }).locator('code').textContent()) ?? ''
    expect(oldLabel).toMatch(new RegExp(`^vault-aadhaar-${key}-\\d+$`))
    await page.getByRole('button', { name: `Rotate the aadhaar ${key} key` }).click()
    await page.getByRole('button', { name: 'Rotate', exact: true }).click()
    await expect(page.getByTestId('vault-msg')).toContainText(`Rotated the aadhaar ${key} key: done:`, { timeout: 90_000 })
    await expect(page.getByTestId('vault-msg')).toContainText(`destroyed ${oldLabel}`)
    await expect(page.getByTestId(`vault-key-${oldLabel}`)).toContainText('destroyed')
    const f = await find(n1)
    expect(f.refs[0]).toBe(ref)
  }

  // An update keeps the key and changes what it holds.
  const change = page.getByTestId('vault-change')
  await change.getByLabel('Kind of the value to change').selectOption('aadhaar')
  await change.getByLabel('Reference key to change').fill(ref)
  await change.getByLabel('Purpose of the change').fill(why)
  await change.getByLabel('New value').fill(n2)
  await change.getByRole('button', { name: 'Update' }).click()
  await expect(page.getByTestId('vault-change-note')).toHaveText(`Updated: ${ref} now holds the new value.`)
  await expect(change.getByLabel('New value')).toHaveValue('')
  expect((await find(n2)).refs[0]).toBe(ref)
  expect((await find(n1)).results[0]).toBe('not found')

  // A delete, after confirming: the key then has nothing behind it.
  await change.getByRole('button', { name: 'Delete…' }).click()
  await page.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByTestId('vault-change-note')).toHaveText(`Deleted ${ref}.`)
  expect((await find(n2)).results[0]).toBe('not found')

  // The access log has each change and its purpose; the numbers are never on
  // the screen.
  await page.getByRole('button', { name: 'Refresh' }).click()
  const log = page.getByRole('table', { name: 'Vault access log' })
  await expect(log.locator('tr', { hasText: why }).filter({ hasText: 'update' })).toHaveCount(1)
  await expect(log.locator('tr', { hasText: why }).filter({ hasText: 'delete' })).toHaveCount(1)
  const text = await page.locator('main').innerText()
  expect(text).not.toContain(n1)
  expect(text).not.toContain(n2)
})
