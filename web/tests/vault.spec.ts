// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Vault page, in a browser, against a real engine and a real vault (point
// 13, step 13.1). scripts/integration_ui.sh sets the vault up with FoxByte's
// own software token. The component tests prove the page's logic against
// mocks; this proves a value put in from the page reaches the vault and comes
// back as a reference key, that the same value finds the same key, that the
// software token is said to be not compliant for Aadhaar, that the keys are
// reported as never leaving the token, and that the number is never on the
// screen.
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

// A synthetic Aadhaar number, new each run: 11 random digits, the first 2 to
// 9, and the Verhoeff check digit. Nobody's.
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

test('the vault: a value put in from the page comes back as a reference key, and the number is never shown', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Vault', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Vault', exact: true })).toBeVisible()

  // FoxByte's own software token, said plainly to be not compliant for Aadhaar.
  await expect(page.getByTestId('vault-token')).toContainText('SoftHSM project')
  await expect(page.getByTestId('vault-token')).toContainText('not UIDAI-compliant (trials and testing only)')
  await expect(page.getByTestId('vault-kind-aadhaar')).toContainText('UIDAI Circular No. 14 of 2025')
  await expect(page.getByTestId('vault-kind-aadhaar')).toContainText('no: software token')
  await expect(page.getByTestId('vault-kind-text')).toContainText('none mapped')
  const keys = page.getByRole('table', { name: 'Vault keys' })
  await expect(keys.getByText('made in the token, never extractable')).toHaveCount(4)

  const n = synthetic()
  const spaced = `${n.slice(0, 4)} ${n.slice(4, 8)} ${n.slice(8)}`
  await page.getByLabel('Kind', { exact: true }).selectOption('aadhaar')
  await page.getByLabel('Value', { exact: true }).fill(spaced)
  await page.getByRole('button', { name: 'Put in the vault' }).click()
  await expect(page.getByTestId('vault-answer')).toContainText('Put in the vault: this is its reference key.')
  const ref = (await page.getByTestId('vault-ref').textContent()) ?? ''
  expect(ref).toMatch(/^AR[0-9A-Z]{26}$/)
  await expect(page.getByLabel('Value', { exact: true })).toHaveValue('')

  // The same number, written another way, finds the same key; nothing new is made.
  await page.getByLabel('Value', { exact: true }).fill(n)
  await page.getByRole('button', { name: 'Find' }).click()
  await expect(page.getByTestId('vault-answer')).toContainText('In the vault: this is its reference key.')
  await expect(page.getByTestId('vault-ref')).toHaveText(ref)
  await page.getByLabel('Value', { exact: true }).fill(n)
  await page.getByRole('button', { name: 'Put in the vault' }).click()
  await expect(page.getByTestId('vault-answer')).toContainText('Already in the vault')
  await expect(page.getByTestId('vault-ref')).toHaveText(ref)

  // The legacy format, for columns that hold only 12 digits.
  const m = synthetic()
  await page.getByLabel('Value', { exact: true }).fill(m)
  await page.getByLabel('Legacy format', { exact: true }).check()
  await page.getByRole('button', { name: 'Put in the vault' }).click()
  await expect(page.getByTestId('vault-ref')).toHaveText(/^1\d{11}$/)

  // A value that is not an Aadhaar number is refused, and nothing is made.
  await page.getByLabel('Value', { exact: true }).fill('1234 1234 1234')
  await page.getByRole('button', { name: 'Put in the vault' }).click()
  await expect(page.getByTestId('vault-answer')).toContainText('Refused: not a aadhaar value')
  await expect(page.getByTestId('vault-ref')).toHaveCount(0)

  // The log holds, and agrees with the head the security log saw.
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page.getByTestId('vault-log')).toContainText('the chain holds.')
  await expect(page.getByTestId('vault-log')).toContainText('is as the security log saw it')

  // The numbers went to the vault and are nowhere on the page.
  for (const x of [n, spaced, m]) await expect(page.locator('body')).not.toContainText(x)
})

test('reading a value back needs a grant, even for an admin: given, used with a purpose, shown masked, revoked', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Vault', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Vault', exact: true })).toBeVisible()

  const n = synthetic()
  await page.getByLabel('Kind', { exact: true }).selectOption('aadhaar')
  await page.getByLabel('Value', { exact: true }).fill(n)
  await page.getByRole('button', { name: 'Put in the vault' }).click()
  const ref = (await page.getByTestId('vault-ref').textContent()) ?? ''
  expect(ref).toMatch(/^AR[0-9A-Z]{26}$/)

  // An admin has no box to read values back until they hold a grant.
  await expect(page.getByTestId('vault-read')).toHaveCount(0)
  const form = page.getByRole('form', { name: 'Give a vault grant' })
  await form.getByLabel('Account', { exact: true }).fill(email)
  await form.getByLabel('Grant kind', { exact: true }).selectOption('aadhaar')
  await form.getByLabel('Permission', { exact: true }).selectOption('detokenise')
  await form.getByLabel('Limit an hour', { exact: true }).fill('2')
  await form.getByRole('button', { name: 'Give the grant' }).click()
  await expect(page.getByTestId('vault-msg')).toContainText(`may read back aadhaar values, up to 2 an hour`)
  const row = page.getByTestId(`grant-${email}-aadhaar-detokenise`)
  await expect(row).toContainText('0 of 2')

  // Read back with a purpose: masked to its last four digits until revealed.
  const read = page.getByTestId('vault-read')
  await read.getByLabel('Reference key', { exact: true }).fill(ref)
  await expect(read.getByRole('button', { name: 'Read back' })).toBeDisabled()
  await read.getByLabel('Purpose', { exact: true }).fill('e2e: KYC re-check')
  await read.getByRole('button', { name: 'Read back' }).click()
  await expect(page.getByTestId('vault-value')).toHaveText(`XXXX XXXX ${n.slice(-4)}`)
  await expect(page.locator('body')).not.toContainText(n)
  await page.getByRole('button', { name: 'Reveal' }).click()
  await expect(page.getByTestId('vault-value')).toHaveText(n)
  await page.getByRole('button', { name: 'Hide' }).click()
  await expect(page.locator('body')).not.toContainText(n)
  await expect(row).toContainText('1 of 2')

  // The limit an hour: one more is allowed, then the engine says no.
  await read.getByRole('button', { name: 'Read back' }).click()
  await expect(row).toContainText('2 of 2')
  await read.getByRole('button', { name: 'Read back' }).click()
  await expect(page.getByTestId('vault-err')).toContainText('limit reached')

  // The access log has the reads, with their purpose, and never the number.
  const log = page.getByRole('table', { name: 'Vault access log' })
  await expect(log).toContainText('e2e: KYC re-check')
  await expect(log).not.toContainText(n)

  // Revoked from the page: the box to read values back goes.
  await row.getByRole('button', { name: 'Revoke…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Revoke' }).click()
  await expect(page.getByTestId('vault-msg')).toContainText('revoked')
  await expect(page.getByTestId('vault-read')).toHaveCount(0)
})
