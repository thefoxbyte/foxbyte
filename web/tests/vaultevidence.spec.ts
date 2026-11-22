// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The vault's evidence page, in a browser, against a real engine and a real
// vault (point 13, step 13.4b). scripts/integration_ui.sh sets the vault up
// with FoxByte's own software token. The component tests prove the page's
// logic against mocks; this proves the engine's verdicts reach the page (para
// 8 not met on the software token), that a declaration made on the page is
// kept with who made it and turns its rule from open to met (and SOC 2 to not
// applicable on premises), that withdrawing it opens the rule again, and that
// the download is the whole document.
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

test('the vault evidence: verdicts rule by rule, a declaration made and withdrawn on the page, the document downloaded', async ({ page }) => {
  test.setTimeout(120_000)
  await signIn(page)
  // Each run starts with hosting undeclared.
  const w = await page.request.post('/api/vault/declarations', { data: { kind: 'aadhaar', item: 'hosting', value: '' } })
  expect(w.ok(), await w.text()).toBeTruthy()

  await page.getByRole('link', { name: 'Vault', exact: true }).click()
  await page.getByTestId('vault-evidence-link').click()
  await expect(page.getByRole('heading', { name: 'Vault evidence', exact: true })).toBeVisible()
  await expect(page.getByTestId('evidence-summary')).toContainText('UIDAI Circular No. 14 of 2025', { timeout: 60_000 })
  await expect(page.getByTestId('evidence-head')).toContainText('not UIDAI-compliant')

  const verdict = (para: string) => page.getByTestId(`rule-${para}`).locator('td').nth(3)
  await expect(verdict('8')).toHaveText('not met')
  await expect(page.getByTestId('rule-8')).toContainText('the software token, for trials and testing only')
  await expect(verdict('2')).toHaveText('met')
  await expect(verdict('5')).toHaveText('open')
  await expect(verdict('6')).toHaveText('open')

  // Declared on the page: kept with who made it, and the rules follow.
  const tag = `on premises, e2e run ${Date.now().toString().slice(-7)}`
  await page.getByTestId('rule-5').getByRole('button', { name: 'Declare…' }).click()
  const box = page.getByTestId('vault-declare')
  await expect(box).toContainText('Where the vault is hosted')
  await box.getByLabel('Declaration: hosting').fill(tag)
  await box.getByRole('button', { name: 'Save the declaration' }).click()
  await expect(page.getByTestId('evidence-msg')).toContainText('declared, not checked')
  await expect(verdict('5')).toHaveText('met')
  await expect(page.getByTestId('rule-5')).toContainText(`Declared hosting by ${email}`)
  await expect(page.getByTestId('rule-5')).toContainText(tag)
  await expect(verdict('6')).toHaveText('not applicable')

  // The download is the whole document, the declaration in it.
  const href = (await page.getByRole('link', { name: 'Download (JSON)' }).getAttribute('href')) ?? ''
  expect(href).toMatch(/\/api\/vault\/evidence\?kind=aadhaar&since=90d$/)
  const doc = await (await page.request.get(href.replace(/^https?:\/\/[^/]+/, ''))).json()
  expect(doc.format).toBe('vault-evidence/1')
  expect(doc.kinds[0].rows).toHaveLength(19)
  expect(JSON.stringify(doc)).toContain(tag)

  // Withdrawn after confirming: open again.
  await page.getByTestId('rule-5').getByRole('button', { name: 'Change…' }).click()
  await page.getByTestId('vault-declare').getByRole('button', { name: 'Withdraw…' }).click()
  await page.getByRole('button', { name: 'Withdraw', exact: true }).click()
  await expect(page.getByTestId('evidence-msg')).toContainText('hosting is open again')
  await expect(verdict('5')).toHaveText('open')
  await expect(page.getByTestId('evidence-branch-main')).toBeVisible()
})
