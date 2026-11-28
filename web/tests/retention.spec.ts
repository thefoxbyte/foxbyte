// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Retention and the safeguards evidence, in a browser, against a real engine
// (points 11.3 and 11.4). The component tests prove the pages' logic against
// mocks; this proves the engine's answers reach them: the safeguards
// evidence's seven clauses of Rule 6 with their verdicts, a declaration made
// on the page turning (f) from open to met and withdrawn again, the download
// being the whole document; and retention turned on from its page, its
// signing key shown once and never again, and off again. Erasing is the
// integration suite's (§11bf): main is kept between runs here.
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

test('the safeguards evidence: Rule 6 clause by clause, a declaration made and withdrawn, the document downloaded', async ({ page }) => {
  test.setTimeout(120_000)
  await signIn(page)
  const w = await page.request.post('/api/dpdp/declarations', { data: { item: 'processors', value: '' } })
  expect(w.ok(), await w.text()).toBeTruthy()

  await page.getByRole('link', { name: 'Safeguards evidence' }).click()
  await expect(page.getByRole('heading', { name: 'Safeguards evidence', exact: true })).toBeVisible()
  await expect(page.getByTestId('safeguards-summary')).toContainText('Rule 6', { timeout: 60_000 })
  for (const c of ['a', 'b', 'c', 'd', 'e', 'f', 'g']) {
    await expect(page.getByTestId(`safeguard-6(1)(${c})`)).toBeVisible()
  }
  const f = page.getByTestId('safeguard-6(1)(f)')
  await expect(f.locator('td').nth(2)).toHaveText('open')
  await expect(f).toContainText('Guards against:')

  await f.getByRole('button', { name: 'Declare…' }).click()
  await f.getByLabel('Declaration: processors').fill('No Data Processor handles this data (e2e).')
  await f.getByRole('button', { name: 'Save the declaration' }).click()
  await expect(page.getByTestId('safeguards-msg')).toContainText('Declared processors')
  await expect(f.locator('td').nth(2)).toHaveText('met')
  await expect(f).toContainText(`by ${email}`)

  const dl = await page.request.get(await page.getByTestId('safeguards-download').getAttribute('href') ?? '')
  expect(dl.ok()).toBeTruthy()
  const doc = await dl.json()
  expect(doc.format).toBe('safeguards-evidence/1')
  expect(doc.rules).toHaveLength(7)

  await f.getByRole('button', { name: 'Change…' }).click()
  await f.getByRole('button', { name: 'Withdraw…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Withdraw', exact: true }).click()
  await expect(f.locator('td').nth(2)).toHaveText('open')
})

test('retention turned on from its page shows its signing key once, and off again', async ({ page }) => {
  test.setTimeout(120_000)
  await signIn(page)
  const off = await page.request.post('/api/dpdp/retention', { data: { on: false } })
  expect(off.ok(), await off.text()).toBeTruthy()
  try {
    await page.getByRole('link', { name: 'Retention', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Retention', exact: true })).toBeVisible()
    const settings = page.getByTestId('retention-settings')
    await expect(settings).toContainText('Retention is off')
    const on = settings.getByRole('button', { name: 'Turn on' })
    await expect(on).toBeDisabled()
    await settings.getByLabel('Notice address').fill('https://hooks.example/fox')
    await on.click()
    await expect(page.getByTestId('retention-secret')).toContainText(/[0-9a-f]{64}/)
    await expect(settings).toContainText('notices go to https://hooks.example/fox')
    await expect(page.getByTestId('retention-limits')).toContainText('Rule 8(3)')
    // The key is not shown again.
    await page.reload()
    await expect(page.getByTestId('retention-settings')).toContainText('Retention is on')
    await expect(page.getByTestId('retention-secret')).toHaveCount(0)
    await page.getByTestId('retention-settings').getByRole('button', { name: 'Turn off…' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Turn off', exact: true }).click()
    await expect(page.getByTestId('retention-settings')).toContainText('Retention is off')
  } finally {
    await page.request.post('/api/dpdp/retention', { data: { on: false } })
  }
})
