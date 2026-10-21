// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Personal data page, in a browser, against a real engine (point 4.1).
//
// The page's component tests prove its logic against mocks. This proves a scan
// started from the page reads a real branch, lands its findings in the right
// rows, keeps them for the next visit, and puts no value on the screen. The
// table it finds them in (public.pii_people, synthetic values) is made by
// scripts/integration_ui.sh before the browser exists.
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

test('a scan from the page finds personal data, keeps where, and shows no value', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Personal data' }).click()
  await expect(page.getByRole('heading', { name: 'Personal data', exact: true })).toBeVisible()
  await page.getByLabel('Branch').selectOption(branch)
  await page.getByRole('button', { name: 'Scan now' }).click()

  const found = page.getByRole('table', { name: 'Personal data found' })
  const row = (column: string) => found.locator('tr', { has: page.getByText(`public.pii_people.${column}`, { exact: true }) })
  await expect(row('aadhaar_no')).toContainText('Aadhaar', { timeout: 60_000 })
  await expect(row('aadhaar_no')).toContainText('high')
  await expect(row('aadhaar_no')).toContainText('2/2')
  await expect(row('email')).toContainText('Email')
  await expect(row('card_no')).toContainText('Card number')
  await expect(found.getByText('public.pii_people.status', { exact: true })).toHaveCount(0)
  // Inside a JSON column, by path (4.2): the phone number, and not the theme.
  const phone = found.locator('tr', { has: page.getByText('$.contact.phone', { exact: true }) })
  await expect(phone).toContainText('public.pii_people.profile')
  await expect(phone).toContainText('Mobile number')
  await expect(phone).toContainText('2/2')
  await expect(found.getByText('$.theme', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'What this cannot claim' })).toBeVisible()
  await expect(page.getByTestId('pii-summary')).toContainText('up to 1000 rows each')

  // Kept, not recomputed: the findings are there on the next visit.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByLabel('Branch').selectOption(branch)
  await expect(row('aadhaar_no')).toContainText('Aadhaar', { timeout: 30_000 })

  // Where, never what: no sampled value reaches the screen.
  const text = await page.locator('main').innerText()
  for (const v of ['234567890124', '456789012341', 'a@example.com', '4111111111111111', '9876543210']) {
    expect(text).not.toContain(v)
  }

  // Review (4.6): masked samples, read as this person's own role, then a
  // decision with a note, which takes the finding out of the queue.
  await page.getByRole('button', { name: 'Review public.pii_people.aadhaar_no (Aadhaar)' }).click()
  const dlg = page.getByRole('dialog', { name: 'Review public.pii_people.aadhaar_no' })
  const samples = dlg.getByRole('list', { name: 'Masked samples' })
  await expect(samples).toContainText('XXXXXXXX0124', { timeout: 30_000 })
  await expect(samples).toContainText('XXXXXXXX2341')
  await expect(dlg).toContainText(`Read as ${email}`)
  expect(await dlg.innerText()).not.toContain('234567890124')
  await dlg.getByLabel('Note (optional)').fill('the KYC column')
  await dlg.getByRole('button', { name: 'Confirm' }).click()
  await expect(dlg.getByRole('list', { name: 'Decisions' })).toContainText(`confirmed by ${email}`)
  await expect(dlg.getByRole('list', { name: 'Decisions' })).toContainText('the KYC column')
  await dlg.getByRole('button', { name: 'Close' }).click()
  await expect(found.getByText('public.pii_people.aadhaar_no', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: /^Confirmed \(\d+\)$/ }).click()
  await expect(row('aadhaar_no')).toContainText(`by ${email}`)

  // Kept in the branch: still confirmed on the next visit.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByLabel('Branch').selectOption(branch)
  await page.getByRole('button', { name: /^Confirmed \(\d+\)$/ }).click()
  await expect(row('aadhaar_no')).toContainText('confirmed', { timeout: 30_000 })
})
