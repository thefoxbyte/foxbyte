// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Masking (F5, point 4.6) in a browser, against a real engine: a rule set on
// a confirmed finding after the page says what it costs, Aadhaar offered only
// the rules it may have, and an account masked and unmasked. The branch was
// set up by integration_ui.sh before Chromium started, as its setup restarts
// it. integration §11ai checks what a masked account then reads.
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'
const masked = 'e2e-masked@foxbyte.dev'

async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

test('a rule is set on a confirmed finding after its cost, and an account is masked and unmasked', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Masking' }).click()
  await expect(page.getByRole('heading', { name: 'Masking', exact: true })).toBeVisible()
  await page.getByLabel('Branch').selectOption('e2emask')
  await expect(page.getByTestId('mask-state')).toContainText('On.', { timeout: 30_000 })

  // Aadhaar: masked by display only, never hashed or faked.
  const aadhaar = page.getByTestId('open-m_people-aadhaar_no')
  await expect(aadhaar.getByRole('combobox').locator('option')).toHaveText(['partial', 'empty'])

  const row = page.getByTestId('open-m_people-email')
  await expect(row.getByRole('combobox')).toHaveValue('hash')
  await row.getByRole('button', { name: 'Mask…' }).click()
  let dlg = page.getByRole('dialog')
  await expect(dlg.getByTestId('mask-cost')).toContainText('3.6 times as long')
  await dlg.getByRole('button', { name: 'Set the rule' }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText('public.m_people.email is masked as hash.', { timeout: 30_000 })
  await expect(page.getByTestId('rule-m_people-email')).toContainText('made')
  await expect(page.getByTestId('open-m_people-email')).toHaveCount(0)

  await aadhaar.getByRole('button', { name: 'Mask…' }).click()
  dlg = page.getByRole('dialog')
  await expect(dlg.getByTestId('mask-cost')).toContainText('nothing on writes')
  await dlg.getByRole('button', { name: 'Set the rule' }).click()
  await expect(page.getByTestId('rule-m_people-aadhaar_no')).toContainText('partial', { timeout: 30_000 })

  // An admin is refused: they can change the masks.
  await page.getByLabel('Account to mask').fill(email)
  await page.locator('form').getByRole('button', { name: 'Mask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Mask', exact: true }).click()
  await expect(page.locator('.err')).toContainText('is an admin')

  await page.getByLabel('Account to mask').fill(masked)
  await page.locator('form').getByRole('button', { name: 'Mask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Mask', exact: true }).click()
  await expect(page.getByTestId(`account-${masked}`)).toBeVisible({ timeout: 30_000 })
  await page.getByTestId(`account-${masked}`).getByRole('button', { name: 'Unmask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Unmask', exact: true }).click()
  await expect(page.getByTestId(`account-${masked}`)).toHaveCount(0, { timeout: 30_000 })

  // Taken off again, so a rerun starts as this one did.
  await page.getByTestId('rule-m_people-email').getByRole('button', { name: 'Take off…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Take it off' }).click()
  await expect(page.getByTestId('open-m_people-email')).toBeVisible({ timeout: 30_000 })
})
