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

// Keys (step 2): a domain made, a table put under it and back, its key
// rotated after the page says what that does, and the domain deleted.
test('a key domain is made, used, rotated and deleted', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Masking' }).click()
  await page.getByLabel('Branch').selectOption('e2emask')
  await expect(page.getByTestId('mask-state')).toContainText('On.', { timeout: 30_000 })
  await expect(page.getByTestId('key-default')).toBeVisible()

  // A keyed rule, so the table has masks a key makes.
  const row = page.getByTestId('open-m_people-email')
  await row.getByRole('button', { name: 'Mask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Set the rule' }).click()
  await expect(page.getByTestId('rule-m_people-email')).toContainText('made', { timeout: 30_000 })

  await page.getByLabel('New key domain').fill('e2e_tenant')
  await page.getByRole('form', { name: 'Make a key domain' }).getByRole('button', { name: 'Make…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Make it' }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText('Key domain e2e_tenant is made.', { timeout: 30_000 })
  await expect(page.getByTestId('key-e2e_tenant')).toContainText('key 1')

  await page.getByLabel('Table to move').selectOption('public.m_people')
  await page.getByLabel('Key domain for the table').selectOption('e2e_tenant')
  await page.getByRole('form', { name: 'Put a table under a key domain' }).getByRole('button', { name: 'Move…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Move it' }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText('public.m_people on e2emask is under key domain e2e_tenant.', { timeout: 60_000 })
  await expect(page.getByTestId('key-e2e_tenant')).toContainText('e2emask: public.m_people')

  await page.getByTestId('key-e2e_tenant').getByRole('button', { name: 'Rotate…' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByTestId('rotate-cost')).toContainText('There is no undo')
  await expect(dlg).toContainText('e2emask: public.m_people')
  await dlg.getByRole('button', { name: 'Rotate the key' }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText("e2e_tenant's key is rotated, and the old one deleted.", { timeout: 120_000 })
  await expect(page.getByTestId('key-e2e_tenant')).toContainText('key 2')

  // In use, so it cannot be deleted; back to the default, then it can.
  await page.getByTestId('key-e2e_tenant').getByRole('button', { name: 'Delete…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Delete it' }).click()
  await expect(page.getByTestId('mask-err')).toContainText('uses e2e_tenant', { timeout: 30_000 })
  await page.getByLabel('Table to move').selectOption('public.m_people')
  await page.getByLabel('Key domain for the table').selectOption('default')
  await page.getByRole('form', { name: 'Put a table under a key domain' }).getByRole('button', { name: 'Move…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Move it' }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText('public.m_people on e2emask is under key domain default.', { timeout: 60_000 })
  await page.getByTestId('key-e2e_tenant').getByRole('button', { name: 'Delete…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Delete it' }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText('Key domain e2e_tenant is deleted.', { timeout: 30_000 })
  await expect(page.getByTestId('key-e2e_tenant')).toHaveCount(0)

  await page.getByTestId('rule-m_people-email').getByRole('button', { name: 'Take off…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Take it off' }).click()
  await expect(page.getByTestId('open-m_people-email')).toBeVisible({ timeout: 30_000 })
})

// Unmask (step 3): a masked account given unmask on a branch, listed, said
// to be audited, shown in the access review, then taken off.
test('a masked account is given unmask on a branch, and the access review says so', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Masking' }).click()
  await page.getByLabel('Branch').selectOption('e2emask')
  await expect(page.getByTestId('mask-state')).toContainText('On.', { timeout: 30_000 })

  await page.getByLabel('Account to mask').fill(masked)
  await page.getByRole('form', { name: 'Mask an account' }).getByRole('button', { name: 'Mask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Mask', exact: true }).click()
  await expect(page.getByTestId(`account-${masked}`)).toBeVisible({ timeout: 30_000 })

  await page.getByLabel('Account to unmask').selectOption(masked)
  await page.getByRole('form', { name: 'Unmask an account' }).getByRole('button', { name: 'Unmask…' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg).toContainText('Every read they make there of a marked table is audited')
  await dlg.getByRole('button', { name: 'Unmask', exact: true }).click()
  await expect(page.getByTestId('mask-msg')).toHaveText(`${masked} sees real values on e2emask, every read audited.`, { timeout: 30_000 })
  await expect(page.getByTestId(`unmask-${masked}`)).toBeVisible()
  await expect(page.getByRole('table', { name: 'Lookups' })).toBeVisible()

  await page.getByRole('link', { name: 'Access review' }).click()
  await expect(page.getByTestId(`unmasked-${masked}`)).toContainText('unmask on e2emask', { timeout: 30_000 })

  await page.getByRole('link', { name: 'Masking' }).click()
  await page.getByLabel('Branch').selectOption('e2emask')
  await page.getByTestId(`unmask-${masked}`).getByRole('button', { name: 'Take off…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Take it off' }).click()
  await expect(page.getByTestId(`unmask-${masked}`)).toHaveCount(0, { timeout: 30_000 })
  await page.getByTestId(`account-${masked}`).getByRole('button', { name: 'Unmask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Unmask', exact: true }).click()
  await expect(page.getByTestId(`account-${masked}`)).toHaveCount(0, { timeout: 30_000 })
})

// The access paths (step 4): the masked account owns e2emask
// (integration_ui.sh) and still reads masks there, in the console's query and
// in the Blackbox, whose statements it cannot read; the Masking page lists
// what the guard closed and the definer function that could leak.
test('a masked account reads masks on its own branch, and the page lists the paths it closed', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Masking' }).click()
  await page.getByLabel('Branch').selectOption('e2emask')
  await expect(page.getByTestId('mask-state')).toContainText('On.', { timeout: 30_000 })
  await page.getByTestId('open-m_people-email').getByRole('button', { name: 'Mask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Set the rule' }).click()
  await expect(page.getByTestId('rule-m_people-email')).toContainText('made', { timeout: 30_000 })
  await page.getByLabel('Account to mask').fill(masked)
  await page.getByRole('form', { name: 'Mask an account' }).getByRole('button', { name: 'Mask…' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg).toContainText('their own included')
  await dlg.getByRole('button', { name: 'Mask', exact: true }).click()
  await expect(page.getByTestId(`account-${masked}`)).toBeVisible({ timeout: 30_000 })

  // What the guard closed, and the definer function that can leak.
  await expect(page.getByTestId('closed-public.m_logins')).toContainText('foreign key into a masked column')
  await expect(page.getByTestId('definer-m_email_of(integer)')).toContainText('public.m_people')

  // As the masked account, which owns e2emask: masks in the console.
  await page.context().clearCookies()
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(masked)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption('e2emask')
  await page.locator('textarea.editor').fill('SELECT email FROM m_people ORDER BY id')
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.getByText(/^[0-9a-f]{64}$/).first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('a@example.com')).toHaveCount(0)
  await page.locator('textarea.editor').fill('SELECT * FROM public.m_people')
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.getByText(/permission denied/).first()).toBeVisible({ timeout: 30_000 })

  // The Blackbox: its entries, without their statements' text.
  await page.goto('/blackbox', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption('e2emask')
  const row = page.locator('tr.lg-row').first()
  await expect(row).toBeVisible({ timeout: 30_000 })
  await row.click()
  await expect(page.locator('pre.lg-statement').first()).toContainText('hidden from masked accounts')

  // Back as the admin: everything taken off, so a rerun starts as this one did.
  await page.context().clearCookies()
  await signIn(page)
  await page.getByRole('link', { name: 'Masking' }).click()
  await page.getByLabel('Branch').selectOption('e2emask')
  await page.getByTestId(`account-${masked}`).getByRole('button', { name: 'Unmask…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Unmask', exact: true }).click()
  await expect(page.getByTestId(`account-${masked}`)).toHaveCount(0, { timeout: 30_000 })
  await page.getByTestId('rule-m_people-email').getByRole('button', { name: 'Take off…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Take it off' }).click()
  await expect(page.getByTestId('open-m_people-email')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByTestId('closed-public.m_logins')).toHaveCount(0)
})
