// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The audit log (F6) in a browser, against a real engine. The component tests
// prove the page against mocks for both states; this proves the page is
// reachable from the menu, reads the engine's own answer, and says how to turn
// it on. The UI suite's install has it off, as every install does until an
// admin runs `fox audit-log setup`; integration §11y turns it on and off.
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

test('the Audit log page says audit is off, what it costs, and the command that turns it on', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Audit log' }).click()
  await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible()
  await expect(page.getByTestId('audit-off')).toContainText('No database runs pgAudit')
  await expect(page.getByTestId('audit-off')).toContainText('It costs capacity')
  await expect(page.getByTestId('audit-setup')).toHaveText(/audit-log setup$/)
})
