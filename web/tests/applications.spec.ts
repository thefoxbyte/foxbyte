// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Application identity (F1) in a browser, against a real engine. The component
// tests prove the Applications page against mocks; this proves a registration
// made here reaches the engine, rotates and is revoked, and that the Blackbox
// shows whom a change was made for. The account is an install admin
// (scripts/integration_ui.sh), as managing applications requires.
import { generateKeyPairSync } from 'node:crypto'
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'
const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'
// Made by integration_ui.sh before Chromium starts: a table created on the
// branch in a transaction that asserted alice, with a token signed by the
// application it registered (FOX_E2E_FOR_APP).
const forTable = process.env.FOX_E2E_FOR_TABLE ?? 'e2e_for_alice'
const forApp = process.env.FOX_E2E_FOR_APP ?? 'uishop'

async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

const publicPem = () => generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString()

test('an application is registered, rotates its key, is reported compromised and removed, from the Applications page', async ({ page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Applications' }).click()
  await expect(page.getByRole('heading', { name: 'Applications', exact: true })).toBeVisible()
  await expect(page.getByTestId('install-id')).toContainText('"aud": "install-')

  const name = `e2eapp${Date.now().toString().slice(-6)}`
  await page.getByPlaceholder('shop', { exact: true }).fill(name)
  await page.getByPlaceholder('shop-service@example.com').fill(email)
  await page.getByPlaceholder(/openssl pkey/).fill(publicPem())
  await page.getByPlaceholder('2026-10').fill('k1')
  await page.getByRole('button', { name: 'Register' }).click()
  await expect(page.getByRole('status')).toContainText(`Registered ${name}.`)
  const card = page.getByTestId(`app-${name}`)
  await expect(card).toContainText(email)
  const keys = card.getByRole('table', { name: `Keys of ${name}` })
  await expect(keys.locator('tr', { hasText: 'k1' })).toContainText('active')

  // A second key, for a rotation: both are active until one is revoked.
  await card.getByRole('button', { name: 'Add key' }).click()
  await card.getByLabel(`New public key for ${name}`).fill(publicPem())
  await card.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(keys.locator('tbody tr')).toHaveCount(2)
  await expect(keys.getByText('active')).toHaveCount(2)

  await keys.locator('tr', { hasText: 'k1' }).getByRole('button', { name: 'Report compromised' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Revoke and report' }).click()
  await expect(keys.locator('tr', { hasText: 'k1' })).toContainText('reported compromised')
  await expect(keys.getByText('active')).toHaveCount(1)

  await card.getByRole('button', { name: 'Remove' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Remove' }).click()
  await expect(page.getByTestId(`app-${name}`)).toHaveCount(0)
})

test('the Blackbox shows whom a change was made for, beside who made it', async ({ page }) => {
  await signIn(page)
  await page.goto('/blackbox', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'Blackbox' })).toBeVisible()
  await page.locator('select').first().selectOption(branch)
  const row = page.locator('tr.lg-row', { hasText: `public.${forTable}` }).first()
  await expect(row).toBeVisible({ timeout: 30_000 })
  await expect(row.locator('.lg-for')).toHaveText(`for alice asserted by ${forApp}`)
  await expect(row).toContainText(email)
})
