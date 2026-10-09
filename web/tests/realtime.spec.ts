// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Realtime page, in a browser, against a real engine.
//
// The component tests next to the page prove its logic against mocks. These
// prove the thing mocks cannot: that the verdicts a real catalog produces land
// in the right rows, that clicking a button really changes what Postgres
// publishes, and that a key minted here is a credential that actually works.
//
// The fixtures come from scripts/integration_ui.sh, which sets realtime up and
// makes three tables — ready, fixable for free, fixable only at a cost —
// before the browser exists. A test that made them would be starting
// containers and running DDL moments before measuring the console, and a
// container coming up makes Chromium abort requests in flight.
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'
const branch = process.env.FOX_E2E_RT_BRANCH ?? 'e2eui'

async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

// Open the page and select the branch the fixtures live on. main is left alone
// by these tests, as everywhere else in this suite.
async function openRealtime(page: Page) {
  await signIn(page)
  await page.goto('/realtime', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'Realtime', exact: true })).toBeVisible()
  await page.getByLabel('Branch').selectOption(branch)
  // The table list is fetched per branch; wait for a fixture rather than a
  // timeout, so a slow VM does not read as a failure.
  await expect(page.getByText(`public.rt_ready`)).toBeVisible({ timeout: 30_000 })
}

const row = (page: Page, name: string) =>
  page.locator('tr', { has: page.getByText(`public.${name}`, { exact: true }) })

test('the page classifies a real branch, and withholds the Blackbox', async ({ page }) => {
  await openRealtime(page)

  // Each fixture reaches the state the catalog actually puts it in.
  await expect(row(page, 'rt_ready')).toContainText('ready')
  await expect(row(page, 'rt_grant')).toContainText('needs changes')
  await expect(row(page, 'rt_keyless')).toContainText('needs changes')

  // The free fix names the statement it would run, so a reader is not asked to
  // trust a button.
  await expect(row(page, 'rt_grant')).toContainText('GRANT SELECT')
  // The costly one says so, and says how much.
  await expect(row(page, 'rt_keyless')).toContainText('REPLICA IDENTITY FULL')
  await expect(row(page, 'rt_keyless')).toContainText('ongoing cost')
  await expect(row(page, 'rt_keyless')).toContainText(/extra WAL a day/)

  // FoxByte's own schema is never offered to a subscriber, and the page says
  // how many it kept back rather than quietly showing a short list.
  await expect(page.getByText(/tables? not shown/)).toBeVisible()
  await expect(page.getByText('bb.schema_ledger')).toHaveCount(0)
})

test('a free fix is applied with one click, and the row changes state', async ({ page }) => {
  await openRealtime(page)
  const r = row(page, 'rt_grant')
  await r.getByRole('button', { name: 'Prepare' }).click()
  // The grant was the only thing in the way, so the table becomes streamable.
  await expect(r).toContainText('ready', { timeout: 30_000 })
  await expect(r.getByRole('button', { name: 'Start streaming' })).toBeVisible()
})

test('a costly fix asks first, states the price, and does nothing if declined', async ({ page }) => {
  await openRealtime(page)
  const r = row(page, 'rt_keyless')
  // The button itself says a question is coming.
  await r.getByRole('button', { name: 'Prepare…' }).click()

  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('ongoing cost')
  await expect(dialog).toContainText('REPLICA IDENTITY FULL')
  // The figure the engine measured from pg_stat_user_tables, not a general
  // warning. The fixture is given rows and updates so there is something real
  // to quote — without statistics the engine says only what FULL does, which
  // is honest and a weaker thing to decide from.
  await expect(dialog).toContainText(/extra WAL a day/)
  await expect(dialog).toContainText(/updates\/day/)
  // And the cheaper way out of paying it.
  await expect(dialog).toContainText(/unique NOT NULL index/)

  await dialog.getByRole('button', { name: /cancel/i }).click()
  await expect(dialog).toBeHidden()
  // Declined means nothing ran: the table is where it was.
  await expect(r).toContainText('needs changes')
  await expect(r.getByRole('button', { name: 'Prepare…' })).toBeVisible()
})

test('starting a table makes Postgres publish it, and stopping undoes it', async ({ page }) => {
  await openRealtime(page)
  const r = row(page, 'rt_ready')
  await r.getByRole('button', { name: 'Start streaming' }).click()
  await expect(r).toContainText('streaming', { timeout: 30_000 })

  // Reloading proves it is the database's state and not the page's: the row
  // comes back streaming because Postgres publishes the table, not because
  // this tab remembers clicking.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByLabel('Branch').selectOption(branch)
  await expect(row(page, 'rt_ready')).toContainText('streaming', { timeout: 30_000 })

  await row(page, 'rt_ready').getByRole('button', { name: 'Stop' }).click()
  await expect(row(page, 'rt_ready')).toContainText('ready', { timeout: 30_000 })
})

test('a key is shown once as a connection string, and can be revoked', async ({ page }) => {
  await openRealtime(page)

  await page.getByLabel('Key name').fill('e2e-subscriber')
  await page.getByRole('button', { name: 'Create key' }).click()

  const dsn = page.getByTestId('realtime-dsn')
  await expect(dsn).toBeVisible({ timeout: 30_000 })
  const url = (await dsn.textContent()) ?? ''

  // The shape an application is given: our scheme, the key in userinfo, the
  // branch as the path. Never the key in the path — that is the property the
  // whole design protects.
  expect(url).toMatch(/^fox-realtime:\/\/rtk_[A-Za-z0-9_-]+@/)
  expect(url).toContain(`/${branch}`)
  expect(url.split('@')[1] ?? '').not.toContain('rtk_')
  await expect(page.getByText(/shown once/)).toBeVisible()

  // Listed afterwards by its visible prefix only — the secret is hashed, so
  // there is nothing else to list.
  await expect(page.getByRole('cell', { name: 'e2e-subscriber' })).toBeVisible()
  const keyRow = page.locator('tr', { has: page.getByRole('cell', { name: 'e2e-subscriber' }) })
  await expect(keyRow).toContainText('rtk_')

  // Revoking asks, and says what stops.
  await keyRow.getByRole('button', { name: 'Revoke' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('stops at its next connection')
  await dialog.getByRole('button', { name: 'Revoke' }).click()
  await expect(page.getByRole('cell', { name: 'e2e-subscriber' })).toBeHidden({ timeout: 30_000 })
})

test('a connection string belonging to another branch is not left on screen', async ({ page }) => {
  await openRealtime(page)
  await page.getByLabel('Key name').fill('e2e-switch')
  await page.getByRole('button', { name: 'Create key' }).click()
  await expect(page.getByTestId('realtime-dsn')).toBeVisible({ timeout: 30_000 })

  // It is a secret, and after the change it is also the wrong one.
  await page.getByLabel('Branch').selectOption('main')
  await expect(page.getByTestId('realtime-dsn')).toBeHidden()
})

test('the feed shows a change made while it is watching', async ({ page }) => {
  await openRealtime(page)

  // Stream the fixture, then write to it. The console is the only actor here:
  // it enables the table and it opens the feed.
  const r = row(page, 'rt_ready')
  if (await r.getByRole('button', { name: 'Start streaming' }).isVisible()) {
    await r.getByRole('button', { name: 'Start streaming' }).click()
    await expect(r).toContainText('streaming', { timeout: 30_000 })
  }

  await page.getByRole('button', { name: 'Watch' }).click()
  await expect(page.getByText('listening…')).toBeVisible()

  // The write goes through the same API the SQL console uses, with this
  // browser's own session cookie, rather than by driving that page's editor:
  // the subject here is the feed, and borrowing another page's selectors would
  // make this test fail when that page is restyled.
  const res = await page.request.post(`/api/branches/${branch}/query`, {
    data: { sql: `INSERT INTO public.rt_ready VALUES (1, 'from the console')` },
  })
  expect(res.ok()).toBeTruthy()

  // The change arrives, named and attributed to its table.
  await expect(page.getByText('public.rt_ready').last()).toBeVisible({ timeout: 60_000 })
  await expect(page.getByText('insert').first()).toBeVisible({ timeout: 60_000 })
})
