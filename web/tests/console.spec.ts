// SPDX-License-Identifier: AGPL-3.0-or-later
import { test, expect, type Page } from '@playwright/test'

const email = process.env.FOX_E2E_EMAIL ?? 'e2e@foxbyte.dev'
const password = process.env.FOX_E2E_PASSWORD ?? 'password123'
const branch = process.env.FOX_E2E_BRANCH ?? 'e2eui'      // made by the harness, owned by this account
const newBranch = process.env.FOX_E2E_NEW_BRANCH ?? 'e2eui2' // made here, through the dashboard
const table = process.env.FOX_E2E_TABLE ?? 'e2e_notes'
// The promotion test's target, made by the harness like `branch` is. It used to
// be made by the test itself, which starts a container moments before the
// interaction being measured — and a container starting changes the host's
// network interfaces, so Chromium aborts whatever is in flight.
const targetBranch = process.env.FOX_E2E_TARGET_BRANCH ?? 'e2eui3'

// Each test signs in and works on its own: the branch the console and Blackbox
// tests use is made by scripts/integration_ui.sh, so no test depends on
// another having run first.
async function signIn(page: Page) {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill(password)
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}

test('signing in reaches the dashboard, which lists main', async ({ page }) => {
  await signIn(page)
  await expect(page.getByRole('cell', { name: 'main', exact: true })).toBeVisible()
})

// Someone locked out is standing on this page, so this is where the way out has to
// be. `fox user passwd` has always existed; until now it appeared only in `fox help`,
// which is no use to anyone who cannot get in.
test('the login page says what to do about a forgotten password', async ({ page }) => {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await expect(page.getByText(/forgotten your password/i)).toBeVisible()
  await expect(page.getByText(/fox user passwd/)).toBeVisible()
  // And it is honest about what is possible: a password is not recoverable.
  await expect(page.getByText(/cannot be recovered/i)).toBeVisible()
})

test('the wrong password is refused', async ({ page }) => {
  await page.goto('/login', { waitUntil: 'domcontentloaded' })
  await page.getByPlaceholder('you@example.com').fill(email)
  await page.getByPlaceholder('password').fill('not-the-password')
  await page.getByRole('button', { name: /log in/i }).click()
  await expect(page.locator('.err')).toContainText(/invalid credentials/i)
  await expect(page).toHaveURL(/\/login$/)
})

test('a branch made in the dashboard appears in the list', async ({ page }) => {
  await signIn(page)
  await page.getByPlaceholder(/new branch name/i).fill(newBranch)
  await page.getByRole('button', { name: /create branch/i }).click()
  await expect(page.getByRole('cell', { name: newBranch, exact: true })).toBeVisible({ timeout: 60_000 })
})

test('the console runs SQL on that branch, and the Blackbox shows the change', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'SQL Console' })).toBeVisible()
  // The branch picker is a select of the branches this account can reach.
  // The branch picker lists what this account may reach.
  const picker = page.locator('select').first()
  await expect(picker.locator(`option[value="${branch}"]`)).toHaveCount(1)
  await picker.selectOption(branch)
  await page.locator('textarea.editor').fill(`CREATE TABLE ${table} (id int)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap, .result, table').first()).toBeVisible()

  await page.goto('/blackbox', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'Blackbox' })).toBeVisible()
  const bbPicker = page.locator('select').first()
  await expect(bbPicker.locator(`option[value="${branch}"]`)).toHaveCount(1)
  await bbPicker.selectOption(branch)
  await expect(page.getByText(`public.${table}`).first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(email).first()).toBeVisible()
})

// A console that cannot take a script is a console people paste into psql
// instead. The results have to be separable too: a stack of grids with no way to
// tell which statement produced which is barely better than one result.
test('the console runs a script and says which statement produced what', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  const t = `e2e_script_${Date.now().toString().slice(-6)}`
  await page.locator('select').first().selectOption(branch)
  await page.locator('textarea.editor').fill(
    `CREATE TABLE ${t} (id int); INSERT INTO ${t} VALUES (1),(2); SELECT count(*) FROM ${t};`)
  await page.getByRole('button', { name: /^run/i }).click()

  // One tab per statement, each labelled with the SQL it came from, so the open
  // one gets the whole pane instead of three tables sharing it.
  await expect(page.locator('.res-tab')).toHaveCount(3, { timeout: 30_000 })
  await expect(page.locator('.res-tab').nth(0)).toContainText(`CREATE TABLE ${t}`)
  await expect(page.locator('.res-tab').nth(1)).toContainText(`INSERT INTO ${t}`)
  await expect(page.locator('.res-tab').nth(2)).toContainText('SELECT count(*)')
  // The third is the one with rows, and selecting it shows them.
  await page.locator('.res-tab').nth(2).click()
  await expect(page.locator('.res-body td:not(.expand-col)').first()).toHaveText('2')

  // A failure names the statement that caused it, and says nothing was applied —
  // the script ran in one transaction, so the row it inserted is gone.
  await page.locator('textarea.editor').fill(
    `INSERT INTO ${t} VALUES (3); SELECT * FROM no_such_table_here;`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.getByText(/nothing was applied/i)).toBeVisible({ timeout: 30_000 })
  // The failing statement is marked, and its tab is the one already open —
  // that is the one being looked for.
  await expect(page.locator('.res-tab.bad')).toHaveCount(1)
  await expect(page.locator('.res-tab.bad')).toHaveClass(/\bon\b/)

  // Proof it rolled back: still two rows, not three.
  await page.locator('textarea.editor').fill(`SELECT count(*) FROM ${t}`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-body td:not(.expand-col)').first()).toHaveText('2', { timeout: 30_000 })
})

// The editor is read-only while a query is in flight. Two reasons: a script's
// results are labelled with the statements they came from, and editing mid-run
// would leave those labels disagreeing with what is on screen — and ⌘↵ used to
// start a second query against the same branch while the first was still going.
test('the editor stops taking edits while a query is running', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const editor = page.locator('textarea.editor')
  await editor.fill('SELECT pg_sleep(2)')
  await page.getByRole('button', { name: /^run/i }).click()

  // While it runs: read-only, and the Run button says so too.
  await expect(editor).toHaveJSProperty('readOnly', true)
  await expect(page.getByRole('button', { name: /running/i })).toBeDisabled()
  // Typing changes nothing while it is read-only.
  await editor.press('a')
  await expect(editor).toHaveValue('SELECT pg_sleep(2)')

  // And it comes back afterwards.
  await expect(editor).toHaveJSProperty('readOnly', false, { timeout: 30_000 })
  await editor.fill('SELECT 1 AS back')
  await expect(editor).toHaveValue('SELECT 1 AS back')
})

// The console is a workbench: it fills the window, the schema rail folds away to
// give both panes its width, and either pane can take the window for a moment.
// Everything here is about space, which is the thing that cannot be checked by
// reading the code.
test('the console fills the window and its panes can take it in turn', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)

  // No page scroll: the window holds the whole thing and the panes scroll inside.
  const scrolls = await page.evaluate(() =>
    document.documentElement.scrollHeight <= document.documentElement.clientHeight + 1)
  expect(scrolls).toBe(true)

  // The rail folds away, and the editor gets the width it was using.
  const rail = page.locator('.wb-rail')
  const editor = page.locator('textarea.editor')
  await expect(rail).not.toHaveClass(/shut/)
  const narrow = (await editor.boundingBox())!.width
  await page.locator('.wb-icon[aria-pressed]').click()
  await expect(rail).toHaveClass(/shut/)
  await expect.poll(async () => (await editor.boundingBox())!.width).toBeGreaterThan(narrow + 100)

  // And the choice survives a reload, because it is a choice about this screen.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await expect(page.locator('.wb-rail')).toHaveClass(/shut/)
  await page.locator('.wb-icon[aria-pressed]').click()
  await expect(page.locator('.wb-rail')).not.toHaveClass(/shut/)

  // Expanding the results hides the editor; Esc brings it back.
  await page.locator('textarea.editor').fill('SELECT 1 AS one')
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-body td:not(.expand-col)').first()).toHaveText('1', { timeout: 30_000 })
  await page.locator('.res-tabs .wb-icon').click()
  await expect(page.locator('textarea.editor')).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(page.locator('textarea.editor')).toHaveCount(1)
})

// Line numbers exist so an error can be found, not for decoration. Postgres
// reports the character offset of a syntax error and it used to be dropped on
// the floor, leaving "syntax error at or near FORM" and forty lines to search.
test('a syntax error says which line, and the gutter marks it', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)

  // The typo is on line 3 of four. Two good lines above it so a gutter that was
  // merely counting from one could not pass by accident.
  await page.locator('textarea.editor').fill('SELECT 1;\nSELECT 2;\nSELCT 3;\nSELECT 4;')
  await page.getByRole('button', { name: /^run/i }).click()

  await expect(page.locator('.err')).toContainText(/syntax error/i, { timeout: 30_000 })
  await expect(page.locator('.err-at')).toContainText('line 3')
  // And the gutter marks that line, which is where someone actually looks.
  await expect(page.locator('.wb-gutter .bad')).toHaveCount(1)
  await expect(page.locator('.wb-gutter .bad')).toHaveText('3')

  // The numbers count the lines, so they are a measure of how long the query is.
  await expect(page.locator('.wb-gutter > div')).toHaveCount(4)

  // A query that is fine marks nothing.
  await page.locator('textarea.editor').fill('SELECT 1 AS ok')
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-body td:not(.expand-col)').first()).toHaveText('1', { timeout: 30_000 })
  await expect(page.locator('.wb-gutter .bad')).toHaveCount(0)
})

test('an API key is shown once, and the account page offers a password change', async ({ page }) => {
  await signIn(page)
  await page.goto('/keys', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'API keys' })).toBeVisible()
  await page.getByPlaceholder(/key name/i).fill('e2e')
  await page.getByRole('button', { name: /create key/i }).click()
  await expect(page.getByText(/copy it now/i)).toBeVisible()
  await expect(page.locator('pre code').first()).toContainText(/^key_/)
  await expect(page.getByRole('heading', { name: 'Your password' })).toBeVisible()
})

// The Blackbox page now keeps itself up to date and shows how an entry is
// chained — the two things that made "a change appears, attributed and linked"
// true in the product rather than only in the docs.
test('the Blackbox picks up a change on its own, and shows the chain', async ({ page }) => {
  await signIn(page)
  await page.goto('/blackbox', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'Blackbox' })).toBeVisible()
  await page.locator('select').first().selectOption(branch)
  // Live is on by default; the dot says so.
  const liveBtn = page.getByRole('button', { name: /live|paused/i })
  await expect(liveBtn).toHaveAttribute('aria-pressed', 'true')

  // A change made elsewhere must arrive without this page being touched. The
  // API call stands in for another tab or a psql session.
  const live = `e2e_live_${Date.now().toString().slice(-6)}`
  await page.evaluate(async ([b, t]) => {
    await fetch(`/api/branches/${b}/query`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ sql: `CREATE TABLE ${t} (id int)` }),
    })
  }, [branch, live])
  // No reload, no Refresh: the poll has to bring it in.
  await expect(page.getByText(`public.${live}`).first()).toBeVisible({ timeout: 30_000 })

  // Expanding it shows the hashes that link it to the entry before.
  await page.getByText(`public.${live}`).first().click()
  const detail = page.locator('.lg-detail').first()
  await expect(detail.locator('.lg-chain')).toBeVisible()
  await expect(detail.locator('.lg-chain code').first()).toHaveText(/^[0-9a-f]{12}…$/)
  await expect(detail).toContainText('links to')
})

// Rewind is offered where the bad change is visible. Creating the branch takes
// minutes, so the test goes as far as the confirmation — that the action exists,
// names the entry, and says main is left alone.
test('a Blackbox entry offers to branch from before it, on main only', async ({ page }) => {
  await signIn(page)
  // main's record can be empty on a fresh install (the suites run with the sample
  // data off), so this makes its own change rather than relying on one being
  // there — no test in this file depends on another having run.
  const onMain = `e2e_rewind_${Date.now().toString().slice(-6)}`
  await page.goto('/blackbox', { waitUntil: 'domcontentloaded' })
  await page.evaluate(async (t) => {
    await fetch('/api/branches/main/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ sql: `CREATE TABLE ${t} (id int)` }),
    })
  }, onMain)
  await page.locator('select').first().selectOption('main')
  const firstChange = page.getByText(`public.${onMain}`).first()
  await expect(firstChange).toBeVisible({ timeout: 30_000 })
  await firstChange.click()
  const detail = page.locator('.lg-detail').first()
  await detail.getByRole('button', { name: /branch from before this change/i }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText(/just before entry #\d+/)
  await expect(dialog).toContainText(/main.*is not modified/i)
  await dialog.getByRole('button', { name: /cancel/i }).click()
  await expect(dialog).toBeHidden()

  // On another branch the action is absent, and the page says why rather than
  // offering something the engine would refuse.
  const onBranch = `e2e_rewind_b_${Date.now().toString().slice(-6)}`
  await page.evaluate(async ([b, t]) => {
    await fetch(`/api/branches/${b}/query`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ sql: `CREATE TABLE ${t} (id int)` }),
    })
  }, [branch, onBranch])
  await page.locator('select').first().selectOption(branch)
  const other = page.getByText(`public.${onBranch}`).first()
  await expect(other).toBeVisible({ timeout: 30_000 })
  await other.click()
  const otherDetail = page.locator('.lg-detail').first()
  await expect(otherDetail.getByRole('button', { name: /branch from before this change/i })).toHaveCount(0)
  await expect(otherDetail).toContainText(/only branch that archives WAL/i)
})

// Promotion: a branch's changes offered for review, then applied. The whole point
// is that nothing reaches the target until someone decides, so the test checks
// both halves — the target is untouched while the request is open, and holds the
// change once it is approved.
test('a branch\'s changes can be reviewed and applied to another branch', async ({ page }) => {
  await signIn(page)
  const table = `e2e_promo_${Date.now().toString().slice(-6)}`
  const target = targetBranch
  await page.goto('/requests', { waitUntil: 'domcontentloaded' })
  // The target is made and owned by this account in the harness: promoting into
  // main would leave the change on main for every later run, and a branch is where
  // the ownership rule (the owner may approve) is exercised anyway. Only the
  // change to promote is made here, which is a query against a branch that is
  // already running.
  await page.evaluate(async ([b, t]) => {
    await fetch(`/api/branches/${b}/query`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ sql: `CREATE TABLE ${t} (id int)` }),
    })
  }, [branch, table])

  await expect(page.getByRole('heading', { name: 'Change requests' })).toBeVisible()
  await page.reload({ waitUntil: 'domcontentloaded' })
  const [from, to] = [page.locator('select').first(), page.locator('select').nth(1)]
  await from.selectOption(branch)
  await to.selectOption(target)
  await page.getByRole('button', { name: /ask for review/i }).click()
  await expect(page.locator('.okmsg')).toContainText(new RegExp(`Nothing has been applied to ${target}`, 'i'), { timeout: 30_000 })

  // The statement is shown for review, and main does not have it yet.
  await expect(page.getByText(`CREATE TABLE ${table}`).first()).toBeVisible()
  const has = (t: string, tgt: string) => page.evaluate(async ([tbl, b]) => {
    const r = await fetch(`/api/branches/${b}/query`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ sql: `SELECT count(*) FROM information_schema.tables WHERE table_name = '${tbl}'` }),
    })
    return String((await r.json()).rows?.[0]?.[0])
  }, [t, tgt])

  expect(await has(table, target)).toBe('0')

  // Approving applies it, through the confirmation that says what will happen.
  await page.getByRole('button', { name: new RegExp(`apply to ${target}`, 'i') }).first().click()
  await expect(page.getByRole('dialog')).toContainText(/no data is moved/i)
  await page.getByRole('dialog').getByRole('button', { name: /^apply$/i }).click()
  // However many statements the source has accumulated from the tests before this
  // one: what matters is that they were applied and the table reached the target.
  await expect(page.locator('.okmsg')).toContainText(/Applied \d+ statement/i, { timeout: 60_000 })
  expect(await has(table, target)).toBe('1')

  // No clean-up here: the target belongs to the harness, which deletes and remakes
  // it at the start of every run. Deleting it would leave a retry with no target
  // to select — the branch list is exactly what the second attempt could not find.
})
