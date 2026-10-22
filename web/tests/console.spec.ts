// SPDX-License-Identifier: AGPL-3.0-or-later
import { test, expect, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

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

  // A failure says what went wrong and that nothing was applied — the script ran
  // in one transaction, so the row the first statement inserted is gone.
  //
  // What it does not do is give the failing statement a tab of its own. This
  // one fails in parse analysis, before Postgres describes any result for it,
  // so it never reaches the stream at all: a script of two comes back with one
  // completed result and a top-level error. The labels notice the counts
  // disagree and step aside rather than put the SQL under the wrong grid, which
  // is the behaviour that was asked for. The error block says which line.
  await page.locator('textarea.editor').fill(
    `INSERT INTO ${t} VALUES (3); SELECT * FROM no_such_table_here;`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.err')).toContainText(/no_such_table_here/, { timeout: 30_000 })
  await expect(page.getByText(/nothing was applied/i)).toBeVisible()

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

// Point 1.1: a result can be copied to paste somewhere else, all of it, the
// rows ticked, or one cell. `fox sql --format` writes the same text: both
// follow web/src/copyformat.vectors.json.
test('a result can be copied as CSV, as Markdown for ticked rows, and one cell at a time', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_copy_${Date.now().toString().slice(-6)}`
  await page.locator('textarea.editor').fill(
    `CREATE TABLE ${t} (id int, name text, f text); INSERT INTO ${t} VALUES (1, 'Ada, Countess', '=1+1'), (2, 'Bob', NULL);`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-tab')).toHaveCount(2, { timeout: 30_000 })
  await page.locator('textarea.editor').fill(`SELECT id, name, f FROM ${t} ORDER BY id`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('1', { timeout: 30_000 })
  const clip = () => page.evaluate(() => navigator.clipboard.readText())

  // The whole result as CSV: quoted where needed, a formula made safe, NULL empty.
  await page.getByRole('button', { name: 'Copy ▾' }).click()
  await page.getByLabel('Copy format').selectOption('csv')
  await page.getByRole('button', { name: /copy all 2 rows/i }).click()
  await expect.poll(clip).toBe('id,name,f\n1,"Ada, Countess",\'=1+1\n2,Bob,\n')

  // Only the ticked row, as Markdown.
  await page.keyboard.press('Escape')
  await page.getByLabel('Select row 2').check()
  await page.getByRole('button', { name: /^cop(y|ied)/i }).first().click()
  await page.getByLabel('Copy format').selectOption('markdown')
  await page.getByRole('button', { name: /copy 1 selected row$/i }).click()
  await expect.poll(clip).toBe('| id | name | f |\n| --- | --- | --- |\n| 2 | Bob | NULL |\n')

  // One cell: pick it, then the copy shortcut.
  await page.keyboard.press('Escape')
  await page.locator('.grid-wrap td', { hasText: 'Ada, Countess' }).click()
  await expect(page.getByText(/cell selected/i)).toBeVisible()
  await page.keyboard.press('ControlOrMeta+c')
  await expect.poll(clip).toBe('Ada, Countess')
})

// Point 1.2: what is on screen can be downloaded as CSV, JSON or an Excel
// workbook. The workbook is opened by a reader other than the code that wrote
// it (Python's zipfile and XML parser), as a spreadsheet would.
test('a result can be exported as CSV and as an Excel workbook', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_export_${Date.now().toString().slice(-6)}`
  await page.locator('textarea.editor').fill(
    `CREATE TABLE ${t} (id int, name text, ok boolean); INSERT INTO ${t} VALUES (1, 'Ada, Countess', true), (2, '=1+1', NULL);`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-tab')).toHaveCount(2, { timeout: 30_000 })
  await page.locator('textarea.editor').fill(`SELECT id, name, ok FROM ${t} ORDER BY id`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('1', { timeout: 30_000 })

  await page.getByRole('button', { name: 'Export ▾' }).click()
  await page.getByLabel('Export format').selectOption('csv')
  let [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /download all 2 rows/i }).click()])
  expect(dl.suggestedFilename()).toMatch(new RegExp(`^${t}-\\d{8}-\\d{4}\\.csv$`))
  expect(readFileSync(await dl.path(), 'utf8')).toBe('id,name,ok\n1,"Ada, Countess",true\n2,\'=1+1,\n')

  await page.getByLabel('Export format').selectOption('xlsx')
  ;[dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /download all 2 rows/i }).click()])
  expect(dl.suggestedFilename()).toMatch(/\.xlsx$/)
  const read = execFileSync('python3', ['-c', `
import sys, zipfile, xml.etree.ElementTree as ET
z = zipfile.ZipFile(sys.argv[1])
ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
r = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
c = lambda ref: r.find(".//s:c[@r='%s']" % ref, ns)
print(z.testzip(), c('A2').find('s:v', ns).text, ''.join(c('B2').itertext()), c('C2').get('t'), c('C3'), ''.join(c('B3').itertext()))
`, await dl.path()], { encoding: 'utf8' }).trim()
  // A sound zip; 1 as a number; the comma kept; true as a boolean; NULL empty;
  // and a formula kept as text rather than escaped, since a typed cell is never run.
  expect(read).toBe('None 1 Ada, Countess b None =1+1')
})

// Point 1.3: everything a query returns, not the 1,000 rows on screen. The
// statement is run again on the server, read only, as the signed-in user.
test('a whole result past the 1,000 on screen can be exported from the server', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  await page.locator('textarea.editor').fill(`SELECT g AS id, 'row ' || g AS note FROM generate_series(1, 2500) g`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('1', { timeout: 30_000 })

  await page.getByRole('button', { name: 'Export ▾' }).click()
  await page.getByLabel('Export format').selectOption('csv')
  // What is on screen stops at what the console holds.
  let [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /download all 1000 rows/i }).click()])
  expect(readFileSync(await dl.path(), 'utf8').trimEnd().split('\n')).toHaveLength(1001)

  await page.getByLabel(/everything the query returns/i).check()
  ;[dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /download every row/i }).click()])
  expect(dl.suggestedFilename()).toMatch(/^generate_series-\d{8}-\d{4}\.csv$/)
  const lines = readFileSync(await dl.path(), 'utf8').trimEnd().split('\n')
  expect(lines).toHaveLength(2501)
  expect([lines[0], lines[1], lines[2500]]).toEqual(['id,note', '1,row 1', '2500,row 2500'])

  // An export is read only: nextval() runs as a query, but an export of it is
  // refused, and the menu says why rather than saving anything.
  await page.keyboard.press('Escape')
  const seq = `e2e_seq_${Date.now().toString().slice(-6)}`
  // A script's result cannot be run again on its own, and the menu says so.
  await page.locator('textarea.editor').fill(`CREATE SEQUENCE ${seq}; SELECT nextval('${seq}') AS n`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-tab')).toHaveCount(2, { timeout: 30_000 })
  await page.locator('.res-tab').nth(1).click()
  await page.getByRole('button', { name: 'Export ▾' }).click()
  await expect(page.getByLabel(/everything the query returns/i)).toHaveCount(0)
  await expect(page.getByText(/run the statement on its own/i)).toBeVisible()
  await page.keyboard.press('Escape')
  await page.locator('textarea.editor').fill(`SELECT nextval('${seq}') AS n`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('2', { timeout: 30_000 })
  await page.getByRole('button', { name: 'Export ▾' }).click()
  await page.getByLabel(/everything the query returns/i).check()
  await page.getByRole('button', { name: /download every row/i }).click()
  await expect(page.getByRole('alert')).toContainText('read-only transaction', { timeout: 30_000 })
})

// Points 8.1 and 8.3: what you type is kept in your history (never a result),
// the console's own reads of a table are not, and you can turn yours off and
// delete it from the account page.
test('the queries you run are kept in your history, which you can turn off and delete', async ({ page }) => {
  await signIn(page)
  const count = async () => {
    await page.goto('/keys', { waitUntil: 'domcontentloaded' })
    const t = (await page.getByTestId('history-count').textContent({ timeout: 30_000 })) ?? ''
    return Number(t.split(' ')[0])
  }
  const run = async (sql: string) => {
    await page.goto('/console', { waitUntil: 'domcontentloaded' })
    await page.locator('select').first().selectOption(branch)
    await page.locator('textarea.editor').fill(sql)
    await page.getByRole('button', { name: /^run/i }).click()
    await expect(page.locator('.grid-wrap td:not(.expand-col), .wb-out').first()).toBeVisible({ timeout: 30_000 })
  }
  const t = `e2e_hist_${Date.now().toString().slice(-6)}`

  // Start from history on: the switch is kept by the engine, so a run that
  // stopped part way could otherwise leave this account opted out.
  await count()
  const mine = page.getByLabel(/keep a history of my queries/i)
  if (!(await mine.isChecked())) {
    await mine.check()
    await expect(page.getByText(/kept again/i)).toBeVisible()
  }
  const before = await count()
  await run(`CREATE TABLE ${t} (id int)`)
  // Browsing the table runs the console's own queries (its rows, its count),
  // which nobody typed: they are not kept.
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).click()
  await expect(page.locator('.grid-wrap, .wb-empty, .muted').first()).toBeVisible({ timeout: 30_000 })
  expect(await count()).toBe(before + 1)
  await expect(page.getByText(/never a result/i)).toBeVisible()

  // Off: nothing new is kept, and what was kept stays.
  await page.getByLabel(/keep a history of my queries/i).uncheck()
  await expect(page.getByText(/no longer kept/i)).toBeVisible()
  await run(`SELECT 1 AS ${t}_off`)
  expect(await count()).toBe(before + 1)
  await page.getByLabel(/keep a history of my queries/i).check()
  await expect(page.getByText(/kept again/i)).toBeVisible()

  // Deleted, after asking.
  await page.getByRole('button', { name: /delete my history/i }).click()
  await page.getByRole('button', { name: /^delete$/i }).click()
  await expect(page.getByText(/^Deleted \d+ entr(y|ies)\.$/)).toBeVisible()
  await expect(page.getByTestId('history-count')).toHaveText(/^0 queries/)
})

// Point 8.2: the console's history panel. What you ran is there to find, open,
// run again and copy, and to keep under a name.
test('the history panel finds, opens, runs again, copies and saves a query', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page)
  // History on for this account, whatever an earlier run left.
  await page.goto('/keys', { waitUntil: 'domcontentloaded' })
  const mine = page.getByLabel(/keep a history of my queries/i)
  await expect(page.getByTestId('history-count')).toBeVisible({ timeout: 30_000 })
  if (!(await mine.isChecked())) await mine.check()

  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const m = `e2e_h82_${Date.now().toString().slice(-6)}`
  const sql = `SELECT 41 + 1 AS ${m}`
  await page.locator('textarea.editor').fill(sql)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('42', { timeout: 30_000 })

  // The panel shows the run, and finds it by a word in it.
  if ((await page.getByRole('button', { name: 'History', exact: true }).getAttribute('aria-pressed')) !== 'true') {
    await page.getByRole('button', { name: 'History', exact: true }).click()
  }
  const panel = page.getByRole('complementary', { name: 'Query history' })
  await panel.getByLabel('Search history').fill(m)
  const item = panel.locator('.hist-item', { hasText: m })
  await expect(item).toHaveCount(1, { timeout: 30_000 })
  await expect(item).toContainText(branch)
  await expect(item).toContainText('1 row')

  // Open puts it in the editor; Run runs it again and the panel shows that too.
  await page.locator('textarea.editor').fill('SELECT 0')
  await item.getByRole('button', { name: 'Open' }).click()
  await expect(page.locator('textarea.editor')).toHaveValue(sql)
  await page.locator('textarea.editor').fill('SELECT 0')
  await item.first().getByRole('button', { name: 'Run' }).click()
  await expect(page.locator('textarea.editor')).toHaveValue(sql)
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('42', { timeout: 30_000 })
  await expect(panel.locator('.hist-item', { hasText: m })).toHaveCount(2, { timeout: 30_000 })

  // Copy.
  await panel.locator('.hist-item', { hasText: m }).first().getByRole('button', { name: 'Copy' }).click()
  await expect(panel.getByText('Copied ✓')).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(sql)

  // Save under a name, and run it from Saved.
  const first = panel.locator('.hist-item', { hasText: m }).first()
  await first.getByRole('button', { name: 'Save' }).click()
  await first.getByLabel('Name for the saved query').fill(`answer ${m}`)
  await first.locator('form').getByRole('button', { name: /^save$/i }).click()
  await expect(panel.getByText(`Saved as “answer ${m}”`)).toBeVisible()
  await panel.getByRole('tab', { name: 'Saved' }).click()
  await panel.getByLabel('Search saved queries').fill(m)
  const saved = panel.locator('.hist-item', { hasText: `answer ${m}` })
  await expect(saved).toHaveCount(1, { timeout: 30_000 })
  await page.locator('textarea.editor').fill('SELECT 0')
  await saved.getByRole('button', { name: 'Run' }).click()
  await expect(page.locator('textarea.editor')).toHaveValue(sql)
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('42', { timeout: 30_000 })

  // Deleted after asking.
  await saved.getByRole('button', { name: `Delete answer ${m}` }).click()
  await page.getByRole('button', { name: /^delete$/i }).click()
  await expect(saved).toHaveCount(0)
})

// Point 9: suggestions in the editor. Typed key by key, as a person does:
// filling the editor at once is a paste, and a paste is not offered names.
test('the editor suggests names as you type, offers a fix for a misspelt one, and writes snippets', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_sg_${Date.now().toString().slice(-6)}`
  const ed = page.locator('textarea.editor')
  await ed.fill(`CREATE TABLE ${t} (id int PRIMARY KEY, label text)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.obj-item', { hasText: t })).toBeVisible({ timeout: 30_000 })

  // 9.1: the table after FROM, and Enter takes it.
  await ed.fill(`SELECT * FROM ${t.slice(0, -2)}`)
  await ed.press('End')
  await ed.pressSequentially(t.slice(-2, -1))
  const list = page.getByRole('listbox', { name: 'Suggestions' })
  await expect(list.getByRole('option', { name: new RegExp(t) })).toBeVisible()
  await ed.press('Enter')
  await expect(ed).toHaveValue(`SELECT * FROM ${t}`)
  await expect(list).toHaveCount(0)

  // …and a table's columns after its alias and a dot.
  await ed.fill(`SELECT x FROM ${t} x`)
  await ed.press('Home')
  for (let i = 0; i < 'SELECT x'.length; i++) await ed.press('ArrowRight')
  await ed.pressSequentially('.')
  await expect(list.getByRole('option')).toHaveCount(2)
  await ed.press('ArrowDown')
  await ed.press('Enter')
  await expect(ed).toHaveValue(`SELECT x.label FROM ${t} x`)

  // 9.2: a misspelt table gets the name meant, fixed where Postgres pointed.
  const typo = t.slice(0, -1)
  await ed.fill(`SELECT count(*) FROM ${typo}`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.getByText(/did you mean/i)).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Fix and run' }).click()
  await expect(ed).toHaveValue(`SELECT count(*) FROM ${t}`)
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('0', { timeout: 30_000 })

  // 9.3: a table's snippet, put in the editor to finish and run.
  await page.locator('.obj-item', { hasText: t }).click()
  await page.getByRole('button', { name: /snippets/i }).click()
  await page.getByRole('menu', { name: `Snippets for ${t}` }).getByRole('menuitem', { name: 'Delete a row' }).click()
  await expect(ed).toHaveValue(`DELETE FROM ${t}\nWHERE id = NULL;`)
  await page.locator('.obj-item', { hasText: t }).click()
  await page.getByRole('button', { name: /snippets/i }).click()
  await page.getByRole('menuitem', { name: 'Count rows' }).click()
  await expect(ed).toHaveValue(`SELECT count(*) FROM ${t};`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.grid-wrap td:not(.expand-col)').first()).toHaveText('0', { timeout: 30_000 })
})

// Point 12.1: the object browser. The rest of what a branch holds, found in
// the rail, and each object's CREATE script.
test('the object browser shows functions, types and a table\'s parts, with their CREATE scripts', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_ob_${Date.now().toString().slice(-6)}`
  const ed = page.locator('textarea.editor')
  await ed.fill(`CREATE TABLE ${t} (id int PRIMARY KEY, n int CHECK (n > 0)); CREATE TYPE ${t}_mood AS ENUM ('ok', 'meh'); CREATE FUNCTION ${t}_f(x int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT x + 1'`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-tab')).toHaveCount(3, { timeout: 30_000 })
  // The rail reloads after DDL; a search opens the groups that hold a match.
  await page.locator('.obj-filter').fill(t)
  const fn = page.locator('.obj-item', { hasText: `${t}_f(x integer)` })
  await expect(fn).toBeVisible({ timeout: 30_000 })
  await expect(page.locator('.obj-item', { hasText: `${t}_mood` })).toBeVisible()

  // A function: what it is, and its script into the editor.
  await fn.click()
  const view = page.getByRole('region', { name: new RegExp(`function ${t}_f`) })
  await expect(view.getByRole('cell', { name: 'immutable', exact: true })).toBeVisible({ timeout: 30_000 })
  await expect(view.getByLabel('CREATE script')).toContainText(`CREATE OR REPLACE FUNCTION public.${t}_f(x integer)`)
  await view.getByRole('button', { name: 'Open in editor' }).click()
  await expect(ed).toHaveValue(new RegExp(`^CREATE OR REPLACE FUNCTION public\\.${t}_f\\(x integer\\)`))

  // A type: its values.
  await page.locator('.obj-item', { hasText: `${t}_mood` }).click()
  await expect(page.getByLabel('CREATE script')).toContainText(`CREATE TYPE public.${t}_mood AS ENUM ('ok', 'meh');`)

  // A table: its constraints and its CREATE script.
  await page.locator('.obj-item', { hasText: t }).filter({ hasNotText: '(' }).filter({ hasNotText: 'mood' }).first().click()
  await page.getByRole('button', { name: 'Constraints' }).click()
  await expect(page.getByText('PRIMARY KEY (id)')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('CHECK (n > 0)')).toBeVisible()
  await page.getByRole('button', { name: 'CREATE script' }).click()
  await expect(page.getByLabel('CREATE script')).toContainText(`CREATE TABLE public.${t} (`)
})

// Point 12.2: the data grid. A table's rows sorted, filtered, and edited in
// place: a change, a deletion and a new row, saved together.
test('the data grid sorts, filters, and saves edits together', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_grid_${Date.now().toString().slice(-6)}`
  await page.locator('textarea.editor').fill(`CREATE TABLE ${t} (id int PRIMARY KEY, name text, qty int); INSERT INTO ${t} VALUES (1, 'b', 20), (2, 'a', 10), (3, 'c', 30)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await expect(page.locator('.res-tab')).toHaveCount(2, { timeout: 30_000 })
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()
  const firstCol = () => page.locator('.grid-wrap tbody tr td:nth-child(2)')
  await expect(firstCol()).toHaveText(['1', '2', '3'], { timeout: 30_000 })

  // Sort: a header click, again for descending.
  await page.getByRole('button', { name: 'name', exact: true }).click()
  await expect(firstCol()).toHaveText(['2', '1', '3'])
  await page.getByRole('button', { name: 'name', exact: true }).click()
  await expect(firstCol()).toHaveText(['3', '1', '2'])

  // Filter: qty above 15, then cleared.
  await page.getByLabel('Filter column').selectOption('qty')
  await page.getByLabel('Filter comparison').selectOption('>')
  await page.getByLabel('Filter value').fill('15')
  await page.getByRole('button', { name: 'Filter', exact: true }).click()
  await expect(firstCol()).toHaveText(['3', '1'])
  await page.getByRole('button', { name: 'Remove filter qty > 15' }).click()
  await expect(firstCol()).toHaveText(['3', '1', '2'])

  // Edit: change a name, delete a row, add one; save them together.
  await page.getByRole('button', { name: 'Edit rows' }).click()
  const rowOf = (id: string) => page.locator('.edit-grid tbody tr', { has: page.locator('td:nth-child(2)', { hasText: new RegExp(`^${id}$`) }) })
  await rowOf('1').locator('td').nth(2).click()
  await page.getByLabel('Value for name').fill('bee')
  await page.getByLabel('Value for name').press('Enter')
  await rowOf('2').getByRole('button', { name: /^Delete row/ }).click()
  await page.getByRole('button', { name: 'Add row' }).click()
  const added = page.locator('.edit-grid tr.row-new')
  await added.locator('td').nth(1).click()
  await page.getByLabel('Value for id').fill('4')
  await page.getByLabel('Value for id').press('Enter')
  await added.locator('td').nth(2).click()
  await page.getByLabel('Value for name').fill('dee')
  await page.getByLabel('Value for name').press('Enter')
  await expect(page.locator('.edit-bar')).toContainText('1 added, 1 changed, 1 deleted')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText('Saved: 1 added, 1 changed, 1 deleted.')).toBeVisible({ timeout: 30_000 })
  // The page reloads from the table: sorted by name, descending, still.
  await expect(firstCol()).toHaveText(['4', '3', '1'], { timeout: 30_000 })
  await expect(page.locator('.grid-wrap tbody tr', { hasText: 'bee' })).toHaveCount(1)
})

// Points 5.1, 5.2 and 6.1: row tracking, turned on from the console. Postgres
// then keeps when each row was made and changed, the login that changed it, and
// whom for (nobody here: the console asserts no application user).
test('a table can be tracked: each row says when it was made and changed, and who changed it', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_trk_${Date.now().toString().slice(-6)}`
  const ed = page.locator('textarea.editor')
  await ed.fill(`CREATE TABLE ${t} (id int PRIMARY KEY, v text)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()

  await page.getByRole('button', { name: 'Track changes…' }).click()
  const dlg = page.getByRole('dialog', { name: `Track changes to ${t}` })
  await expect(dlg).toContainText('INSERT written without a column list')
  await dlg.getByRole('button', { name: 'Track', exact: true }).click()
  await expect(page.getByText('Tracked:')).toBeVisible({ timeout: 30_000 })

  // A row added as the signed-in user, with a name it tried to forge. (The
  // table's view hides the editor: back to the query first.)
  await page.locator('.obj-item.special').click()
  await ed.fill(`INSERT INTO ${t} (id, v, last_modified_by) VALUES (1, 'x', 'mallory')`)
  await page.getByRole('button', { name: /^run/i }).click()
  await page.locator('.obj-item', { hasText: t }).first().click()
  const row = page.locator('.grid-wrap tbody tr').first()
  await expect(row).toContainText(email, { timeout: 30_000 })
  await expect(row).not.toContainText('mallory')
  await expect(page.locator('.grid-wrap thead')).toContainText('last_modified_for')

  // The grid will not edit what Postgres keeps.
  await page.getByRole('button', { name: 'Edit rows' }).click()
  const byCell = page.locator('.edit-grid tbody tr').first().locator('td').nth(5)
  await expect(byCell).toHaveAttribute('title', /Kept by row tracking/)
  const forCell = page.locator('.edit-grid tbody tr').first().locator('td').nth(6)
  await expect(forCell).toHaveAttribute('title', /Kept by row tracking/)
  await page.getByRole('button', { name: 'Done' }).click()

  // Stopped, after asking: the columns stay.
  await page.getByRole('button', { name: 'Stop tracking' }).click()
  await page.getByRole('button', { name: 'Stop tracking' }).last().click()
  await expect(page.getByRole('button', { name: 'Track changes…' })).toBeVisible({ timeout: 30_000 })
  await expect(page.locator('.grid-wrap thead')).toContainText('last_modified_by')
})

// Point 5.2 on a table tracked before whom-for: one click adds the column, and
// nothing else about the table changes.
test('a table tracked without whom-for gains it from the console', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = `e2e_trkf_${Date.now().toString().slice(-6)}`
  const ed = page.locator('textarea.editor')
  await ed.fill(`CREATE TABLE ${t} (id int PRIMARY KEY, v text)`)
  await page.getByRole('button', { name: /^run/i }).click()
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()

  await page.getByRole('button', { name: 'Track changes…' }).click()
  const dlg = page.getByRole('dialog', { name: `Track changes to ${t}` })
  await dlg.getByLabel('Keep whom for').uncheck()
  await dlg.getByRole('button', { name: 'Track', exact: true }).click()
  const on = page.locator('.track-on')
  await expect(on).toBeVisible({ timeout: 30_000 })
  await expect(on).not.toContainText('last_modified_for')

  await page.getByRole('button', { name: 'Add whom for' }).click()
  await expect(on).toContainText('last_modified_for', { timeout: 30_000 })
  await expect(page.getByRole('button', { name: 'Add whom for' })).toHaveCount(0)
  await expect(on).toContainText('last_modified_by')
})

// Point 5.2 end to end: a row integration_ui.sh changed through the Gateway in
// a transaction an application asserted alice for keeps that, beside the login.
test('a tracked row shows whom it was last changed for', async ({ page }) => {
  await signIn(page)
  await page.goto('/console', { waitUntil: 'domcontentloaded' })
  await page.locator('select').first().selectOption(branch)
  const t = process.env.FOX_E2E_FOR_ROWS ?? 'e2e_for_rows'
  await page.locator('.obj-filter').fill(t)
  await page.locator('.obj-item', { hasText: t }).first().click()
  const row = page.locator('.grid-wrap tbody tr').first()
  await expect(row).toContainText('asserted:uishop:alice', { timeout: 30_000 })
  await expect(row).toContainText(email)
})
