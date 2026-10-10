// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Retake docs/screenshots/*.png.
//
//   make screenshots
//
// Why this exists as a file rather than as instructions: the last retake was
// done by hand, and docs/screenshots/README.md described the method in detail
// without shipping it. So ledger.png was left behind on 21 September showing
// the old fox-head mark and the orange accent, the README said so, and it
// stayed that way for three weeks — because retaking one picture meant
// rebuilding the harness first. A picture of the product is documentation, and
// documentation that is expensive to regenerate goes stale.
//
// It serves web/dist with a canned control plane behind it. Real sample data
// would mean a real install with interesting data in it, which no fresh install
// has: one empty branch makes a dull and unrepresentative picture.
//
// Chrome rather than a downloaded Chromium (`channel: 'chrome'`), so this needs
// no extra 150 MB. Playwright is already a dev dependency of web/.
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { extname, join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'web', 'dist')
const out = join(root, 'docs', 'screenshots')

if (!existsSync(join(dist, 'index.html'))) {
  console.error('web/dist is not built. Run `make web-build` first.')
  process.exit(2)
}

// The canned control plane.
//
// Enterprise with every feature licensed, because the pictures are of the whole
// product. A Standard install would show the paid pages locked, which is honest
// for that install and misleading as a picture of what FoxByte is.
const NOW = Date.parse('2026-10-11T09:14:02Z')
const ago = ms => new Date(NOW - ms).toISOString()

const api = {
  '/auth/me': { user: { id: 1, email: 'avery@acme.dev' }, admin: true },
  '/auth/providers': { providers: [] },
  '/api/account': { user: { id: 1, email: 'avery@acme.dev' }, admin: true },
  '/api/status': {
    mainReady: true, branches: 5, agents: 1,
    edition: 'enterprise',
    features: ['realtime', 'anchors', 'policy', 'impact', 'promotion', 'export', 'pipelines'],
    ha: { enabled: true, standby: 'running', streaming: true, primary: 'main' },
    storage: { used: '2.74G', avail: '91.2G' },
    servers: { gateway: true, api: true },
  },
  '/api/license': {
    edition: 'enterprise', present: true, state: 'active', unlocks: true,
    features: ['realtime', 'anchors', 'policy', 'impact', 'promotion', 'export', 'pipelines'],
    reason: '', action: '',
    expires: '2027-01-07T18:18:33Z',
    id: 'FB-2026-0184', customer: 'Acme Ltd',
    issuedAt: '2026-10-07T18:18:33Z', issuedFor: '', boundTo: '', rebinds: 0,
  },
  '/api/branches': [
    { name: 'main', primary: true, agent: false, state: 'running', used: '2.41G', refer: '2.41G', connections: 7, port: '5432' },
    { name: 'agent-claude-7f2a', primary: false, agent: true, state: 'running', used: '41.8M', refer: '2.44G', connections: 2, port: '5433' },
    { name: 'pr-1482-migration', primary: false, agent: false, state: 'exited', used: '12.6M', refer: '2.42G', connections: 0, port: '5434' },
    { name: 'qa-checkout', primary: false, agent: false, state: 'running', used: '96.2M', refer: '2.50G', connections: 1, port: '5435' },
    { name: 'staging', primary: false, agent: false, state: 'running', used: '184M', refer: '2.59G', connections: 3, port: '5436' },
  ],
  // A bare array, which is what listBackups expects. The first draft wrapped
  // it in an object and the dashboard died on `backups.slice`.
  '/api/backups': [
    { name: 'base_000000010000000000000071', finished_at: ago(0.4 * 86400e3), size_bytes: 2576980378, newest: true },
    { name: 'base_000000010000000000000063', finished_at: ago(1.4 * 86400e3), size_bytes: 2576980378 },
    { name: 'base_000000010000000000000055', finished_at: ago(2.4 * 86400e3), size_bytes: 2469606195 },
  ],
  '/api/replication': [],
}

// The Blackbox: the page is only worth a picture with a record in it that shows
// what the record is *for* — an agent's change beside a person's, one blocked
// and one flagged.
// The column names are the page's, not an approximation of them: it reads
// command_tag and object_identity, and the status pill is keyed on the
// uppercase value. The first draft used `kind`/`object` and lowercase
// statuses, which rendered an empty CHANGE column and colourless badges — and
// looked plausible enough in a terminal to have been committed unlooked at.
const ledgerColumns = ['id', 'at', 'actor', 'actor_kind', 'tool', 'command_tag', 'object_identity', 'risk', 'status', 'statement']
const ledgerRows = [
  ['a1', '2026-10-11 09:14:02', 'ada@lovelace.dev', 'human', 'console', 'CREATE INDEX', 'public.ix_app_user_email', '', 'APPLIED',
    'CREATE INDEX CONCURRENTLY ix_app_user_email ON public.app_user (lower(email));'],
  ['a2', '2026-10-11 09:02:41', 'agent-claude-7f2a', 'agent', 'mcp', 'ALTER TABLE', 'public.orders', '', 'APPLIED',
    'ALTER TABLE public.orders ADD COLUMN fulfilled_at timestamptz;'],
  ['a3', '2026-10-11 08:58:12', 'grace@hopper.navy', 'human', 'psql', 'DROP TABLE', 'public.legacy_sessions', 'drop', 'BLOCKED',
    'DROP TABLE public.legacy_sessions;'],
  ['a4', '2026-10-10 22:41:55', 'alan@turing.org', 'human', 'console', 'ALTER TABLE', 'public.invoice', 'type-change', 'FLAGGED',
    'ALTER TABLE public.invoice ALTER COLUMN total TYPE numeric(14,2);'],
  ['a5', '2026-10-10 17:20:09', 'agent-claude-7f2a', 'agent', 'mcp', 'CREATE TABLE', 'public.fulfilment_batch', '', 'APPLIED',
    'CREATE TABLE public.fulfilment_batch (id bigserial PRIMARY KEY, shipped_at timestamptz);'],
  ['a6', '2026-10-10 14:03:28', 'avery@acme.dev', 'human', 'console', 'GRANT', 'public.orders', '', 'APPLIED',
    'GRANT SELECT ON public.orders TO db_client;'],
  ['a7', '2026-10-10 11:47:55', 'katherine@nasa.gov', 'human', 'psql', 'ALTER TABLE', 'public.app_user', 'not-null', 'FLAGGED',
    'ALTER TABLE public.app_user ALTER COLUMN email SET NOT NULL;'],
  ['a8', '2026-10-09 19:12:40', 'agent-claude-3b81', 'agent', 'mcp', 'CREATE INDEX', 'public.ix_orders_placed_at', '', 'APPLIED',
    'CREATE INDEX ix_orders_placed_at ON public.orders (placed_at DESC);'],
  ['a9', '2026-10-09 16:55:02', 'margaret@mit.edu', 'human', 'console', 'DROP COLUMN', 'public.orders.legacy_ref', 'drop', 'BLOCKED',
    'ALTER TABLE public.orders DROP COLUMN legacy_ref;'],
  ['a10', '2026-10-09 09:31:17', 'ada@lovelace.dev', 'human', 'console', 'CREATE TABLE', 'public.shipment', '', 'APPLIED',
    'CREATE TABLE public.shipment (id bigserial PRIMARY KEY, order_id bigint REFERENCES public.orders);'],
  ['a11', '2026-10-08 20:08:44', 'grace@hopper.navy', 'human', 'psql', 'ALTER TABLE', 'public.payment', '', 'APPLIED',
    'ALTER TABLE public.payment ADD COLUMN settled_at timestamptz;'],
  ['a12', '2026-10-08 12:49:03', 'avery@acme.dev', 'human', 'console', 'CREATE INDEX', 'public.ix_payment_settled', '', 'APPLIED',
    'CREATE INDEX ix_payment_settled ON public.payment (settled_at);'],
]

// The realtime verdicts: one of each rung of the ladder, because the page's
// whole argument is that a refusal is a path and not a wall.
const realtimeTables = {
  branch: 'main',
  withheld: 9,
  tables: [
    { table: tbl('public', 'orders', { has_primary_key: true }), status: 'streaming' },
    { table: tbl('public', 'order_items', { has_primary_key: true }), status: 'streaming' },
    { table: tbl('public', 'customers', { has_primary_key: true }), status: 'ready' },
    {
      table: tbl('public', 'audit_trail', { client_can_select: false }),
      status: 'needs changes',
      fixes: [{ sql: 'GRANT SELECT ON public.audit_trail TO db_client;', why: 'a subscriber reads as db_client' }],
    },
    {
      table: tbl('public', 'event_log', { has_primary_key: false, unique_index: '' , updates: 41200, avg_row_bytes: 980 }),
      status: 'needs changes',
      fixes: [{
        sql: 'ALTER TABLE public.event_log REPLICA IDENTITY FULL;',
        why: 'nothing unique identifies a row',
        cost: 'about 38 MB of extra WAL a day at this table’s current rate (41k updates/day), and the same again in your backup archive',
      }],
      alternatives: ['a primary key, or any unique NOT NULL index, would cost the same as this table costs today'],
    },
    {
      table: tbl('public', 'card_tokens', { rls_enabled: true }),
      status: 'cannot stream',
      reason: 'public.card_tokens has row-level security, and decoded WAL carries no policy evaluation — every subscriber would receive every row',
    },
  ],
}

function tbl(schema, name, over = {}) {
  return {
    schema, name, kind: 'r',
    has_primary_key: true, rls_enabled: false,
    client_can_select: true, client_can_use_schema: true,
    is_system: false, is_extension_owned: false,
    inserts: 0, updates: 0, deletes: 0, stats_days: 7, avg_row_bytes: 0,
    ...over,
  }
}

const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.json': 'application/json',
}

/** The request body, for the two questions that arrive on one endpoint. */
async function body(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  return chunks.length ? Buffer.concat(chunks).toString() : ''
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')
  const p = url.pathname

  const json = v => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(v))
  }

  if (p in api) return json(api[p])
  if (p === '/api/branches/main/realtime/activity') {
    return json({
      activity: {
        branch: 'main', warm: true,
        warm_since: ago(3 * 3600e3), warm_for: '3h0m0s',
        subscribers: 2, events_delivered: 18402, peak_subscribers: 3, tables_streaming: 2,
        measured: {
          from: ago(24 * 3600e3), to: ago(0), over: '24h0m0s',
          transactions: 184203, rows_returned: 2910448, transactions_per_day: 184203, samples: 288,
        },
        slots: [{ slot: 'fox_rt_main_stream', active: true, status: 'reserved', held_bytes: 5 << 20, safe_bytes: 1019 << 20 }],
      },
      cost: 'Warm for 3h0m0s with 2 subscriber(s) attached, holding 5 MB of write-ahead log. A subscribed branch is never suspended — that is what makes the feed continuous.',
      max_subscribers: 8,
    })
  }
  if (p.endsWith('/realtime/tables') || p.startsWith('/realtime/v1/')) return json(realtimeTables)
  if (p.endsWith('/realtime/keys')) {
    return json({ keys: [{ id: 'k3f9a2', name: 'checkout-service', prefix: 'rtk_8Qd2Lm0p', created: Math.floor((NOW - 6 * 86400e3) / 1000), scope: 'main', kind: 'realtime' }] })
  }
  if (p.endsWith('/admins')) return json({ admins: ['avery@acme.dev'] })
  if (p.startsWith('/api/branches/') && p.endsWith('/ledger')) {
    return json({
      columns: ledgerColumns,
      rows: ledgerRows,
    })
  }
  if (p.startsWith('/api/branches/') && p.endsWith('/query')) {
    // The console asks two different questions through this one endpoint: the
    // schema panel lists information_schema.tables when it opens, and the
    // editor runs whatever was typed. Answering both with the same literals
    // put "main.1 284 402" in the table list — visibly wrong, and the kind of
    // thing that only shows up by looking at the picture.
    const sql = await body(req)
    if (/information_schema\.tables/i.test(sql)) {
      return json({
        columns: ['table_schema', 'table_name', 'table_type'],
        rows: [
          ['public', 'app_user', 'BASE TABLE'],
          ['public', 'customers', 'BASE TABLE'],
          ['public', 'invoice', 'BASE TABLE'],
          ['public', 'order_items', 'BASE TABLE'],
          ['public', 'orders', 'BASE TABLE'],
          ['public', 'payment', 'BASE TABLE'],
          ['public', 'shipment', 'BASE TABLE'],
          ['public', 'v_monthly_revenue', 'VIEW'],
        ],
      })
    }
    return json({
      columns: ['branch', 'rows', 'size', 'created'],
      rows: [
        ['main', '1 284 402', '2.41 GB', '2026-08-14'],
        ['qa-checkout', '1 284 402', '96.2 MB', '2026-10-09'],
        ['staging', '1 284 402', '184 MB', '2026-10-02'],
      ],
    })
  }
  if (p.startsWith('/api/')) return json({})

  // Static, then the app's own routing.
  const file = p === '/' ? 'index.html' : p.replace(/^\//, '')
  try {
    const body = await readFile(join(dist, file))
    res.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream' })
    return res.end(body)
  } catch {
    const body = await readFile(join(dist, 'index.html'))
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    return res.end(body)
  }
})

await new Promise(r => server.listen(0, '127.0.0.1', r))
const base = `http://127.0.0.1:${server.address().port}`

const { chromium } = await import(join(root, 'web', 'node_modules', '@playwright', 'test', 'index.mjs'))
const browser = await chromium.launch({ channel: 'chrome' })
const context = await browser.newContext({
  // 1512 logical pixels at a device pixel ratio of 2 — ~3024px files, which is
  // what reads correctly on GitHub.
  viewport: { width: 1512, height: 1000 },
  deviceScaleFactor: 2,
  colorScheme: 'dark',
})

// The theme before first paint. The app reads this on mount, and a shot taken
// while it switches catches the light theme behind a dark one.
await context.addInitScript(() => {
  try {
    localStorage.setItem('theme', 'dark')
    document.documentElement.dataset.theme = 'dark'
  } catch { /* private window */ }
})

await mkdir(out, { recursive: true })
const page = await context.newPage()

/** Settle: fonts loaded, no animation mid-flight. */
async function settle(ms = 700) {
  await page.evaluate(() => document.fonts?.ready)
  await page.waitForTimeout(ms)
}

async function shot(name, { path, ready, full = true, act }) {
  process.stdout.write(`  ${name}… `)
  await page.goto(base + path, { waitUntil: 'domcontentloaded' })
  if (ready) {
    try {
      await page.waitForSelector(ready, { timeout: 15000 })
    } catch (e) {
      console.log('\n  --- page said ---')
      console.log((await page.innerText('body')).slice(0, 600))
      console.log('  --- url:', page.url())
      throw e
    }
  }
  if (act) await act()
  await settle()
  await page.screenshot({ path: join(out, name), fullPage: full })
  console.log('ok')
}

console.log(`capturing from ${base}`)

await shot('landing.png', { path: '/', ready: 'text=/branches like code/i' })

await shot('dashboard.png', {
  path: '/dashboard',
  ready: 'text=/Live control plane/i',
})

await shot('ledger.png', {
  path: '/blackbox',
  ready: 'text=/every schema change/i',
})

await shot('console.png', {
  path: '/console',
  ready: 'textarea.editor',
  async act() {
    // Driven rather than merely loaded: the console is only worth a picture
    // with a query run in it.
    await page.locator('textarea.editor').fill(
      "SELECT branch, rows, size, created\n  FROM fox.branches\n ORDER BY created DESC;")
    await page.getByRole('button', { name: /^run/i }).click()
    // A value that exists only in the result. Waiting for a branch name
    // matched the hidden <option> in the branch picker, which is present
    // before the query has run at all.
    await page.waitForSelector('text=1 284 402', { timeout: 15000 })
  },
})

await shot('realtime.png', {
  path: '/realtime',
  ready: 'text=/Row-level changes as they are committed/i',
})

await browser.close()
server.close()
console.log(`\nwrote ${out}`)
