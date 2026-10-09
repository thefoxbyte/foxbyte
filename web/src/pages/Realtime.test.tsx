// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Realtime page's decisions, asserted where they are made.
//
// Three of these matter more than the rest:
//
//   * a costly fix is never applied without being confirmed, and the dialog
//     carries the cost the engine measured — this is the one button on the page
//     with a permanent bill behind it;
//   * a connection string is shown once and said to be, because the secret is
//     hashed on the way in and there is no second chance to copy it;
//   * changing branch clears the connection string on screen — it is a secret,
//     and after the change it is also the wrong one.
import { render, screen, waitFor, cleanup, fireEvent, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { RealtimeVerdict, Status } from '../api'
import { ConfirmProvider } from '../confirm'

const table = (over: Partial<RealtimeVerdict['table']> = {}): RealtimeVerdict['table'] => ({
  schema: 'public', name: 't', kind: 'r',
  has_primary_key: true, rls_enabled: false,
  client_can_select: true, client_can_use_schema: true,
  is_system: false, is_extension_owned: false,
  inserts: 0, updates: 0, deletes: 0, stats_days: 1, avg_row_bytes: 0,
  ...over,
})

const READY: RealtimeVerdict = { table: table({ name: 'orders' }), status: 'ready' }
const STREAMING: RealtimeVerdict = { table: table({ name: 'events' }), status: 'streaming' }
const FREE_FIX: RealtimeVerdict = {
  table: table({ name: 'needs_grant', client_can_select: false }),
  status: 'needs changes',
  fixes: [{ sql: 'GRANT SELECT ON public.needs_grant TO db_client;', why: 'a subscriber reads as db_client' }],
}
const COSTLY_FIX: RealtimeVerdict = {
  table: table({ name: 'keyless', has_primary_key: false }),
  status: 'needs changes',
  fixes: [{
    sql: 'ALTER TABLE public.keyless REPLICA IDENTITY FULL;',
    why: 'nothing unique identifies a row',
    // The shape FullCost actually produces, so this fixture documents the
    // real thing rather than a phrase that exists only here.
    cost: 'about 39 MB of extra WAL a day at this table\'s current rate (200 updates/day), and the same again in your backup archive',
  }],
  alternatives: ['stream inserts only'],
}
const IMPOSSIBLE: RealtimeVerdict = {
  table: table({ name: 'secrets', rls_enabled: true }),
  status: 'cannot stream',
  reason: 'public.secrets has row-level security, and decoded WAL carries no policy evaluation',
}

const STATUS: Status = {
  mainReady: true, branches: 1, agents: 0, edition: 'enterprise', features: ['realtime'],
  ha: { enabled: false, standby: '', streaming: false, primary: 'main' },
  storage: { used: '1G', avail: '9G' },
  servers: { gateway: true, api: true },
}

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getStatus: vi.fn(async () => STATUS),
    getBranches: vi.fn(async () => [
      { name: 'main', primary: true, agent: false, state: 'running', used: '1G', refer: '1G', connections: 0, port: '5432' },
      { name: 'other', primary: false, agent: false, state: 'running', used: '1G', refer: '1G', connections: 0, port: '5433' },
    ]),
    listRealtimeTables: vi.fn(),
    enableRealtimeTable: vi.fn(),
    disableRealtimeTable: vi.fn(),
    prepareRealtimeTable: vi.fn(),
    listRealtimeKeys: vi.fn(async () => ({ keys: [] })),
    getRealtimeActivity: vi.fn(),
    createRealtimeKey: vi.fn(),
    revokeRealtimeKey: vi.fn(async () => ({ revoked: 'k1' })),
    streamChanges: vi.fn(() => () => {}),
  }
})

import Realtime from './Realtime'
import {
  createRealtimeKey, disableRealtimeTable, enableRealtimeTable, getRealtimeActivity,
  getStatus, listRealtimeKeys, listRealtimeTables, prepareRealtimeTable, revokeRealtimeKey,
} from '../api'
import type { RealtimeActivity, RealtimeEvent } from '../api'

const mockTables = vi.mocked(listRealtimeTables)
const mockEnable = vi.mocked(enableRealtimeTable)
const mockDisable = vi.mocked(disableRealtimeTable)
const mockPrepare = vi.mocked(prepareRealtimeTable)
const mockKeys = vi.mocked(listRealtimeKeys)
const mockCreateKey = vi.mocked(createRealtimeKey)
const mockRevokeKey = vi.mocked(revokeRealtimeKey)
const mockActivity = vi.mocked(getRealtimeActivity)

const ACTIVITY: RealtimeActivity = {
  branch: 'main', warm: true,
  warm_since: '2026-10-09T12:00:00Z', warm_for: '3h0m0s',
  subscribers: 2, events_delivered: 1420, peak_subscribers: 3,
  tables_streaming: 4,
  measured: {
    from: '2026-10-09T12:00:00Z', to: '2026-10-09T15:00:00Z', over: '3h0m0s',
    transactions: 7200, rows_returned: 91000, transactions_per_day: 57600, samples: 36,
  },
  slots: [{ slot: 'fox_rt_main_stream', active: true, status: 'reserved', held_bytes: 5 << 20, safe_bytes: 1019 << 20 }],
}

const show = () => render(<ConfirmProvider><Realtime /></ConfirmProvider>)

// The dialog, as its own scope. The page deliberately says the same things in
// two places — a row shows a fix's cost, and the dialog repeats it — so an
// unscoped query matches twice and proves neither.
const dialog = async () => within(await screen.findByRole('dialog'))

const rowFor = async (name: string) => {
  const cell = await screen.findByText(`public.${name}`)
  return cell.closest('tr')!
}

beforeEach(() => {
  // clearAllMocks resets calls but keeps implementations, so a test that points
  // getStatus at a Standard engine leaks that into every test after it — which
  // is how six of these failed in file order while each passed alone. Every
  // default a test might override is re-asserted here rather than relying on
  // the module factory, which runs once.
  vi.clearAllMocks()
  vi.mocked(getStatus).mockResolvedValue(STATUS)
  mockTables.mockResolvedValue({
    branch: 'main', withheld: 3,
    tables: [READY, STREAMING, FREE_FIX, COSTLY_FIX, IMPOSSIBLE],
  })
  mockKeys.mockResolvedValue({ keys: [] })
  mockActivity.mockResolvedValue({ activity: ACTIVITY, cost: 'Warm for 3h0m0s with 2 subscriber(s) attached, holding 5 MB of write-ahead log.', max_subscribers: 8 })
})
afterEach(cleanup)

it('offers the action each state actually has', async () => {
  show()
  // Ready: start it. Streaming: stop it. Needs changes: prepare it.
  expect(within(await rowFor('orders')).getByRole('button', { name: 'Start streaming' })).toBeTruthy()
  expect(within(await rowFor('events')).getByRole('button', { name: 'Stop' })).toBeTruthy()
  expect(within(await rowFor('needs_grant')).getByRole('button', { name: 'Prepare' })).toBeTruthy()
  // Cannot stream: no button at all, and the reason instead. Offering an action
  // that will be refused is worse than offering none.
  const dead = within(await rowFor('secrets'))
  expect(dead.queryAllByRole('button')).toHaveLength(0)
  expect(dead.getByText(/row-level security/)).toBeTruthy()
})

it('says how many tables it withheld, rather than silently hiding them', async () => {
  show()
  expect(await screen.findByText(/3 tables not shown/)).toBeTruthy()
  expect(screen.getByText(/belong to FoxByte, to\s+Postgres or to an extension/)).toBeTruthy()
})

it('starts streaming a ready table and redraws it from the answer', async () => {
  mockEnable.mockResolvedValue({ table: { ...READY, status: 'streaming' } })
  show()
  fireEvent.click(within(await rowFor('orders')).getByRole('button', { name: 'Start streaming' }))
  expect(mockEnable).toHaveBeenCalledWith('main', { schema: 'public', table: 'orders' })
  // The row reflects the verdict the server returned, not a guess: afterwards
  // it offers Stop.
  await waitFor(async () =>
    expect(within(await rowFor('orders')).getByRole('button', { name: 'Stop' })).toBeTruthy())
})

it('stops a streaming table', async () => {
  mockDisable.mockResolvedValue({ table: { ...STREAMING, status: 'ready' } })
  show()
  fireEvent.click(within(await rowFor('events')).getByRole('button', { name: 'Stop' }))
  expect(mockDisable).toHaveBeenCalledWith('main', { schema: 'public', table: 'events' })
})

it('applies a free fix without a dialog', async () => {
  mockPrepare.mockResolvedValue({ applied: true, statements: FREE_FIX.fixes!, table: { ...FREE_FIX, status: 'ready' } })
  show()
  fireEvent.click(within(await rowFor('needs_grant')).getByRole('button', { name: 'Prepare' }))
  // A grant is the whole decision; a confirmation step would be ceremony.
  expect(mockPrepare).toHaveBeenCalledWith('main', { schema: 'public', table: 'needs_grant', apply: true })
})

it('will not apply a costly fix without confirming, and states the cost', async () => {
  show()
  const row = within(await rowFor('keyless'))
  // Labelled differently, so the button itself says a question is coming.
  fireEvent.click(row.getByRole('button', { name: 'Prepare…' }))

  // The dialog has to carry the measured cost, not a general warning: this is
  // the number that makes the decision different from the free ones.
  const d = await dialog()
  expect(d.getByText(/39 MB of extra WAL a day/)).toBeTruthy()
  expect(d.getByText(/REPLICA IDENTITY FULL/)).toBeTruthy()
  // And the way to avoid paying it.
  expect(d.getByText(/stream inserts only/)).toBeTruthy()

  // Nothing has run yet.
  expect(mockPrepare).not.toHaveBeenCalled()
})

it('a cancelled costly fix changes nothing', async () => {
  show()
  fireEvent.click(within(await rowFor('keyless')).getByRole('button', { name: 'Prepare…' }))
  fireEvent.click((await dialog()).getByRole('button', { name: /cancel/i }))
  expect(mockPrepare).not.toHaveBeenCalled()
})

it('a confirmed costly fix runs', async () => {
  mockPrepare.mockResolvedValue({ applied: true, statements: COSTLY_FIX.fixes!, table: { ...COSTLY_FIX, status: 'ready' } })
  show()
  fireEvent.click(within(await rowFor('keyless')).getByRole('button', { name: 'Prepare…' }))
  fireEvent.click((await dialog()).getByRole('button', { name: 'Run it anyway' }))
  await waitFor(() =>
    expect(mockPrepare).toHaveBeenCalledWith('main', { schema: 'public', table: 'keyless', apply: true }))
})

it('an install without the feed set up says the one command that fixes it', async () => {
  const { ApiError } = await vi.importActual<typeof import('../api')>('../api')
  mockTables.mockRejectedValue(new ApiError(409, 'the change feed is not set up on this install — run `fox realtime setup`'))
  show()
  expect(await screen.findByText(/not set up on this install/)).toBeTruthy()
  // And what it will do, because it restarts main — somebody has to know that
  // before they run it, not after.
  expect(screen.getByText(/restarts/)).toBeTruthy()
  expect(screen.getByText(/drops connections/)).toBeTruthy()
})

it('shows a new connection string once, and says so', async () => {
  mockCreateKey.mockResolvedValue({
    key: { id: 'k1', name: 'checkout', prefix: 'rtk_aaaabbbb', created: 1_700_000_000, scope: 'main', kind: 'realtime' },
    url: 'fox-realtime://rtk_aaaabbbbccccdddd@127.0.0.1:8080/main',
  })
  show()
  fireEvent.change(screen.getByLabelText('Key name'), { target: { value: 'checkout' } })
  fireEvent.click(screen.getByRole('button', { name: 'Create key' }))

  const dsn = await screen.findByTestId('realtime-dsn')
  expect(dsn.textContent).toBe('fox-realtime://rtk_aaaabbbbccccdddd@127.0.0.1:8080/main')
  expect(screen.getByText(/shown once/)).toBeTruthy()
  expect(mockCreateKey).toHaveBeenCalledWith('main', 'checkout')
})

it('forgets the connection string when the branch changes', async () => {
  mockCreateKey.mockResolvedValue({
    key: { id: 'k1', name: 'app', prefix: 'rtk_aaaabbbb', created: 1, scope: 'main', kind: 'realtime' },
    url: 'fox-realtime://rtk_aaaabbbbccccdddd@127.0.0.1:8080/main',
  })
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Create key' }))
  await screen.findByTestId('realtime-dsn')

  // A secret belonging to another branch must not stay on screen.
  fireEvent.change(await screen.findByLabelText('Branch'), { target: { value: 'other' } })
  await waitFor(() => expect(screen.queryByTestId('realtime-dsn')).toBeNull())
  // And the tables are re-read for the branch now selected.
  expect(mockTables).toHaveBeenCalledWith('other')
})

it('revoking a key asks first, and says what stops', async () => {
  mockKeys.mockResolvedValue({
    keys: [{ id: 'k1', name: 'checkout', prefix: 'rtk_aaaabbbb', created: 1_700_000_000, scope: 'main', kind: 'realtime' }],
  })
  show()
  fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
  const d = await dialog()
  expect(d.getByText(/stops at its next connection/)).toBeTruthy()
  expect(mockRevokeKey).not.toHaveBeenCalled()
  fireEvent.click(d.getByRole('button', { name: 'Revoke' }))
  await waitFor(() => expect(mockRevokeKey).toHaveBeenCalledWith('main', 'k1'))
})

it('a standard install explains the lock instead of showing dead controls', async () => {
  const { getStatus } = await import('../api')
  vi.mocked(getStatus).mockResolvedValue({ ...STATUS, edition: 'standard', features: [] })
  show()
  // Said twice on purpose: once at the top for the page, once in the Tables
  // panel in place of the controls it would otherwise show.
  expect((await screen.findAllByText(/part of Enterprise/)).length).toBeGreaterThanOrEqual(2)
  // Locked, not hidden: the Watch button is still there, disabled and labelled.
  const watch = await screen.findByRole('button', { name: 'Watch (Enterprise)' })
  expect(watch).toHaveProperty('disabled', true)
  // The panel does ask before /api/status answers — useFeatures treats unknown
  // as available so a newer console cannot disable an older engine — so what
  // matters is that the refusal is not shown as a fault next to the sentence
  // that already explains it.
  const { ApiError } = await vi.importActual<typeof import('../api')>('../api')
  mockTables.mockRejectedValue(new ApiError(403, 'realtime needs an Enterprise licence'))
  cleanup()
  show()
  await screen.findByRole('button', { name: 'Watch (Enterprise)' })
  expect(screen.queryByText(/needs an Enterprise licence/)).toBeNull()
})

// --- what staying warm has cost -------------------------------------------

it('says what being warm is costing, and for how long', async () => {
  show()
  expect((await screen.findByTestId('realtime-cost')).textContent)
    .toMatch(/Warm for 3h0m0s with 2 subscriber\(s\) attached/)
  // The cap alongside the count, so "2" reads as "2 of 8" rather than as a
  // number with no scale.
  expect((await screen.findByTestId('rt-subscribers')).textContent).toMatch(/^2 of 8 subscribers/)
  // The high-water mark, which is what tells somebody a client is reconnecting
  // more than it should.
  expect(screen.getByTestId('rt-subscribers').textContent).toMatch(/3 at most so far/)
  expect(screen.getByTestId('rt-tables').textContent).toMatch(/4 tables streaming/)
})

it('reports work as transactions, over a stated period', async () => {
  show()
  // Transactions, not queries. Without pg_stat_statements loaded that is what
  // Postgres counts, and this is a number somebody may bill from.
  const line = await screen.findByTestId('rt-measured')
  expect(line.textContent).toMatch(/Over the last 3h0m0s/)
  expect(line.textContent).toMatch(/7,200/)
  expect(line.textContent).toMatch(/transactions/)
  expect(line.textContent).toMatch(/57,600\/day/)
  expect(line.textContent).toMatch(/91,000 rows returned/)
  expect(line.textContent).not.toMatch(/quer/i)
  // And how many readings are behind it, so the figure can be judged.
  expect(line.textContent).toMatch(/36 readings/)
})

it('says so plainly when there are not yet two readings', async () => {
  mockActivity.mockResolvedValue({
    activity: { ...ACTIVITY, measured: undefined },
    cost: 'Warm for 2m0s.', max_subscribers: 8,
  })
  show()
  expect((await screen.findByTestId('rt-measured')).textContent).toMatch(/Not enough readings yet/)
  // A rate is not invented from one reading.
  expect(screen.getByTestId('rt-measured').textContent).not.toMatch(/\/day/)
})

it('shows what each bookmark holds and how much room is left', async () => {
  show()
  expect(await screen.findByText('fox_rt_main_stream')).toBeTruthy()
  expect(screen.getByText('5 MB')).toBeTruthy()
  // The number that turns "a subscriber went away" into something actionable
  // before the disk decides for you.
  expect(screen.getByText('1019 MB')).toBeTruthy()
})

it('passes on the caveats rather than hiding them behind a number', async () => {
  mockActivity.mockResolvedValue({
    activity: {
      ...ACTIVITY,
      notes: ['the branch was suspended and resumed during this period, so the rate above is averaged over time it was not running'],
    },
    cost: 'Warm for 3h0m0s.', max_subscribers: 8,
  })
  show()
  expect(await screen.findByText(/suspended and resumed during this period/)).toBeTruthy()
})

it('a suspended branch is described as the cheap state, not as a fault', async () => {
  mockActivity.mockResolvedValue({
    activity: { ...ACTIVITY, warm: false, warm_since: undefined, warm_for: undefined, subscribers: 0, slots: [] },
    cost: 'Not running. A suspended branch costs its disk and nothing else.', max_subscribers: 8,
  })
  show()
  expect((await screen.findByTestId('realtime-cost')).textContent).toMatch(/Not running/)
  // Nothing about subscribers or events, which would be zeroes dressed as data.
  expect(screen.queryByTestId('rt-subscribers')).toBeNull()
  expect(screen.queryByTestId('rt-events')).toBeNull()
})

// The panel disappears rather than repeating a refusal the page already
// explains once below it.
it('stays silent when the engine cannot answer', async () => {
  const { ApiError } = await vi.importActual<typeof import('../api')>('../api')
  mockActivity.mockRejectedValue(new ApiError(409, 'the change feed is not set up on this install'))
  show()
  await screen.findByRole('heading', { name: 'Tables' })
  expect(screen.queryByTestId('realtime-cost')).toBeNull()
  expect(screen.queryByRole('heading', { name: 'What this is costing' })).toBeNull()
})

// --- transaction framing ---------------------------------------------------

it('asks for transaction frames, so boundaries are visible', async () => {
  const { streamChanges } = await import('../api')
  show()
  fireEvent.click(await screen.findByRole('button', { name: 'Watch' }))
  // Without this the feed cannot show that two rows moved together, which is
  // the only place a person can see framing working at all.
  expect(vi.mocked(streamChanges).mock.calls[0]?.[2]).toMatchObject({ transactions: true })
})

it('renders a transaction as a boundary around its changes', async () => {
  const { streamChanges } = await import('../api')
  let emit: ((e: RealtimeEvent) => void) | undefined
  vi.mocked(streamChanges).mockImplementation((_n, onEvent) => { emit = onEvent; return () => {} })

  show()
  fireEvent.click(await screen.findByRole('button', { name: 'Watch' }))

  // The sequence a framed subscriber receives for one commit that moved two
  // rows — the case framing exists for.
  const change = (id: string): RealtimeEvent => ({
    type: 'change', table: 'public.accounts', action: 'update',
    commit_lsn: '0/ABCDEF', lsn: '0/AB0001', xid: 4242,
    identity: { id }, new: { id, balance: '10' },
  })
  await waitFor(() => expect(emit).toBeDefined())
  emit!({ type: 'begin', xid: 4242, commit_lsn: '0/ABCDEF', at: '2026-10-09T12:00:00Z' })
  emit!(change('1'))
  emit!(change('2'))
  emit!({ type: 'commit', xid: 4242, commit_lsn: '0/ABCDEF', changes: 2, at: '2026-10-09T12:00:00Z' })

  const commit = await screen.findByTestId('tx-commit')
  expect(commit.textContent).toMatch(/transaction 4242 committed 2 changes/)
  // The boundary a subscriber resumes from, said where it is useful.
  expect(commit.textContent).toMatch(/resume from/)
  expect(commit.textContent).toMatch(/0\/ABCDEF/)
  expect((await screen.findByTestId('tx-begin')).textContent).toMatch(/transaction 4242 began/)

  // And the changes themselves are still rows.
  expect(screen.getAllByText('public.accounts')).toHaveLength(2)
})

it('a commit of one change is not pluralised', async () => {
  const { streamChanges } = await import('../api')
  let emit: ((e: RealtimeEvent) => void) | undefined
  vi.mocked(streamChanges).mockImplementation((_n, onEvent) => { emit = onEvent; return () => {} })
  show()
  fireEvent.click(await screen.findByRole('button', { name: 'Watch' }))
  await waitFor(() => expect(emit).toBeDefined())
  emit!({ type: 'commit', xid: 7, commit_lsn: '0/1', changes: 1 })
  expect((await screen.findByTestId('tx-commit')).textContent).toMatch(/1 change · /)
})

// --- the shape of what the engine answers with ------------------------------

// The crash this page actually suffered, as a test.
//
// On a Standard build the paid routes are not compiled in, so the request fell
// through to the console's own catch-all and came back as index.html with
// status 200. req() turned that into `{}`, so `r.tables` was undefined and the
// page died on `rows.length` — a blank "Unexpected Application Error" naming a
// property rather than the missing route.
//
// req() now refuses a non-JSON 200, and these assert the second line of
// defence: whatever arrives, the page renders.
it('survives a response with no tables in it', async () => {
  mockTables.mockResolvedValue({} as never)
  show()
  // The page renders, and says what it found rather than dying.
  expect(await screen.findByRole('heading', { name: 'Tables' })).toBeTruthy()
  expect(await screen.findByText(/No application tables/)).toBeTruthy()
})

it('survives tables being something other than an array', async () => {
  mockTables.mockResolvedValue({ branch: 'main', tables: 'nope', withheld: 'lots' } as never)
  show()
  expect(await screen.findByRole('heading', { name: 'Tables' })).toBeTruthy()
  // And a withheld count that is not a number does not reach the sentence.
  expect(screen.queryByText(/not shown/)).toBeNull()
})

it('survives a keys response with no keys in it', async () => {
  mockKeys.mockResolvedValue({} as never)
  show()
  expect(await screen.findByRole('heading', { name: 'Connecting an application' })).toBeTruthy()
})

it('survives an activity response with no activity in it', async () => {
  mockActivity.mockResolvedValue({} as never)
  show()
  // The panel hides rather than rendering half a report.
  await screen.findByRole('heading', { name: 'Tables' })
  expect(screen.queryByTestId('realtime-cost')).toBeNull()
})
