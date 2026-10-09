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
    createRealtimeKey: vi.fn(),
    revokeRealtimeKey: vi.fn(async () => ({ revoked: 'k1' })),
    streamChanges: vi.fn(() => () => {}),
  }
})

import Realtime from './Realtime'
import {
  createRealtimeKey, disableRealtimeTable, enableRealtimeTable,
  listRealtimeKeys, listRealtimeTables, prepareRealtimeTable, revokeRealtimeKey,
} from '../api'

const mockTables = vi.mocked(listRealtimeTables)
const mockEnable = vi.mocked(enableRealtimeTable)
const mockDisable = vi.mocked(disableRealtimeTable)
const mockPrepare = vi.mocked(prepareRealtimeTable)
const mockKeys = vi.mocked(listRealtimeKeys)
const mockCreateKey = vi.mocked(createRealtimeKey)
const mockRevokeKey = vi.mocked(revokeRealtimeKey)

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
  vi.clearAllMocks()
  mockTables.mockResolvedValue({
    branch: 'main', withheld: 3,
    tables: [READY, STREAMING, FREE_FIX, COSTLY_FIX, IMPOSSIBLE],
  })
  mockKeys.mockResolvedValue({ keys: [] })
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
