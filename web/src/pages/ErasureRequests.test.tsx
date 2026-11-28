// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    listErasures: vi.fn(),
    getErasure: vi.fn(),
    newErasure: vi.fn(),
    replanErasure: vi.fn(),
    applyErasure: vi.fn(),
    rewriteErasure: vi.fn(),
    withdrawErasure: vi.fn(),
    remakeErasureBranch: vi.fn(),
    deleteErasureBranch: vi.fn(),
    getErasureOutcomes: vi.fn(),
    checkErasure: vi.fn(),
    getStatus: vi.fn(),
  }
})

import {
  ApiError, applyErasure, checkErasure, getErasure, getErasureOutcomes, getStatus, listErasures, newErasure, remakeErasureBranch,
  type ErasureOutcomes, type ErasureRequest, type ErasureTable, type Status,
} from '../api'
import { ConfirmProvider } from '../confirm'
import ErasureRequests, { readValues } from './ErasureRequests'

const status = (features: string[]) => ({ edition: 'enterprise', features }) as unknown as Status

const table = (o: Partial<ErasureTable>): ErasureTable => ({
  schema: 'public', table: 'customers', why: 'holds a value in email', depth: 0, rows: 1, action: 'clear',
  columns: [{ column: 'email', categories: ['email'], to: 'NULL' }], entry: null, default: true,
  exceptions: [], problems: [], notes: [], keyed: true, size: 8192, rewrite: 'apply', ...o,
})

const request = (o: Partial<ErasureRequest> = {}): ErasureRequest => ({
  id: 7, branch: 'main', state: 'planned', note: 'DPO-42', fingerprint: 'fp',
  createdBy: 'dpo@example.com', created: '2026-11-25T09:00:00Z', plannedBy: 'dpo@example.com', planned: '2026-11-25T09:00:00Z',
  refs: [{ categories: ['email'], last4: 'e.in' }], events: {},
  plan: {
    branch: 'main', made: '2026-11-25T09:00:00Z', by: 'dpo@example.com', refs: [{ categories: ['email'], last4: 'e.in' }],
    tables: [
      table({}),
      table({ table: 'orders', action: 'keep', why: 'refers to public.customers (orders_customer_id_fkey)', depth: 1, rows: 2, columns: [], rewrite: '' }),
      table({ table: 'kyc', action: 'kept', columns: [], exceptions: [{ column: '', citation: 'PML Rules, Rule 10', keep: { count: 5, unit: 'years', from: 'account_closed', reason: 'law', citation: 'PML Rules, Rule 10' }, text: 'the table is kept under PML Rules, Rule 10' }], rewrite: '' }),
    ],
    matched: 1, rows: 1, blocked: false, searched: 4,
    limits: ['This request erases main. Every other branch … the next steps of F4.'],
    review: 'not yet been reviewed',
  },
  ...o,
})

const outcomes = (o: Partial<ErasureOutcomes> = {}): ErasureOutcomes => ({
  request: 7, checked: '2026-11-27T10:00:00Z', never: [], unknown: [], notes: [],
  outcomes: [
    { key: 'live', name: 'Removed from live queries', state: 'met', date: '2026-11-25T10:00:00Z', evidence: ['main: 1 row(s) changed'] },
    { key: 'backups', name: 'Backup and WAL expiry', state: 'pending', date: '2026-12-02T10:00:00Z', estimated: true,
      why: 'held in backups and WAL until the prune after the 7-th backup', evidence: ['Backups every 24h0m0s, 7 kept'] },
    { key: 'outside', name: 'Outside FoxByte', state: 'outside', evidence: ['2 place(s) listed'] },
  ],
  clearsOn: '2026-12-02T10:00:00Z',
  outside: [
    { kind: 'pipeline', what: 'pipeline "crm" loads main: its source holds the person and will bring them back on its next run', branch: 'main', warn: true },
    { kind: 'disk', what: 'freed disk blocks, which FoxByte cannot read or wipe' },
  ],
  ...o,
})

function page() { render(<MemoryRouter><ConfirmProvider><ErasureRequests /></ConfirmProvider></MemoryRouter>) }

describe('Erasure requests', () => {
  beforeEach(() => {
    vi.mocked(getStatus).mockResolvedValue(status(['dpdp']))
    vi.mocked(getErasureOutcomes).mockResolvedValue(outcomes())
    vi.mocked(listErasures).mockReset().mockResolvedValue([request()])
    vi.mocked(getErasure).mockReset().mockResolvedValue(request())
    vi.mocked(newErasure).mockReset()
    vi.mocked(applyErasure).mockReset()
  })
  afterEach(cleanup)

  it('reads values one a line, with or without a category', () => {
    expect(readValues('email:Asha@Example.in\n\n 98765 43210 \nmobile: +91 98765 43210')).toEqual([
      { category: 'email', value: 'Asha@Example.in' },
      { category: '', value: '98765 43210' },
      { category: 'mobile', value: '+91 98765 43210' },
    ])
  })

  it('lists the requests by their last four characters, and says it has not been reviewed', async () => {
    page()
    const list = await screen.findByRole('table', { name: 'Erasure requests' })
    expect(list.textContent).toContain('email ending e.in')
    expect(screen.getByTestId('erasure-review').textContent).toContain('not yet been reviewed by a privacy lawyer')
  })

  it('makes a request from the values and shows its plan, table by table', async () => {
    vi.mocked(newErasure).mockResolvedValue(request())
    page()
    fireEvent.click(await screen.findByRole('button', { name: 'New request…' }))
    const form = screen.getByTestId('erasure-new')
    fireEvent.change(within(form).getByLabelText('Values'), { target: { value: 'email:asha@example.in' } })
    fireEvent.change(within(form).getByLabelText('Event dates'), { target: { value: 'account-closed=2025-03-31' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Plan the erasure' }))
    await waitFor(() => expect(newErasure).toHaveBeenCalledWith([{ category: 'email', value: 'asha@example.in' }], '', { account_closed: '2025-03-31' }))
    const detail = await screen.findByTestId('erasure-detail')
    expect(within(detail).getByTestId('erasure-table-public.customers-clear').textContent).toContain('email (email) → NULL')
    expect(within(detail).getByTestId('erasure-table-public.orders-keep').textContent).toContain('Left as it is, 2 row(s)')
    expect(within(detail).getByTestId('erasure-table-public.kyc-kept').textContent).toContain('PML Rules, Rule 10')
    expect(screen.getByRole('status').textContent).toContain('Nothing has been changed')
  })

  it('applies only with the values again and the request number typed', async () => {
    vi.mocked(applyErasure).mockResolvedValue(request({
      state: 'applied',
      result: { applied: '2026-11-25T10:00:00Z', by: 'dpo@example.com', tables: [], rows: 1, verified: true,
        vacuumed: '2026-11-25T10:00:01Z', rewrites: [{ schema: 'public', table: 'customers', size: 8192, state: 'done', at: '2026-11-25T10:00:02Z' }],
        statistics: '2026-11-25T10:00:03Z', notes: [] },
    }))
    page()
    const list = await screen.findByRole('table', { name: 'Erasure requests' })
    fireEvent.click(within(list).getByRole('button', { name: 'Open' }))
    const detail = await screen.findByTestId('erasure-detail')
    fireEvent.click(within(detail).getByRole('button', { name: 'Apply to main…' }))
    const ask = screen.getByTestId('erasure-values')
    const apply = within(ask).getByRole('button', { name: 'Apply' }) as HTMLButtonElement
    fireEvent.change(within(ask).getByLabelText('Values'), { target: { value: 'asha@example.in' } })
    expect(apply.disabled).toBe(true) // the number is not typed yet
    fireEvent.change(within(ask).getByLabelText('Request number'), { target: { value: '7' } })
    expect(apply.disabled).toBe(false)
    fireEvent.click(apply)
    await waitFor(() => expect(applyErasure).toHaveBeenCalledWith(7, [{ category: '', value: 'asha@example.in' }]))
    const result = await screen.findByTestId('erasure-result')
    expect(result.textContent).toContain('a search afterwards found none')
    expect(result.textContent).toContain('removed from live queries')
  })

  it('applies nothing when the plan has changed, and shows the new one', async () => {
    vi.mocked(applyErasure).mockRejectedValue(new ApiError(409, 'nothing was applied: the plan has changed since it was shown; review the new plan, then apply again'))
    page()
    const list = await screen.findByRole('table', { name: 'Erasure requests' })
    fireEvent.click(within(list).getByRole('button', { name: 'Open' }))
    const detail = await screen.findByTestId('erasure-detail')
    fireEvent.click(within(detail).getByRole('button', { name: 'Apply to main…' }))
    const ask = screen.getByTestId('erasure-values')
    fireEvent.change(within(ask).getByLabelText('Values'), { target: { value: 'asha@example.in' } })
    fireEvent.change(within(ask).getByLabelText('Request number'), { target: { value: '7' } })
    fireEvent.click(within(ask).getByRole('button', { name: 'Apply' }))
    expect(await screen.findByText(/Nothing was applied: the plan has changed since it was shown/)).toBeTruthy()
    await waitFor(() => expect(getErasure).toHaveBeenCalledTimes(2)) // opened, then read again
  })

  it('does not offer to apply a plan with a problem', async () => {
    const blocked = request()
    blocked.plan.blocked = true
    blocked.plan.tables[0].problems = ['phone is NOT NULL with no default, so it cannot be cleared']
    vi.mocked(getErasure).mockResolvedValue(blocked)
    page()
    const list = await screen.findByRole('table', { name: 'Erasure requests' })
    fireEvent.click(within(list).getByRole('button', { name: 'Open' }))
    const detail = await screen.findByTestId('erasure-detail')
    expect((within(detail).getByRole('button', { name: 'Apply to main…' }) as HTMLButtonElement).disabled).toBe(true)
    expect(detail.textContent).toContain('cannot be applied until the problems below are dealt with')
  })

  it('without the licence, requests can be read but not made', async () => {
    vi.mocked(getStatus).mockResolvedValue({ edition: 'standard', features: [] } as unknown as Status)
    page()
    await screen.findByRole('table', { name: 'Erasure requests' })
    await waitFor(() => expect((screen.getByRole('button', { name: 'New request…' }) as HTMLButtonElement).disabled).toBe(true))
  })

  it('says what it finds and removes beside the branches: history, the audit log, requests, the vault', async () => {
    const copies = {
      history: 3, saved: [{ id: 4, owner: 'alice@example.com', name: 'cp find' }], forensic: 2, rawAudit: 1,
      rawUntil: '2026-11-27T09:00:00Z', requests: 1, openRequests: [12], vault: 1, notes: [],
    }
    const planned = request({ plan: { ...request().plan, copies } })
    vi.mocked(getErasure).mockResolvedValue(planned)
    page()
    const list = await screen.findByRole('table', { name: 'Erasure requests' })
    fireEvent.click(within(list).getByRole('button', { name: 'Open' }))
    const plan = await screen.findByTestId('erasure-copies-plan')
    expect(plan.textContent).toContain('3 query history entr(ies) to delete')
    expect(plan.textContent).toContain('2 audit')
    expect(plan.textContent).toContain('1 vault record(s)')
    expect(plan.textContent).toContain('“cp find” (alice@example.com)')
    expect(plan.textContent).toContain('#12')
    expect(plan.textContent).toContain('1 raw audit file(s) not yet collected')

    cleanup()
    vi.mocked(getErasure).mockResolvedValue(request({
      state: 'applied',
      result: {
        applied: '2026-11-25T10:00:00Z', by: 'dpo@example.com', tables: [], rows: 1, verified: true, rewrites: [], notes: [], aadhaarPlaces: 1,
        copies: { history: 3, forensic: 2, requests: 1, vault: 0, vaultKept: 1, logPlaces: 2, notes: ['The vault\'s record of the Aadhaar number is kept: a law keeps the number.'] },
      },
    }))
    page()
    fireEvent.click(within(await screen.findByRole('table', { name: 'Erasure requests' })).getByRole('button', { name: 'Open' }))
    const done = await screen.findByTestId('erasure-copies-result')
    expect(done.textContent).toContain('3 query history entr(ies) deleted')
    expect(done.textContent).toContain('1 kept by law')
    expect(done.textContent).toContain('2 Aadhaar log report place(s) removed')
    expect(done.textContent).toContain('1 Aadhaar exposure report place(s)')
    expect(done.textContent).toContain('a law keeps the number')
  })

  it('shows the outcomes and the one date, searches again, and offers the evidence', async () => {
    vi.mocked(getErasure).mockResolvedValue(request({
      state: 'applied',
      result: { applied: '2026-11-25T10:00:00Z', by: 'dpo@example.com', tables: [], rows: 1, verified: true, rewrites: [], notes: [] },
    }))
    vi.mocked(checkErasure).mockResolvedValue(outcomes({
      clearsOn: undefined, never: ['Removed from live queries: searched again by the request\'s row keys, 1 row(s) of public.customers on main hold the person again'],
      outcomes: [{ key: 'live', name: 'Removed from live queries', state: 'lost', why: '1 row(s) of public.customers on main hold the person again', evidence: [] }],
      recheck: { checked: '2026-11-27T11:00:00Z', branches: [{ branch: 'main', tables: [{ schema: 'public', table: 'customers', found: 1 }] }] },
    }))
    page()
    fireEvent.click(within(await screen.findByRole('table', { name: 'Erasure requests' })).getByRole('button', { name: 'Open' }))
    const panel = await screen.findByTestId('erasure-outcomes')
    expect(within(panel).getByTestId('erasure-clears-on').textContent).toContain(new Date('2026-12-02T10:00:00Z').toLocaleDateString())
    expect(within(panel).getByTestId('erasure-outcome-backups').textContent).toContain('Pending')
    expect(within(panel).getByTestId('erasure-outcome-backups').textContent).toContain('about ')
    expect(within(panel).queryByTestId('erasure-outcome-outside')).toBeNull()
    expect(within(panel).getByTestId('erasure-outside-pipeline').className).toContain('pii-warning')
    expect(within(panel).getByTestId('erasure-evidence').getAttribute('href')).toContain('/api/dpdp/erasures/7/evidence?download=1')
    expect(within(panel).getByTestId('erasure-evidence-keys').getAttribute('href')).toContain('keys=1')
    fireEvent.click(within(panel).getByTestId('erasure-check'))
    await waitFor(() => expect(within(panel).getByTestId('erasure-clears-on').textContent).toContain('never, as things stand'))
    expect(within(panel).getByTestId('erasure-never').textContent).toContain('hold the person again')
    expect(within(panel).getByTestId('erasure-outcome-live').textContent).toContain('Lost')
    expect(within(panel).getByTestId('erasure-rechecked')).toBeTruthy()
    expect(checkErasure).toHaveBeenCalledWith(7)
  })

  it('lists the restores past a request: who decided, why, and the erasure applied again', async () => {
    vi.mocked(getErasure).mockResolvedValue(request({
      state: 'applied',
      result: { applied: '2026-11-25T10:00:00Z', by: 'dpo@example.com', tables: [], rows: 1, verified: true, rewrites: [], notes: [] },
      restores: [
        { id: 1, request: 7, door: 'restore', source: 'main', target: 'restore', point: '2026-11-25 09:00', by: 'ops@example.com',
          reason: 'incident 9', at: '2026-11-26T09:00:00Z', state: 'done',
          detail: JSON.stringify({ request: 7, keys: 'main', result: { rows: 1, blackbox: { redacted: 2, originals: 1 } }, blackbox: true, notes: [] }) },
        { id: 2, request: 7, door: 'backup restore', source: 'qa', target: 'qa-old', point: 'the export of 2026-11-20 08:00', by: 'ops@example.com',
          reason: 'audit', at: '2026-11-26T10:00:00Z', state: 'failed', detail: '{}', error: 'public.people has no primary key in the copy' },
      ],
    }))
    page()
    fireEvent.click(within(await screen.findByRole('table', { name: 'Erasure requests' })).getByRole('button', { name: 'Open' }))
    const rs = await screen.findByRole('table', { name: 'Restores' })
    expect(within(rs).getByTestId('erasure-restore-1').textContent).toContain('restore of main from 2026-11-25 09:00, into restore')
    expect(within(rs).getByTestId('erasure-restore-1').textContent).toContain('“incident 9”')
    expect(within(rs).getByTestId('erasure-restore-1').textContent).toContain('1 row(s) changed; 2 Blackbox entr(ies) redacted')
    expect(within(rs).getByTestId('erasure-restore-2').textContent).toContain('failed: public.people has no primary key in the copy. The copy stays closed.')
  })

  it('shows every branch, applies a skipped one on its own, and remakes one made before the erasure', async () => {
    const applied = request({
      state: 'applied',
      result: { applied: '2026-11-25T10:00:00Z', by: 'dpo@example.com', tables: [], rows: 1, verified: true, rewrites: [], notes: [] },
      branches: [
        { branch: 'dev', parent: 'main', masked: false, state: 'applied', plan: request().plan, result: { applied: '2026-11-25T10:00:00Z', by: 'dpo@example.com', tables: [], rows: 2, verified: true, rewrites: [], notes: [] } },
        { branch: 'qa', parent: 'main', masked: false, state: 'skipped', why: 'its plan changed since it was shown', plan: request().plan },
        { branch: 'demo', parent: 'main', masked: true, state: 'listed', why: 'a masked branch being made' },
      ],
      madeBefore: [{ branch: 'dev', parent: 'main', made: '2026-11-01T00:00:00Z', owner: 'dev@example.com', why: 'made 2026-11-01, before main\'s erasure finished' }],
      old: [{ branch: 'dev', made: '2026-06-01T00:00:00Z', days: 178, personal: true }],
    })
    vi.mocked(getErasure).mockResolvedValue(applied)
    vi.mocked(applyErasure).mockResolvedValue(applied)
    vi.mocked(remakeErasureBranch).mockResolvedValue({ ...applied, madeBefore: [] })
    page()
    const list = await screen.findByRole('table', { name: 'Erasure requests' })
    fireEvent.click(within(list).getByRole('button', { name: 'Open' }))
    const branches = await screen.findByRole('table', { name: 'Branches' })
    expect(within(branches).getByTestId('erasure-branch-dev').textContent).toContain('Erased')
    expect(within(branches).getByTestId('erasure-branch-dev').textContent).toContain('2 row(s) changed')
    expect(within(branches).getByTestId('erasure-branch-demo').textContent).toContain('a masked branch being made')
    expect(screen.getByTestId('erasure-old').textContent).toContain('dev (178 days)')

    // The skipped branch, on its own, with the values again.
    fireEvent.click(within(branches).getByRole('button', { name: 'Apply to qa…' }))
    const ask = screen.getByTestId('erasure-values')
    expect(ask.textContent).toContain('on qa for good')
    fireEvent.change(within(ask).getByLabelText('Values'), { target: { value: 'asha@example.in' } })
    fireEvent.change(within(ask).getByLabelText('Request number'), { target: { value: '7' } })
    fireEvent.click(within(ask).getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(applyErasure).toHaveBeenCalledWith(7, [{ category: '', value: 'asha@example.in' }], 'qa'))

    // Made before the erasure: remade, after saying what is lost.
    const before = await screen.findByTestId('erasure-made-before')
    expect(before.textContent).toContain('owned by dev@example.com')
    fireEvent.click(within(before).getByRole('button', { name: 'Remake…' }))
    expect((await screen.findByRole('dialog')).textContent).toContain('everything done on it is discarded')
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remake' }))
    await waitFor(() => expect(remakeErasureBranch).toHaveBeenCalledWith(7, 'dev'))
    expect((await screen.findByTestId('erasure-made-before')).textContent).toContain('No branch made before the erasure is left')
  })
})
