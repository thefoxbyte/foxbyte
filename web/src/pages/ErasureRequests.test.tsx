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
    getStatus: vi.fn(),
  }
})

import {
  ApiError, applyErasure, getErasure, getStatus, listErasures, newErasure,
  type ErasureRequest, type ErasureTable, type Status,
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

function page() { render(<MemoryRouter><ConfirmProvider><ErasureRequests /></ConfirmProvider></MemoryRouter>) }

describe('Erasure requests', () => {
  beforeEach(() => {
    vi.mocked(getStatus).mockResolvedValue(status(['dpdp']))
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
    expect((await screen.findByRole('alert')).textContent).toContain('the plan has changed since it was shown')
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
})
