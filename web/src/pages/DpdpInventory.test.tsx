// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getDPDPInventory: vi.fn(),
    setDPDPEntry: vi.fn(),
    removeDPDPEntry: vi.fn(),
    getDPDPHistory: vi.fn(),
    getBranches: vi.fn(async () => []),
    getStatus: vi.fn(),
  }
})

import {
  getDPDPHistory, getDPDPInventory, getStatus, removeDPDPEntry, setDPDPEntry,
  type DPDPEntry, type DPDPInventory, type Status,
} from '../api'
import { ConfirmProvider } from '../confirm'
import DpdpInventory, { keepText } from './DpdpInventory'

const status = (features: string[], edition: 'standard' | 'enterprise' = 'enterprise') =>
  ({ edition, features }) as unknown as Status

const vocabulary = {
  bases: [{ value: 'consent', label: 'Consent (s.6)' }, { value: '7d', label: 'A legal duty to disclose information to the State (s.7(d))' }],
  principals: [{ value: 'customer', label: 'Customers and users' }, { value: 'employee', label: 'Employees' }, { value: 'child', label: 'Children, under 18 (s.2(f))' }],
  units: [{ value: 'days', label: 'days' }, { value: 'months', label: 'months' }, { value: 'years', label: 'years' }],
  from: [{ value: 'last_contact', label: "the person's last contact (s.8(8))" }, { value: 'account_closed', label: 'the account is closed' }, { value: 'purpose_served', label: 'the purpose is served (s.8(7)(a))' }],
  reasons: [{ value: 'law', label: 'A law requires it (s.8(7))' }, { value: 'contract', label: 'A contract' }, { value: 'purpose', label: 'The purpose needs it' }],
}

const entry = (o: Partial<DPDPEntry>): DPDPEntry => ({
  schema: 'public', table: 'customers', column: '', basis: 'consent', purpose: 'Delivering orders',
  principals: ['customer'], keep: { count: 3, unit: 'years', from: 'last_contact', reason: 'purpose', citation: '' },
  note: '', setBy: 'dpo@example.com', setAt: '2026-11-24T09:00:00Z', ...o,
})

const inventory = (): DPDPInventory => ({
  branch: 'main',
  tables: [
    {
      schema: 'public', table: 'customers', entry: entry({}), gaps: 0, notices: [],
      columns: [
        { column: 'aadhaar_no', categories: ['aadhaar'], paths: [], by: 'column',
          override: entry({ column: 'aadhaar_no', basis: '7d', keep: { count: 8, unit: 'years', from: 'account_closed', reason: 'law', citation: 'PMLA s.12' } }) },
        { column: 'email', categories: ['email'], paths: [], by: 'table', override: null },
      ],
    },
    {
      schema: 'public', table: 'staff', entry: null, gaps: 1,
      notices: ["dob holds a child's data (a confirmed finding), but its entry does not list children"],
      columns: [{ column: 'dob', categories: ['child', 'date_of_birth'], paths: [], by: '', override: null }],
    },
  ],
  gapColumns: 1, gapTables: 1,
  stale: [entry({ table: 'invoices' })],
  undecided: 2,
  scanned: '2026-11-24T08:00:00Z',
  limits: ['Only places a reviewer confirmed as personal data are listed (fox pii mark).'],
  vocabulary,
})

function page() { render(<MemoryRouter><ConfirmProvider><DpdpInventory /></ConfirmProvider></MemoryRouter>) }

describe('DPDP inventory', () => {
  beforeEach(() => {
    vi.mocked(getStatus).mockResolvedValue(status(['dpdp', 'personal-data']))
    vi.mocked(getDPDPInventory).mockReset().mockResolvedValue(inventory())
    vi.mocked(setDPDPEntry).mockReset().mockImplementation(async (_b, e) => e)
    vi.mocked(removeDPDPEntry).mockReset().mockResolvedValue({})
    vi.mocked(getDPDPHistory).mockReset().mockResolvedValue([])
  })
  afterEach(cleanup)

  it('shows each table, what covers each column, the gaps, the notices and the stale entries', async () => {
    page()
    const summary = await screen.findByTestId('dpdp-summary')
    expect(summary.textContent).toContain('2 table(s) with confirmed personal data')
    expect(summary.textContent).toContain('1 column(s) in 1 table(s) have no entry')
    const cust = screen.getByTestId('dpdp-table-public.customers')
    expect(cust.textContent).toContain('Consent (s.6)')
    expect(cust.textContent).toContain("kept 3 years after the person's last contact (s.8(8))")
    const rows = within(within(cust).getByRole('table', { name: 'Columns of public.customers' })).getAllByRole('row')
    expect(rows[1].textContent).toContain('its own entry')
    expect(rows[1].textContent).toContain('8 years after the account is closed; a law requires it: PMLA s.12')
    expect(rows[2].textContent).toContain("the table's entry")
    const staff = screen.getByTestId('dpdp-table-public.staff')
    expect(staff.textContent).toContain('1 gap(s)')
    expect(staff.textContent).toContain('no entry')
    expect(within(staff).getByRole('status').textContent).toContain("a child's data")
    expect(screen.getByTestId('dpdp-stale').textContent).toContain('public.invoices')
    expect(screen.getByRole('link', { name: 'Export CSV' }).getAttribute('href')).toContain('/api/branches/main/dpdp/inventory?format=csv')
  })

  it('sets a table entry, asking which law when a law sets the period', async () => {
    page()
    const staff = await screen.findByTestId('dpdp-table-public.staff')
    fireEvent.click(within(staff).getByRole('button', { name: 'Set entry…' }))
    const form = screen.getByTestId('dpdp-form')
    const save = within(form).getByRole('button', { name: 'Save entry' }) as HTMLButtonElement
    expect(save.disabled).toBe(true) // no purpose yet
    fireEvent.change(within(form).getByLabelText('Purpose'), { target: { value: 'Payroll' } })
    fireEvent.click(within(form).getByLabelText(/Employees/))
    fireEvent.click(within(form).getByLabelText(/Customers and users/)) // off again: it was the default
    fireEvent.click(within(form).getByLabelText(/Children/))
    fireEvent.change(within(form).getByLabelText('Keep for'), { target: { value: '8' } })
    fireEvent.change(within(form).getByLabelText('After'), { target: { value: 'account_closed' } })
    fireEvent.change(within(form).getByLabelText('Because'), { target: { value: 'law' } })
    expect(save.disabled).toBe(true) // which law?
    fireEvent.change(within(form).getByLabelText('Citation'), { target: { value: 'Income-tax Act, 1961' } })
    expect(save.disabled).toBe(false)
    fireEvent.click(save)
    await waitFor(() => expect(setDPDPEntry).toHaveBeenCalledWith('main', {
      schema: 'public', table: 'staff', column: '', basis: 'consent', purpose: 'Payroll',
      principals: ['employee', 'child'],
      keep: { count: 8, unit: 'years', from: 'account_closed', reason: 'law', citation: 'Income-tax Act, 1961' }, note: '',
    }))
    await waitFor(() => expect(getDPDPInventory).toHaveBeenCalledTimes(2))
    expect(screen.queryByTestId('dpdp-form')).toBeNull()
  })

  it("gives a column its own entry, starting from the table's", async () => {
    page()
    const cust = await screen.findByTestId('dpdp-table-public.customers')
    fireEvent.click(within(cust).getByRole('button', { name: 'Own entry…' }))
    const form = screen.getByTestId('dpdp-form')
    expect(form.textContent).toContain("it replaces the table's for this column")
    expect((within(form).getByLabelText('Purpose') as HTMLTextAreaElement).value).toBe('Delivering orders')
    expect(within(form).queryByRole('button', { name: 'Remove entry…' })).toBeNull() // it has none of its own
    fireEvent.click(within(form).getByRole('button', { name: 'Save entry' }))
    await waitFor(() => expect(setDPDPEntry).toHaveBeenCalledWith('main', expect.objectContaining({ table: 'customers', column: 'email' })))
  })

  it('removes an entry once it is confirmed', async () => {
    page()
    const cust = await screen.findByTestId('dpdp-table-public.customers')
    fireEvent.click(within(cust).getByRole('button', { name: 'Edit its entry…' }))
    fireEvent.click(within(screen.getByTestId('dpdp-form')).getByRole('button', { name: 'Remove entry…' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(removeDPDPEntry).toHaveBeenCalledWith('main', 'public', 'customers', 'aadhaar_no'))
  })

  it("shows a table's history", async () => {
    vi.mocked(getDPDPHistory).mockResolvedValue([{ id: 1, action: 'set', entry: entry({}), actor: 'dpo@example.com', at: '2026-11-24T09:00:00Z' }])
    page()
    const cust = await screen.findByTestId('dpdp-table-public.customers')
    fireEvent.click(within(cust).getByRole('button', { name: 'History' }))
    const h = await screen.findByTestId('dpdp-history')
    expect(getDPDPHistory).toHaveBeenCalledWith('main', 'public', 'customers')
    expect(h.textContent).toContain('dpo@example.com')
    expect(h.textContent).toContain('(table)')
  })

  it('reads, but does not set, without the licence', async () => {
    vi.mocked(getStatus).mockResolvedValue(status(['personal-data']))
    page()
    expect(await screen.findByText(/Entries recorded earlier can still be read and exported/)).toBeTruthy()
    const staff = screen.getByTestId('dpdp-table-public.staff')
    await waitFor(() => expect((within(staff).getByRole('button', { name: 'Set entry…' }) as HTMLButtonElement).disabled).toBe(true))
    expect(screen.getByTestId('dpdp-summary')).toBeTruthy()
  })

  it('says what to do first when nothing is confirmed', async () => {
    vi.mocked(getDPDPInventory).mockResolvedValue({ ...inventory(), tables: [], gapColumns: 0, gapTables: 0, stale: [] })
    page()
    expect(await screen.findByText(/has no confirmed personal data yet/)).toBeTruthy()
  })
})

describe('keepText', () => {
  it('reads a retention', () => {
    expect(keepText(vocabulary, { count: 0, unit: 'days', from: 'purpose_served', reason: 'purpose', citation: '' })).toBe('until the purpose is served (s.8(7)(a))')
    expect(keepText(vocabulary, { count: 1, unit: 'years', from: 'account_closed', reason: 'contract', citation: 'MSA cl. 9' })).toBe('1 year after the account is closed; a contract: MSA cl. 9')
  })
})
