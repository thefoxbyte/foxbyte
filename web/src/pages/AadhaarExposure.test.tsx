// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getAadhaar: vi.fn(),
    runAadhaar: vi.fn(),
    getAadhaarPlaces: vi.fn(),
    getAadhaarLogPlaces: vi.fn(),
    getAccount: vi.fn(async () => ({ admin: false })),
    getBranches: vi.fn(async () => [{ name: 'main' }, { name: 'dev' }]),
    getStatus: vi.fn(),
  }
})

import {
  getAadhaar, getAadhaarLogPlaces, getAadhaarPlaces, getAccount, getStatus, runAadhaar,
  type AadhaarLogs, type AadhaarReport, type Status,
} from '../api'
import AadhaarExposure from './AadhaarExposure'

const status = (features: string[], edition: 'standard' | 'enterprise' = 'enterprise') =>
  ({ edition, features }) as unknown as Status

const report: AadhaarReport = {
  branch: 'main',
  run: {
    id: 3, started: '2026-11-12T10:00:00Z', finished: '2026-11-12T10:00:02Z', actor: 'owner@example.com',
    tables: 4, columns: 9, rows: 5, numbers: 6, people: 3, listed: 6,
    skipped: [{ object: 'public.remote', reason: 'a foreign table: its data is held somewhere else' }],
    limits: ['There is no Aadhaar vault in FoxByte yet (point 13), so every number found is outside one.'],
  },
  columns: [
    { schema: 'public', table: 'customers', column: 'aadhaar', path: '', numbers: 3, rows: 3, listed: 3, capped: false, since: '2026-10-01T00:00:00Z' },
    { schema: 'public', table: 'orders', column: 'meta', path: '$.kyc.uid', numbers: 2, rows: 2, listed: 2, capped: false, since: '2026-11-12T10:00:00Z' },
  ],
  people: [
    { person: 1, masked: 'XXXX XXXX 0124', places: 3, since: '2026-10-01T00:00:00Z', where: ['public.customers.aadhaar', 'public.orders.meta $.kyc.uid', 'public.tickets.notes'] },
    { person: 2, masked: 'XXXX XXXX 5555', places: 1, since: '2026-11-12T10:00:00Z', where: ['public.customers.aadhaar'] },
  ],
  peopleListed: 2,
  gone: 1,
}

function page() {
  render(<MemoryRouter><AadhaarExposure /></MemoryRouter>)
}

describe('Aadhaar exposure page', () => {
  beforeEach(() => {
    vi.mocked(getAadhaar).mockReset()
    vi.mocked(runAadhaar).mockReset()
    vi.mocked(getAadhaarPlaces).mockReset()
    vi.mocked(getStatus).mockResolvedValue(status(['personal-data']))
  })
  afterEach(cleanup)

  it('says a branch has no report yet', async () => {
    vi.mocked(getAadhaar).mockResolvedValue({ branch: 'main', run: null, columns: [], people: [], peopleListed: 0, gone: 0 })
    page()
    expect(await screen.findByText(/has no Aadhaar exposure report yet/)).toBeTruthy()
  })

  it('shows each column and each person by the last four digits, with what it cannot claim', async () => {
    vi.mocked(getAadhaar).mockResolvedValue(report)
    page()
    const cols = await screen.findByRole('table', { name: 'Aadhaar by column' })
    expect(cols.textContent).toContain('public.customers.aadhaar')
    expect(cols.textContent).toContain('public.orders.meta $.kyc.uid')
    const people = screen.getByRole('table', { name: 'Aadhaar by person' })
    expect(people.textContent).toContain('XXXX XXXX 0124')
    expect(people.textContent).toContain('public.tickets.notes')
    expect(screen.getByTestId('aadhaar-summary').textContent).toContain('6 number(s) found, 3 distinct')
    expect(screen.getByText(/public.remote/)).toBeTruthy()
    expect(screen.getByText(/no Aadhaar vault in FoxByte yet/)).toBeTruthy()
    expect(screen.getByText(/1 place\(s\) earlier runs found are no longer there/)).toBeTruthy()
  })

  it("opens a person's rows", async () => {
    vi.mocked(getAadhaar).mockResolvedValue(report)
    vi.mocked(getAadhaarPlaces).mockResolvedValue({
      branch: 'main',
      places: [{ id: 7, schema: 'public', table: 'tickets', column: 'notes', path: '', row: 'id=9', last4: '0124', masked: 'XXXX XXXX 0124',
        person: 1, firstSeen: '2026-11-12T10:00:00Z', lastSeen: '2026-11-12T10:00:00Z', rowCreated: '2026-10-01T00:00:00Z',
        since: '2026-10-01T00:00:00Z', gone: false }],
    })
    page()
    fireEvent.click(await screen.findByRole('button', { name: 'Rows of person 1' }))
    const places = await screen.findByRole('table', { name: 'Aadhaar places' })
    expect(vi.mocked(getAadhaarPlaces)).toHaveBeenCalledWith('main', { person: 1 })
    expect(places.textContent).toContain('id=9')
    expect(places.textContent).toContain('row created')
  })

  it('runs the report with the time limit given', async () => {
    vi.mocked(getAadhaar).mockResolvedValue({ branch: 'main', run: null, columns: [], people: [], peopleListed: 0, gone: 0 })
    vi.mocked(runAadhaar).mockResolvedValue(report)
    page()
    const btn = await screen.findByRole('button', { name: 'Run the report' })
    fireEvent.change(screen.getByLabelText('Seconds per table'), { target: { value: '60' } })
    fireEvent.click(btn)
    await waitFor(() => expect(vi.mocked(runAadhaar)).toHaveBeenCalledWith('main', 60))
    expect(await screen.findByRole('table', { name: 'Aadhaar by column' })).toBeTruthy()
  })

  it('says a run is Enterprise and still shows an earlier report', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    vi.mocked(getAadhaar).mockResolvedValue(report)
    page()
    expect(await screen.findByRole('table', { name: 'Aadhaar by column' })).toBeTruthy()
    const btn = screen.getByRole('button', { name: /Run the report \(Enterprise\)/ }) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
  })

  describe('the logs part (admins)', () => {
    const logs = (linked: boolean): AadhaarLogs => ({
      run: {
        id: 2, branch: 'main', branchRun: linked ? 3 : 2, started: '2026-11-12T10:00:02Z', finished: '2026-11-12T10:00:03Z',
        actor: 'admin@example.com', read: { history: 12, audit: 0, blackbox: 40 }, numbers: 3, people: 2, linked: 1, listed: 3,
        skipped: [], limits: ['The Blackbox keeps the statements of the branch\'s schema changes.'],
      },
      linked,
      sources: [
        { source: 'history', entries: 1, places: 2, since: '2026-11-01T00:00:00Z' },
        { source: 'blackbox', entries: 1, places: 1, since: '2026-11-02T00:00:00Z' },
      ],
      people: [{ person: 1, masked: 'XXXX XXXX 0124', places: 2, since: '2026-11-01T00:00:00Z', where: ['query history'], logs: { history: 2 } }],
      gone: 1,
    })

    it('is offered to an admin only', async () => {
      vi.mocked(getAadhaar).mockResolvedValue({ branch: 'main', run: null, columns: [], people: [], peopleListed: 0, gone: 0 })
      vi.mocked(runAadhaar).mockResolvedValue(report)
      page()
      await screen.findByRole('button', { name: 'Run the report' })
      expect(screen.queryByLabelText(/Read the logs too/)).toBeNull()
      cleanup()
      vi.mocked(getAccount).mockResolvedValueOnce({ admin: true })
      page()
      fireEvent.click(await screen.findByLabelText(/Read the logs too/))
      fireEvent.click(screen.getByRole('button', { name: 'Run the report' }))
      await waitFor(() => expect(vi.mocked(runAadhaar)).toHaveBeenCalledWith('main', 300, true))
    })

    it("shows what the logs hold, and a person's log entries with their rows", async () => {
      const merged = { ...report.people![0], places: 5, where: [...report.people![0].where!, 'query history'], logs: { history: 2 } }
      vi.mocked(getAadhaar).mockResolvedValue({ ...report, people: [merged, report.people![1]], logs: logs(true) })
      vi.mocked(getAadhaarPlaces).mockResolvedValue({ branch: 'main', places: [] })
      vi.mocked(getAadhaarLogPlaces).mockResolvedValue({
        branch: 'main',
        places: [{ id: 4, source: 'history', entry: 77, field: 'error', last4: '0124', masked: 'XXXX XXXX 0124', actor: 'ada@example.com',
          at: '2026-11-01T09:00:00Z', person: 1, firstSeen: '2026-11-12T10:00:02Z', lastSeen: '2026-11-12T10:00:02Z', gone: false }],
      })
      page()
      const inLogs = await screen.findByRole('table', { name: 'Aadhaar in the logs' })
      expect(inLogs.textContent).toContain('query history')
      expect(inLogs.textContent).toContain('Blackbox')
      expect(screen.getByTestId('aadhaar-logs-summary').textContent).toContain('12 query history entries')
      expect(screen.getByTestId('aadhaar-logs-summary').textContent).toContain('1 also in the tables')
      expect(screen.getByText(/1 log place\(s\) earlier runs found are no longer there/)).toBeTruthy()
      // Linked: no separate list of the logs' people.
      expect(screen.queryByRole('table', { name: 'Aadhaar by person in the logs' })).toBeNull()
      expect(screen.getByRole('table', { name: 'Aadhaar by person' }).textContent).toContain('query history')

      fireEvent.click(screen.getByRole('button', { name: 'Rows of person 1' }))
      const entries = await screen.findByRole('table', { name: 'Aadhaar log entries' })
      expect(vi.mocked(getAadhaarPlaces)).toHaveBeenCalledWith('main', { person: 1 })
      expect(vi.mocked(getAadhaarLogPlaces)).toHaveBeenCalledWith('main', { person: 1 })
      expect(entries.textContent).toContain('77 (error)')
      expect(entries.textContent).toContain('ada@example.com')

      fireEvent.click(screen.getByRole('button', { name: 'Entries of Blackbox' }))
      await waitFor(() => expect(vi.mocked(getAadhaarLogPlaces)).toHaveBeenCalledWith('main', { source: 'blackbox' }))
    })

    it('lists the people apart when the logs were read with an earlier run', async () => {
      vi.mocked(getAadhaar).mockResolvedValue({ ...report, logs: logs(false) })
      page()
      const apart = await screen.findByRole('table', { name: 'Aadhaar by person in the logs' })
      expect(apart.textContent).toContain('XXXX XXXX 0124')
      expect(screen.getByText(/before the latest, so these people are numbered apart/)).toBeTruthy()
    })
  })
})
