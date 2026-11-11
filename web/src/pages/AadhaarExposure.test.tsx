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
    getBranches: vi.fn(async () => [{ name: 'main' }, { name: 'dev' }]),
    getStatus: vi.fn(),
  }
})

import { getAadhaar, getAadhaarPlaces, getStatus, runAadhaar, type AadhaarReport, type Status } from '../api'
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
})
