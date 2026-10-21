// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getPersonalData: vi.fn(),
    scanPersonalData: vi.fn(),
    getBranches: vi.fn(async () => [{ name: 'main' }, { name: 'dev' }]),
    getStatus: vi.fn(),
  }
})

import { getPersonalData, getStatus, scanPersonalData, type PersonalData as Report, type Status } from '../api'
import PersonalData from './PersonalData'

const status = (features: string[], edition: 'standard' | 'enterprise' = 'enterprise') =>
  ({ edition, features }) as unknown as Status

const scan = {
  id: 2, started: '2026-10-21T10:00:00Z', finished: '2026-10-21T10:00:01Z', actor: 'owner@example.com',
  sample: 1000, tables: 3, columns: 11,
  skipped: [{ object: 'public.remote', reason: 'a foreign table: its data is held somewhere else' }],
  limits: ['A check digit shows a value is well-formed, not that it was issued, or whose it is.'],
}
const scanned: Report = {
  branch: 'main',
  scan,
  findings: [
    { id: 1, schema: 'public', table: 'customers', column: 'aadhaar_no', path: '', category: 'aadhaar', rule: 'name+value',
      confidence: 'high', why: 'the column’s name, and 12 of 12 sampled values are 12 digits…', matched: 12, sampled: 12,
      state: 'suggested', firstScan: 1, lastScan: 2, lastSeen: '2026-10-21T10:00:01Z' },
    { id: 3, schema: 'public', table: 'customers', column: 'profile', path: '$.contact.phone', category: 'mobile', rule: 'name+value',
      confidence: 'high', why: 'the column’s name, and 4 of 4 sampled values are 10 digits…', matched: 4, sampled: 4,
      state: 'suggested', firstScan: 1, lastScan: 2, lastSeen: '2026-10-21T10:00:01Z' },
    { id: 2, schema: 'public', table: 'old', column: 'pan', path: '', category: 'pan', rule: 'name',
      confidence: 'medium', why: 'the column’s name; no values to check', matched: 0, sampled: 0,
      state: 'suggested', firstScan: 1, lastScan: 1, lastSeen: '2026-10-20T10:00:00Z' },
  ],
}

function page() {
  render(<MemoryRouter><PersonalData /></MemoryRouter>)
}

describe('Personal data page', () => {
  beforeEach(() => {
    vi.mocked(getPersonalData).mockReset()
    vi.mocked(scanPersonalData).mockReset()
    vi.mocked(getStatus).mockResolvedValue(status(['personal-data']))
  })
  afterEach(cleanup)

  it('says a branch has not been scanned', async () => {
    vi.mocked(getPersonalData).mockResolvedValue({ branch: 'main', scan: null, findings: [] })
    page()
    expect(await screen.findByText(/has not been scanned/)).toBeTruthy()
  })

  it('lists where personal data is, what kind, how sure, and what the scan cannot claim', async () => {
    vi.mocked(getPersonalData).mockResolvedValue(scanned)
    page()
    const table = await screen.findByRole('table', { name: 'Personal data found' })
    expect(table.textContent).toContain('public.customers.aadhaar_no')
    expect(table.textContent).toContain('Aadhaar')
    expect(table.textContent).toContain('12/12')
    expect(table.textContent).toContain('name and values')
    // A name with nothing to check has no matched count to show.
    expect(table.textContent).toContain('name only')
    expect(table.textContent).toContain('not seen in the latest scan')
    // A finding inside a JSON column names its path beside the column (4.2).
    expect(screen.getByText('$.contact.phone').closest('tr')!.textContent).toMatch(/public\.customers\.profile.*Mobile number.*4\/4/)
    expect(screen.getByTestId('pii-summary').textContent).toMatch(/3 table\(s\), 11 column\(s\) read, up to 1000 rows each; 1 not read/)
    expect(screen.getByText(/a foreign table/)).toBeTruthy()
    expect(screen.getByText(/not that it was issued/)).toBeTruthy()
  })

  it('scans the chosen branch with the chosen sample, and shows the result', async () => {
    vi.mocked(getPersonalData).mockResolvedValue({ branch: 'dev', scan: null, findings: [] })
    vi.mocked(scanPersonalData).mockResolvedValue({ ...scanned, branch: 'dev' })
    page()
    await screen.findByText(/has not been scanned/)
    await screen.findByRole('option', { name: 'dev' })
    fireEvent.change(screen.getByLabelText('Branch'), { target: { value: 'dev' } })
    fireEvent.change(screen.getByLabelText('Rows per table'), { target: { value: '250' } })
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await waitFor(() => expect(scanPersonalData).toHaveBeenCalledWith('dev', 250))
    expect(await screen.findByRole('table', { name: 'Personal data found' })).toBeTruthy()
  })

  it('refuses a sample outside 1 to 100,000 without asking the engine', async () => {
    vi.mocked(getPersonalData).mockResolvedValue({ branch: 'main', scan: null, findings: [] })
    page()
    await screen.findByText(/has not been scanned/)
    fireEvent.change(screen.getByLabelText('Rows per table'), { target: { value: '0' } })
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    expect(await screen.findByText(/1 to 100,000 rows/)).toBeTruthy()
    expect(scanPersonalData).not.toHaveBeenCalled()
  })

  it('without the feature, scanning is locked and earlier findings still show', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    vi.mocked(getPersonalData).mockResolvedValue(scanned)
    page()
    const btn = await screen.findByRole('button', { name: 'Scan now (Enterprise)' })
    expect((btn as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/Findings from earlier scans can still be read/)).toBeTruthy()
    expect(await screen.findByRole('table', { name: 'Personal data found' })).toBeTruthy()
  })

  it('says why when the engine refuses, as it does for someone who does not own the branch', async () => {
    vi.mocked(getPersonalData).mockRejectedValue(new Error('only the owner of "main" or an admin may do that'))
    page()
    expect(await screen.findByText(/only the owner of "main" or an admin/)).toBeTruthy()
  })
})
