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
    getFinding: vi.fn(),
    markFinding: vi.fn(),
    getSamples: vi.fn(),
    getUnclassified: vi.fn(),
    acceptColumn: vi.fn(),
    getBranches: vi.fn(async () => [{ name: 'main' }, { name: 'dev' }]),
    getStatus: vi.fn(),
  }
})

import { acceptColumn, getFinding, getPersonalData, getSamples, getStatus, getUnclassified, markFinding, scanPersonalData, type PersonalData as Report, type PIIColumn, type Status } from '../api'
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
    vi.mocked(getFinding).mockReset().mockResolvedValue({ finding: scanned.findings![0], decisions: [] })
    vi.mocked(markFinding).mockReset()
    vi.mocked(getSamples).mockReset()
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
    await waitFor(() => expect(scanPersonalData).toHaveBeenCalledWith('dev', 250, false))
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

  it('shows what is still to review first, and the rest under their state', async () => {
    const pan = scanned.findings!.find(f => f.column === 'pan')!
    const decidedOne = { ...pan, state: 'confirmed' as const, decidedBy: 'owner@example.com' }
    vi.mocked(getPersonalData).mockResolvedValue({ ...scanned, findings: [scanned.findings![0], decidedOne] })
    page()
    const table = await screen.findByRole('table', { name: 'Personal data found' })
    expect(table.textContent).toContain('public.customers.aadhaar_no')
    expect(table.textContent).not.toContain('public.old.pan')
    expect(screen.getByRole('button', { name: 'To review (1)' }).getAttribute('aria-pressed')).toBe('true')
    fireEvent.click(screen.getByRole('button', { name: 'Confirmed (1)' }))
    const confirmed = screen.getByRole('table', { name: 'Personal data found' })
    expect(confirmed.textContent).toContain('public.old.pan')
    expect(confirmed.textContent).toContain('by owner@example.com')
  })

  it('reviews a finding from masked samples, and records the decision with its note', async () => {
    vi.mocked(getPersonalData).mockResolvedValue(scanned)
    vi.mocked(getSamples).mockResolvedValue({ finding: scanned.findings![0], read: 12, as: 'owner@example.com',
      samples: [{ masked: 'XXXX XXXX 0124', matches: true }, { masked: 'X/X', matches: false }] })
    const confirmed = { ...scanned.findings![0], state: 'confirmed' as const, decidedBy: 'owner@example.com', note: 'KYC column' }
    vi.mocked(markFinding).mockResolvedValue({ finding: confirmed,
      decisions: [{ id: 1, state: 'confirmed', actor: 'owner@example.com', note: 'KYC column', at: '2026-10-21T11:00:00Z' }] })
    page()
    fireEvent.click(await screen.findByRole('button', { name: 'Review public.customers.aadhaar_no (Aadhaar)' }))
    const dlg = screen.getByRole('dialog', { name: 'Review public.customers.aadhaar_no' })
    const list = await screen.findByRole('list', { name: 'Masked samples' })
    expect(list.textContent).toContain('XXXX XXXX 0124')
    expect(list.textContent).toContain('looks like aadhaar')
    expect(dlg.textContent).toContain('Read as owner@example.com')
    expect(getSamples).toHaveBeenCalledWith('main', 1)
    fireEvent.change(screen.getByLabelText('Note (optional)'), { target: { value: ' KYC column ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(markFinding).toHaveBeenCalledWith('main', 1, 'confirmed', 'KYC column'))
    expect((await screen.findByRole('list', { name: 'Decisions' })).textContent).toMatch(/confirmed by owner@example.com.*KYC column/)
    // Decided, so it has left the queue behind the dialog.
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(screen.getByRole('table', { name: 'Personal data found' }).textContent).not.toContain('public.customers.aadhaar_no')
    expect(screen.getByRole('button', { name: 'Confirmed (1)' })).toBeTruthy()
  })

  it('says when the reviewer’s own role may not read the samples', async () => {
    vi.mocked(getPersonalData).mockResolvedValue(scanned)
    vi.mocked(getSamples).mockRejectedValue(new Error('your role cannot read this location: public.customers.aadhaar_no (permission denied)'))
    page()
    fireEvent.click(await screen.findByRole('button', { name: /^Review public\.customers\.aadhaar_no/ }))
    expect(await screen.findByText(/your role cannot read this location/)).toBeTruthy()
  })

  it('without the feature, a finding can be read but not decided, and no sample is read', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    vi.mocked(getPersonalData).mockResolvedValue(scanned)
    page()
    fireEvent.click(await screen.findByRole('button', { name: /^Review public\.customers\.aadhaar_no/ }))
    expect(await screen.findByText(/Reading samples and deciding are part of Enterprise/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull()
    expect(getSamples).not.toHaveBeenCalled()
  })

  const col = (id: number, column: string, findings: number, undecided: number): PIIColumn => ({
    id, schema: 'public', table: 'people', column, path: '', status: 'unclassified', firstScan: 2, lastScan: 3,
    firstSeen: '2026-10-21T12:00:00Z', reviewedBy: '', reviewedAt: null, note: '', findings, undecided,
  })

  it('scans only what is new when asked', async () => {
    vi.mocked(getPersonalData).mockResolvedValue({ branch: 'main', scan: null, findings: [] })
    vi.mocked(scanPersonalData).mockResolvedValue(scanned)
    page()
    await screen.findByText(/has not been scanned/)
    fireEvent.click(screen.getByLabelText(/Only what is new/))
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await waitFor(() => expect(scanPersonalData).toHaveBeenCalledWith('main', 1000, true))
  })

  it('lists what appeared since the first scan, accepts a place with nothing to decide, and sends the rest to review', async () => {
    vi.mocked(getPersonalData).mockResolvedValue({ ...scanned, unclassified: 2 })
    vi.mocked(getUnclassified).mockResolvedValue({ branch: 'main', columns: [col(9, 'status', 0, 0), col(10, 'mobile', 1, 1)] })
    vi.mocked(acceptColumn).mockResolvedValue({ ...col(9, 'status', 0, 0), status: 'reviewed' })
    page()
    fireEvent.click(await screen.findByRole('button', { name: 'Unclassified (2)' }))
    const table = await screen.findByRole('table', { name: 'Unclassified places' })
    expect(table.textContent).toContain('public.people.status')
    fireEvent.click(screen.getByRole('button', { name: 'Accept public.people.status' }))
    await waitFor(() => expect(acceptColumn).toHaveBeenCalledWith('main', 9))
    await waitFor(() => expect(screen.getByRole('table', { name: 'Unclassified places' }).textContent).not.toContain('public.people.status'))
    expect(screen.getByRole('button', { name: 'Unclassified (1)' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Decide its 1 finding(s)' }))
    expect(screen.getByRole('button', { name: /^To review/ }).getAttribute('aria-pressed')).toBe('true')
  })

  it('a finding a scan of what is new skipped is not called "not seen"', async () => {
    const f = { ...scanned.findings![0], lastScan: 1 }
    vi.mocked(getPersonalData).mockResolvedValue({ ...scanned, scan: { ...scan, id: 3, newOnly: true }, fullScan: 1, findings: [f] })
    page()
    const table = await screen.findByRole('table', { name: 'Personal data found' })
    expect(table.textContent).not.toContain('not seen in the latest scan')
    expect(screen.getByTestId('pii-summary').textContent).toContain('(what is new)')
  })
})
