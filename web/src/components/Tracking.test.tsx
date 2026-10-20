// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfirmProvider } from '../confirm'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, trackTable: vi.fn(), untrackTable: vi.fn(), setTrackNew: vi.fn() }
})

import { setTrackNew, trackTable, untrackTable, type Tracking } from '../api'
import { TrackingControl, trackedOf } from './Tracking'

const none: Tracking = { settings: { track_new: false, created: 'created_at', updated: 'updated_at', by: 'last_modified_by' }, tables: [] }
const tracked: Tracking = { ...none, tables: [{ schema: 'public', name: 'orders', created: 'created_at', updated: 'updated_at', by: 'last_modified_by' }] }

function control(t: Tracking | null, onChange = vi.fn()) {
  render(<ConfirmProvider><TrackingControl branch="dev" schema="public" table="orders" tracking={t} onChange={onChange} /></ConfirmProvider>)
  return onChange
}

describe('TrackingControl', () => {
  beforeEach(() => { vi.mocked(trackTable).mockReset(); vi.mocked(untrackTable).mockReset(); vi.mocked(setTrackNew).mockReset() })
  afterEach(cleanup)

  it('offers tracking with the usual names, and says what it does to INSERTs', () => {
    control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Track changes…' }))
    const dlg = screen.getByRole('dialog', { name: 'Track changes to orders' })
    expect((screen.getByLabelText('Column for when made') as HTMLInputElement).value).toBe('created_at')
    expect((screen.getByLabelText('Column for when last changed') as HTMLInputElement).value).toBe('updated_at')
    expect((screen.getByLabelText('Column for who last changed it') as HTMLInputElement).value).toBe('last_modified_by')
    expect(dlg.textContent).toMatch(/INSERT written without a column list/)
  })

  it('tracks with the columns chosen, labelling the rows already there when asked', async () => {
    vi.mocked(trackTable).mockResolvedValue(tracked)
    const onChange = control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Track changes…' }))
    fireEvent.click(screen.getByLabelText('Keep when made'))
    fireEvent.change(screen.getByLabelText('Column for who last changed it'), { target: { value: 'changed_by' } })
    fireEvent.click(screen.getByLabelText('Label with this moment'))
    fireEvent.click(screen.getByRole('button', { name: 'Track' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(tracked))
    expect(trackTable).toHaveBeenCalledWith('dev', 'public', 'orders', { created: '', updated: 'updated_at', by: 'changed_by', label_existing: true })
  })

  it('needs at least one column', () => {
    control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Track changes…' }))
    for (const k of ['Keep when made', 'Keep when last changed', 'Keep who last changed it']) fireEvent.click(screen.getByLabelText(k))
    expect((screen.getByRole('button', { name: 'Track' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('shows why the engine refused', async () => {
    vi.mocked(trackTable).mockRejectedValue(new Error('column created_at of public.orders is date, and tracking keeps timestamp with time zone there'))
    control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Track changes…' }))
    fireEvent.click(screen.getByRole('button', { name: 'Track' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/is date/)
  })

  it('a tracked table shows its columns, and stops only after asking', async () => {
    vi.mocked(untrackTable).mockResolvedValue(none)
    const onChange = control(tracked)
    expect(screen.getByText('last_modified_by')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Stop tracking' }))
    expect(await screen.findByText(/the columns, and what they hold, stay/i)).toBeTruthy()
    const stops = screen.getAllByRole('button', { name: 'Stop tracking' })
    fireEvent.click(stops[stops.length - 1])
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(none))
    expect(untrackTable).toHaveBeenCalledWith('dev', 'public', 'orders')
  })

  it('turns tracking of new tables on for the branch', async () => {
    vi.mocked(setTrackNew).mockResolvedValue({ ...none, settings: { ...none.settings, track_new: true } })
    control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Track changes…' }))
    fireEvent.click(screen.getByLabelText(/track every new table on dev/i))
    await waitFor(() => expect(setTrackNew).toHaveBeenCalledWith('dev', true, { created: 'created_at', updated: 'updated_at', by: 'last_modified_by' }))
  })
})

describe('trackedOf', () => {
  it('finds a table by schema and name', () => {
    expect(trackedOf(tracked, 'public', 'orders')?.by).toBe('last_modified_by')
    expect(trackedOf(tracked, 'shop', 'orders')).toBeNull()
    expect(trackedOf(null, 'public', 'orders')).toBeNull()
  })
})
