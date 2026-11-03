// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, markAudited: vi.fn(), unmarkAudited: vi.fn() }
})

import { markAudited, unmarkAudited, type AuditMarks } from '../api'
import { ConfirmProvider } from '../confirm'
import { AuditControl } from './AuditMark'

const none: AuditMarks = { audit_on: true, tables: [] }
const writes: AuditMarks = { audit_on: true, tables: [{ schema: 'public', name: 'orders', writes: true, reads: false }] }

function control(marks: AuditMarks | null, onChange = vi.fn()) {
  render(<ConfirmProvider><AuditControl branch="main" schema="public" table="orders" marks={marks} onChange={onChange} /></ConfirmProvider>)
  return onChange
}

describe('Audit control', () => {
  beforeEach(() => {
    vi.mocked(markAudited).mockReset().mockResolvedValue(writes)
    vi.mocked(unmarkAudited).mockReset().mockResolvedValue(none)
  })
  afterEach(cleanup)

  it('marks a table for writes, or for writes and reads', async () => {
    const onChange = control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Audit…' }))
    const dlg = screen.getByRole('dialog', { name: 'Audit orders' })
    expect(dlg.textContent).toContain('Never what the statement held')
    fireEvent.click(within(dlg).getByLabelText('Writes and reads'))
    fireEvent.click(within(dlg).getByRole('button', { name: 'Audit' }))
    await waitFor(() => expect(markAudited).toHaveBeenCalledWith('main', 'public', 'orders', true))
    expect(onChange).toHaveBeenCalledWith(writes)
  })

  it('shows a mark, adds reads to it, and takes it off after asking', async () => {
    control(writes)
    expect(screen.getByTestId('audit-mark').textContent).toContain('Audited: writes')
    fireEvent.click(screen.getByRole('button', { name: 'Audit reads too' }))
    await waitFor(() => expect(markAudited).toHaveBeenCalledWith('main', 'public', 'orders', true))
    fireEvent.click(screen.getByRole('button', { name: 'Stop auditing' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop auditing' }))
    await waitFor(() => expect(unmarkAudited).toHaveBeenCalledWith('main', 'public', 'orders'))
  })

  it('says a mark waits while the audit log is off', () => {
    control({ ...writes, audit_on: false })
    expect(screen.getByTestId('audit-mark').textContent).toContain('the audit log is off')
  })

  it('shows nothing until the marks are known', () => {
    control(null)
    expect(screen.queryByRole('button', { name: 'Audit…' })).toBeNull()
  })

  it('shows why a mark was refused', async () => {
    vi.mocked(markAudited).mockRejectedValue(new Error('public.v is not a table: mark the tables it reads and writes'))
    control(none)
    fireEvent.click(screen.getByRole('button', { name: 'Audit…' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Audit' }))
    expect((await screen.findByRole('alert')).textContent).toContain('is not a table')
  })
})
