// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getAuditLog: vi.fn(), getAuditMarks: vi.fn(), getBranches: vi.fn(), unmarkAudited: vi.fn() }
})

import { getAuditLog, getAuditMarks, getBranches, unmarkAudited, type AuditLogReply } from '../api'
import { ConfirmProvider } from '../confirm'
import AuditLog from './AuditLog'

const off: AuditLogReply = { on: false, root: '/dbpool/audit', used: 0, quota: 0, pending: [], setup: 'fox audit-log setup', off: 'fox audit-log off' }

function page() { render(<MemoryRouter><ConfirmProvider><AuditLog /></ConfirmProvider></MemoryRouter>) }

describe('Audit log page', () => {
  beforeEach(() => {
    vi.mocked(getAuditLog).mockReset()
    vi.mocked(getBranches).mockReset().mockResolvedValue([])
    vi.mocked(getAuditMarks).mockReset().mockResolvedValue({ audit_on: false, tables: [] })
  })
  afterEach(cleanup)

  it('off: says so, what it costs, and the command that turns it on', async () => {
    vi.mocked(getAuditLog).mockResolvedValue(off)
    page()
    expect((await screen.findByTestId('audit-off')).textContent).toContain('No database runs pgAudit')
    expect(screen.getByTestId('audit-setup').textContent).toBe('fox audit-log setup')
    expect(screen.queryByTestId('audit-on')).toBeNull()
  })

  it('on: the mode, where the log is, and its space against the quota', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', used: 512 * 1024 * 1024, quota: 2 * 1024 * 1024 * 1024 })
    page()
    expect((await screen.findByTestId('audit-on')).textContent).toContain('Default mode')
    expect(screen.getByTestId('audit-space').textContent).toBe('512.0 MB of 2.0 GB (25%)')
    expect(screen.getByRole('table', { name: 'Audit log' }).textContent).toContain('/dbpool/audit/<branch>')
  })

  it('warns when the log is nearly full, because a full one loses lines silently', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', used: 1700, quota: 2000 })
    page()
    expect((await screen.findByTestId('audit-space')).textContent).toContain('a full log loses audit lines without a word')
  })

  it('names the databases still running as before the last change', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', pending: ['feature-x', 'old'] })
    page()
    expect((await screen.findByTestId('audit-pending')).textContent).toContain('feature-x, old')
  })

  it('shows the error when it cannot be read (not an admin)', async () => {
    vi.mocked(getAuditLog).mockRejectedValue(new Error("only an admin may see the audit log's settings"))
    page()
    expect(await screen.findByText(/only an admin/)).toBeTruthy()
  })

  it('lists the marked tables on a branch, and takes a mark off', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default' })
    vi.mocked(getAuditMarks).mockResolvedValue({ audit_on: true, tables: [
      { schema: 'public', name: 'orders', writes: true, reads: false },
      { schema: 'public', name: 'cards', writes: true, reads: true },
    ] })
    vi.mocked(unmarkAudited).mockResolvedValue({ audit_on: true, tables: [{ schema: 'public', name: 'cards', writes: true, reads: true }] })
    page()
    const t = await screen.findByRole('table', { name: 'Marked tables on main' })
    expect(t.textContent).toMatch(/public\.orders.*writes/)
    expect(t.textContent).toMatch(/public\.cards.*writes and reads/)
    fireEvent.click(within(t).getAllByRole('button', { name: 'Stop auditing' })[0])
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop auditing' }))
    await waitFor(() => expect(unmarkAudited).toHaveBeenCalledWith('main', 'public', 'orders'))
    await waitFor(() => expect(screen.getByRole('table', { name: 'Marked tables on main' }).textContent).not.toContain('orders'))
  })

  it('says when no table is marked', async () => {
    vi.mocked(getAuditLog).mockResolvedValue(off)
    page()
    expect((await screen.findByTestId('no-marks')).textContent).toContain('No table on main is marked')
  })
})
