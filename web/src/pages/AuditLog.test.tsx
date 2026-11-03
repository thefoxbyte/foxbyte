// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getAuditLog: vi.fn() }
})

import { getAuditLog, type AuditLogReply } from '../api'
import AuditLog from './AuditLog'

const off: AuditLogReply = { on: false, root: '/dbpool/audit', used: 0, quota: 0, pending: [], setup: 'fox audit-log setup', off: 'fox audit-log off' }

function page() { render(<MemoryRouter><AuditLog /></MemoryRouter>) }

describe('Audit log page', () => {
  beforeEach(() => { vi.mocked(getAuditLog).mockReset() })
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
})
