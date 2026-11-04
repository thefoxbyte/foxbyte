// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getAuditLog: vi.fn(), getAuditMarks: vi.fn(), getAuditRecords: vi.fn(), getBranches: vi.fn(), unmarkAudited: vi.fn(), setAuditMode: vi.fn(), setAuditRetention: vi.fn(), purgeAuditText: vi.fn(), setAuditForward: vi.fn(), stopAuditForward: vi.fn(), sendAuditForward: vi.fn() }
})

import { getAuditLog, getAuditMarks, getAuditRecords, getBranches, purgeAuditText, sendAuditForward, setAuditForward, setAuditMode, setAuditRetention, stopAuditForward, unmarkAudited, type AuditForward, type AuditLogReply } from '../api'
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

  it('reads the records with filters: how each statement ended, and whom it was for', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default' })
    vi.mocked(getAuditRecords).mockResolvedValue({ records: [
      { seq: 3, time: '2026-11-04T10:00:04Z', branch: 'main', login: 'alice@x.in', kind: 'statement', class: 'WRITE', command: 'INSERT',
        object: 'public.orders', txn_outcome: 'COMMIT', txn_for: { state: 'asserted', issuer: 'shop', actor: 'priya' } },
      { seq: 2, time: '2026-11-04T10:00:02Z', branch: 'main', login: 'bob', kind: 'statement', class: 'WRITE', command: 'UPDATE',
        object: 'public.orders', txn_outcome: 'ROLLBACK', error: '23505' },
      { seq: 1, time: '2026-11-04T10:00:01Z', branch: 'main', login: 'eve', kind: 'outcome', outcome: 'FATAL', sqlstate: '28P01' },
    ] })
    page()
    fireEvent.change(await screen.findByLabelText('Records table'), { target: { value: 'orders' } })
    fireEvent.click(screen.getByLabelText('Errors only'))
    fireEvent.click(screen.getByRole('button', { name: 'Show' }))
    await waitFor(() => expect(getAuditRecords).toHaveBeenCalledWith(expect.objectContaining({ table: 'orders', errors: true, since: '24h' })))
    const t = await screen.findByRole('table', { name: 'Audit records' })
    const rows = within(t).getAllByRole('row').map(r => r.textContent)
    expect(rows[1]).toMatch(/alice@x\.in.*INSERT.*public\.orders.*commit.*priya, asserted by shop/)
    expect(rows[2]).toMatch(/bob.*UPDATE.*rollback \(23505\)/)
    expect(rows[3]).toMatch(/eve.*FATAL.*28P01/)
  })

  it('"ever" asks with no since', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default' })
    vi.mocked(getAuditRecords).mockResolvedValue({ records: [] })
    page()
    fireEvent.change(await screen.findByLabelText('Records since'), { target: { value: 'all' } })
    fireEvent.click(screen.getByRole('button', { name: 'Show' }))
    expect(await screen.findByTestId('no-records')).toBeTruthy()
    expect(getAuditRecords).toHaveBeenCalledWith(expect.objectContaining({ since: '' }))
  })

  it('lists what is found wrong, or says nothing is', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', findings: [
      { kind: 'gap', branch: 'main', detail: '3 audit line(s) missing in a session of alice', since: '2026-11-04T10:00:00Z' },
      { kind: 'mark', branch: 'main', detail: 'public.orders was marked by bob, and its mark has been taken off outside FoxByte' },
    ] })
    page()
    const f = await screen.findByTestId('audit-findings')
    expect(f.textContent).toMatch(/gap.*main: 3 audit line\(s\) missing/)
    expect(f.textContent).toMatch(/mark.*taken off outside FoxByte/)
    cleanup()
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', findings: [] })
    page()
    expect((await screen.findByTestId('audit-findings')).textContent).toContain('Nothing found wrong')
  })

  it('forensic mode needs a reason and a confirmation, and shows where it is on and can be turned back', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', forensic: { feature: { by: 'bob', reason: 'incident 42', since: '2026-11-04T10:00:00Z' } }, retention: { days: 365, forensic_days: 30 } })
    vi.mocked(setAuditMode).mockResolvedValue({ forensic: {}, reached: ['main'] })
    page()
    const mode = await screen.findByTestId('audit-mode')
    expect(mode.textContent).toMatch(/forensic.*on feature.*by bob.*incident 42/)
    const on = screen.getByRole('button', { name: 'Turn on forensic mode' }) as HTMLButtonElement
    expect(on.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Forensic reason'), { target: { value: 'who changed the orders?' } })
    fireEvent.click(on)
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Turn on' }))
    await waitFor(() => expect(setAuditMode).toHaveBeenCalledWith(true, '', 'who changed the orders?'))
    fireEvent.click(screen.getByRole('button', { name: 'Back to default' }))
    await waitFor(() => expect(setAuditMode).toHaveBeenCalledWith(false, 'feature', ''))
  })

  it('sets retention, and purges a person\'s statement text after asking', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', retention: { days: 365, forensic_days: 30 } })
    vi.mocked(setAuditRetention).mockResolvedValue({ days: 180, forensic_days: 30 })
    vi.mocked(purgeAuditText).mockResolvedValue({ purged: 4 })
    page()
    fireEvent.change(await screen.findByLabelText('Records kept days'), { target: { value: '180' } })
    fireEvent.click(screen.getAllByRole('button', { name: 'Save' })[0])
    await waitFor(() => expect(setAuditRetention).toHaveBeenCalledWith(180, false))
    expect(await screen.findByText('Records are kept 180 days.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Purge login'), { target: { value: 'alice@x.in' } })
    fireEvent.click(screen.getByRole('button', { name: 'Purge' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Purge' }))
    await waitFor(() => expect(purgeAuditText).toHaveBeenCalledWith('alice@x.in'))
    expect(await screen.findByText('Removed 4 statement text(s).')).toBeTruthy()
  })

  it('shows a forensic record\'s text, or that it was removed', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default' })
    vi.mocked(getAuditRecords).mockResolvedValue({ records: [
      { seq: 2, time: '2026-11-04T10:00:02Z', branch: 'main', login: 'bob', kind: 'statement', command: 'UPDATE', text: "UPDATE orders SET x = 'y'" },
      { seq: 1, time: '2026-11-04T10:00:01Z', branch: 'main', login: 'eve', kind: 'statement', command: 'INSERT', text_gone: true },
    ] })
    page()
    fireEvent.click(await screen.findByRole('button', { name: 'Show' }))
    expect((await screen.findByTestId('text-2')).textContent).toBe("UPDATE orders SET x = 'y'")
    expect(screen.getByTestId('text-1').textContent).toContain('removed')
  })

  const fwd: AuditForward = { url: 'https://siem.example.com/ingest', ca: true, token: true, by: 'admin@x.in', since: '2026-11-04T10:00:00Z',
    host: 'siem.example.com', position: 40, head: 42, waiting: 2, sent: 40, last_ok: '2026-11-04T10:05:00Z' }

  it('says when records are not forwarded, and forwards them after saying what goes', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', forward: null })
    vi.mocked(setAuditForward).mockResolvedValue({ forward: fwd })
    page()
    expect((await screen.findByTestId('audit-forward')).textContent).toContain('Not forwarded.')
    const go = screen.getByRole('button', { name: 'Forward' })
    expect((go as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Forward URL'), { target: { value: 'https://siem.example.com/ingest' } })
    fireEvent.change(screen.getByLabelText('Forward token'), { target: { value: 'tok-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Forward' }))
    const d = await screen.findByRole('dialog')
    expect(d.textContent).toContain('from the next record collected')
    expect(d.textContent).toContain('Statement text is not sent.')
    fireEvent.click(within(d).getByRole('button', { name: 'Forward' }))
    await waitFor(() => expect(setAuditForward).toHaveBeenCalledWith({ url: 'https://siem.example.com/ingest', token: 'tok-1', ca_pem: undefined, text: false, from_start: false }))
    expect(await screen.findByText('Forwarding to https://siem.example.com/ingest.')).toBeTruthy()
    expect((screen.getByLabelText('Forward token') as HTMLInputElement).value).toBe('')
  })

  it('warns, before sending statement text, that retention and purge no longer reach it there', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default', forward: null })
    page()
    fireEvent.change(await screen.findByLabelText('Forward URL'), { target: { value: 'syslog://logs.example.com' } })
    fireEvent.click(screen.getByLabelText(/Statement text too/))
    fireEvent.click(screen.getByLabelText(/Every record still kept/))
    fireEvent.click(screen.getByRole('button', { name: 'Forward' }))
    const d = await screen.findByRole('dialog')
    expect(d.textContent).toContain('retention and purge here no longer reach it')
    expect(d.textContent).toContain('every record the store still holds')
  })

  it('shows how far delivery has got and why it fails, sends now, and stops', async () => {
    vi.mocked(getAuditLog).mockResolvedValue({ ...off, on: true, mode: 'default',
      forward: { ...fwd, last_err: 'siem.example.com answered 503 Service Unavailable', err_since: '2026-11-04T10:06:00Z' } })
    vi.mocked(sendAuditForward).mockResolvedValue({ sent: 0, waiting: 2, skipped: 0, error: 'siem.example.com answered 503 Service Unavailable', forward: fwd })
    vi.mocked(stopAuditForward).mockResolvedValue({ forward: null })
    page()
    expect((await screen.findByTestId('forward-position')).textContent).toContain('Delivered up to record 40 of 42 (2 waiting)')
    expect(screen.getByTestId('audit-forward').textContent).toContain('TLS checked against its own CA bundle')
    expect(screen.getByTestId('forward-error').textContent).toContain('503')
    expect(screen.getByTestId('audit-forward').textContent).not.toContain('tok')
    fireEvent.click(screen.getByRole('button', { name: 'Send now' }))
    expect(await screen.findByText(/Forwarding failed after 0 record\(s\)/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Stop forwarding' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Stop forwarding' }))
    await waitFor(() => expect(stopAuditForward).toHaveBeenCalled())
    expect(await screen.findByText('Forwarding stopped.')).toBeTruthy()
  })
})
