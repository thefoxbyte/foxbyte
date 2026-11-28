// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getRetention: vi.fn(),
    getRetentionNotices: vi.fn(async () => []),
    setRetention: vi.fn(),
    setRetentionColumn: vi.fn(),
    previewRetention: vi.fn(),
    armRetention: vi.fn(),
    disarmRetention: vi.fn(),
    runRetention: vi.fn(),
    getStatus: vi.fn(),
  }
})

import {
  armRetention, getRetention, getStatus, previewRetention, runRetention, setRetention, setRetentionColumn,
  type RetentionStatus, type Status,
} from '../api'
import { ConfirmProvider } from '../confirm'
import Retention from './Retention'

const status = (features: string[]) => ({ edition: 'enterprise', features }) as unknown as Status
const keep = { count: 2, unit: 'years', from: 'collection', reason: 'purpose', citation: '' }
const st = (on: boolean, over: Partial<RetentionStatus> = {}): RetentionStatus => ({
  settings: { on, notify: on ? 'https://hooks.example/fox' : '', by: 'admin@example.com', since: '2026-11-28T10:00:00Z' },
  notice: '48h0m0s',
  tables: [
    { schema: 'public', table: 'people', keep, column: 'created_at', armed: false, raised: false, due: 3, undated: 1, noticed: 0,
      why: 'not armed: its rows past the period are listed, never erased, until an admin arms it' },
    { schema: 'public', table: 'leads', keep: { ...keep, count: 6, unit: 'months' }, column: '', armed: false, raised: true, due: 0, undated: 0, noticed: 0,
      why: 'no date column: name the one its period runs from' },
  ],
  limits: ['A row is kept at least a year from that date'],
  ...over,
})

function page() { render(<MemoryRouter><ConfirmProvider><Retention /></ConfirmProvider></MemoryRouter>) }

describe('Retention', () => {
  beforeEach(() => { vi.mocked(getStatus).mockResolvedValue(status(['dpdp'])) })
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('turns retention on with the notice address and shows the signing key once', async () => {
    vi.mocked(getRetention).mockResolvedValue(st(false))
    vi.mocked(setRetention).mockResolvedValue({ on: true, secret: 'a'.repeat(64), header: 'X-FoxByte-Signature' })
    page()
    fireEvent.change(await screen.findByLabelText('Notice address'), { target: { value: 'https://hooks.example/fox' } })
    vi.mocked(getRetention).mockResolvedValue(st(true))
    fireEvent.click(screen.getByRole('button', { name: 'Turn on' }))
    await waitFor(() => expect(setRetention).toHaveBeenCalledWith(true, 'https://hooks.example/fox'))
    expect((await screen.findByTestId('retention-secret')).textContent).toContain('a'.repeat(64))
  })

  it('lists each table with its period and why it is not acted on; a period under a year is raised', async () => {
    vi.mocked(getRetention).mockResolvedValue(st(true))
    page()
    const people = await screen.findByTestId('retention-table-public.people')
    expect(people.textContent).toContain('2 years after collection')
    expect(people.textContent).toContain('not armed')
    const leads = screen.getByTestId('retention-table-public.leads')
    expect(leads.textContent).toContain('a year, Rule 8(3)')
    expect((within(leads).getByRole('button', { name: 'Arm…' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(within(leads).getByLabelText('Date column of public.leads'), { target: { value: 'signed_up' } })
    fireEvent.click(within(leads).getByRole('button', { name: 'Set' }))
    await waitFor(() => expect(setRetentionColumn).toHaveBeenCalledWith('public.leads', 'signed_up'))
  })

  it('arms a table only after its preview and a reason', async () => {
    vi.mocked(getRetention).mockResolvedValue(st(true))
    vi.mocked(previewRetention).mockResolvedValue({ schema: 'public', table: 'people', column: 'created_at', keyColumns: ['id'],
      cutoff: '2024-11-28T10:00:00Z', total: 3, undated: 1, rows: [{ key: '["7"]', since: '2023-01-01T00:00:00Z' }] })
    page()
    fireEvent.click(within(await screen.findByTestId('retention-table-public.people')).getByRole('button', { name: 'Arm…' }))
    const arm = await screen.findByTestId('retention-arm')
    expect(within(arm).getByTestId('retention-preview').textContent).toContain('3 row(s) dated by created_at')
    expect(arm.textContent).toContain('["7"]')
    expect((within(arm).getByRole('button', { name: 'Arm it' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(within(arm).getByLabelText('Why arm it'), { target: { value: 'the DPO policy' } })
    fireEvent.click(within(arm).getByRole('button', { name: 'Arm it' }))
    await waitFor(() => expect(armRetention).toHaveBeenCalledWith('public.people', 'the DPO policy'))
  })

  it('runs now and says what each armed table did', async () => {
    vi.mocked(getRetention).mockResolvedValue(st(true))
    vi.mocked(runRetention).mockResolvedValue({ at: '2026-11-28T11:00:00Z', by: 'admin@example.com', notes: [],
      tables: [{ table: 'public.people', due: 3, noticed: 0, waiting: 1, renewed: 1, erased: 1, request: 12 }] })
    page()
    fireEvent.click(await screen.findByTestId('retention-run'))
    const r = await screen.findByTestId('retention-run-result')
    expect(r.textContent).toContain('1 renewed, 1 erased')
    expect(r.textContent).toContain('request #12')
  })
})
