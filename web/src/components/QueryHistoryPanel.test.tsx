// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfirmProvider } from '../confirm'
import QueryHistoryPanel from './QueryHistoryPanel'

type Settings = { enabled: boolean; retention_days: number; mine: boolean; count: number; admin: boolean }

function engine(start: Settings) {
  let s = { ...start }
  const calls: { method: string; url: string; body?: unknown }[] = []
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(init.body as string) : undefined
    calls.push({ method, url, body })
    if (url.endsWith('/api/history/settings') && method === 'PUT') {
      if ((body.enabled !== undefined || body.retention_days !== undefined) && !s.admin) {
        return new Response(JSON.stringify({ error: 'only an admin can change the install\'s history settings' }), { status: 403 })
      }
      if (body.mine !== undefined) s.mine = body.mine
      if (body.enabled !== undefined) s.enabled = body.enabled
      if (body.retention_days !== undefined) s.retention_days = body.retention_days
    }
    if (url.endsWith('/api/history') && method === 'DELETE') {
      const n = s.count
      s.count = 0
      return new Response(JSON.stringify({ deleted: n }), { status: 200 })
    }
    return new Response(JSON.stringify(s), { status: 200 })
  })
  vi.stubGlobal('fetch', fetch)
  return calls
}

const panel = () => render(<ConfirmProvider><QueryHistoryPanel /></ConfirmProvider>)

describe('QueryHistoryPanel', () => {
  beforeEach(() => { vi.unstubAllGlobals() })
  afterEach(() => { cleanup(); vi.unstubAllGlobals() })

  it('says how much it holds and for how long, and that no result is kept', async () => {
    engine({ enabled: true, retention_days: 90, mine: true, count: 3, admin: false })
    panel()
    expect((await screen.findByTestId('history-count')).textContent).toBe('3 queries in your history, kept 90 days.')
    expect(screen.getByText(/never a result/i)).toBeTruthy()
    // Not an admin: the install's switches are not offered.
    expect(screen.queryByLabelText('Keep history for')).toBeNull()
  })

  it('turns your own history off', async () => {
    const calls = engine({ enabled: true, retention_days: 90, mine: true, count: 3, admin: false })
    panel()
    const box = await screen.findByLabelText(/keep a history of my queries/i) as HTMLInputElement
    fireEvent.click(box)
    await waitFor(() => expect(box.checked).toBe(false))
    expect(calls.find(c => c.method === 'PUT')?.body).toEqual({ mine: false })
    expect(screen.getByText(/no longer kept/i)).toBeTruthy()
  })

  it('deletes your history only after asking', async () => {
    const calls = engine({ enabled: true, retention_days: 90, mine: true, count: 2, admin: false })
    panel()
    fireEvent.click(await screen.findByRole('button', { name: /delete my history/i }))
    expect(await screen.findByText(/delete all 2 entries/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(calls.some(c => c.method === 'DELETE')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: /delete my history/i }))
    fireEvent.click(await screen.findByRole('button', { name: /^delete$/i }))
    expect(await screen.findByText('Deleted 2 entries.')).toBeTruthy()
    expect(screen.getByTestId('history-count').textContent).toMatch(/^0 queries/)
    expect((screen.getByRole('button', { name: /delete my history/i }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('moves the switch back when the engine refuses', async () => {
    engine({ enabled: true, retention_days: 90, mine: true, count: 0, admin: false })
    const fail = vi.fn(async (_url: string, init?: RequestInit) => init?.method === 'PUT'
      ? new Response(JSON.stringify({ error: 'the store is busy' }), { status: 500 })
      : new Response(JSON.stringify({ enabled: true, retention_days: 90, mine: true, count: 0, admin: false }), { status: 200 }))
    vi.stubGlobal('fetch', fail)
    panel()
    const box = await screen.findByLabelText(/keep a history of my queries/i) as HTMLInputElement
    fireEvent.click(box)
    expect((await screen.findByRole('alert')).textContent).toMatch(/busy/)
    expect(box.checked).toBe(true)
  })

  it('gives an admin the install\'s switch and retention', async () => {
    const calls = engine({ enabled: true, retention_days: 90, mine: true, count: 0, admin: true })
    panel()
    fireEvent.change(await screen.findByLabelText('Keep history for'), { target: { value: '30' } })
    await waitFor(() => expect(screen.getByTestId('history-count').textContent).toMatch(/kept 30 days/))
    fireEvent.click(screen.getByLabelText(/query history on/i))
    expect(await screen.findByText(/history is off for this install: nothing new is kept/i)).toBeTruthy()
    const puts = calls.filter(c => c.method === 'PUT').map(c => c.body)
    expect(puts).toEqual([{ retention_days: 30 }, { enabled: false }])
  })
})
