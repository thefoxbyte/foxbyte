// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfirmProvider } from '../confirm'
import HistoryPanel, { when } from './HistoryPanel'

const NOW = Date.now()

// The entries, once they have arrived (the list also holds a loading line).
const items = async (first: string) => {
  await screen.findByText(first)
  return Array.from(document.querySelectorAll('.hist-item')) as HTMLElement[]
}
const entry = (id: number, sql: string, extra: Record<string, unknown> = {}) => ({
  id, branch: 'main', source: 'console', kind: 'query', sql, at: NOW - 60_000, duration_ms: 4, rows: 3, ok: true, ...extra,
})

// A fake engine for the panel's routes; it records what it was asked.
function engine(opts: { entries?: ReturnType<typeof entry>[]; saved?: { id: number; name: string; sql: string }[]; off?: boolean } = {}) {
  let saved = opts.saved ?? []
  const calls: { method: string; url: string; body?: any }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(init.body as string) : undefined
    calls.push({ method, url, body })
    const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status })
    if (url.includes('/api/history/settings')) return json({ enabled: !opts.off, mine: true, retention_days: 90, count: 0, admin: false })
    if (url.includes('/api/history') && method === 'GET') {
      const q = new URL(url, 'http://x').searchParams
      let es = opts.entries ?? []
      if (q.get('q')) es = es.filter(e => e.sql.toLowerCase().includes(q.get('q')!.toLowerCase()))
      if (q.get('failed')) es = es.filter(e => !e.ok)
      return json({ entries: es })
    }
    if (url.match(/\/api\/history\/\d+$/) && method === 'DELETE') return new Response(null, { status: 204 })
    if (url.includes('/api/saved-queries') && method === 'GET') return json({ queries: saved })
    if (url.endsWith('/api/saved-queries') && method === 'POST') {
      if (saved.some(s => s.name === body.name)) return json({ error: 'you already have a saved query with that name' }, 409)
      const q = { id: saved.length + 1, name: body.name, sql: body.sql }
      saved = [...saved, q]
      return json(q, 201)
    }
    if (url.match(/\/api\/saved-queries\/\d+$/) && method === 'DELETE') {
      saved = saved.filter(s => !url.endsWith(`/${s.id}`))
      return new Response(null, { status: 204 })
    }
    return json({})
  }))
  return calls
}

function panel(p: Partial<Parameters<typeof HistoryPanel>[0]> = {}) {
  const onOpen = vi.fn(), onRun = vi.fn()
  render(
    <ConfirmProvider>
      <HistoryPanel branch="dev" branches={['main', 'dev']} tick={0} busy={false} current="SELECT 42"
        onOpen={onOpen} onRun={onRun} {...p} />
    </ConfirmProvider>,
  )
  return { onOpen, onRun }
}

describe('HistoryPanel', () => {
  beforeEach(() => { vi.unstubAllGlobals() })
  afterEach(() => { cleanup(); vi.unstubAllGlobals() })

  it('lists what you ran, with when, where, how long and how many rows', async () => {
    engine({ entries: [entry(2, 'SELECT *\n  FROM orders'), entry(1, 'SELECT nope', { ok: false, error: 'no such column', rows: 0, source: 'cli' })] })
    panel()
    const it2 = await items('SELECT * FROM orders')
    expect(it2[0].textContent).toMatch(/1 min ago.*main.*4 ms.*3 rows/)
    expect(it2[1].textContent).toMatch(/failed/)
    expect(it2[1].textContent).toContain('CLI')
  })

  it('searches as you type, and filters to the failed ones and this branch', async () => {
    const calls = engine({ entries: [entry(2, 'SELECT * FROM orders'), entry(1, 'SELECT 1')] })
    panel()
    await screen.findByText('SELECT 1')
    fireEvent.change(screen.getByLabelText('Search history'), { target: { value: 'ORDERS' } })
    await waitFor(() => expect(screen.queryByText('SELECT 1')).toBeNull())
    expect(screen.getByText('SELECT * FROM orders')).toBeTruthy()
    fireEvent.click(screen.getByLabelText(/failed only/i))
    fireEvent.click(screen.getByLabelText(/only dev/i))
    await waitFor(() => expect(calls.some(c => /q=ORDERS/.test(c.url) && /failed=1/.test(c.url) && /branch=dev/.test(c.url))).toBe(true))
    expect(await screen.findByText('Nothing matches.')).toBeTruthy()
  })

  it('opens, runs where it ran, and copies', async () => {
    engine({ entries: [entry(2, 'SELECT 2', { branch: 'main' }), entry(1, 'SELECT 1', { branch: 'gone' })] })
    const write = vi.fn(async () => {})
    Object.assign(navigator, { clipboard: { writeText: write } })
    const { onOpen, onRun } = panel()
    const [first, second] = await items('SELECT 2')
    fireEvent.click(within(first).getByRole('button', { name: 'Open' }))
    expect(onOpen).toHaveBeenCalledWith('SELECT 2')
    fireEvent.click(within(first).getByRole('button', { name: 'Run' }))
    expect(onRun).toHaveBeenCalledWith('SELECT 2', 'main')
    // A branch that is gone: it runs on the one in use, and says so.
    const run2 = within(second).getByRole('button', { name: 'Run' })
    expect(run2.getAttribute('title')).toMatch(/gone is gone: runs on dev/)
    fireEvent.click(run2)
    expect(onRun).toHaveBeenLastCalledWith('SELECT 1', 'dev')
    fireEvent.click(within(first).getByRole('button', { name: 'Copy' }))
    await waitFor(() => expect(write).toHaveBeenCalledWith('SELECT 2'))
    expect(await screen.findByText('Copied ✓')).toBeTruthy()
  })

  it('saves an entry under a name, and says when the name is taken', async () => {
    const calls = engine({ entries: [entry(1, 'SELECT 1')], saved: [{ id: 9, name: 'taken', sql: 'SELECT 0' }] })
    panel()
    const [item] = await items('SELECT 1')
    fireEvent.click(within(item).getByRole('button', { name: 'Save' }))
    fireEvent.change(screen.getByLabelText('Name for the saved query'), { target: { value: 'taken' } })
    fireEvent.click(within(item.querySelector('form')!).getByRole('button', { name: /^save$/i }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/already have a saved query/)
    fireEvent.change(screen.getByLabelText('Name for the saved query'), { target: { value: 'ones' } })
    fireEvent.click(within(item.querySelector('form')!).getByRole('button', { name: /^save$/i }))
    expect(await screen.findByText('Saved as “ones”')).toBeTruthy()
    expect(calls.filter(c => c.method === 'POST').map(c => c.body)).toEqual([{ name: 'taken', sql: 'SELECT 1' }, { name: 'ones', sql: 'SELECT 1' }])
  })

  it('deletes an entry from history', async () => {
    const calls = engine({ entries: [entry(7, 'SELECT 7')] })
    panel()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete from history' }))
    await waitFor(() => expect(screen.queryByText('SELECT 7')).toBeNull())
    expect(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/api/history/7'))).toBe(true)
  })

  it('keeps saved queries: the editor\'s, run on this branch, deleted after asking', async () => {
    engine({ saved: [{ id: 1, name: 'big orders', sql: 'SELECT * FROM orders WHERE total > 100' }] })
    const { onRun } = panel()
    fireEvent.click(await screen.findByRole('tab', { name: 'Saved' }))
    expect(await screen.findByText('big orders')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /save the editor/i }))
    fireEvent.change(screen.getByLabelText('Name for the saved query'), { target: { value: 'answer' } })
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }))
    expect(await screen.findByText('answer')).toBeTruthy()
    const row = screen.getByText('big orders').closest('li')!
    fireEvent.click(within(row).getByRole('button', { name: 'Run' }))
    expect(onRun).toHaveBeenCalledWith('SELECT * FROM orders WHERE total > 100', 'dev')
    fireEvent.click(within(row).getByRole('button', { name: 'Delete big orders' }))
    fireEvent.click(await screen.findByRole('button', { name: /^delete$/i }))
    await waitFor(() => expect(screen.queryByText('big orders')).toBeNull())
  })

  it('says when history is off, and does not offer Run while a query runs', async () => {
    engine({ entries: [], off: true })
    panel()
    expect(await screen.findByText(/history is off for you or for this install/i)).toBeTruthy()
    cleanup()
    engine({ entries: [entry(1, 'SELECT 1')] })
    panel({ busy: true })
    const [item] = await items('SELECT 1')
    expect((within(item).getByRole('button', { name: 'Run' }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('when', () => {
  it('says how long ago in words', () => {
    const now = Date.UTC(2026, 9, 19, 12, 0, 0)
    expect(when(now - 10_000, now)).toBe('just now')
    expect(when(now - 5 * 60_000, now)).toBe('5 min ago')
    expect(when(now - 3 * 3600_000, now)).toBe('3 h ago')
    expect(when(now - 3 * 86400_000, now)).toMatch(/Oct/)
  })
})
