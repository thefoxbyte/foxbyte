// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getSessions: vi.fn(), signalSession: vi.fn().mockResolvedValue({}),
    getBranches: vi.fn().mockResolvedValue([{ name: 'main' }, { name: 'dev' }]) }
})

import { getSessions, signalSession, type DbSession } from '../api'
import { ConfirmProvider } from '../confirm'
import Sessions from './Sessions'

const s = (o: Partial<DbSession>): DbSession => ({ pid: 1, user: 'a@x.io', app: 'psql', state: 'active', wait: '', started: '', since: new Date().toISOString(),
  xact: '', query: 'SELECT pg_sleep(30)', blockedBy: [], engine: false, ...o })
function page() { render(<MemoryRouter><ConfirmProvider><Sessions /></ConfirmProvider></MemoryRouter>) }

describe('Sessions page', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('lists the sessions, says who blocks whom, and never offers to stop the engine', async () => {
    vi.mocked(getSessions).mockResolvedValue({ branch: 'main', all: true, sessions: [
      s({ pid: 11, blockedBy: [12] }), s({ pid: 12, state: 'idle in transaction' }), s({ pid: 13, user: 'dbadmin', engine: true }),
    ] })
    page()
    expect((await screen.findByTestId('session-11')).textContent).toContain('blocked by 12')
    expect(screen.getByTestId('session-13').textContent).toContain('(FoxByte)')
    expect(screen.getByTestId('session-13').querySelectorAll('button')).toHaveLength(0)
    expect(screen.queryByTestId('sessions-own')).toBeNull()
  })

  it('cancels at once, ends only after asking, and says when only your own are shown', async () => {
    vi.mocked(getSessions).mockResolvedValue({ branch: 'main', all: false, sessions: [s({ pid: 21 })] })
    page()
    const row = await screen.findByTestId('session-21')
    expect(screen.getByTestId('sessions-own').textContent).toContain('Your sessions')
    fireEvent.click(row.querySelector('button')!)
    await waitFor(() => expect(signalSession).toHaveBeenCalledWith('main', 21, false))
    fireEvent.click(screen.getByRole('button', { name: 'End…' }))
    fireEvent.click(await screen.findByRole('button', { name: 'End it' }))
    await waitFor(() => expect(signalSession).toHaveBeenCalledWith('main', 21, true))
    expect((await screen.findByTestId('sessions-msg')).textContent).toBe('Session 21 ended.')
  })
})
