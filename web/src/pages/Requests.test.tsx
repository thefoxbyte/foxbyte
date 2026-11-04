// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, listRequests: vi.fn(), getBranches: vi.fn().mockResolvedValue([]), getStatus: vi.fn().mockResolvedValue({ edition: 'enterprise', features: ['promotion'] }) }
})

import { listRequests, type ChangeRequest } from '../api'
import { ConfirmProvider } from '../confirm'
import Requests from './Requests'

const run = 'CREATE TABLE t (id int); CREATE VIEW v AS SELECT id FROM t'
const req: ChangeRequest = {
  id: 7, source: 'feature', target: 'main', created_by: 'ada@example.com', created: '2026-11-05T10:00:00Z',
  status: 'open', fork_after_id: 40, applied: 0,
  entries: [
    { id: 41, at: '2026-11-05T09:00:00Z', actor: 'ada@example.com', kind: 'human', command: 'CREATE TABLE', object: 'public.t', sql: run },
    { id: 42, at: '2026-11-05T09:00:00Z', actor: 'ada@example.com', kind: 'human', command: 'CREATE VIEW', object: 'public.v', sql: run, same_run: 41 },
  ],
}

describe('Change requests page', () => {
  afterEach(cleanup)

  it('shows a run of several statements once, and says which entries it made', async () => {
    vi.mocked(listRequests).mockResolvedValue([req])
    render(<MemoryRouter><ConfirmProvider><Requests /></ConfirmProvider></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Review' }))
    expect(screen.getAllByText(run)).toHaveLength(1)
    expect(screen.getByTestId('same-run-42').textContent).toBe('Made by the same run as #41, above: it runs once, there.')
  })
})
