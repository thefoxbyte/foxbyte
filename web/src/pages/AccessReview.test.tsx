// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getAccessReview: vi.fn(), getStatus: vi.fn() }
})

import { getAccessReview, getStatus, type AccessReview as Report, type Status } from '../api'
import AccessReview from './AccessReview'

const status = (features: string[], edition: 'standard' | 'enterprise' = 'enterprise') => ({ edition, features }) as unknown as Status

const report: Report = {
  generated: '2026-10-22T12:00:00Z',
  dormantDays: 90,
  summary: { accounts: 2, admins: 1, dormant: 1, keys: 2, agentKeys: 1, staleKeys: 1, branches: 2, unowned: 0 },
  accounts: [
    { id: 1, email: 'admin@example.com', created: '2025-01-01T00:00:00Z', admin: true, reaches: 'every branch (an install admin)',
      owns: [], overrideOn: ['qa'], keys: 1, unmasked: 'everything…', lastSignIn: null, lastKeyUse: '2026-10-21T00:00:00Z',
      lastQuery: null, lastActive: '2026-10-21T00:00:00Z', dormant: false },
    { id: 3, email: 'gone@example.com', created: '2025-01-01T00:00:00Z', admin: false, reaches: 'main', owns: [], overrideOn: [],
      keys: 1, unmasked: 'everything…', lastSignIn: '2026-01-01T00:00:00Z', lastKeyUse: null, lastQuery: null,
      lastActive: '2026-01-01T00:00:00Z', dormant: true },
  ],
  keys: [
    { id: 'k1', name: 'ci', prefix: 'key_ab', owner: 'admin@example.com', kind: 'account', identity: '…', reach: 'what admin@example.com reaches',
      created: '2026-01-01T00:00:00Z', lastUsed: '2026-10-21T00:00:00Z', ageDays: 294, stale: false },
    { id: 'k2', name: 'bot', prefix: 'agk_cd', owner: 'gone@example.com', kind: 'agent', identity: 'an agent…', reach: 'what gone@example.com reaches',
      created: '2026-01-01T00:00:00Z', lastUsed: null, ageDays: 294, stale: true, why: 'never used, made 294 days ago' },
  ],
  branches: [
    { name: 'main', state: 'running', owner: '', admins: ['admin@example.com'], asked: true },
    { name: 'qa', state: 'exited', owner: 'admin@example.com', admins: [], asked: false },
  ],
  limits: ['No masking is in place yet (point 7)…'],
}

function page() { render(<MemoryRouter><AccessReview /></MemoryRouter>) }

describe('Access review page', () => {
  beforeEach(() => {
    vi.mocked(getAccessReview).mockReset().mockResolvedValue(report)
    vi.mocked(getStatus).mockResolvedValue(status(['access-review']))
  })
  afterEach(cleanup)

  it('shows the counts, the accounts, the keys and the branches, and what it cannot claim', async () => {
    page()
    const accounts = await screen.findByRole('table', { name: 'Accounts' })
    expect(accounts.textContent).toMatch(/admin@example\.com.*admin.*every branch/)
    expect(accounts.textContent).toMatch(/gone@example\.com.*dormant/)
    expect(screen.getByRole('table', { name: 'Keys' }).textContent).toContain('stale: never used, made 294 days ago')
    expect(screen.getByRole('table', { name: 'Branches' }).textContent).toContain('not running: not read')
    expect(screen.getByText(/No masking is in place yet/)).toBeTruthy()
    expect(getAccessReview).toHaveBeenCalledWith(90)
  })

  it('produces it again for another window, and links each table as CSV for that window', async () => {
    page()
    await screen.findByRole('table', { name: 'Accounts' })
    fireEvent.change(screen.getByLabelText('Dormant after (days)'), { target: { value: '30' } })
    fireEvent.click(screen.getByRole('button', { name: 'Produce report' }))
    await waitFor(() => expect(getAccessReview).toHaveBeenCalledWith(30))
    expect(screen.getByRole('link', { name: 'Keys' }).getAttribute('href')).toMatch(/\/api\/access-review\?dormant=30&format=csv&section=keys$/)
  })

  it('refuses a window outside 1 to 3,650 days without asking', async () => {
    page()
    await screen.findByRole('table', { name: 'Accounts' })
    vi.mocked(getAccessReview).mockClear()
    fireEvent.change(screen.getByLabelText('Dormant after (days)'), { target: { value: '0' } })
    fireEvent.click(screen.getByRole('button', { name: 'Produce report' }))
    expect(await screen.findByText(/1 to 3,650 days/)).toBeTruthy()
    expect(getAccessReview).not.toHaveBeenCalled()
  })

  it('says why for someone who is not an admin', async () => {
    vi.mocked(getAccessReview).mockRejectedValue(new Error('only an admin may produce the access review'))
    page()
    expect(await screen.findByText(/only an admin may produce the access review/)).toBeTruthy()
  })

  it('without the feature, says so and offers no controls', async () => {
    // Until the engine says, nothing is refused (features.ts): it is the
    // authority, and refuses for itself. Once it has said, the page does.
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    vi.mocked(getAccessReview).mockRejectedValue(new Error('not licensed'))
    page()
    expect(await screen.findByText(/The access review report is part of Enterprise/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Produce report' })).toBeNull()
  })
})
