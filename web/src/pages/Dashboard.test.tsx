// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getStatus: vi.fn().mockResolvedValue({
      mainReady: true, branches: 1, agents: 1, edition: 'standard', features: [],
      ha: { enabled: false }, storage: { used: '1 GiB' }, servers: { gateway: true, api: true },
    }),
    getLicense: vi.fn().mockResolvedValue({}),
    listBackups: vi.fn().mockResolvedValue([]),
    getBranches: vi.fn(),
    createBranch: vi.fn(),
    getDPDPInventory: vi.fn().mockRejectedValue(new Error('only the owner of "main" or an admin may do that')),
  }
})

import { createBranch, getBranches, getDPDPInventory, getStatus, type Branch, type DPDPInventory, type Status } from '../api'
import { ConfirmProvider } from '../confirm'
import Dashboard from './Dashboard'

const b = (o: Partial<Branch>): Branch => ({ name: 'x', primary: false, agent: false, state: 'running', used: '1M', refer: '1M', connections: 0, port: '', ...o })
function page() { render(<MemoryRouter><ConfirmProvider><Dashboard /></ConfirmProvider></MemoryRouter>) }

// Branches are unmasked by default (PRIV-1). The list says which ones hand
// real personal data to whoever uses them, and creating one says so too. A
// warning, never a refusal: the branch is made either way.
describe('Dashboard: unmasked personal data', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('badges the branches whose personal data reaches their readers unmasked, and only those', async () => {
    const summary = 'this branch holds unmasked personal data: 2 Aadhaar columns (customers.aadhaar, leads.aadhaar); agents using it see real values.'
    vi.mocked(getBranches).mockResolvedValue([
      b({ name: 'main', primary: true }),
      b({ name: 'agent-a', agent: true, personalData: { unmasked: 2, summary } }),
      b({ name: 'qa' }),
    ])
    page()
    const badge = await screen.findByTestId('pii-agent-a')
    expect(badge.textContent).toBe('unmasked personal data')
    expect(badge.getAttribute('title')).toBe(summary)
    expect(screen.queryByTestId('pii-main')).toBeNull()
    expect(screen.queryByTestId('pii-qa')).toBeNull()
  })

  it('shows what the engine said about the branch it just made', async () => {
    vi.mocked(getBranches).mockResolvedValue([b({ name: 'main', primary: true })])
    const w = 'this branch holds unmasked personal data: 1 email column (customers.email); people and agents using it see real values. Masking can hide them, and masking needs FoxByte Enterprise.'
    vi.mocked(createBranch).mockResolvedValue({ name: 'qa', status: 'created', warnings: [w] })
    page()
    fireEvent.change(await screen.findByPlaceholderText(/new branch name/), { target: { value: 'qa' } })
    fireEvent.click(screen.getByRole('button', { name: '+ Create branch' }))
    await waitFor(() => expect(createBranch).toHaveBeenCalledWith('qa', undefined, false))
    expect((await screen.findByTestId('create-warning')).textContent).toBe(w)
  })

  it('says nothing when there is nothing to say', async () => {
    vi.mocked(getBranches).mockResolvedValue([b({ name: 'main', primary: true })])
    vi.mocked(createBranch).mockResolvedValue({ name: 'qa', status: 'created' })
    page()
    fireEvent.change(await screen.findByPlaceholderText(/new branch name/), { target: { value: 'qa' } })
    fireEvent.click(screen.getByRole('button', { name: '+ Create branch' }))
    await waitFor(() => expect(createBranch).toHaveBeenCalled())
    await waitFor(() => expect(getBranches).toHaveBeenCalledTimes(2))
    expect(screen.queryByTestId('create-warning')).toBeNull()
  })
})

// main's DPDP inventory gaps (point 11.1): reported and warned, never blocked.
describe('Dashboard: DPDP inventory gaps', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })
  const licensed = {
    mainReady: true, branches: 1, agents: 0, edition: 'enterprise', features: ['dpdp'],
    ha: { enabled: false }, storage: { used: '1 GiB' }, servers: { gateway: true, api: true },
  } as unknown as Status

  it("says how many of main's confirmed columns have no entry, and links to the inventory", async () => {
    vi.mocked(getStatus).mockResolvedValue(licensed)
    vi.mocked(getBranches).mockResolvedValue([b({ name: 'main', primary: true })])
    vi.mocked(getDPDPInventory).mockResolvedValue({ gapColumns: 3, gapTables: 2 } as DPDPInventory)
    page()
    const w = await screen.findByTestId('dpdp-gaps')
    expect(w.textContent).toContain('3 column(s) in 2 table(s) of main hold confirmed personal data with no DPDP inventory entry')
    expect(screen.getByRole('link', { name: 'Open the DPDP inventory' }).getAttribute('href')).toBe('/dpdp-inventory')
    expect(getDPDPInventory).toHaveBeenCalledWith('main')
  })

  it('says nothing when every column has an entry, or the caller may not read the inventory', async () => {
    vi.mocked(getStatus).mockResolvedValue(licensed)
    vi.mocked(getBranches).mockResolvedValue([b({ name: 'main', primary: true })])
    vi.mocked(getDPDPInventory).mockResolvedValue({ gapColumns: 0, gapTables: 0 } as DPDPInventory)
    page()
    await waitFor(() => expect(getDPDPInventory).toHaveBeenCalled())
    await screen.findAllByText('main')
    expect(screen.queryByTestId('dpdp-gaps')).toBeNull()
    cleanup()
    vi.mocked(getDPDPInventory).mockRejectedValue(new Error('only the owner of "main" or an admin may do that'))
    page()
    await waitFor(() => expect(getDPDPInventory).toHaveBeenCalledTimes(2))
    expect(screen.queryByTestId('dpdp-gaps')).toBeNull()
  })
})
