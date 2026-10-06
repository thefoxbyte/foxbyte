// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The line the anchors gating draws, asserted in the console: creating a
// checkpoint is Enterprise, and everything else on this page is not.
import { render, screen, waitFor, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { IntegrityReport, Status } from '../api'

const REPORT: IntegrityReport = {
  intact: true, rows: 10, chained_rows: 10, legacy_rows: 0,
  checkpoints: 1, anchored_rows: 8, unanchored_rows: 2, problems: [], notes: [],
}

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getStatus: vi.fn(),
    getIntegrity: vi.fn(async () => REPORT),
    getLedgerEntries: vi.fn(async () => []),
    getBranches: vi.fn(async () => [{ name: 'main', primary: true, agent: false, state: 'running', used: '1G', refer: '1G', connections: 0, port: '5432' }]),
  }
})

import Integrity from './Integrity'
import { getStatus } from '../api'

const mockStatus = vi.mocked(getStatus)

const status = (over: Partial<Status> = {}): Status => ({
  mainReady: true, branches: 0, agents: 0, edition: 'standard', features: [],
  ha: {} as Status['ha'], storage: {} as Status['storage'],
  servers: { gateway: true, api: true }, ...over,
})

const show = () => render(<MemoryRouter><Integrity /></MemoryRouter>)

// The braces matter. mockImplementation and mockReset both return the mock, so
// an expression-bodied hook hands vitest a function -- which it takes for a
// teardown callback and *calls* after the test. With a rejecting implementation
// installed, that call produces a rejected promise nobody is waiting on, and
// the test fails with the component's own error message while the component is
// handling it correctly. Cost an hour; worth the four characters.
beforeEach(() => { mockStatus.mockImplementation(async () => status()) })
afterEach(cleanup)

it('locks the checkpoint button without the feature, and says what still works', async () => {
  mockStatus.mockResolvedValue(status())
  show()
  const btn = await screen.findByRole('button', { name: /Create checkpoint \(Enterprise\)/ })
  expect((btn as HTMLButtonElement).disabled).toBe(true)
  expect(await screen.findByText(/Verifying and checking anchors already written are unaffected/)).toBeTruthy()
})

// Locked, not hidden: a feature nobody can see sells nothing, and a button that
// vanished reads as a broken page.
it('does not hide the control', async () => {
  mockStatus.mockResolvedValue(status())
  show()
  await waitFor(() => expect(screen.getByRole('button', { name: /Create checkpoint/ })).toBeTruthy())
})

it('leaves the button working when the feature is licensed', async () => {
  mockStatus.mockResolvedValue(status({ edition: 'enterprise', features: ['anchors'] }))
  show()
  const btn = await screen.findByRole('button', { name: /^Create checkpoint$/ })
  expect((btn as HTMLButtonElement).disabled).toBe(false)
  expect(screen.queryByText(/Creating checkpoints is part of Enterprise/)).toBeNull()
})

// An engine too old to report features must not have its controls disabled by a
// newer console: unknown is not the same as refused.
it('assumes the control works when the engine cannot be asked', async () => {
  // Lazily, so the rejected promise is created on the call the component
  // makes and catches, not eagerly by the mock helper.
  mockStatus.mockImplementation(async () => { throw new Error('HTTP 404') }) // an engine too old for the route
  show()
  const btn = await screen.findByRole('button', { name: /^Create checkpoint$/ })
  expect((btn as HTMLButtonElement).disabled).toBe(false)
})
