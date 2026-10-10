// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Activating from the console. The point of the page is that somebody who met
// a locked feature here can fix it here, so the cases that matter are the ones
// where they cannot: a Standard build, a bad paste, and what is still left to
// do afterwards.
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { License } from '../api'

const ENTERPRISE: License = {
  edition: 'enterprise', present: false, state: 'invalid', unlocks: false,
  features: [], reason: 'no licence is installed', action: 'run `fox license activate <file>`',
}

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getLicense: vi.fn(), activateLicense: vi.fn() }
})

import LicensePage from './License'
import { getLicense, activateLicense } from '../api'

const mockGet = vi.mocked(getLicense)
const mockActivate = vi.mocked(activateLicense)

beforeEach(() => {
  vi.clearAllMocks()
  mockGet.mockResolvedValue(ENTERPRISE)
})
afterEach(cleanup)

it('offers a paste box and sends what was pasted', async () => {
  mockActivate.mockResolvedValue({
    activated: 'FB-EVAL-001', customer: 'FoxByte evaluation', edition: 'enterprise',
    state: 'active', unlocks: true, reason: '', action: '',
  })
  render(<LicensePage />)
  const box = await screen.findByLabelText('Licence')
  fireEvent.change(box, { target: { value: '{"id":"FB-EVAL-001"}' } })
  fireEvent.click(screen.getByRole('button', { name: 'Activate' }))
  await waitFor(() => expect(mockActivate).toHaveBeenCalledWith('{"id":"FB-EVAL-001"}'))
  const ok = await screen.findByTestId('licence-activated')
  expect(ok.textContent).toMatch(/Activated FB-EVAL-001/)
  expect(ok.textContent).toMatch(/paid features are available/)
})

it('will not submit an empty box', async () => {
  render(<LicensePage />)
  await screen.findByLabelText('Licence')
  expect(screen.getByRole('button', { name: 'Activate' })).toHaveProperty('disabled', true)
})

it('shows the engine’s refusal rather than swallowing it', async () => {
  const { ApiError } = await vi.importActual<typeof import('../api')>('../api')
  mockActivate.mockRejectedValue(new ApiError(400, 'the licence is not signed — nothing was installed'))
  render(<LicensePage />)
  fireEvent.change(await screen.findByLabelText('Licence'), { target: { value: '{}' } })
  fireEvent.click(screen.getByRole('button', { name: 'Activate' }))
  const err = await screen.findByTestId('licence-error')
  // Including the part that answers "did that half-work?".
  expect(err.textContent).toMatch(/nothing was installed/)
})

it('passes on what is still left to do', async () => {
  mockActivate.mockResolvedValue({
    activated: 'FB-EVAL-002', customer: 'FoxByte evaluation', edition: 'enterprise',
    state: 'active', unlocks: true, reason: '', action: '',
    notes: ['Restart the engine so the Gateway and the Agent API do too.'],
  })
  render(<LicensePage />)
  fireEvent.change(await screen.findByLabelText('Licence'), { target: { value: '{"id":"x"}' } })
  fireEvent.click(screen.getByRole('button', { name: 'Activate' }))
  expect((await screen.findByTestId('licence-activated')).textContent).toMatch(/Restart the engine/)
})

// A licence cannot unlock code that is not in the binary, so offering a box
// would be inviting somebody to paste one and wonder why nothing changed.
it('a Standard build says a licence cannot help, and offers no box', async () => {
  mockGet.mockResolvedValue({ ...ENTERPRISE, edition: 'standard' })
  render(<LicensePage />)
  expect(await screen.findByText(/This is the Standard edition/)).toBeTruthy()
  expect(screen.getByText(/not part of this build/)).toBeTruthy()
  expect(screen.getByText(/--edition enterprise/)).toBeTruthy()
  expect(screen.queryByLabelText('Licence')).toBeNull()
})

it('shows what is installed, and calls an unbound licence a site licence', async () => {
  mockGet.mockResolvedValue({
    ...ENTERPRISE, present: true, state: 'active', unlocks: true,
    features: ['realtime', 'anchors'], reason: '', action: '',
    id: 'FB-EVAL-001', customer: 'FoxByte evaluation',
    expires: '2027-01-07T18:18:33Z', issuedFor: '',
  })
  render(<LicensePage />)
  expect((await screen.findByTestId('licence-state')).textContent).toBe('active')
  expect(screen.getByText('FB-EVAL-001')).toBeTruthy()
  // An empty fingerprint is not "unknown": it is a licence tied to no machine,
  // which is a different thing and matters the first time a standby is
  // promoted somewhere else.
  expect(screen.getByText(/site licence/)).toBeTruthy()
})
