// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A banner is the easiest thing in an application to get wrong, and every rule
// in LicenseBanner.tsx is a decision that a later change could quietly undo.
// These are those rules, asserted.
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { License } from '../api'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getLicense: vi.fn() }
})

import LicenseBanner from './LicenseBanner'
import { getLicense } from '../api'

const mockGet = vi.mocked(getLicense)

const lic = (over: Partial<License> = {}): License => ({
  edition: 'enterprise', present: true, state: 'active', unlocks: true,
  features: ['anchors'], reason: '', action: '', ...over,
})

beforeEach(() => {
  sessionStorage.clear()
  mockGet.mockReset()
})
afterEach(cleanup)

// Nothing is wrong, so nothing is said. A notice that is always there is
// wallpaper, and the next one that matters goes unread.
it('says nothing about a working licence', async () => {
  mockGet.mockResolvedValue(lic())
  const { container } = render(<LicenseBanner />)
  await waitFor(() => expect(mockGet).toHaveBeenCalled())
  expect(container.querySelector('.lic-banner')).toBeNull()
})

// A Standard user is not a failed Enterprise user. A permanent strip about a
// licence they never bought is an advert, not a notice.
it('says nothing in the standard edition', async () => {
  mockGet.mockResolvedValue(lic({ edition: 'standard', present: false, state: 'invalid', unlocks: false }))
  const { container } = render(<LicenseBanner />)
  await waitFor(() => expect(mockGet).toHaveBeenCalled())
  expect(container.querySelector('.lic-banner')).toBeNull()
})

it('reports a warning in amber, with the reason and what to do', async () => {
  mockGet.mockResolvedValue(lic({
    state: 'warning', unlocks: true,
    reason: 'the licence expired on 1 October 2027',
    action: 'renew it within 9 days, after which the paid features stop',
  }))
  render(<LicenseBanner />)
  const el = await screen.findByRole('status')
  expect(el.className).toContain('lic-banner')
  expect(el.className).toContain('warn')
  expect(screen.getByText(/expired on 1 October 2027/)).toBeTruthy()
  expect(screen.getByText(/renew it within 9 days/)).toBeTruthy()
})

// A lapse has taken the paid features away. It is red, it is an alert to a
// screen reader, and it cannot be closed.
it('reports a lapse in red and does not let it be dismissed', async () => {
  mockGet.mockResolvedValue(lic({ state: 'lapsed', unlocks: false, reason: 'the licence expired', action: 'renew it' }))
  render(<LicenseBanner />)
  const el = await screen.findByRole('alert')
  expect(el.className).toContain('lic-banner')
  expect(el.className).toContain('stop')
  expect(screen.queryByLabelText('Dismiss this notice')).toBeNull()
})

it('tells an enterprise build with no licence how to install one', async () => {
  mockGet.mockResolvedValue(lic({
    present: false, state: 'invalid', unlocks: false,
    reason: 'no licence is installed', action: 'run `fox license activate <file>`',
  }))
  render(<LicenseBanner />)
  expect(await screen.findByText('No licence is installed')).toBeTruthy()
  expect(screen.getByText(/fox license activate/)).toBeTruthy()
  // The headline already is the reason; printing it again underneath reads as
  // a stutter, which is what it did the first time this was rendered.
  expect(screen.queryAllByText('no licence is installed')).toHaveLength(0)
})

// Grace exists so that an expiry does not interrupt anyone. A strip that cannot
// be closed interrupts them for a fortnight.
it('stays dismissed for the same problem and comes back for a different one', async () => {
  const expiring = lic({ state: 'warning', reason: 'the licence expired on 1 October 2027', action: 'renew it' })
  mockGet.mockResolvedValue(expiring)
  const first = render(<LicenseBanner />)
  fireEvent.click(await screen.findByLabelText('Dismiss this notice'))
  await waitFor(() => expect(first.container.querySelector('.lic-banner')).toBeNull())

  // Reloading the console must not bring the same notice back.
  cleanup()
  const again = render(<LicenseBanner />)
  await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
  expect(again.container.querySelector('.lic-banner')).toBeNull()

  // But a different problem is a different notice.
  cleanup()
  mockGet.mockResolvedValue(lic({ state: 'warning', reason: 'this licence was activated on a different machine', action: 'rebind it' }))
  const third = render(<LicenseBanner />)
  await waitFor(() => expect(third.container.querySelector('.lic-banner')).not.toBeNull())
})

// An engine too old to have the route, or one that cannot answer, must leave
// the console exactly as it was.
it('leaves the page alone when the engine cannot answer', async () => {
  mockGet.mockRejectedValue(new Error('HTTP 404'))
  const { container } = render(<LicenseBanner />)
  await waitFor(() => expect(mockGet).toHaveBeenCalled())
  expect(container.querySelector('.lic-banner')).toBeNull()
})
