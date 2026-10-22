// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, listApps: vi.fn(), registerApp: vi.fn(), addAppKey: vi.fn(), revokeAppKey: vi.fn(), removeApp: vi.fn() }
})

import { addAppKey, listApps, registerApp, revokeAppKey, removeApp, type AppsReply } from '../api'
import { ConfirmProvider } from '../confirm'
import Applications from './Applications'

const reply: AppsReply = {
  install_id: 'install-0123456789abcdef0123',
  apps: [{
    name: 'shop', user_id: 2, account: 'shop@example.com', created: 1792600000, max_life_seconds: 300, on_invalid: 'none',
    keys: [
      { kid: 'k1', public_key: 'ab'.repeat(32), created: 1792600000 },
      { kid: 'k0', public_key: 'cd'.repeat(32), created: 1792500000, revoked: 1792550000, compromised_since: 1792540000 },
    ],
  }],
  readiness: { main: 'checked', old: 'unavailable' },
}

function page() { render(<MemoryRouter><ConfirmProvider><Applications /></ConfirmProvider></MemoryRouter>) }

describe('Applications page', () => {
  beforeEach(() => {
    vi.mocked(listApps).mockReset().mockResolvedValue(reply)
    for (const f of [registerApp, addAppKey, revokeAppKey, removeApp]) vi.mocked(f).mockReset().mockResolvedValue({})
  })
  afterEach(cleanup)

  it('shows the audience, the applications and their keys, and which branches cannot check tokens', async () => {
    page()
    expect((await screen.findByTestId('install-id')).textContent).toContain('install-0123456789abcdef0123')
    const keys = screen.getByRole('table', { name: 'Keys of shop' })
    expect(keys.textContent).toMatch(/k1.*active/)
    expect(keys.textContent).toMatch(/k0.*revoked.*reported compromised/)
    expect(screen.getByTestId('not-ready').textContent).toContain('old (its container predates the image')
    expect(screen.getByTestId('app-shop').textContent).toContain('shop@example.com')
  })

  it('registers an application with its key', async () => {
    page()
    await screen.findByTestId('app-shop')
    fireEvent.change(screen.getByPlaceholderText('shop'), { target: { value: 'billing' } })
    fireEvent.change(screen.getByPlaceholderText('shop-service@example.com'), { target: { value: 'billing@example.com' } })
    fireEvent.change(screen.getByPlaceholderText(/openssl pkey/), { target: { value: 'ef'.repeat(32) } })
    vi.mocked(registerApp).mockResolvedValue({ unsynced: { qa: 'not reachable' } })
    fireEvent.click(screen.getByRole('button', { name: 'Register' }))
    await waitFor(() => expect(registerApp).toHaveBeenCalledWith({
      name: 'billing', account: 'billing@example.com', max_life_seconds: 300, on_invalid: 'none', public_key: 'ef'.repeat(32), kid: undefined,
    }))
    expect((await screen.findByRole('status')).textContent).toMatch(/Registered billing\. Not yet copied to qa/)
  })

  it('refuses to register without a name and an account', async () => {
    page()
    await screen.findByTestId('app-shop')
    fireEvent.click(screen.getByRole('button', { name: 'Register' }))
    expect((await screen.findByText(/needs a name and the account/))).toBeTruthy()
    expect(registerApp).not.toHaveBeenCalled()
  })

  it('reports a key compromised only after confirming, and only the active key offers it', async () => {
    page()
    await screen.findByTestId('app-shop')
    const buttons = screen.getAllByRole('button', { name: 'Report compromised' })
    expect(buttons).toHaveLength(1)
    fireEvent.click(buttons[0])
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke and report' }))
    await waitFor(() => expect(revokeAppKey).toHaveBeenCalledWith('shop', 'k1', 'now'))
  })

  it('adds a key, and removes an application after confirming', async () => {
    page()
    await screen.findByTestId('app-shop')
    fireEvent.click(screen.getByRole('button', { name: 'Add key' }))
    fireEvent.change(screen.getByLabelText('New public key for shop'), { target: { value: '01'.repeat(32) } })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(addAppKey).toHaveBeenCalledWith('shop', '01'.repeat(32)))
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(removeApp).toHaveBeenCalledWith('shop'))
  })
})
