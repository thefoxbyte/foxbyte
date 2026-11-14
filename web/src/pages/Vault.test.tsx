// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getVault: vi.fn(),
    getVaultKinds: vi.fn(),
    vaultTokenise: vi.fn(),
    vaultFind: vi.fn(),
    getStatus: vi.fn(),
  }
})

import { getStatus, getVault, getVaultKinds, vaultFind, vaultTokenise, type Status, type VaultState } from '../api'
import Vault from './Vault'

const status = (features: string[], edition: 'standard' | 'enterprise' = 'enterprise') =>
  ({ edition, features }) as unknown as Status

const key = (label: string, role: 'data' | 'index', records: number) => ({
  label, role, current: true, destroyed: false, uses: records, records,
  sensitive: true, extractable: false, always_sensitive: true, never_extractable: true, local: true,
})

const setUp: VaultState = {
  set_up: true,
  config: { set_up_at: '2026-11-14T10:00:00Z', subnet: '172.29.213.0/29', db_addr: '172.29.213.2', service_addr: '172.29.213.3', pg_major: '18', token: 'fox-vault' },
  database_running: true,
  service_running: true,
  status: {
    token: { label: 'fox-vault', maker: 'SoftHSM project', model: 'SoftHSM v2', serial: 'abc123', software: true },
    kinds: [
      { name: 'aadhaar', prefix: 'AR', rules: 'UIDAI Circular No. 14 of 2025', hsm_required: true, compliant: 'no: software token (trials and testing only)', records: 3,
        keys: [key('vault-aadhaar-data-1', 'data', 3), key('vault-aadhaar-index-1', 'index', 3)] },
      { name: 'text', prefix: 'TX', rules: '', hsm_required: false, compliant: 'no rules mapped', records: 1,
        keys: [key('vault-text-data-1', 'data', 1), key('vault-text-index-1', 'index', 1)] },
    ],
    log: { entries: 7, broken_at: 0, head: '7:' + 'a'.repeat(64) },
  },
  anchor: { recorded: '7:' + 'a'.repeat(64), holds: true, note: 'entry 7 is as the security log saw it' },
}

function page() {
  render(<MemoryRouter><Vault /></MemoryRouter>)
}

describe('Vault page', () => {
  beforeEach(() => {
    vi.mocked(getVault).mockReset()
    vi.mocked(vaultTokenise).mockReset()
    vi.mocked(vaultFind).mockReset()
    vi.mocked(getVaultKinds).mockResolvedValue([
      { name: 'aadhaar', prefix: 'AR', check: '12 digits, the first 2 to 9, passing the Verhoeff check', legacy: '12 digits starting with 1, which no Aadhaar number does', rules: 'UIDAI Circular No. 14 of 2025', hsm_required: true },
      { name: 'text', prefix: 'TX', check: 'any text, up to 4,096 bytes', hsm_required: false },
    ])
    vi.mocked(getStatus).mockResolvedValue(status(['vault']))
  })
  afterEach(cleanup)

  it('is locked without the feature, and never asks the engine', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    page()
    expect((await screen.findByTestId('vault-locked')).textContent).toMatch(/part of Enterprise/)
    expect(getVault).not.toHaveBeenCalled()
  })

  it('says how to set it up when the install has none', async () => {
    vi.mocked(getVault).mockResolvedValue({ set_up: false, database_running: false, service_running: false, anchor: { holds: true, note: '' } })
    page()
    expect((await screen.findByTestId('vault-state')).textContent).toMatch(/Not set up.*fox vault setup/)
    expect(getVaultKinds).not.toHaveBeenCalled()
  })

  it('shows the token, the kinds, the keys and the log, and that a software token is not compliant', async () => {
    vi.mocked(getVault).mockResolvedValue(setUp)
    page()
    expect((await screen.findByTestId('vault-token')).textContent).toMatch(/SoftHSM project.*not UIDAI-compliant/)
    expect((screen.getByTestId('vault-kind-aadhaar')).textContent).toMatch(/AR….*3.*Verhoeff.*UIDAI.*no: software token/)
    expect((screen.getByTestId('vault-kind-aadhaar')).textContent).toMatch(/legacy: 12 digits starting with 1/)
    expect((screen.getByTestId('vault-kind-text')).textContent).toMatch(/none mapped/)
    expect(screen.getAllByText('made in the token, never extractable')).toHaveLength(4)
    expect((screen.getByTestId('vault-log')).textContent).toMatch(/7 entries; the chain holds\. Against the security log: entry 7 is as the security log saw it/)
  })

  it('warns when the log was cut, or a key could leave the token', async () => {
    const bad = structuredClone(setUp)
    bad.anchor = { recorded: '9:' + 'b'.repeat(64), holds: false, note: 'the security log saw entry 9, which the vault’s access log no longer holds: entries were cut off its end' }
    bad.status!.kinds[0].keys[0].extractable = true
    vi.mocked(getVault).mockResolvedValue(bad)
    page()
    expect((await screen.findByTestId('vault-log')).textContent).toMatch(/cut off its end/)
    expect(screen.getByText(/not protected: it can leave the token/)).toBeTruthy()
  })

  it('puts a value in, shows its reference key, and does not keep the value', async () => {
    vi.mocked(getVault).mockResolvedValue(setUp)
    vi.mocked(vaultTokenise).mockResolvedValue({ refs: ['AR' + '7'.repeat(26)], new: [true], results: ['done'] })
    page()
    await screen.findByTestId('vault-tool')
    const input = screen.getByLabelText('Value') as HTMLInputElement
    expect(input.type).toBe('password')
    fireEvent.change(input, { target: { value: '2341 2341 2346' } })
    fireEvent.click(screen.getByLabelText('Legacy format'))
    fireEvent.click(screen.getByText('Put in the vault'))
    await waitFor(() => expect(vaultTokenise).toHaveBeenCalledWith('aadhaar', ['2341 2341 2346'], 'legacy'))
    expect((await screen.findByTestId('vault-ref')).textContent).toContain('AR' + '7'.repeat(26))
    expect((screen.getByTestId('vault-answer')).textContent).toMatch(/Put in the vault/)
    expect(input.value).toBe('')
  })

  it('finds a reference key, and says plainly when a value is not there or refused', async () => {
    vi.mocked(getVault).mockResolvedValue(setUp)
    vi.mocked(vaultFind).mockResolvedValueOnce({ refs: [''], results: ['not found'] })
    page()
    await screen.findByTestId('vault-tool')
    fireEvent.change(screen.getByLabelText('Value'), { target: { value: '234123412346' } })
    fireEvent.click(screen.getByText('Find'))
    expect((await screen.findByTestId('vault-answer')).textContent).toContain('Not in the vault.')
    vi.mocked(vaultTokenise).mockResolvedValueOnce({ refs: [''], new: [false], results: ['refused'] })
    fireEvent.change(screen.getByLabelText('Value'), { target: { value: '123412341234' } })
    fireEvent.click(screen.getByText('Put in the vault'))
    await waitFor(() => expect((screen.getByTestId('vault-answer')).textContent).toMatch(/Refused: not a aadhaar value/))
    expect(screen.queryByTestId('vault-ref')).toBeNull()
  })

  it('shows the engine’s refusal to a non-admin', async () => {
    vi.mocked(getVault).mockRejectedValue(new Error('the vault is for admins'))
    page()
    expect((await screen.findByTestId('vault-err')).textContent).toContain('the vault is for admins')
  })
})
