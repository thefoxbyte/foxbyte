// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getVault: vi.fn(),
    getVaultKinds: vi.fn(),
    getVaultMine: vi.fn(),
    getVaultGrants: vi.fn(),
    getVaultLog: vi.fn(),
    grantVault: vi.fn(),
    revokeVaultGrant: vi.fn(),
    vaultTokenise: vi.fn(),
    vaultFind: vi.fn(),
    vaultDetokenise: vi.fn(),
    getStatus: vi.fn(),
  }
})

import {
  getStatus, getVault, getVaultGrants, getVaultKinds, getVaultLog, getVaultMine, grantVault, revokeVaultGrant, vaultDetokenise, vaultFind,
  vaultTokenise, type Status, type VaultGrant, type VaultKind, type VaultMine, type VaultState,
} from '../api'
import { ConfirmProvider } from '../confirm'
import Vault, { masked } from './Vault'

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

const KINDS: VaultKind[] = [
  { name: 'aadhaar', prefix: 'AR', check: '12 digits, the first 2 to 9, passing the Verhoeff check', legacy: '12 digits starting with 1, which no Aadhaar number does', rules: 'UIDAI Circular No. 14 of 2025', hsm_required: true },
  { name: 'text', prefix: 'TX', check: 'any text, up to 4,096 bytes', hsm_required: false },
]

const grant = (id: number, email: string, kind: string, permission: 'use' | 'detokenise', extra: Partial<VaultGrant> = {}): VaultGrant => ({
  id, email, kind, permission, per_hour: permission === 'detokenise' ? 100 : 100000, granted_by: 'admin@example.com',
  granted_at: '2026-11-15T10:00:00Z', used_last_hour: 0, ...extra,
})

const mine = (over: Partial<VaultMine> = {}): VaultMine => ({ set_up: true, admin: true, grants: [], kinds: KINDS, ...over })

function page() {
  render(<MemoryRouter><ConfirmProvider><Vault /></ConfirmProvider></MemoryRouter>)
}

describe('Vault page', () => {
  beforeEach(() => {
    for (const f of [getVault, getVaultMine, getVaultGrants, getVaultLog, grantVault, revokeVaultGrant, vaultTokenise, vaultFind, vaultDetokenise]) vi.mocked(f).mockReset()
    vi.mocked(getVaultKinds).mockResolvedValue(KINDS)
    vi.mocked(getVaultMine).mockResolvedValue(mine())
    vi.mocked(getVaultGrants).mockResolvedValue([])
    vi.mocked(getVaultLog).mockResolvedValue({ entries: [] })
    vi.mocked(getStatus).mockResolvedValue(status(['vault']))
  })
  afterEach(cleanup)

  it('is locked without the feature, and never asks the engine', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    page()
    expect((await screen.findByTestId('vault-locked')).textContent).toMatch(/part of Enterprise/)
    expect(getVaultMine).not.toHaveBeenCalled()
    expect(getVault).not.toHaveBeenCalled()
  })

  it('says how to set it up when the install has none', async () => {
    vi.mocked(getVaultMine).mockResolvedValue(mine({ set_up: false }))
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

  it('an admin holds no read-back by being one: no box to read values back without a grant', async () => {
    vi.mocked(getVault).mockResolvedValue(setUp)
    page()
    await screen.findByTestId('vault-tool')
    expect(screen.queryByTestId('vault-read')).toBeNull()
  })

  it('an account with no grant is told so, and asks nothing an admin would', async () => {
    vi.mocked(getVaultMine).mockResolvedValue(mine({ admin: false, kinds: [] }))
    page()
    expect((await screen.findByTestId('vault-mine')).textContent).toContain('You hold no vault grant')
    expect(getVault).not.toHaveBeenCalled()
    expect(getVaultGrants).not.toHaveBeenCalled()
    expect(screen.queryByTestId('vault-tool')).toBeNull()
    expect(screen.queryByTestId('vault-read')).toBeNull()
  })

  it('an account with a use grant on text may put text in, and nothing else', async () => {
    vi.mocked(getVaultMine).mockResolvedValue(mine({ admin: false, grants: [grant(4, 'dev@example.com', 'text', 'use', { used_last_hour: 3 })] }))
    page()
    expect((await screen.findByTestId('vault-mine')).textContent).toMatch(/Put in and find text values, 3 of 100000 this hour/)
    const kind = screen.getByLabelText('Kind') as HTMLSelectElement
    expect([...kind.options].map(o => o.value)).toEqual(['text'])
    expect(screen.queryByTestId('vault-read')).toBeNull()
    expect(screen.queryByLabelText('Vault grants')).toBeNull()
  })

  it('reads a value back with a purpose, shows it masked, and reveals it only when asked', async () => {
    vi.mocked(getVaultMine).mockResolvedValue(mine({ admin: false, grants: [grant(5, 'kyc@example.com', 'aadhaar', 'detokenise')] }))
    vi.mocked(vaultDetokenise).mockResolvedValue({ values: ['234123412346'], results: ['done'] })
    page()
    await screen.findByTestId('vault-read')
    fireEvent.change(screen.getByLabelText('Reference key'), { target: { value: 'AR' + '7'.repeat(26) } })
    const go = screen.getByText('Read back') as HTMLButtonElement
    expect(go.disabled).toBe(true) // no purpose yet
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'KYC re-check, ticket 42' } })
    fireEvent.click(go)
    await waitFor(() => expect(vaultDetokenise).toHaveBeenCalledWith('aadhaar', ['AR' + '7'.repeat(26)], 'KYC re-check, ticket 42'))
    expect((await screen.findByTestId('vault-value')).textContent).toBe('XXXX XXXX 2346')
    expect(document.body.textContent).not.toContain('234123412346')
    fireEvent.click(screen.getByText('Reveal'))
    expect(screen.getByTestId('vault-value').textContent).toBe('234123412346')
    fireEvent.click(screen.getByText('Hide'))
    expect(screen.getByTestId('vault-value').textContent).toBe('XXXX XXXX 2346')
  })

  it('says when a reference key is not there, or its record did not verify', async () => {
    vi.mocked(getVaultMine).mockResolvedValue(mine({ admin: false, grants: [grant(5, 'kyc@example.com', 'aadhaar', 'detokenise')] }))
    vi.mocked(vaultDetokenise).mockResolvedValueOnce({ values: [''], results: ['did not verify'] })
    page()
    await screen.findByTestId('vault-read')
    fireEvent.change(screen.getByLabelText('Reference key'), { target: { value: 'ARX' } })
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'audit' } })
    fireEvent.click(screen.getByText('Read back'))
    expect((await screen.findByTestId('vault-read-answer')).textContent).toMatch(/did not verify: it was changed, or moved/)
    expect(screen.queryByTestId('vault-value')).toBeNull()
  })

  it('shows the engine’s refusal: a limit reached, say', async () => {
    vi.mocked(getVaultMine).mockResolvedValue(mine({ admin: false, grants: [grant(5, 'kyc@example.com', 'aadhaar', 'detokenise', { used_last_hour: 100 })] }))
    vi.mocked(vaultDetokenise).mockRejectedValue(new Error('limit reached: the grant allows 100 values an hour, and 100 were used in the last hour'))
    page()
    await screen.findByTestId('vault-read')
    fireEvent.change(screen.getByLabelText('Reference key'), { target: { value: 'ARX' } })
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'audit' } })
    fireEvent.click(screen.getByText('Read back'))
    expect((await screen.findByTestId('vault-err')).textContent).toMatch(/limit reached/)
  })

  it('an admin gives a grant from the page', async () => {
    vi.mocked(getVault).mockResolvedValue(setUp)
    vi.mocked(grantVault).mockResolvedValue(grant(9, 'kyc@example.com', 'aadhaar', 'detokenise', { per_hour: 5 }))
    page()
    const form = await screen.findByRole('form', { name: 'Give a vault grant' })
    fireEvent.change(within(form).getByLabelText('Account'), { target: { value: 'kyc@example.com' } })
    fireEvent.change(within(form).getByLabelText('Permission'), { target: { value: 'detokenise' } })
    fireEvent.change(within(form).getByLabelText('Limit an hour'), { target: { value: '5' } })
    fireEvent.change(within(form).getByLabelText('Expires'), { target: { value: '7d' } })
    fireEvent.click(within(form).getByText('Give the grant'))
    await waitFor(() => expect(grantVault).toHaveBeenCalledWith({ email: 'kyc@example.com', kind: 'aadhaar', permission: 'detokenise', per_hour: 5, expires: '7d' }))
    expect((await screen.findByTestId('vault-msg')).textContent).toMatch(/Grant 9: kyc@example.com may read back aadhaar values, up to 5 an hour/)
  })

  it('an admin revokes a grant after confirming, and the log shows calls without values', async () => {
    vi.mocked(getVault).mockResolvedValue(setUp)
    vi.mocked(getVaultGrants).mockResolvedValue([grant(9, 'kyc@example.com', 'aadhaar', 'detokenise', { used_last_hour: 2 })])
    vi.mocked(getVaultLog).mockResolvedValue({ entries: [{ seq: 7, at: '2026-11-15T10:00:00Z', actor: 'kyc@example.com', action: 'detokenise', kind: 'aadhaar', refs: ['ARX'], n: 1, purpose: 'audit', result: 'done 1' }] })
    vi.mocked(revokeVaultGrant).mockResolvedValue(grant(9, 'kyc@example.com', 'aadhaar', 'detokenise', { revoked_at: '2026-11-16T10:00:00Z' }))
    page()
    const row = await screen.findByTestId('grant-kyc@example.com-aadhaar-detokenise')
    expect(row.textContent).toMatch(/read back.*2 of 100/)
    const log = screen.getByRole('table', { name: 'Vault access log' })
    expect(log.textContent).toMatch(/kyc@example.com.*detokenise.*aadhaar.*audit.*done 1/)
    fireEvent.click(within(row).getByText('Revoke…'))
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(revokeVaultGrant).toHaveBeenCalledWith(9))
  })

  it('masks a value read back by its kind', () => {
    expect(masked('aadhaar', '234123412346')).toBe('XXXX XXXX 2346')
    expect(masked('text', 'Asha Rao')).toBe('(8 characters)')
    expect(masked('pan', 'ABCDE1234F')).toBe('••••')
  })
})
