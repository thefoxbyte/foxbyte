// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getVaultEvidence: vi.fn(),
    getVaultDeclarations: vi.fn(),
    getVaultKinds: vi.fn(async () => []),
    declareVault: vi.fn(),
    getStatus: vi.fn(),
  }
})

import { declareVault, getStatus, getVaultDeclarations, getVaultEvidence, getVaultKinds, type Status, type VaultEvidence } from '../api'
import { ConfirmProvider } from '../confirm'
import VaultEvidencePage from './VaultEvidence'

const status = (features: string[], edition: 'standard' | 'enterprise' = 'enterprise') => ({ edition, features }) as unknown as Status

const doc = (over: Partial<VaultEvidence['kinds'][0]> = {}): VaultEvidence => ({
  format: 'vault-evidence/1', generated: '2026-11-22T12:00:00Z', by: 'admin@example.com', product: 'FoxByte', version: 'v1.9', edition: 'enterprise',
  since: '2026-08-24T12:00:00Z',
  token: { label: 'fox-vault', maker: 'SoftHSM project', model: 'SoftHSM v2', serial: 'abc', software: true },
  log: { entries: 12, broken_at: 0, head: '12:' + 'a'.repeat(64), anchor: { holds: true, note: 'entry 12 is as the security log saw it' } },
  kinds: [{
    kind: 'aadhaar', rules: 'UIDAI Circular No. 14 of 2025', hsm_required: true, records: 3, keys: [],
    activity: { calls: { tokenise: 4, delete: 1 }, values: {}, refused: 2, changed_since_data_key: 1 },
    grants: [], summary: { 'met': 1, 'not met': 1, 'open': 1 },
    rows: [
      { para: '2', requirement: 'A separate secure database', whose: 'FoxByte', verdict: 'met', checks: [{ what: 'the vault is set up', ok: true, basis: 'checked', detail: 'fox vault setup' }] },
      { para: '8', requirement: 'An HSM is mandatory', whose: 'FoxByte talks to it; the customer supplies it', verdict: 'not met',
        checks: [{ what: 'the token is an HSM, not FoxByte’s software token', ok: false, basis: 'checked', detail: 'SoftHSM project SoftHSM v2: the software token, for trials and testing only' }] },
      { para: '5', requirement: 'Hosted on premises, GCC or as a service', whose: 'The customer', verdict: 'open', checks: [], items: ['hosting'] },
    ],
    branches: [
      { branch: 'main', state: 'running', run: 4, ran: '2026-11-21T10:00:00Z', numbers: 0, people: 0, log_numbers: 0 },
      { branch: 'dev', state: 'running', numbers: 0, people: 0, log_numbers: 0, flag: 'never scanned' },
    ],
    ...over,
  }],
  limits: ['A declaration is the customer’s statement.'],
})

function page() {
  render(<MemoryRouter><ConfirmProvider><VaultEvidencePage /></ConfirmProvider></MemoryRouter>)
}

describe('Vault evidence page', () => {
  beforeEach(() => {
    vi.mocked(getStatus).mockResolvedValue(status(['vault']))
    vi.mocked(getVaultEvidence).mockReset().mockResolvedValue(doc())
    vi.mocked(getVaultDeclarations).mockReset().mockResolvedValue({ items: [{ item: 'hosting', para: '5', asks: 'Where the vault is hosted' }], declarations: [] })
    vi.mocked(declareVault).mockReset()
    vi.mocked(getVaultKinds).mockResolvedValue([])
  })
  afterEach(cleanup)

  it('is locked without the feature, and never asks the engine', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([], 'standard'))
    page()
    expect(await screen.findByTestId('vault-evidence-locked')).toBeTruthy()
    expect(getVaultEvidence).not.toHaveBeenCalled()
  })

  it('shows each rule with its verdict and why, the software token, the branches, and the limits', async () => {
    page()
    expect((await screen.findByTestId('evidence-summary')).textContent).toMatch(/UIDAI Circular No\. 14 of 2025: 1 met, 1 not met, 1 open/)
    expect(getVaultEvidence).toHaveBeenCalledWith('aadhaar', '90d')
    expect((screen.getByTestId('rule-8')).textContent).toMatch(/not met.*✗ the token is an HSM.*software token, for trials/)
    expect((screen.getByTestId('rule-2')).textContent).toMatch(/met.*✓ the vault is set up \(checked: fox vault setup\)/)
    expect((screen.getByTestId('rule-5')).textContent).toMatch(/open.*hosting: not declared/)
    expect((screen.getByTestId('evidence-head')).textContent).toMatch(/not UIDAI-compliant.*12 entries; the chain holds/)
    expect((screen.getByTestId('evidence-branch-dev')).textContent).toMatch(/never.*never scanned/)
    expect((screen.getByTestId('evidence-branch-main')).textContent).toMatch(/clean/)
    expect((screen.getByTestId('evidence-activity')).textContent).toMatch(/tokenise 4, delete 1; 2 refusal\(s\)\. 1 value\(s\) deleted or replaced/)
    expect((screen.getByTestId('evidence-limits')).textContent).toMatch(/customer’s statement/)
    const dl = screen.getByText('Download (JSON)') as HTMLAnchorElement
    expect(dl.getAttribute('href')).toMatch(/\/api\/vault\/evidence\?kind=aadhaar&since=90d$/)
    expect((screen.getByText('With the access log') as HTMLAnchorElement).getAttribute('href')).toMatch(/&entries=1$/)
  })

  it('declares an item from its rule, says it is declared and not checked, and reads the evidence again', async () => {
    vi.mocked(declareVault).mockResolvedValue({ id: 1, kind: 'aadhaar', item: 'hosting', value: 'on premises, Mumbai', declared_by: 'admin@example.com', declared_at: '2026-11-22T12:00:00Z' })
    page()
    const row = await screen.findByTestId('rule-5')
    fireEvent.click(within(row).getByText('Declare…'))
    const box = await screen.findByTestId('vault-declare')
    expect(box.textContent).toMatch(/Where the vault is hosted/)
    fireEvent.change(within(box).getByLabelText('Declaration: hosting'), { target: { value: 'on premises, Mumbai' } })
    fireEvent.click(within(box).getByText('Save the declaration'))
    await waitFor(() => expect(declareVault).toHaveBeenCalledWith('aadhaar', 'hosting', 'on premises, Mumbai'))
    expect((await screen.findByTestId('evidence-msg')).textContent).toMatch(/declared, not checked/)
    await waitFor(() => expect(getVaultEvidence).toHaveBeenCalledTimes(2))
  })

  it('shows a declaration with who and when, and withdraws it after confirming', async () => {
    const declared = doc()
    declared.kinds[0].rows[2] = { ...declared.kinds[0].rows[2], verdict: 'met',
      declared: [{ id: 3, kind: 'aadhaar', item: 'hosting', value: 'on premises, Pune', declared_by: 'ops@example.com', declared_at: '2026-11-20T10:00:00Z' }] }
    vi.mocked(getVaultEvidence).mockResolvedValue(declared)
    vi.mocked(declareVault).mockResolvedValue({ id: 4, kind: 'aadhaar', item: 'hosting', value: '', declared_by: 'admin@example.com', declared_at: '2026-11-22T12:00:00Z' })
    page()
    const row = await screen.findByTestId('rule-5')
    expect(row.textContent).toMatch(/Declared hosting by ops@example.com on .*“on premises, Pune”/)
    fireEvent.click(within(row).getByText('Change…'))
    fireEvent.click(within(await screen.findByTestId('vault-declare')).getByText('Withdraw…'))
    fireEvent.click(await screen.findByRole('button', { name: 'Withdraw' }))
    await waitFor(() => expect(declareVault).toHaveBeenCalledWith('aadhaar', 'hosting', ''))
    expect((await screen.findByTestId('evidence-msg')).textContent).toMatch(/hosting is open again/)
  })

  it('says plainly when a kind has no rules mapped, and shows the engine’s refusal', async () => {
    vi.mocked(getVaultEvidence).mockResolvedValueOnce(doc({ kind: 'aadhaar', rows: [], rules: '' }))
    page()
    expect(await screen.findByTestId('evidence-no-rules')).toBeTruthy()
    vi.mocked(getVaultEvidence).mockRejectedValue(new Error('the vault is for admins'))
    fireEvent.click(screen.getByText('Read it again'))
    expect((await screen.findByTestId('evidence-err')).textContent).toBe('the vault is for admins')
  })
})
