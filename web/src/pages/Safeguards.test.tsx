// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getSafeguards: vi.fn(), declareSafeguard: vi.fn(), getStatus: vi.fn() }
})

import { declareSafeguard, getSafeguards, getStatus, type SafeguardsEvidence, type Status } from '../api'
import { ConfirmProvider } from '../confirm'
import Safeguards from './Safeguards'

const status = (features: string[]) => ({ edition: 'enterprise', features }) as unknown as Status
const doc: SafeguardsEvidence = {
  format: 'safeguards-evidence/1', generated: '2026-11-28T10:00:00Z', by: 'admin@example.com', product: 'FoxByte', version: 'v1', edition: 'enterprise',
  rule: 'Digital Personal Data Protection Rules, 2025 (G.S.R. 846(E), 13 Nov 2025), Rule 6', inForce: '13 May 2027',
  summary: { 'met': 1, 'not met': 1, 'open': 1 },
  items: [{ item: 'processors', clause: '6(1)(f)', asks: 'Each Data Processor’s contract provides for safeguards.' }],
  rules: [
    { clause: '6(1)(c)', requirement: 'visibility on the accessing', verdict: 'met', items: [], declared: [], guards: 'Unseen access.', notAgainst: 'Logs no one reads.',
      checks: [{ what: 'The audit log is on', ok: true, basis: 'checked', detail: 'on' }] },
    { clause: '6(1)(d)', requirement: 'continued processing', verdict: 'not met', items: [], declared: [], guards: 'Loss.', notAgainst: 'Losing both.',
      checks: [{ what: 'A recent base backup exists', ok: false, basis: 'checked', detail: 'there is no base backup' }] },
    { clause: '6(1)(f)', requirement: 'provision in the contract', verdict: 'open', checks: null as unknown as [], items: ['processors'], declared: [], guards: 'A weaker processor.', notAgainst: 'Contracts unseen.' },
  ],
  limits: ['A declaration is the customer’s.'],
}

function page() { render(<MemoryRouter><ConfirmProvider><Safeguards /></ConfirmProvider></MemoryRouter>) }

describe('Safeguards evidence', () => {
  beforeEach(() => { vi.mocked(getStatus).mockResolvedValue(status(['dpdp'])); vi.mocked(getSafeguards).mockResolvedValue(doc) })
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('shows each clause with its verdict, checks and threat model, and offers the download', async () => {
    page()
    expect((await screen.findByTestId('safeguards-summary')).textContent).toContain('1 met, 1 not met, 1 open')
    const d = screen.getByTestId('safeguard-6(1)(d)')
    expect(d.textContent).toContain('not met')
    expect(d.textContent).toContain('✗ A recent base backup exists')
    expect(d.textContent).toContain('Not against: Losing both.')
    expect(screen.getByTestId('safeguards-download').getAttribute('href')).toContain('/api/dpdp/evidence?download=1')
  })

  it('declares an item for an open clause', async () => {
    vi.mocked(declareSafeguard).mockResolvedValue({ id: 1, kind: 'dpdp-safeguards', item: 'processors', value: 'No processor.', declared_by: 'dpo@x', declared_at: '2026-11-28T10:00:00Z' })
    page()
    const f = await screen.findByTestId('safeguard-6(1)(f)')
    fireEvent.click(within(f).getByRole('button', { name: 'Declare…' }))
    fireEvent.change(within(f).getByLabelText('Declaration: processors'), { target: { value: 'No processor.' } })
    fireEvent.click(within(f).getByRole('button', { name: 'Save the declaration' }))
    await waitFor(() => expect(declareSafeguard).toHaveBeenCalledWith('processors', 'No processor.'))
    expect((await screen.findByTestId('safeguards-msg')).textContent).toContain('Declared processors')
  })

  it('is refused without the licence', async () => {
    vi.mocked(getStatus).mockResolvedValue(status([]))
    page()
    expect(await screen.findByTestId('safeguards-locked')).toBeTruthy()
    expect(getSafeguards).not.toHaveBeenCalled()
  })
})
