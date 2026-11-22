// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getVaultMigrations: vi.fn(), migrateToVault: vi.fn() }
})

import { ApiError, getVaultMigrations, migrateToVault, type VaultMigration } from '../api'
import { ConfirmProvider } from '../confirm'
import VaultMigrate from './VaultMigrate'

const col = (column: string, over: Partial<VaultMigration['columns'][number]> = {}) => ({
  schema: 'public', table: 'kyc', column, type: 'text', format: 'opaque', rows: 2, numbers: 3, replaced: 2, left: 0, ...over,
})

const run = (over: Partial<VaultMigration> = {}): VaultMigration => ({
  id: 5, branch: 'rehearse', kind: 'aadhaar', actor: 'ops@example.com', dry: false, state: 'done', started: '2026-11-21T10:00:00Z',
  columns: [col('aadhaar'), col('legacy_id', { type: 'bigint', format: 'legacy' }), col('remote', { skipped: 'the table has no primary key', type: '' })],
  distinct: 3, made: 2, reused: 1, passes: 1, limits: ['Run the exposure report again to see what the branch still holds.'], ...over,
})

function panel(branch = 'rehearse', admin = false) {
  render(<ConfirmProvider><VaultMigrate branch={branch} admin={admin} licensed /></ConfirmProvider>)
}

describe('Move into the vault', () => {
  beforeEach(() => {
    vi.mocked(getVaultMigrations).mockReset().mockResolvedValue([])
    vi.mocked(migrateToVault).mockReset()
  })
  afterEach(cleanup)

  it('previews without confirming: the columns, their keys, and what is skipped', async () => {
    vi.mocked(migrateToVault).mockResolvedValue(run({ dry: true, made: 0, reused: 0, columns: [col('aadhaar', { replaced: 0 }), col('remote', { skipped: 'the table has no primary key' })] }))
    panel()
    fireEvent.click(await screen.findByRole('button', { name: 'Preview' }))
    await waitFor(() => expect(migrateToVault).toHaveBeenCalledWith('rehearse', { dryRun: true }))
    const t = await screen.findByRole('table', { name: 'Columns moved' })
    expect(t.textContent).toMatch(/public\.kyc\.aadhaar.*opaque/)
    expect(t.textContent).toMatch(/skipped: the table has no primary key/)
    expect(screen.getByTestId('vault-migration-summary').textContent).toMatch(/^Preview 5: 3 distinct number\(s\) in 2 column\(s\)\./)
  })

  it('moves a branch after confirming, and says when every column is clean', async () => {
    vi.mocked(migrateToVault).mockResolvedValue(run({ columns: [col('aadhaar'), col('legacy_id', { type: 'bigint', format: 'legacy' })] }))
    vi.mocked(getVaultMigrations).mockResolvedValueOnce([]).mockResolvedValue([run()])
    panel()
    fireEvent.click(await screen.findByRole('button', { name: 'Move into the vault' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Move' }))
    await waitFor(() => expect(migrateToVault).toHaveBeenCalledWith('rehearse', { dryRun: false }))
    expect((await screen.findByTestId('vault-migration-summary')).textContent).toMatch(/2 key\(s\) made in the vault, 1 it held already\. Every column is moved, with no number left\./)
    const runs = await screen.findByRole('table', { name: 'Vault migrations' })
    expect(within(runs).getByText('ops@example.com')).toBeTruthy()
  })

  it('after a preview, moves only the columns left ticked', async () => {
    vi.mocked(migrateToVault).mockResolvedValueOnce(run({ dry: true, columns: [col('aadhaar'), col('note'), col('remote', { skipped: 'no primary key' })] }))
      .mockResolvedValueOnce(run({ columns: [col('aadhaar')] }))
    panel()
    fireEvent.click(await screen.findByRole('button', { name: 'Preview' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Move public.kyc.note' }))
    expect(screen.queryByRole('checkbox', { name: 'Move public.kyc.remote' })).toBeNull()
    expect(screen.getByText('1 column(s) ticked in the preview')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Move into the vault' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Move' }))
    await waitFor(() => expect(migrateToVault).toHaveBeenLastCalledWith('rehearse', { columns: ['public.kyc.aadhaar'], dryRun: false }))
  })

  it('does nothing when the move is not confirmed', async () => {
    panel()
    fireEvent.click(await screen.findByRole('button', { name: 'Move into the vault' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await new Promise(r => setTimeout(r, 20))
    expect(migrateToVault).not.toHaveBeenCalled()
  })

  it('shows what is left in a column, and why', async () => {
    vi.mocked(migrateToVault).mockResolvedValue(run({ columns: [col('legacy_id', { type: 'bigint', format: 'legacy', left: 1, left_why: { 'its key in the vault is opaque, which this column cannot hold': 1 } })] }))
    panel()
    fireEvent.click(await screen.findByRole('button', { name: 'Move into the vault' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Move' }))
    expect((await screen.findByRole('table', { name: 'Columns moved' })).textContent).toMatch(/1: its key in the vault is opaque, which this column cannot hold/)
    expect(screen.getByTestId('vault-migration-summary').textContent).not.toMatch(/no number left/)
  })

  it('on main: an admin is told it needs a rehearsal; anyone else cannot move it', async () => {
    vi.mocked(migrateToVault).mockRejectedValue(new ApiError(409, 'not rehearsed: main is moved into the vault only after a branch made from main has moved the same columns'))
    panel('main', true)
    fireEvent.click(await screen.findByRole('button', { name: 'Move main' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Move' }))
    expect((await screen.findByText(/only after a branch made from main/, { selector: '.err' }))).toBeTruthy()
    cleanup()
    panel('main', false)
    expect((await screen.findByRole('button', { name: 'Move main' })).hasAttribute('disabled')).toBe(true)
    expect((screen.getByRole('button', { name: 'Preview' })).hasAttribute('disabled')).toBe(false)
  })
})
