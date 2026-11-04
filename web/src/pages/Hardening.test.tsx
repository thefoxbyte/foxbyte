// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getHardening: vi.fn(), getBranches: vi.fn().mockResolvedValue([{ name: 'main' }, { name: 'dev' }]) }
})

import { getHardening, type HardeningReport } from '../api'
import Hardening from './Hardening'

const report: HardeningReport = {
  branch: 'main', generated: '2026-11-05T10:00:00Z', postgres: '18.1', basis: "FoxByte's own hardening checks.",
  summary: { pass: 1, fail: 1, manual: 1, 'n/a': 1 },
  checks: [
    { id: 'roles.scram', section: 'roles', level: 'basic', title: 'Passwords stored with SCRAM-SHA-256', status: 'pass', evidence: 'scram-sha-256', why: 'MD5 is weak.' },
    { id: 'conn.idle', section: 'connections', level: 'strict', title: 'Sessions idle in a transaction ended', status: 'fail', evidence: 'never', why: 'Locks.', fix: "ALTER SYSTEM SET idle_in_transaction_session_timeout = '10min'" },
    { id: 'set.fips', section: 'settings', level: 'strict', title: 'FIPS-validated cryptography', status: 'manual', evidence: "the host's OpenSSL", why: 'Regulators.', fix: 'only where required' },
    { id: 'conn.ssl_protocol', section: 'connections', level: 'strict', title: 'TLS 1.2 or later', status: 'n/a', evidence: 'the Gateway encrypts', why: 'Old TLS.' },
  ],
  limits: ['It reads the branch as it is now.'],
}

describe('Hardening page', () => {
  afterEach(cleanup)

  it('shows each check by section, with what was found and the fix, and the basis it stands on', async () => {
    vi.mocked(getHardening).mockResolvedValue(report)
    render(<MemoryRouter><Hardening /></MemoryRouter>)
    expect((await screen.findByTestId('hardening-summary')).textContent).toContain('1 pass, 1 fail, 1 manual, 1 not applicable')
    const idle = screen.getByTestId('check-conn.idle')
    expect(idle.textContent).toContain('fail')
    expect(within(idle).getByText(/idle_in_transaction_session_timeout = '10min'/)).toBeTruthy()
    expect(screen.getByRole('table', { name: 'Hardening: roles' })).toBeTruthy()
    expect(screen.getByText("FoxByte's own hardening checks.")).toBeTruthy()
    expect(screen.getByRole('link', { name: 'JSON' }).getAttribute('href')).toContain('/api/hardening?branch=main')
  })

  it('filters to what did not pass, and to one level', async () => {
    vi.mocked(getHardening).mockResolvedValue(report)
    render(<MemoryRouter><Hardening /></MemoryRouter>)
    await screen.findByTestId('hardening-summary')
    fireEvent.click(screen.getByLabelText('Only what did not pass'))
    expect(screen.queryByTestId('check-roles.scram')).toBeNull()
    expect(screen.queryByTestId('check-conn.ssl_protocol')).toBeNull()
    expect(screen.getByTestId('check-set.fips')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Level'), { target: { value: 'basic' } })
    expect(screen.getByTestId('hardening-none')).toBeTruthy()
  })

  it('checks the chosen branch, and says why when it cannot', async () => {
    vi.mocked(getHardening).mockResolvedValueOnce(report).mockRejectedValueOnce(new Error('dev is not running — start it first'))
    render(<MemoryRouter><Hardening /></MemoryRouter>)
    await screen.findByTestId('hardening-summary')
    fireEvent.change(await screen.findByLabelText('Branch'), { target: { value: 'dev' } })
    fireEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/dev is not running/)).toBeTruthy()
    expect(getHardening).toHaveBeenLastCalledWith('dev')
  })
})
