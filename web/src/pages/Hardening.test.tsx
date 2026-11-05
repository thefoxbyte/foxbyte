// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getHardening: vi.fn(), getBranches: vi.fn().mockResolvedValue([{ name: 'main' }, { name: 'dev' }]),
    getStatus: vi.fn(), planHardeningFix: vi.fn(), applyHardeningFix: vi.fn(), planHardeningProfile: vi.fn(), applyHardeningProfile: vi.fn() }
})

import { applyHardeningFix, applyHardeningProfile, getHardening, getStatus, planHardeningFix, planHardeningProfile, type HardeningReport, type Status } from '../api'
import { ConfirmProvider } from '../confirm'
import Hardening from './Hardening'

function page() { render(<MemoryRouter><ConfirmProvider><Hardening /></ConfirmProvider></MemoryRouter>) }
const licensed = (yes: boolean) => vi.mocked(getStatus).mockResolvedValue(
  { edition: yes ? 'enterprise' : 'standard', features: yes ? ['hardening'] : [] } as unknown as Status)

const report: HardeningReport = {
  branch: 'main', generated: '2026-11-05T10:00:00Z', postgres: '18.1', basis: "FoxByte's own hardening checks.",
  summary: { pass: 1, fail: 1, manual: 1, 'n/a': 1 },
  checks: [
    { id: 'roles.scram', section: 'roles', level: 'basic', title: 'Passwords stored with SCRAM-SHA-256', status: 'pass', evidence: 'scram-sha-256', why: 'MD5 is weak.' },
    { id: 'conn.idle', section: 'connections', level: 'strict', title: 'Sessions idle in a transaction ended', status: 'fail', evidence: 'never', why: 'Locks.', fix: "ALTER SYSTEM SET idle_in_transaction_session_timeout = '10min'", fixable: true },
    { id: 'set.fips', section: 'settings', level: 'strict', title: 'FIPS-validated cryptography', status: 'manual', evidence: "the host's OpenSSL", why: 'Regulators.', fix: 'only where required' },
    { id: 'conn.ssl_protocol', section: 'connections', level: 'strict', title: 'TLS 1.2 or later', status: 'n/a', evidence: 'the Gateway encrypts', why: 'Old TLS.' },
  ],
  limits: ['It reads the branch as it is now.'],
}

describe('Hardening page', () => {
  afterEach(cleanup)
  beforeEach(() => licensed(true))

  it('shows each check by section, with what was found and the fix, and the basis it stands on', async () => {
    vi.mocked(getHardening).mockResolvedValue(report)
    page()
    expect((await screen.findByTestId('hardening-summary')).textContent).toContain('1 pass, 1 fail, 1 manual, 1 not applicable')
    const idle = screen.getByTestId('check-conn.idle')
    expect(idle.textContent).toContain('fail')
    expect(within(idle).getByRole('button', { name: 'Fix…' })).toBeTruthy() // fixable here: a fix, not a command
    expect(within(screen.getByTestId('check-set.fips')).getByText('only where required')).toBeTruthy()
    expect(screen.getByRole('table', { name: 'Hardening: roles' })).toBeTruthy()
    expect(screen.getByText("FoxByte's own hardening checks.")).toBeTruthy()
    expect(screen.getByRole('link', { name: 'JSON' }).getAttribute('href')).toContain('/api/hardening?branch=main')
  })

  it('filters to what did not pass, and to one level', async () => {
    vi.mocked(getHardening).mockResolvedValue(report)
    page()
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
    page()
    await screen.findByTestId('hardening-summary')
    fireEvent.change(await screen.findByLabelText('Branch'), { target: { value: 'dev' } })
    fireEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/dev is not running/)).toBeTruthy()
    expect(getHardening).toHaveBeenLastCalledWith('dev')
  })

  const idleFix = { id: 'conn.idle', title: 'Sessions idle in a transaction ended', level: 'strict', changes: ['idle_in_transaction_session_timeout: 0 → 10min'],
    sql: ["ALTER SYSTEM SET idle_in_transaction_session_timeout = '10min'"] }

  it('fixes a check after showing what it changes, and checks again', async () => {
    vi.mocked(getHardening).mockResolvedValue(report)
    vi.mocked(planHardeningFix).mockResolvedValue({ fix: idleFix })
    vi.mocked(applyHardeningFix).mockResolvedValue({ result: { fix: idleFix, before: report.checks[1], after: { ...report.checks[1], status: 'pass' } } })
    page()
    fireEvent.click(within(await screen.findByTestId('check-conn.idle')).getByRole('button', { name: 'Fix…' }))
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByTestId('plan-conn.idle').textContent).toContain('idle_in_transaction_session_timeout: 0 → 10min')
    fireEvent.click(within(dlg).getByRole('button', { name: 'Make this change' }))
    expect((await screen.findByTestId('hardening-msg')).textContent).toBe('conn.idle: fail → pass.')
    expect(applyHardeningFix).toHaveBeenCalledWith('main', 'conn.idle')
  })

  it('previews a profile, with what it leaves to a person, and applies it', async () => {
    vi.mocked(getHardening).mockResolvedValue(report)
    vi.mocked(planHardeningProfile).mockResolvedValue({ fixes: [idleFix], manual: [{ ...report.checks[2], status: 'fail' }] })
    vi.mocked(applyHardeningProfile).mockResolvedValue({ results: [{ fix: idleFix, before: report.checks[1], after: { ...report.checks[1], status: 'pass' } }] })
    page()
    const profiles = await screen.findByTestId('hardening-profiles')
    fireEvent.change(within(profiles).getByLabelText('Profile'), { target: { value: 'strict' } })
    fireEvent.click(within(profiles).getByRole('button', { name: 'Preview' }))
    const pv = await screen.findByTestId('profile-preview')
    expect(pv.textContent).toContain('idle_in_transaction_session_timeout')
    expect(pv.textContent).toContain('left to a person: set.fips')
    fireEvent.click(within(profiles).getByRole('button', { name: 'Apply strict' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Make 1 change(s)' }))
    expect((await screen.findByTestId('hardening-msg')).textContent).toBe('The strict profile: 1 fix(es) made.')
    expect(applyHardeningProfile).toHaveBeenCalledWith('main', 'strict')
  })

  it('without the licence, the report is all there and fixing says it is Enterprise', async () => {
    licensed(false)
    vi.mocked(getHardening).mockResolvedValue(report)
    page()
    await screen.findByTestId('hardening-summary')
    await within(screen.getByTestId('hardening-profiles')).findByText(/part of Enterprise/)
    expect(screen.queryByRole('button', { name: 'Fix…' })).toBeNull()
    expect(within(screen.getByTestId('check-conn.idle')).getByText(/10min/)).toBeTruthy()
  })
})
