// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { getHardening, hardeningJsonUrl, type HardeningCheck, type HardeningReport } from '../api'
import { useBranches } from '../useBranches'

// The hardening report (point 3.2): how a branch's PostgreSQL, and the install
// around it, stand against FoxByte's hardening checks. Pass, fail, manual (a
// person judges, from the evidence) or not applicable; each with why it
// matters and the fix. Admins only, every edition. The page prints, for a PDF.

const LABEL: Record<HardeningCheck['status'], string> = { pass: 'pass', fail: 'fail', manual: 'manual', 'n/a': 'n/a' }

export default function Hardening() {
  const { branches } = useBranches()
  const [branch, setBranch] = useState('main')
  const [report, setReport] = useState<HardeningReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [level, setLevel] = useState<'' | 'basic' | 'strict'>('')
  const [open, setOpen] = useState(false) // only what did not pass

  const load = useCallback(async (b: string) => {
    setBusy(true); setErr('')
    try { setReport(await getHardening(b)) }
    catch (e) { setReport(null); setErr((e as Error).message) }
    finally { setBusy(false) }
  }, [])
  useEffect(() => { load('main') }, [load])

  const shown = (report?.checks ?? []).filter(c =>
    (!level || c.level === level) && (!open || c.status === 'fail' || c.status === 'manual'))
  const sections = [...new Set(shown.map(c => c.section))]
  const s = report?.summary

  return (
    <div className="fade-up hardening">
      <h1>Hardening</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        How a branch&rsquo;s PostgreSQL, and this install around it, stand against hardening checks: what passes, what
        fails and how to fix it, and what needs a person to judge.
      </p>

      <div className="row no-print" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
        <label className="field">Branch
          <select aria-label="Branch" value={branch} onChange={e => setBranch(e.target.value)}>
            {(branches.length ? branches.map(b => b.name) : ['main']).map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <button className="primary" onClick={() => load(branch)} disabled={busy}>{busy ? 'Checking…' : 'Check'}</button>
        <label className="field">Level
          <select aria-label="Level" value={level} onChange={e => setLevel(e.target.value as typeof level)}>
            <option value="">basic and strict</option>
            <option value="basic">basic</option>
            <option value="strict">strict</option>
          </select>
        </label>
        <label className="check-row"><input type="checkbox" checked={open} onChange={e => setOpen(e.target.checked)} /> Only what did not pass</label>
        {report && (
          <>
            <a className="btn ghost" href={hardeningJsonUrl(report.branch)} download={`hardening-${report.branch}.json`}>JSON</a>
            <button className="ghost" onClick={() => window.print()}>Print or save as PDF</button>
          </>
        )}
      </div>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {report && s && (
        <>
          <p className="muted" style={{ marginTop: 14 }} data-testid="hardening-summary">
            {report.branch}, PostgreSQL {report.postgres}, checked {new Date(report.generated).toLocaleString()}:{' '}
            <b>{s.pass}</b> pass, <b>{s.fail}</b> fail, <b>{s.manual}</b> manual, {s['n/a']} not applicable.
          </p>
          {sections.map(sec => (
            <div key={sec}>
              <h2 style={{ marginTop: 18, textTransform: 'capitalize' }}>{sec}</h2>
              <div className="table-wrap">
                <table aria-label={`Hardening: ${sec}`}>
                  <thead><tr><th>Status</th><th>Check</th><th>Found</th><th>Fix</th></tr></thead>
                  <tbody>
                    {shown.filter(c => c.section === sec).map(c => (
                      <tr key={c.id} data-testid={`check-${c.id}`}>
                        <td><span className={'badge' + (c.status === 'pass' ? ' primary' : '')}>{LABEL[c.status]}</span></td>
                        <td>
                          {c.title} <span className="muted" style={{ fontSize: 12 }}>({c.level})</span>
                          <div className="muted" style={{ fontSize: 12 }}>{c.why}</div>
                        </td>
                        <td style={{ fontSize: 13 }}>{c.evidence}</td>
                        <td style={{ fontSize: 13 }}>{c.fix ? <code>{c.fix}</code> : '–'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
          {shown.length === 0 && <p className="muted" data-testid="hardening-none">Nothing to show with these filters.</p>}
          <div className="panel" style={{ marginTop: 16 }}>
            <p style={{ marginTop: 0 }}>{report.basis}</p>
            <ul style={{ margin: 0 }}>{report.limits.map(l => <li key={l}>{l}</li>)}</ul>
          </div>
        </>
      )}
    </div>
  )
}
