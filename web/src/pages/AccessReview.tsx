// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { accessReviewCsvUrl, getAccessReview, type AccessReview as Report } from '../api'
import { useFeatures, why } from '../features'

// The access review report (point 4.8): who can reach what, with which keys,
// who may override the guardrails where, and who has gone quiet. Admins only,
// and Enterprise. The tables download as CSV; the page prints, for a PDF.

const day = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString() : 'never')

export default function AccessReview() {
  const [dormant, setDormant] = useState('90')
  const [days, setDays] = useState(90)
  const [report, setReport] = useState<Report | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const { can, edition } = useFeatures()
  const licensed = can('access-review')

  const load = useCallback(async (n: number) => {
    setBusy(true); setErr('')
    try { setReport(await getAccessReview(n)) }
    catch (e) { setReport(null); setErr((e as Error).message) }
    finally { setBusy(false) }
  }, [])
  useEffect(() => { if (licensed) load(90) }, [licensed, load])

  const produce = () => {
    const n = Number(dormant)
    if (!Number.isInteger(n) || n < 1 || n > 3650) { setErr('Dormant is 1 to 3,650 days.'); return }
    setDays(n)
    load(n)
  }

  const s = report?.summary
  const stat = (label: string, value: number) => (
    <div className="panel" style={{ padding: '10px 14px', minWidth: 120 }}>
      <div className="muted" style={{ fontSize: 12 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700 }}>{value}</div>
    </div>
  )

  return (
    <div className="fade-up access-review">
      <h1>Access review</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Every account, what it can reach and with which keys, who may override the guardrails, and who has gone quiet.
      </p>

      {edition && !licensed && (
        <div className="panel" style={{ marginTop: 8 }}><p style={{ margin: 0 }}>{why(edition, 'The access review report')}</p></div>
      )}

      {licensed && (
        <div className="row no-print" style={{ flexWrap: 'wrap', gap: 10 }}>
          <label className="muted" style={{ fontSize: 13 }} htmlFor="ar-dormant">Dormant after (days)</label>
          <input id="ar-dormant" type="number" min={1} max={3650} value={dormant} style={{ width: 90 }}
            onChange={e => setDormant(e.target.value)} />
          <button className="primary" onClick={produce} disabled={busy}>{busy ? 'Producing…' : 'Produce report'}</button>
          {report && (
            <>
              <span className="muted" style={{ fontSize: 13, marginLeft: 8 }}>CSV:</span>
              {(['accounts', 'keys', 'branches'] as const).map(sec => (
                <a key={sec} className="btn ghost" href={accessReviewCsvUrl(days, sec)} download>{sec[0].toUpperCase() + sec.slice(1)}</a>
              ))}
              <button className="ghost" onClick={() => window.print()}>Print or save as PDF</button>
            </>
          )}
        </div>
      )}

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {report && s && (
        <>
          <p className="muted" style={{ marginTop: 14 }} data-testid="ar-generated">
            Produced {new Date(report.generated).toLocaleString()}; dormant after {report.dormantDays} days.
          </p>
          <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
            {stat('Accounts', s.accounts)}{stat('Admins', s.admins)}{stat('Dormant', s.dormant)}
            {stat('Keys', s.keys)}{stat('Agent keys', s.agentKeys)}{stat('Stale keys', s.staleKeys)}
            {stat('Branches', s.branches)}{stat('Unowned', s.unowned)}
          </div>

          <h2 style={{ marginTop: 22 }}>Accounts</h2>
          <div className="table-wrap">
            <table aria-label="Accounts">
              <thead><tr><th>Account</th><th>Reaches</th><th>May override on</th><th className="num">Keys</th><th>Last active</th><th>Status</th></tr></thead>
              <tbody>
                {(report.accounts ?? []).map(a => (
                  <tr key={a.id}>
                    <td>{a.email}{a.admin && <> <span className="badge primary">admin</span></>}</td>
                    <td>{a.reaches}{(a.owns ?? []).length > 0 && <div className="muted" style={{ fontSize: 12 }}>owns {a.owns!.join(', ')}</div>}</td>
                    <td>{(a.overrideOn ?? []).length > 0 ? a.overrideOn!.join(', ') : '–'}</td>
                    <td className="num">{a.keys}</td>
                    <td title={`sign-in ${day(a.lastSignIn)} · key ${day(a.lastKeyUse)} · query ${day(a.lastQuery)}`}>{day(a.lastActive)}</td>
                    <td>{a.dormant ? <span className="badge">dormant</span> : 'active'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h2 style={{ marginTop: 22 }}>Keys</h2>
          {(report.keys ?? []).length === 0 ? <p className="muted">No keys.</p> : (
            <div className="table-wrap">
              <table aria-label="Keys">
                <thead><tr><th>Key</th><th>Owner</th><th>Kind</th><th>Reach</th><th className="num">Age</th><th>Last used</th><th>Status</th></tr></thead>
                <tbody>
                  {report.keys!.map(k => (
                    <tr key={k.id}>
                      <td><code>{k.prefix}…</code> {k.name}</td>
                      <td>{k.owner}</td>
                      <td title={k.identity}>{k.kind}</td>
                      <td>{k.reach}</td>
                      <td className="num">{k.ageDays}d</td>
                      <td>{day(k.lastUsed)}</td>
                      <td>{k.stale ? <span className="badge" title={k.why}>stale: {k.why}</span> : 'in use'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h2 style={{ marginTop: 22 }}>Branches</h2>
          <div className="table-wrap">
            <table aria-label="Branches">
              <thead><tr><th>Branch</th><th>State</th><th>Owner</th><th>May override its guardrails</th></tr></thead>
              <tbody>
                {(report.branches ?? []).map(b => (
                  <tr key={b.name}>
                    <td><code>{b.name}</code></td>
                    <td>{b.state}</td>
                    <td>{b.owner || (b.name === 'main' ? '(the install)' : '–')}</td>
                    <td>{b.asked ? ((b.admins ?? []).join(', ') || '–') : <span className="muted">not running: not read</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="panel" style={{ marginTop: 14 }}>
            <h3 style={{ marginTop: 0 }}>What this report cannot claim</h3>
            <ul style={{ margin: 0 }}>{(report.limits ?? []).map(l => <li key={l}>{l}</li>)}</ul>
          </div>
        </>
      )}
    </div>
  )
}
