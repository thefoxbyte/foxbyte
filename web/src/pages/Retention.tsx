// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  armRetention, disarmRetention, getRetention, getRetentionNotices, previewRetention, runRetention, setRetention, setRetentionColumn,
  type RetentionDue, type RetentionNotice, type RetentionRun, type RetentionStatus, type RetentionView,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'

// Retention acted on (point 11.3): each table with a period in main's DPDP
// inventory, the date its period runs from, and whether an admin armed it.
// A run, daily or from here, notices the rows past the period through the
// customer's webhook (Rule 8(2)) and erases them a notice period later if
// they are still past it, as erasure requests. Never sooner than a year from
// a row's date (Rule 8(3)). Admins; acting is Enterprise.

const WARN = 'color-mix(in srgb, var(--red) 78%, var(--text))'
const when = (s?: string) => (s ? new Date(s).toLocaleString() : '')
const day = (s?: string) => (s ? new Date(s).toLocaleDateString() : '')

export default function Retention() {
  const { can, edition } = useFeatures()
  const licensed = can('dpdp')
  const [st, setSt] = useState<RetentionStatus | null>(null)
  const [notices, setNotices] = useState<RetentionNotice[]>([])
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [secret, setSecret] = useState('')
  const [notify, setNotify] = useState('')
  const [run, setRun] = useState<RetentionRun | null>(null)
  const [busy, setBusy] = useState(false)
  const [arming, setArming] = useState<{ table: string; due: RetentionDue } | null>(null)
  const confirm = useConfirm()

  const load = useCallback(async () => {
    try {
      const [s, n] = await Promise.all([getRetention(), getRetentionNotices()])
      setSt(s); setNotices(n.slice(0, 50)); setErr('')
    } catch (e) { setErr((e as Error).message) }
  }, [])
  useEffect(() => { load() }, [load])

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true); setErr(''); setMsg('')
    try { await fn(); setMsg(ok); await load() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  const set = st?.settings
  return (
    <div className="fade-up">
      <h1>Retention</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Each table&rsquo;s period is its <Link to="/dpdp-inventory">DPDP inventory</Link> entry&rsquo;s. Only an armed table is erased from: its rows past the period
        are noticed through your webhook, and erased {st?.notice ?? '48h0m0s'} later if they still are, on main and every branch, as erasure requests.
      </p>
      {!licensed && edition !== null && <p className="muted" data-testid="retention-locked">{why(edition, 'Acting on retention')} The tables and notices can still be read.</p>}
      {err && <div className="err" data-testid="retention-err">{err}</div>}
      {msg && <p className="ok" data-testid="retention-msg">{msg}</p>}

      {set && (
        <div className="panel" style={{ marginTop: 12 }} data-testid="retention-settings">
          {set.on ? (
            <>
              <p style={{ margin: 0 }}>Retention is <b>on</b>, since {when(set.since)} ({set.by}); notices go to <code>{set.notify}</code>, {st?.notice} before an erasure.</p>
              {set.lastRun && <p className="muted" style={{ margin: '6px 0 0' }} data-testid="retention-last-run">Last run {when(set.lastRun)}: {set.lastSummary}</p>}
              <div className="row" style={{ gap: 8, marginTop: 10 }}>
                <button className="primary" disabled={!licensed || busy} data-testid="retention-run" onClick={async () => {
                  setBusy(true); setErr('')
                  try { setRun(await runRetention()); await load() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
                }}>{busy ? 'Running…' : 'Run now'}</button>
                <button className="ghost" disabled={busy} onClick={async () => {
                  if (!await confirm({ title: 'Turn retention off?', message: 'Nothing is noticed or erased until it is on again. Open notices wait.', confirmText: 'Turn off' })) return
                  act(() => setRetention(false), 'Retention is off.')
                }}>Turn off…</button>
              </div>
            </>
          ) : (
            <form className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', margin: 0 }} onSubmit={e => {
              e.preventDefault()
              act(async () => { const r = await setRetention(true, notify.trim()); setSecret(r.secret ?? '') }, 'Retention is on.')
            }}>
              <p style={{ margin: 0, width: '100%' }}>Retention is <b>off</b>: nothing is noticed or erased.</p>
              <label className="field" style={{ flex: 1, minWidth: 280 }}>Notices go to (HTTPS)
                <input aria-label="Notice address" placeholder="https://…" value={notify} onChange={e => setNotify(e.target.value)} />
              </label>
              <button className="primary" disabled={!licensed || busy || !notify.trim()}>Turn on</button>
            </form>
          )}
          {secret && (
            <div className="pii-warning" role="status" style={{ marginTop: 10 }} data-testid="retention-secret">
              Each notice is signed in the <code>X-FoxByte-Signature</code> header (sha256=HMAC-SHA256 of the body) with this key, shown once: <code>{secret}</code>
            </div>
          )}
        </div>
      )}

      {run && (
        <div className="panel" style={{ marginTop: 12 }} data-testid="retention-run-result">
          <p style={{ margin: 0 }}>Run at {when(run.at)}:</p>
          <ul style={{ margin: '6px 0 0' }}>
            {run.tables.length === 0 && <li>No table is armed.</li>}
            {run.tables.map(t => (
              <li key={t.table}>
                <code>{t.table}</code>: {t.due} past the period; {t.noticed} noticed, {t.waiting} waiting, {t.renewed} renewed, {t.erased} erased
                {t.request ? <> (<Link to="/erasure-requests">request #{t.request}</Link>)</> : null}
                {t.error && <div style={{ color: WARN }}>{t.error}</div>}
              </li>
            ))}
            {run.notes.map((n, i) => <li key={i} className="muted">{n}</li>)}
          </ul>
        </div>
      )}

      <h2 style={{ marginTop: 18 }}>Tables with a period</h2>
      {st && st.tables.length === 0 && <p className="muted" data-testid="retention-none">No table in main&rsquo;s inventory has an entry, so none has a period.</p>}
      {st && st.tables.length > 0 && (
        <div className="table-wrap">
          <table aria-label="Retention tables">
            <thead><tr><th>Table</th><th>Kept</th><th>Dated by</th><th className="num">Past it</th><th className="num">Undated</th><th className="num">Noticed</th><th>Armed</th></tr></thead>
            <tbody>
              {st.tables.map(t => (
                <TableRow key={`${t.schema}.${t.table}`} t={t} licensed={licensed} busy={busy}
                  onColumn={c => act(() => setRetentionColumn(`${t.schema}.${t.table}`, c), `${t.schema}.${t.table}'s period runs from ${c}.`)}
                  onArm={async () => {
                    setErr('')
                    try { setArming({ table: `${t.schema}.${t.table}`, due: await previewRetention(`${t.schema}.${t.table}`) }) } catch (e) { setErr((e as Error).message) }
                  }}
                  onDisarm={() => act(() => disarmRetention(`${t.schema}.${t.table}`), `${t.schema}.${t.table} is disarmed.`)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {arming && <Arm a={arming} onCancel={() => setArming(null)} onArm={reason => act(async () => { await armRetention(arming.table, reason); setArming(null) }, `${arming.table} is armed.`)} />}

      <h2 style={{ marginTop: 18 }}>Notices</h2>
      {notices.length === 0 ? <p className="muted" data-testid="retention-no-notices">No notice has been sent.</p> : (
        <div className="table-wrap">
          <table aria-label="Retention notices">
            <thead><tr><th>Table</th><th>Row</th><th>Dated</th><th>Noticed</th><th>Erased after</th><th>State</th></tr></thead>
            <tbody>
              {notices.map(n => (
                <tr key={n.id} data-testid={`retention-notice-${n.id}`}>
                  <td><code>{n.schema}.{n.table}</code></td><td><code>{n.key}</code></td><td>{day(n.since)}</td>
                  <td>{when(n.noticed)}</td><td>{when(n.eraseAfter)}</td>
                  <td>{n.state}{n.request ? ` (request #${n.request})` : ''}{n.error ? `: ${n.error}` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {st && (
        <>
          <h2 style={{ marginTop: 18 }}>What this cannot claim</h2>
          <ul className="muted" style={{ fontSize: 13 }} data-testid="retention-limits">{st.limits.map(l => <li key={l}>{l}</li>)}</ul>
        </>
      )}
    </div>
  )
}

function TableRow({ t, licensed, busy, onColumn, onArm, onDisarm }: {
  t: RetentionView; licensed: boolean; busy: boolean; onColumn: (c: string) => void; onArm: () => void; onDisarm: () => void
}) {
  const [col, setCol] = useState(t.column)
  const kept = `${t.keep.count} ${t.keep.unit} after ${t.keep.from}`
  return (
    <tr data-testid={`retention-table-${t.schema}.${t.table}`}>
      <td><code>{t.schema}.{t.table}</code>{t.why && <div className="muted" style={{ fontSize: 12 }}>{t.why}</div>}</td>
      <td style={{ fontSize: 13 }}>{kept}{t.raised && <div className="muted">a year, Rule 8(3)</div>}</td>
      <td>
        <form className="row" style={{ gap: 4, margin: 0 }} onSubmit={e => { e.preventDefault(); onColumn(col.trim()) }}>
          <input aria-label={`Date column of ${t.schema}.${t.table}`} style={{ width: 130 }} value={col} onChange={e => setCol(e.target.value)} />
          <button className="ghost" disabled={!licensed || busy || !col.trim() || col.trim() === t.column}>Set</button>
        </form>
      </td>
      <td className="num">{t.due}</td><td className="num">{t.undated}</td><td className="num">{t.noticed}</td>
      <td>
        {t.armed
          ? <>yes{t.armedBy ? <span className="muted"> ({t.armedBy})</span> : null} <button className="ghost" disabled={busy} onClick={onDisarm}>Disarm</button></>
          : <button className="ghost" disabled={!licensed || busy || !t.column} onClick={onArm}>Arm…</button>}
      </td>
    </tr>
  )
}

function Arm({ a, onCancel, onArm }: { a: { table: string; due: RetentionDue }; onCancel: () => void; onArm: (reason: string) => void }) {
  const [reason, setReason] = useState('')
  const d = a.due
  return (
    <form className="panel" style={{ marginTop: 12 }} data-testid="retention-arm" onSubmit={e => { e.preventDefault(); onArm(reason.trim()) }}>
      <h3 style={{ marginTop: 0 }}>Arm {a.table}?</h3>
      <p style={{ margin: 0 }} data-testid="retention-preview">
        {d.total} row(s) dated by <code>{d.column}</code> before {day(d.cutoff)} are past their period now; {d.undated} have no date and are never acted on.
        Each is noticed on the next run, and erased after its notice period if it still is.
      </p>
      {d.rows.length > 0 && <ul style={{ fontSize: 13 }}>{d.rows.map(r => <li key={r.key}><code>{r.key}</code> dated {day(r.since)}</li>)}</ul>}
      <label className="field" style={{ marginTop: 8 }}>Why (who decided, or the policy)
        <input aria-label="Why arm it" value={reason} onChange={e => setReason(e.target.value)} />
      </label>
      <div className="row" style={{ gap: 8, marginTop: 8 }}>
        <button className="primary" disabled={!reason.trim()}>Arm it</button>
        <button type="button" className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  )
}
