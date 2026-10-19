// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { deleteMyHistory, historySettings, setHistorySettings, type HistorySettings } from '../api'
import { useConfirm } from '../confirm'

const RETENTION = [7, 30, 90, 180, 365]

/**
 * Query history settings (point 8.3), on the account page. The engine keeps
 * the SQL you run from the console and the API (point 8.1) — the statement,
 * branch, when, how long, how many rows and whether it worked, never a result —
 * and this is where you see how much it holds, turn yours off, or delete it.
 * An admin also sets the install's switch and how long it is kept.
 */
export default function QueryHistoryPanel() {
  const confirm = useConfirm()
  const [s, setS] = useState<HistorySettings | null>(null)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    historySettings().then(setS).catch(e => setErr((e as Error).message))
  }, [])

  // The switch moves when it is clicked, and moves back if the engine refuses:
  // a box that waits for the server before it changes reads as one that ignored
  // the click.
  const change = async (p: Parameters<typeof setHistorySettings>[0], done: string) => {
    const was = s
    setErr(''); setMsg(''); setBusy(true)
    if (s) setS({ ...s, ...p })
    try { setS(await setHistorySettings(p)); setMsg(done) } catch (e) { setS(was); setErr((e as Error).message) } finally { setBusy(false) }
  }

  const clear = async () => {
    const ok = await confirm({
      title: 'Delete your query history',
      message: <>Delete all {s?.count} {s?.count === 1 ? 'entry' : 'entries'} of your query history? This can't be undone.</>,
      confirmText: 'Delete',
      danger: true,
    })
    if (!ok) return
    setErr(''); setMsg(''); setBusy(true)
    try {
      const r = await deleteMyHistory()
      setS(await historySettings())
      setMsg(`Deleted ${r.deleted} ${r.deleted === 1 ? 'entry' : 'entries'}.`)
    } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <div className="panel" style={{ marginTop: 24 }} aria-label="Query history">
      <h2 style={{ marginTop: 0 }}>Query history</h2>
      <p className="muted">
        The SQL you run from the console and the API is kept so you can find it again: the statement, the branch,
        when, how long it took, how many rows and whether it worked. Never a result. Only you can see yours.
      </p>
      {!s && !err && <p className="muted">Loading…</p>}
      {s && (
        <>
          {!s.enabled && <p className="err-hint">History is off for this install: nothing new is kept.</p>}
          <p data-testid="history-count">
            {s.count} {s.count === 1 ? 'query' : 'queries'} in your history, kept {s.retention_days} days.
          </p>
          <label className="check-row">
            <input type="checkbox" checked={s.mine} disabled={busy}
              onChange={e => change({ mine: e.target.checked }, e.target.checked ? 'Your queries are kept again.' : 'Your queries are no longer kept. What is there stays until you delete it or it expires.')} />
            {' '}Keep a history of my queries
          </label>
          <div style={{ marginTop: 12 }}>
            <button type="button" className="ghost" onClick={clear} disabled={busy || s.count === 0}>Delete my history</button>
          </div>
          {s.admin && (
            <fieldset className="history-admin" style={{ marginTop: 16, border: 0, padding: 0 }}>
              <legend className="muted">For everyone on this install (admins)</legend>
              <label className="check-row">
                <input type="checkbox" checked={s.enabled} disabled={busy}
                  onChange={e => change({ enabled: e.target.checked }, e.target.checked ? 'History is on for this install.' : 'History is off for this install.')} />
                {' '}Query history on
              </label>
              <label className="fld" style={{ maxWidth: 240 }}>Keep history for
                <select aria-label="Keep history for" value={s.retention_days} disabled={busy}
                  onChange={e => change({ retention_days: Number(e.target.value) }, `History is kept ${e.target.value} days; anything older was deleted.`)}>
                  {(RETENTION.includes(s.retention_days) ? RETENTION : [...RETENTION, s.retention_days].sort((a, b) => a - b))
                    .map(d => <option key={d} value={d}>{d} days</option>)}
                </select>
              </label>
            </fieldset>
          )}
        </>
      )}
      {err && <div className="err" role="alert">{err}</div>}
      {msg && <p className="muted">{msg}</p>}
    </div>
  )
}
