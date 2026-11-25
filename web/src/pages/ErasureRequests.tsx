// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import {
  ApiError, applyErasure, getErasure, listErasures, newErasure, replanErasure, rewriteErasure, withdrawErasure,
  type ErasureRequest, type ErasureTable, type ErasureValue,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'

// Erasure requests (point 11.2, F4, Gate 1 step 1). One request erases one
// person's personal data on main: the rows found from the values given and
// the columns a reviewer confirmed, and the rows that refer to them, each
// table as its DPDP inventory entry says. The plan is shown first; nothing
// changes until an admin applies it. A request keeps no value, only each
// one's category and last four characters, so planning again and applying
// ask for the values again. Admins only.

const actionText: Record<string, string> = {
  clear: 'Cleared',
  delete: 'Deleted',
  cascade: 'Deleted with it',
  'set-null': 'Reference cleared',
  keep: 'Left as it is',
  kept: 'Kept: a law requires it',
  'refers-to': 'Refers to it',
}

// readValues reads the textarea: one value a line, "category:value" or the
// value alone.
export function readValues(text: string): ErasureValue[] {
  return text.split('\n').map(l => l.trim()).filter(Boolean).map(l => {
    const m = /^([a-z_]{1,12}):(.*)$/.exec(l)
    return m ? { category: m[1], value: m[2].trim() } : { category: '', value: l }
  })
}

const when = (s?: string) => (s ? new Date(s).toLocaleString() : '')
const size = (n: number) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GB` : n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.round(n / 1024)} kB`)

export default function ErasureRequests() {
  const [list, setList] = useState<ErasureRequest[] | null>(null)
  const [sel, setSel] = useState<ErasureRequest | null>(null)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [making, setMaking] = useState(false)
  const { can, edition } = useFeatures()
  const licensed = can('dpdp')

  const load = useCallback(async (pick?: number) => {
    try {
      const l = await listErasures()
      setList(l)
      if (pick) setSel(await getErasure(pick))
    } catch (e) { setErr((e as Error).message) }
  }, [])
  useEffect(() => { load() }, [load])

  const done = async (r: ErasureRequest, text: string) => { setMsg(text); setErr(''); setSel(r); await load() }

  return (
    <div className="fade-up">
      <h1>Erasure requests</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Erase one person's personal data on <code>main</code>: their rows, found from the values they are known by in the
        columns a reviewer confirmed, and the rows that refer to them, each table as its DPDP inventory entry says.
        The plan comes first; nothing changes until an admin applies it.
      </p>
      <div className="pii-warning" role="note" data-testid="erasure-review">
        FoxByte's reading of erasure under the DPDP Act, 2023 has not yet been reviewed by a privacy lawyer or a storage
        engineer. It is not legal advice; have it reviewed before relying on it.
      </div>
      {edition && !licensed && (
        <p className="muted" style={{ fontSize: 13 }}>{why(edition, 'Making and applying erasure requests')} Requests made earlier can still be read.</p>
      )}

      {err && <div className="err" style={{ marginTop: 12 }} role="alert">{err}</div>}
      {msg && <div className="okmsg" style={{ marginTop: 12 }} role="status">{msg}</div>}

      <div className="row" style={{ marginTop: 14, gap: 8 }}>
        <button className="primary" disabled={!licensed} onClick={() => { setMaking(true); setSel(null); setMsg('') }}>New request…</button>
      </div>

      {making && (
        <NewForm onCancel={() => setMaking(false)} onMade={async r => { setMaking(false); await done(r, `Request #${r.id} is planned. Nothing has been changed.`) }}
          onError={setErr} />
      )}

      {list && list.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 14 }}>
          <table aria-label="Erasure requests">
            <thead><tr><th>#</th><th>State</th><th>For</th><th>Rows</th><th>Made</th><th>By</th><th><span className="sr-only">Open</span></th></tr></thead>
            <tbody>
              {list.map(r => (
                <tr key={r.id}>
                  <td>{r.id}</td><td>{r.state}</td>
                  <td>{r.refs.map(x => `${x.categories.join('/')} ending ${x.last4}`).join('; ')}</td>
                  <td>{r.result ? `${r.result.rows} changed` : r.plan.rows}</td>
                  <td>{when(r.created)}</td><td>{r.createdBy}</td>
                  <td><button onClick={async () => { setMsg(''); setErr(''); try { setSel(await getErasure(r.id)) } catch (e) { setErr((e as Error).message) } }}>Open</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {list && list.length === 0 && !making && <p className="muted" style={{ marginTop: 14 }}>No erasure requests yet.</p>}

      {sel && <Detail key={`${sel.id}-${sel.planned}-${sel.state}`} r={sel} licensed={licensed} onDone={done} onError={setErr} reload={() => load(sel.id)} />}
    </div>
  )
}

function ValuesField({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  return (
    <label className="field">{label}
      <textarea aria-label="Values" rows={3} value={value} onChange={e => onChange(e.target.value)}
        autoComplete="off" spellCheck={false} placeholder={'email:asha@example.com\nmobile:98765 43210'} />
      <span className="muted" style={{ fontSize: 12 }}>
        One a line, as category:value or the value alone. They are not kept: only each one's category and last four characters.
      </span>
    </label>
  )
}

function NewForm({ onCancel, onMade, onError }: { onCancel: () => void; onMade: (r: ErasureRequest) => void; onError: (e: string) => void }) {
  const [values, setValues] = useState('')
  const [note, setNote] = useState('')
  const [events, setEvents] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <form className="form panel" style={{ marginTop: 14 }} aria-label="New erasure request" data-testid="erasure-new"
      onSubmit={async e => {
        e.preventDefault()
        const ev: Record<string, string> = {}
        for (const part of events.split(/[,\n]/).map(s => s.trim()).filter(Boolean)) {
          const [k, v] = part.split('=')
          ev[(k ?? '').trim().replace(/-/g, '_')] = (v ?? '').trim()
        }
        setBusy(true)
        try { const r = await newErasure(readValues(values), note.trim(), ev); setValues(''); onMade(r) }
        catch (x) { onError((x as Error).message) }
        finally { setBusy(false) }
      }}>
      <h3 style={{ margin: 0 }}>New erasure request</h3>
      <ValuesField value={values} onChange={setValues} label="The values the person is known by" />
      <label className="field">Your reference (optional; never the person's details)
        <input aria-label="Note" maxLength={500} value={note} onChange={e => setNote(e.target.value)} placeholder="DPO ticket 1234" />
      </label>
      <label className="field">Event dates for a law's retention (optional)
        <input aria-label="Event dates" value={events} onChange={e => setEvents(e.target.value)} placeholder="account_closed=2025-03-31" />
      </label>
      <div className="row" style={{ gap: 8 }}>
        <button className="primary" type="submit" disabled={busy || readValues(values).length === 0}>{busy ? 'Planning…' : 'Plan the erasure'}</button>
        <button type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  )
}

function Detail({ r, licensed, onDone, onError, reload }: {
  r: ErasureRequest
  licensed: boolean
  onDone: (r: ErasureRequest, msg: string) => void
  onError: (e: string) => void
  reload: () => void
}) {
  const [asking, setAsking] = useState<'' | 'plan' | 'apply'>('')
  const [values, setValues] = useState('')
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const confirm = useConfirm()
  const p = r.plan
  const planned = r.state === 'planned'

  const run = async () => {
    setBusy(true)
    try {
      if (asking === 'plan') {
        const n = await replanErasure(r.id, readValues(values))
        onDone(n, `Request #${r.id} planned again. Nothing has been changed.`)
      } else {
        const n = await applyErasure(r.id, readValues(values))
        onDone(n, `Request #${r.id} applied to ${r.branch}: ${n.result?.rows ?? 0} row(s) changed.`)
      }
      setValues(''); setAsking('')
    } catch (x) {
      if (x instanceof ApiError && x.status === 409 && /plan has changed/.test(x.message)) {
        setValues(''); setAsking('')
        onError(`Nothing was applied: the plan has changed since it was shown. Review the new plan below, then apply again.`)
        reload()
      } else onError((x as Error).message)
    } finally { setBusy(false) }
  }

  return (
    <div className="panel" style={{ marginTop: 16 }} data-testid="erasure-detail">
      <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <h2 style={{ margin: 0 }}>Request #{r.id} <span className="badge">{r.state}</span></h2>
        <div className="row" style={{ gap: 8 }}>
          {planned && <button disabled={!licensed} onClick={() => { setAsking('plan'); setValues('') }}>Plan again…</button>}
          {planned && <button className="primary" disabled={!licensed || p.blocked} title={p.blocked ? 'A table has a problem; see below' : ''}
            onClick={() => { setAsking('apply'); setValues(''); setTyped('') }}>Apply to {r.branch}…</button>}
          {planned && <button className="danger" disabled={!licensed} onClick={async () => {
            if (!await confirm({ title: `Withdraw request #${r.id}?`, message: <>It is closed without applying anything.</>, confirmText: 'Withdraw', danger: true })) return
            try { onDone(await withdrawErasure(r.id), `Request #${r.id} withdrawn; nothing was applied.`) } catch (x) { onError((x as Error).message) }
          }}>Withdraw…</button>}
        </div>
      </div>
      <p className="muted" style={{ marginTop: 6 }}>
        For {r.refs.map(x => `${x.categories.join('/')} ending ${x.last4}`).join('; ')}
        {r.note && <> · {r.note}</>} · made by {r.createdBy}, {when(r.created)} · planned by {r.plannedBy}, {when(r.planned)}
      </p>

      {asking && (
        <form className="form" style={{ marginTop: 10 }} aria-label={asking === 'apply' ? 'Apply the erasure' : 'Plan again'}
          onSubmit={e => { e.preventDefault(); run() }} data-testid="erasure-values">
          {asking === 'apply' && (
            <div className="pii-warning" role="alert">
              Applying erases the rows below on <code>{r.branch}</code> for good, in one transaction. The rows are found
              again first: if the plan has changed since it was shown, nothing is applied.
            </div>
          )}
          <ValuesField value={values} onChange={setValues} label={asking === 'apply' ? 'The values again' : 'The values the request was made for'} />
          {asking === 'apply' && (
            <label className="field">Type the request's number, {r.id}, to apply it
              <input aria-label="Request number" value={typed} onChange={e => setTyped(e.target.value)} style={{ width: 100 }} />
            </label>
          )}
          <div className="row" style={{ gap: 8 }}>
            <button className={asking === 'apply' ? 'danger' : 'primary'} type="submit"
              disabled={busy || readValues(values).length === 0 || (asking === 'apply' && typed.trim() !== String(r.id))}>
              {busy ? 'Working…' : asking === 'apply' ? 'Apply' : 'Plan again'}
            </button>
            <button type="button" onClick={() => { setAsking(''); setValues('') }}>Cancel</button>
          </div>
        </form>
      )}

      <h3>Plan</h3>
      <p data-testid="erasure-plan-summary">
        {p.matched} row(s) hold a value; {p.rows} row(s) change. {p.searched} confirmed place(s) searched.
        {p.blocked && <b className="dpdp-gap"> It cannot be applied until the problems below are dealt with.</b>}
      </p>
      {p.tables.length === 0 && <p className="muted">No row holds any of the values in a confirmed place.</p>}
      {p.tables.map((t, i) => <PlanTable key={`${t.schema}.${t.table}.${t.action}.${i}`} t={t} />)}

      {r.result && (
        <>
          <h3>What applying did</h3>
          <p data-testid="erasure-result">
            Applied {when(r.result.applied)} by {r.result.by}: {r.result.rows} row(s) changed
            {r.result.verified && '; a search afterwards found none of the values where they were erased'}.
            {r.result.vacuumed && <> Vacuumed {when(r.result.vacuumed)}: removed from live queries.</>}
            {r.result.statistics && <> Statistics rewritten and the WAL switched out {when(r.result.statistics)}.</>}
          </p>
          <div className="table-wrap">
            <table aria-label="Rewrites">
              <thead><tr><th>Table</th><th>Size</th><th>Rewritten in the files</th></tr></thead>
              <tbody>
                {r.result.rewrites.map(w => (
                  <tr key={`${w.schema}.${w.table}`}>
                    <td><code>{w.schema}.{w.table}</code></td><td>{size(w.size)}</td>
                    <td>{w.state === 'done' ? when(w.at) : w.state === 'failed' ? <>Not rewritten: {w.error}</> : <>Not yet: {w.why}</>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {r.result.rewrites.some(w => w.state !== 'done') && (
            <button style={{ marginTop: 8 }} disabled={!licensed} onClick={async () => {
              if (!await confirm({ title: 'Rewrite the tables left?', message: <>Each table is locked against every read and write while it is rewritten.</>, confirmText: 'Rewrite' })) return
              try { onDone(await rewriteErasure(r.id), `Request #${r.id}: rewrite run.`) } catch (x) { onError((x as Error).message) }
            }}>Rewrite the tables left…</button>
          )}
          {r.result.notes.length > 0 && <ul className="muted">{r.result.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
        </>
      )}

      <h3>What this cannot claim</h3>
      <ul className="muted" style={{ fontSize: 13 }}>
        {p.limits.map((l, i) => <li key={i}>{l}</li>)}
      </ul>
    </div>
  )
}

function PlanTable({ t }: { t: ErasureTable }) {
  const where = `${t.schema}.${t.table}`
  return (
    <div className="panel" style={{ marginTop: 10 }} data-testid={`erasure-table-${where}-${t.action}`}>
      <h4 style={{ margin: 0 }}>
        <code>{where}</code>: {actionText[t.action] ?? t.action}, {t.rows} row(s)
        {t.problems.length > 0 && <> <span className="badge pii">problem</span></>}
      </h4>
      <p className="muted" style={{ margin: '4px 0' }}>{t.why}{t.default && ' · no inventory entry: cleared, the default'}</p>
      {t.columns.length > 0 && (
        <ul style={{ margin: '4px 0' }}>
          {t.columns.map(c => (
            <li key={`${c.column}${c.path ?? ''}`}><code>{c.column}{c.path ? ` at ${c.path}` : ''}</code> ({c.categories.join(', ')}) → {c.to}</li>
          ))}
        </ul>
      )}
      {t.exceptions.map((x, i) => <p key={i} style={{ margin: '4px 0' }}>Kept: {x.text}</p>)}
      {t.rewrite === 'apply' && <p className="muted" style={{ margin: '4px 0' }}>Rewritten in the files with the apply ({size(t.size)}).</p>}
      {t.rewrite === 'later' && <p className="muted" style={{ margin: '4px 0' }}>Rewritten later: {t.rewriteWhy}</p>}
      {t.notes.map((n, i) => <p key={i} className="muted" style={{ margin: '4px 0' }}>{n}</p>)}
      {t.problems.map((n, i) => <div key={i} className="err" role="alert" style={{ marginTop: 4 }}>{n}</div>)}
    </div>
  )
}
