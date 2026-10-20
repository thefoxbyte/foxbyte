// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react'
import { setTrackNew, trackTable, untrackTable, type Tracking } from '../api'
import { useConfirm } from '../confirm'

// Row tracking for one table (points 5.1, 6.1): who changed each row and when,
// kept by Postgres. Opt-in, and never done to a table unasked: adding columns
// breaks an INSERT written without a column list, so the dialog says so.

type Col = { key: 'created' | 'updated' | 'by'; label: string; hint: string }
const COLS: Col[] = [
  { key: 'created', label: 'When made', hint: 'Set when a row is added, never after' },
  { key: 'updated', label: 'When last changed', hint: 'Set when a row is added and each time it changes' },
  { key: 'by', label: 'Who last changed it', hint: 'The login that changed it, which a session cannot fake' },
]

/** trackedOf is the tracking of one table, if it has any. */
export function trackedOf(t: Tracking | null, schema: string, name: string) {
  return t?.tables.find(x => x.schema === schema && x.name === name) ?? null
}

export function TrackingControl({ branch, schema, table, tracking, onChange }: {
  branch: string
  schema: string
  table: string
  tracking: Tracking | null
  onChange: (t: Tracking) => void
}) {
  const confirm = useConfirm()
  const [open, setOpen] = useState(false)
  const [names, setNames] = useState({ created: 'created_at', updated: 'updated_at', by: 'last_modified_by' })
  const [keep, setKeep] = useState({ created: true, updated: true, by: true })
  const [label, setLabel] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const box = useRef<HTMLDivElement>(null)
  const mine = trackedOf(tracking, schema, table)
  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const run = async (f: () => Promise<Tracking>) => {
    setBusy(true); setErr('')
    try { onChange(await f()); setOpen(false) } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const chosen = { created: keep.created ? names.created : '', updated: keep.updated ? names.updated : '', by: keep.by ? names.by : '' }
  const start = () => run(() => trackTable(branch, schema, table, { ...chosen, label_existing: label }))
  const stop = async () => {
    const ok = await confirm({
      title: 'Stop tracking',
      message: <>Stop keeping who changed each row of <b>{table}</b> and when? The columns, and what they hold, stay.</>,
      confirmText: 'Stop tracking',
    })
    if (ok) run(() => untrackTable(branch, schema, table))
  }
  const newOn = tracking?.settings.track_new ?? false

  return (
    <div className="copy-menu track" ref={box}>
      {mine ? (
        <span className="track-on" title={[mine.created, mine.updated, mine.by].filter(Boolean).join(', ')}>
          Tracked: {[mine.created, mine.updated, mine.by].filter(Boolean).map(c => <code key={c}>{c}</code>)}
          <button type="button" className="ghost sm" onClick={stop} disabled={busy}>Stop tracking</button>
        </span>
      ) : (
        <button type="button" className="ghost" aria-haspopup="dialog" aria-expanded={open} onClick={() => setOpen(o => !o)}>Track changes…</button>
      )}
      {err && !open && <span className="err" role="alert">{err}</span>}
      {open && (
        <div className="copy-pop track-pop" role="dialog" aria-label={`Track changes to ${table}`}>
          <p className="muted">Keep who changed each row of <b>{table}</b> and when. Postgres writes these columns on every insert and update, whatever a statement says.</p>
          {COLS.map(c => (
            <label key={c.key} className="track-col" title={c.hint}>
              <input type="checkbox" checked={keep[c.key]} aria-label={`Keep ${c.label.toLowerCase()}`}
                onChange={e => setKeep(k => ({ ...k, [c.key]: e.target.checked }))} />
              <span>{c.label}</span>
              <input aria-label={`Column for ${c.label.toLowerCase()}`} value={names[c.key]} disabled={!keep[c.key]} maxLength={63}
                onChange={e => setNames(n => ({ ...n, [c.key]: e.target.value }))} />
            </label>
          ))}
          <fieldset className="track-existing">
            <legend className="muted">Rows already in the table</legend>
            <label className="check-row"><input type="radio" name="track-existing" checked={!label} onChange={() => setLabel(false)} /> Leave empty</label>
            <label className="check-row"><input type="radio" name="track-existing" checked={label} onChange={() => setLabel(true)} /> Label with this moment</label>
          </fieldset>
          <p className="err-hint">This adds columns to the table: an INSERT written without a column list will need them listed.</p>
          {err && <div className="err" role="alert">{err}</div>}
          <div className="track-actions">
            <button type="button" className="ghost sm" onClick={() => setOpen(false)}>Cancel</button>
            <button type="button" className="primary sm" onClick={start}
              disabled={busy || (!keep.created && !keep.updated && !keep.by)}>{busy ? 'Tracking…' : 'Track'}</button>
          </div>
          <label className="check-row track-new" title="Tables that exist now are not changed">
            <input type="checkbox" checked={newOn} disabled={busy}
              onChange={e => run(() => setTrackNew(branch, e.target.checked, chosen))} />
            Track every new table on {branch} as it is made
          </label>
        </div>
      )}
    </div>
  )
}
