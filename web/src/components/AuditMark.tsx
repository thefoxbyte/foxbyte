// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react'
import { markAudited, markOf, unmarkAudited, type AuditMarks } from '../api'
import { useConfirm } from '../confirm'

// Marking one table for the audit log (F6 step 2). Its writes, and reads if
// asked, become lines in pgAudit's log: who, which kind of statement, which
// table and when, never what the statement held. A mark is a grant, so a branch
// made from this one has it; it takes effect while the audit log is on.

export function AuditControl({ branch, schema, table, marks, onChange }: {
  branch: string
  schema: string
  table: string
  marks: AuditMarks | null
  onChange: (m: AuditMarks) => void
}) {
  const confirm = useConfirm()
  const [open, setOpen] = useState(false)
  const [reads, setReads] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const box = useRef<HTMLDivElement>(null)
  const mine = markOf(marks, schema, table)
  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])
  if (!marks) return null

  const run = async (f: () => Promise<AuditMarks>) => {
    setBusy(true); setErr('')
    try { onChange(await f()); setOpen(false) } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const stop = async () => {
    const ok = await confirm({
      title: 'Stop auditing',
      message: <>Stop recording who writes to <b>{table}</b>{mine?.reads ? ' and who reads it' : ''}? What the log already holds stays. Taking a mark off is itself recorded.</>,
      confirmText: 'Stop auditing',
    })
    if (ok) run(() => unmarkAudited(branch, schema, table))
  }
  const what = mine ? (mine.writes && mine.reads ? 'writes and reads' : mine.reads ? 'reads' : 'writes') : ''

  return (
    <div className="copy-menu audit-mark" ref={box}>
      {mine ? (
        <span className="track-on" data-testid="audit-mark">
          Audited: {what}{!marks.audit_on && <span className="muted"> (the audit log is off)</span>}
          <button type="button" className="ghost sm" disabled={busy}
            onClick={() => run(() => markAudited(branch, schema, table, !mine.reads))}>
            {mine.reads ? 'Stop auditing reads' : 'Audit reads too'}
          </button>
          <button type="button" className="ghost sm" onClick={stop} disabled={busy}>Stop auditing</button>
        </span>
      ) : (
        <button type="button" className="ghost" aria-haspopup="dialog" aria-expanded={open} onClick={() => setOpen(o => !o)}>Audit…</button>
      )}
      {err && !open && <span className="err" role="alert">{err}</span>}
      {open && (
        <div className="copy-pop track-pop" role="dialog" aria-label={`Audit ${table}`}>
          <p className="muted">
            Record who writes to <b>{table}</b>: each insert, update and delete, by every login, as a line in the audit log.
            Never what the statement held.
          </p>
          <label className="check-row"><input type="radio" name="audit-reads" checked={!reads} onChange={() => setReads(false)} /> Writes</label>
          <label className="check-row"><input type="radio" name="audit-reads" checked={reads} onChange={() => setReads(true)} /> Writes and reads</label>
          <p className="err-hint">
            Each audited statement costs capacity, and reads are most statements on a busy table.
            {!marks.audit_on && ' The audit log is off: the mark takes effect when it is turned on.'}
          </p>
          {err && <div className="err" role="alert">{err}</div>}
          <div className="track-actions">
            <button type="button" className="ghost sm" onClick={() => setOpen(false)}>Cancel</button>
            <button type="button" className="primary sm" onClick={() => run(() => markAudited(branch, schema, table, reads))} disabled={busy}>
              {busy ? 'Marking…' : 'Audit'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
