// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react'
import { formatResult, guessTable } from '../copyformat'
import { xlsx } from '../xlsx'
import { exportQuery } from '../api'

export type ExportFormat = 'csv' | 'json' | 'xlsx'

const FORMATS: { id: ExportFormat; label: string; mime: string }[] = [
  { id: 'csv', label: 'CSV', mime: 'text/csv;charset=utf-8' },
  { id: 'json', label: 'JSON', mime: 'application/json' },
  { id: 'xlsx', label: 'Excel workbook (.xlsx)', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
]

// The format and switch someone last used, kept in this browser only.
const KEY = 'fox.export'
type Saved = { format: ExportFormat; safe: boolean }
function load(): Saved {
  const d: Saved = { format: 'csv', safe: true }
  try {
    const s = JSON.parse(localStorage.getItem(KEY) ?? 'null')
    if (s && FORMATS.some(f => f.id === s.format)) return { ...d, ...s }
  } catch { /* defaults */ }
  return d
}
function save(s: Saved) {
  try { localStorage.setItem(KEY, JSON.stringify(s)) } catch { /* not kept */ }
}

// fileName names a download after the table the query read and the minute it
// was made: orders-20261017-1405.csv.
export function fileName(sql: string | undefined, ext: string, now = new Date()): string {
  const base = (guessTable(sql ?? '').replace(/"/g, '').split('.').pop() || 'result')
    .replace(/[^A-Za-z0-9_-]+/g, '_').slice(0, 60) || 'result'
  const p = (n: number) => String(n).padStart(2, '0')
  const stamp = `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}`
  return `${base}-${stamp}.${ext}`
}

// exportFile builds the file for a result.
export function exportFile(cols: string[], rows: unknown[][], format: ExportFormat, safe: boolean): Blob {
  const f = FORMATS.find(x => x.id === format)!
  if (format === 'xlsx') return new Blob([xlsx(cols, rows) as BlobPart], { type: f.mime })
  return new Blob([formatResult(cols, rows, { format, header: true, safe })], { type: f.mime })
}

// save hands a file to the browser to download.
function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/**
 * Export what is on screen, or the rows ticked, to a CSV, JSON or Excel file
 * (point 1.2). CSV and JSON are the same text the Copy menu and
 * `fox sql --format` write; the workbook is the same as `fox sql --format xlsx`.
 *
 * Where branch is given, the statement can instead be run again on the server
 * and every row it returns exported (point 1.3), as `fox export` does: past the
 * 1,000 rows on screen, read only, and recorded in the security log. A result
 * that is one statement of a script cannot be, and says so.
 */
export default function ExportMenu({ cols, rows, selected, sql, branch, script }: {
  cols: string[]
  rows: unknown[][]
  selected: number
  sql?: string
  branch?: string
  script?: boolean
}) {
  const [open, setOpen] = useState(false)
  const [opts, setOpts] = useState<Saved>(load)
  const [done, setDone] = useState('')
  // What to export: what is on screen, or everything the query returns. Not
  // kept: the full export runs the query again, so it is chosen each time.
  const [scope, setScope] = useState<'screen' | 'full'>('screen')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const canFull = !!branch && !!sql?.trim() && !script
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false) }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    window.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDoc); window.removeEventListener('keydown', onKey) }
  }, [open])

  const set = (p: Partial<Saved>) => { const n = { ...opts, ...p }; setOpts(n); save(n); setDone(''); setErr('') }
  const full = canFull && scope === 'full'
  const what = selected > 0 ? `${selected} selected row${selected === 1 ? '' : 's'}` : `all ${rows.length} row${rows.length === 1 ? '' : 's'}`

  const download = async () => {
    const name = fileName(sql, opts.format)
    setDone(''); setErr('')
    if (!full) {
      saveBlob(exportFile(cols, rows, opts.format, opts.safe), name)
      setDone(name)
      return
    }
    setBusy(true)
    try {
      saveBlob(await exportQuery(branch!, sql!, opts.format, opts.safe), name)
      setDone(name)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="copy-menu" ref={box}>
      <button type="button" className="ghost" aria-haspopup="dialog" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        Export ▾
      </button>
      {open && (
        <div className="copy-pop" role="dialog" aria-label="Export the result">
          <label className="fld">Format
            <select value={opts.format} onChange={e => set({ format: e.target.value as ExportFormat })} aria-label="Export format">
              {FORMATS.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
            </select>
          </label>
          {opts.format === 'csv' && (
            <label className="check-row" title="Text a spreadsheet would run as a formula (=, +, -, @) gets a leading apostrophe. Numbers are left alone.">
              <input type="checkbox" checked={opts.safe} onChange={e => set({ safe: e.target.checked })} /> Spreadsheet-safe
            </label>
          )}
          {canFull && (
            <fieldset className="export-scope">
              <label className="check-row">
                <input type="radio" name="export-scope" checked={scope === 'screen'} onChange={() => { setScope('screen'); setErr('') }} /> What is on screen
              </label>
              <label className="check-row" title="Runs the statement again on the server, read only, and saves every row it returns. Recorded in the security log.">
                <input type="radio" name="export-scope" checked={scope === 'full'} onChange={() => { setScope('full'); setErr('') }} /> Everything the query returns
              </label>
            </fieldset>
          )}
          <button type="button" className="primary" onClick={download} disabled={busy || (!full && rows.length === 0)}>
            {busy ? 'Exporting…' : full ? 'Download every row' : `Download ${what}`}
          </button>
          {done && <p className="muted">Saved {done}</p>}
          {err && <p className="err" role="alert">{err}</p>}
          {full
            ? <p className="muted">Runs the statement again, read only, as you{opts.format === 'xlsx' ? '; a workbook stops at Excel\'s 1,048,576 rows' : ''}. Recorded in the security log.</p>
            : <p className="muted">What the console holds, at most 1,000 rows.{script ? ' To export every row, run the statement on its own.' : ''}</p>}
        </div>
      )}
    </div>
  )
}
