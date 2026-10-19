// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react'
import { buildChanges, FILTER_OPS, summary, toText, type Filter, type FilterOp, type RowChange } from '../gridquery'

// The data grid (point 12.2): a table's rows filtered, and edited in place.
// The query is gridquery.ts's; the save is the engine's, in one transaction.

/** FilterBar narrows the rows: a column, a comparison and a value, as many as wanted, all of them. */
export function FilterBar({ cols, filters, onChange }: { cols: string[]; filters: Filter[]; onChange: (f: Filter[]) => void }) {
  const [col, setCol] = useState(cols[0] ?? '')
  const [op, setOp] = useState<FilterOp>('=')
  const [value, setValue] = useState('')
  useEffect(() => { if (!cols.includes(col)) setCol(cols[0] ?? '') }, [cols, col])
  const needs = FILTER_OPS.find(o => o.op === op)?.needsValue ?? true
  const add = (e: React.FormEvent) => {
    e.preventDefault()
    if (!col || (needs && value === '')) return
    onChange([...filters, { col, op, value: needs ? value : '' }])
    setValue('')
  }
  const label = (f: Filter) => `${f.col} ${FILTER_OPS.find(o => o.op === f.op)?.label ?? f.op}${FILTER_OPS.find(o => o.op === f.op)?.needsValue ? ` ${f.value}` : ''}`
  return (
    <div className="grid-filter">
      <form className="grid-filter-form" onSubmit={add} aria-label="Filter rows">
        <select aria-label="Filter column" value={col} onChange={e => setCol(e.target.value)}>
          {cols.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select aria-label="Filter comparison" value={op} onChange={e => setOp(e.target.value as FilterOp)}>
          {FILTER_OPS.map(o => <option key={o.op} value={o.op}>{o.label}</option>)}
        </select>
        {needs && <input aria-label="Filter value" placeholder="value" value={value} onChange={e => setValue(e.target.value)} />}
        <button type="submit" className="ghost sm" disabled={!col || (needs && value === '')}>Filter</button>
      </form>
      {filters.map((f, i) => (
        <span key={i} className="grid-chip">
          <code>{label(f)}</code>
          <button type="button" aria-label={`Remove filter ${label(f)}`} onClick={() => onChange(filters.filter((_, j) => j !== i))}>×</button>
        </span>
      ))}
      {filters.length > 1 && <button type="button" className="ghost sm" onClick={() => onChange([])}>Clear</button>}
    </div>
  )
}

export type ColInfo = { name: string; type: string; key: boolean; locked?: string } // locked: why it cannot be set

type Edit = Map<number, Map<number, string | null>>

/**
 * EditGrid is one page of a table, editable: a cell on click, a row marked for
 * deletion, rows added. Nothing reaches the table until Save, which sends every
 * change at once; Discard forgets them.
 */
export function EditGrid({ cols, rows, info, onSave, onCancel }: {
  cols: string[]
  rows: unknown[][]
  info: ColInfo[]
  onSave: (changes: RowChange[]) => Promise<void>
  onCancel: () => void
}) {
  const [edits, setEdits] = useState<Edit>(new Map())
  const [deleted, setDeleted] = useState<Set<number>>(new Set())
  const [added, setAdded] = useState<Map<number, string | null>[]>([])
  const [at, setAt] = useState<{ row: number; col: number; isNew: boolean } | null>(null)
  const [draft, setDraft] = useState('')
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const key = info.filter(c => c.key).map(c => c.name)
  const changes = buildChanges(cols, rows, key, edits, deleted, added)
  const lockOf = (j: number) => info.find(c => c.name === cols[j])?.locked

  useEffect(() => { if (at) input.current?.focus() }, [at])

  const valueAt = (i: number, j: number, isNew: boolean): string | null | undefined =>
    isNew ? added[i]?.get(j) : edits.get(i)?.has(j) ? edits.get(i)!.get(j)! : toText(rows[i][j])
  const begin = (row: number, col: number, isNew: boolean) => {
    if (lockOf(col) || (!isNew && deleted.has(row))) return
    setAt({ row, col, isNew }); setErr('')
    setDraft(valueAt(row, col, isNew) ?? '')
  }
  const commit = (v: string | null) => {
    if (!at) return
    if (at.isNew) {
      setAdded(a => a.map((m, i) => (i === at.row ? new Map(m).set(at.col, v) : m)))
    } else {
      setEdits(e => { const n = new Map(e); n.set(at.row, new Map(n.get(at.row) ?? []).set(at.col, v)); return n })
    }
    setAt(null)
  }
  const toggleDelete = (i: number) => setDeleted(d => { const n = new Set(d); if (n.has(i)) n.delete(i); else n.add(i); return n })
  const save = async () => {
    setSaving(true); setErr('')
    try { await onSave(changes) } catch (e) { setErr((e as Error).message) } finally { setSaving(false) }
  }
  const dirty = (i: number, j: number) => edits.get(i)?.has(j) && edits.get(i)!.get(j) !== toText(rows[i][j])
  const shown = (v: string | null | undefined, isNew: boolean) =>
    v === undefined ? (isNew ? <span className="muted">DEFAULT</span> : '') : v === null ? <span className="muted">NULL</span> : v

  const cell = (i: number, j: number, isNew: boolean) => {
    const editing = at && at.row === i && at.col === j && at.isNew === isNew
    const locked = lockOf(j)
    return (
      <td key={j} className={(dirty(i, j) && !isNew ? 'cell-dirty' : '') + (locked ? ' cell-locked' : '')}
        title={locked} onClick={() => !editing && begin(i, j, isNew)}>
        {editing ? (
          <span className="cell-edit">
            <input ref={input} aria-label={`Value for ${cols[j]}`} value={draft} onChange={e => setDraft(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') { e.preventDefault(); commit(draft) }
                if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setAt(null) }
              }}
              onBlur={() => commit(draft)} />
            <button type="button" className="ghost sm" onMouseDown={e => { e.preventDefault(); commit(null) }}>NULL</button>
          </span>
        ) : shown(valueAt(i, j, isNew), isNew)}
      </td>
    )
  }

  return (
    <div className="edit-grid">
      <div className="edit-bar" role="status">
        <span>{changes.length ? summary(changes) : 'Click a cell to change it.'}</span>
        <span className="wb-sp" />
        <button type="button" className="ghost sm" onClick={() => setAdded(a => [...a, new Map()])}>Add row</button>
        <button type="button" className="ghost sm" onClick={onCancel} disabled={saving}>{changes.length ? 'Discard' : 'Done'}</button>
        <button type="button" className="primary sm" onClick={save} disabled={saving || changes.length === 0}>{saving ? 'Saving…' : 'Save'}</button>
      </div>
      {err && <div className="err" role="alert">{err} Nothing was saved.</div>}
      <div className="grid-wrap table-wrap">
        <table>
          <thead><tr><th className="expand-col" />{cols.map(c => {
            const i = info.find(x => x.name === c)
            return <th key={c} title={i?.locked ?? i?.type}>{c}{i?.key && <span className="obj-sub">key</span>}</th>
          })}</tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={deleted.has(i) ? 'row-deleted' : undefined}>
                <td className="expand-col">
                  <button type="button" className="ghost sm" aria-label={deleted.has(i) ? `Keep row ${i + 1}` : `Delete row ${i + 1}`}
                    title={deleted.has(i) ? 'Keep this row' : 'Delete this row'} onClick={() => toggleDelete(i)}>{deleted.has(i) ? '↺' : '×'}</button>
                </td>
                {r.map((_, j) => cell(i, j, false))}
              </tr>
            ))}
            {added.map((_, i) => (
              <tr key={`new${i}`} className="row-new">
                <td className="expand-col">
                  <button type="button" className="ghost sm" aria-label={`Remove new row ${i + 1}`}
                    onClick={() => setAdded(a => a.filter((_, k) => k !== i))}>×</button>
                </td>
                {cols.map((_, j) => cell(i, j, true))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
