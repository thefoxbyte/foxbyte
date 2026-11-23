// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import {
  dpdpInventoryCsvUrl, getDPDPHistory, getDPDPInventory, removeDPDPEntry, setDPDPEntry,
  type Branch, type DPDPChange, type DPDPChoice, type DPDPEntry, type DPDPInventory, type DPDPKeep,
  type DPDPTable, type DPDPVocabulary,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'
import { useBranches } from '../useBranches'

// The DPDP personal-data inventory (point 11.1). Every table holding personal
// data a reviewer confirmed on the Personal data page, with its entry: the
// basis it is processed on under the DPDP Act, 2023, its purpose, whose data
// it is and how long it is kept. A column can have its own entry, which
// replaces the table's for it. A confirmed column with neither is a gap.
// Reading is free; setting and removing entries are Enterprise.

const label = (cs: DPDPChoice[] | undefined, v: string) => cs?.find(c => c.value === v)?.label ?? v

export function keepText(v: DPDPVocabulary | undefined, k: DPDPKeep) {
  const from = label(v?.from, k.from)
  let s = k.count === 0 ? `until ${from}` : `${k.count} ${k.count === 1 ? k.unit.replace(/s$/, '') : k.unit} after ${from}`
  if (k.reason === 'law') s += `; a law requires it: ${k.citation}`
  if (k.reason === 'contract') s += `; a contract: ${k.citation}`
  return s
}

type Editing = { table: DPDPTable; column: string; entry: DPDPEntry | null }

export default function DpdpInventory() {
  const [branch, setBranch] = useState('main')
  const [inv, setInv] = useState<DPDPInventory | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [onlyGaps, setOnlyGaps] = useState(false)
  const [editing, setEditing] = useState<Editing | null>(null)
  const [history, setHistory] = useState<{ where: string; changes: DPDPChange[] } | null>(null)
  const { branches } = useBranches()
  const { can, edition } = useFeatures()
  const licensed = can('dpdp')
  const confirm = useConfirm()

  const load = useCallback(async () => {
    setLoading(true); setErr('')
    try { setInv(await getDPDPInventory(branch)) }
    catch (e) { setInv(null); setErr((e as Error).message) }
    finally { setLoading(false) }
  }, [branch])
  useEffect(() => { setEditing(null); setHistory(null); load() }, [load])

  const save = async (e: DPDPEntry) => {
    setErr('')
    try { await setDPDPEntry(branch, e); setEditing(null); await load(); return true }
    catch (x) { setErr((x as Error).message); return false }
  }
  const remove = async (e: DPDPEntry) => {
    const where = `${e.schema}.${e.table}${e.column ? '.' + e.column : ''}`
    const yes = await confirm({
      title: 'Remove this entry?',
      message: <>The entry for <code>{where}</code> is removed from the inventory. Its history keeps it.</>,
      confirmText: 'Remove', danger: true,
    })
    if (!yes) return
    setErr('')
    try { await removeDPDPEntry(branch, e.schema, e.table, e.column); setEditing(null); await load() }
    catch (x) { setErr((x as Error).message) }
  }
  const showHistory = async (t: DPDPTable) => {
    setErr('')
    try { setHistory({ where: `${t.schema}.${t.table}`, changes: await getDPDPHistory(branch, t.schema, t.table) }) }
    catch (x) { setErr((x as Error).message) }
  }

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const v = inv?.vocabulary
  const tables = (inv?.tables ?? []).filter(t => !onlyGaps || t.gaps > 0)
  const entryLine = (e: DPDPEntry) => (
    <>
      <b>{label(v?.bases, e.basis)}</b>; whose: {e.principals.map(p => label(v?.principals, p)).join('; ')}; kept {keepText(v, e.keep)}.
      <br /><span className="muted">Purpose:</span> {e.purpose}
      {e.note && <><br /><span className="muted">Note:</span> {e.note}</>}
    </>
  )

  return (
    <div className="fade-up">
      <h1>DPDP inventory</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Each table holding personal data a reviewer confirmed: the basis it is processed on under the DPDP Act, 2023,
        what for, whose data it is and how long it is kept. A confirmed column with no entry is a gap.
      </p>

      {edition && !licensed && (
        <p className="muted" style={{ marginTop: -6, fontSize: 13 }}>
          {why(edition, 'Setting the DPDP inventory')} Entries recorded earlier can still be read and exported.
        </p>
      )}

      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <label className="muted" style={{ fontSize: 13 }} htmlFor="dpdp-branch">Branch</label>
        <select id="dpdp-branch" value={branch} onChange={e => setBranch(e.target.value)}>
          {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
        <label style={{ fontSize: 13 }}>
          <input type="checkbox" checked={onlyGaps} onChange={e => setOnlyGaps(e.target.checked)} /> Only tables with gaps
        </label>
        <a className="btn ghost" href={dpdpInventoryCsvUrl(branch)} download>Export CSV</a>
      </div>

      {err && <div className="err" style={{ marginTop: 12 }} role="alert">{err}</div>}

      {loading && !inv ? <p className="muted">Loading…</p> : inv && (
        <>
          <p className="muted" style={{ marginTop: 16 }} data-testid="dpdp-summary">
            {inv.tables.length} table(s) with confirmed personal data
            {inv.scanned ? `, scanned ${new Date(inv.scanned).toLocaleString()}` : ', never scanned'}.
            {inv.gapColumns > 0
              ? ` ${inv.gapColumns} column(s) in ${inv.gapTables} table(s) have no entry.`
              : inv.tables.length > 0 ? ' Every confirmed column has an entry.' : ''}
          </p>

          {inv.tables.length === 0 && (
            <div className="panel" style={{ padding: 22, textAlign: 'center' }}>
              <p className="muted" style={{ margin: 0 }}>
                <code>{branch}</code> has no confirmed personal data yet. Scan it and confirm the findings on the Personal data page first.
              </p>
            </div>
          )}

          {tables.map(t => {
            const where = `${t.schema}.${t.table}`
            return (
              <div className="panel" key={where} style={{ marginTop: 14 }} data-testid={`dpdp-table-${where}`}>
                <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
                  <h3 style={{ margin: 0 }}><code>{where}</code>{t.gaps > 0 && <> <span className="badge pii">{t.gaps} gap(s)</span></>}</h3>
                  <div className="row" style={{ gap: 8 }}>
                    <button onClick={() => showHistory(t)}>History</button>
                    <button className="primary" disabled={!licensed} title={licensed ? '' : why(edition, 'Setting the DPDP inventory')}
                      onClick={() => setEditing({ table: t, column: '', entry: t.entry })}>
                      {t.entry ? 'Edit entry…' : 'Set entry…'}
                    </button>
                  </div>
                </div>
                <p style={{ marginBottom: 8 }}>{t.entry ? entryLine(t.entry) : <span className="muted">No entry for the table.</span>}</p>
                {t.notices.map((n, i) => <div className="pii-warning" role="status" key={i}>{n}</div>)}
                <div className="table-wrap">
                  <table aria-label={`Columns of ${where}`}>
                    <thead><tr><th>Column</th><th>Holds</th><th>Covered by</th><th><span className="sr-only">Actions</span></th></tr></thead>
                    <tbody>
                      {t.columns.map(c => (
                        <tr key={c.column}>
                          <td><code>{c.column}</code></td>
                          <td>{c.categories.join(', ')}{c.paths.length > 0 && <span className="muted"> at {c.paths.join(', ')}</span>}</td>
                          <td>
                            {c.by === 'column' && c.override ? <>its own entry: {entryLine(c.override)}</>
                              : c.by === 'table' ? <span className="muted">the table's entry</span>
                              : <b className="dpdp-gap">no entry</b>}
                          </td>
                          <td>
                            <button disabled={!licensed} onClick={() => setEditing({ table: t, column: c.column, entry: c.override ?? t.entry })}>
                              {c.override ? 'Edit its entry…' : 'Own entry…'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {editing && editing.table.schema === t.schema && editing.table.table === t.table && v && (
                  <EntryForm key={editing.column} vocab={v} editing={editing} onSave={save}
                    onRemove={(editing.column ? editing.table.columns.find(c => c.column === editing.column)?.override : editing.table.entry) ?? null}
                    onRemoveClick={remove} onCancel={() => setEditing(null)} />
                )}
              </div>
            )
          })}

          {history && (
            <div className="panel" style={{ marginTop: 14 }} data-testid="dpdp-history">
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <h3 style={{ margin: 0 }}>History of <code>{history.where}</code></h3>
                <button onClick={() => setHistory(null)}>Close</button>
              </div>
              {history.changes.length === 0 ? <p className="muted">No entry has been set here.</p> : (
                <div className="table-wrap">
                  <table aria-label="Entry history">
                    <thead><tr><th>When</th><th>Who</th><th>What</th><th>Where</th><th>Basis</th><th>Kept</th></tr></thead>
                    <tbody>
                      {history.changes.map(h => (
                        <tr key={h.id}>
                          <td>{new Date(h.at).toLocaleString()}</td><td>{h.actor}</td><td>{h.action}</td>
                          <td><code>{h.entry.column || '(table)'}</code></td>
                          <td>{h.entry.basis}</td><td>{keepText(v, h.entry.keep)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {inv.stale.length > 0 && (
            <div className="panel" style={{ marginTop: 14 }} data-testid="dpdp-stale">
              <h3 style={{ marginTop: 0 }}>Entries for places that no longer hold confirmed personal data</h3>
              <p className="muted" style={{ marginTop: 0 }}>A finding was rejected, or the column has gone. Remove the entry, or confirm the findings again.</p>
              <ul>
                {inv.stale.map(e => {
                  const where = `${e.schema}.${e.table}${e.column ? '.' + e.column : ''}`
                  return (
                    <li key={where}>
                      <code>{where}</code> <span className="muted">set by {e.setBy}</span>{' '}
                      <button disabled={!licensed} onClick={() => remove(e)}>Remove</button>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}

          <h3>What this cannot claim</h3>
          <ul className="muted" style={{ fontSize: 13 }}>
            {inv.limits.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </>
      )}
    </div>
  )
}

function EntryForm({ vocab, editing, onSave, onRemove, onRemoveClick, onCancel }: {
  vocab: DPDPVocabulary
  editing: Editing
  onSave: (e: DPDPEntry) => Promise<boolean>
  onRemove: DPDPEntry | null
  onRemoveClick: (e: DPDPEntry) => void
  onCancel: () => void
}) {
  const start = editing.entry
  const [basis, setBasis] = useState(start?.basis ?? 'consent')
  const [purpose, setPurpose] = useState(start?.purpose ?? '')
  const [principals, setPrincipals] = useState<string[]>(start?.principals ?? ['customer'])
  const [count, setCount] = useState(String(start?.keep.count ?? 3))
  const [unit, setUnit] = useState(start?.keep.unit ?? 'years')
  const [from, setFrom] = useState(start?.keep.from ?? 'last_contact')
  const [reason, setReason] = useState(start?.keep.reason ?? 'purpose')
  const [citation, setCitation] = useState(start?.keep.citation ?? '')
  const [note, setNote] = useState(start?.note ?? '')
  const [busy, setBusy] = useState(false)
  const where = `${editing.table.schema}.${editing.table.table}${editing.column ? '.' + editing.column : ''}`
  const toggle = (p: string) => setPrincipals(ps => ps.includes(p) ? ps.filter(x => x !== p) : [...ps, p])
  const n = Number(count)
  const ready = purpose.trim() !== '' && principals.length > 0 && Number.isInteger(n) && n >= 0 && (reason === 'purpose' || citation.trim() !== '')

  return (
    <form className="form" style={{ marginTop: 14 }} data-testid="dpdp-form" aria-label={`Entry for ${where}`}
      onSubmit={async e => {
        e.preventDefault()
        if (!ready) return
        setBusy(true)
        await onSave({
          schema: editing.table.schema, table: editing.table.table, column: editing.column,
          basis, purpose: purpose.trim(), principals,
          keep: { count: n, unit, from, reason, citation: reason === 'purpose' ? '' : citation.trim() }, note: note.trim(),
        })
        setBusy(false)
      }}>
      <h4 style={{ margin: 0 }}>
        {editing.column ? <>Entry for the column <code>{where}</code>; it replaces the table's for this column</> : <>Entry for <code>{where}</code></>}
      </h4>
      <label className="field">Basis (s.4)
        <select aria-label="Basis" value={basis} onChange={e => setBasis(e.target.value)}>
          {vocab.bases.map(b => <option key={b.value} value={b.value}>{b.label}</option>)}
        </select>
      </label>
      <label className="field">Purpose, as the notice to the person states it
        <textarea aria-label="Purpose" rows={2} maxLength={1000} value={purpose} onChange={e => setPurpose(e.target.value)} />
      </label>
      <fieldset className="dpdp-whose" aria-label="Whose data">
        <legend className="muted" style={{ fontSize: 13 }}>Whose data</legend>
        {vocab.principals.map(p => (
          <label key={p.value}><input type="checkbox" checked={principals.includes(p.value)} onChange={() => toggle(p.value)} /> {p.label}</label>
        ))}
      </fieldset>
      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <label className="field">Keep for
          <input aria-label="Keep for" inputMode="numeric" value={count} onChange={e => setCount(e.target.value)} style={{ width: 80 }} />
        </label>
        <label className="field">Unit
          <select aria-label="Unit" value={unit} onChange={e => setUnit(e.target.value)}>
            {vocab.units.map(u => <option key={u.value} value={u.value}>{u.label}</option>)}
          </select>
        </label>
        <label className="field">After
          <select aria-label="After" value={from} onChange={e => setFrom(e.target.value)}>
            {vocab.from.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
        </label>
        <label className="field">Because
          <select aria-label="Because" value={reason} onChange={e => setReason(e.target.value)}>
            {vocab.reasons.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
        </label>
      </div>
      {reason !== 'purpose' && (
        <label className="field">{reason === 'law' ? 'Which law, and where in it' : 'Which contract, and where in it'}
          <input aria-label="Citation" maxLength={500} value={citation} onChange={e => setCitation(e.target.value)}
            placeholder={reason === 'law' ? 'Prevention of Money-laundering Act, 2002, s.12' : 'Master services agreement, cl. 9'} />
        </label>
      )}
      <label className="field">Note (optional)
        <input aria-label="Note" maxLength={1000} value={note} onChange={e => setNote(e.target.value)} />
      </label>
      <div className="row" style={{ gap: 8 }}>
        <button className="primary" type="submit" disabled={!ready || busy}>{busy ? 'Saving…' : 'Save entry'}</button>
        <button type="button" onClick={onCancel}>Cancel</button>
        {onRemove && (editing.column ? onRemove.column === editing.column : onRemove.column === '') && (
          <button type="button" className="danger" onClick={() => onRemoveClick(onRemove)}>Remove entry…</button>
        )}
      </div>
    </form>
  )
}
