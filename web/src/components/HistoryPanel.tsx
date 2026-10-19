// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  deleteHistoryEntry, deleteSaved, historySettings, listHistory, listSaved, saveQuery, updateSaved,
  type HistoryEntry, type SavedQuery,
} from '../api'
import { useConfirm } from '../confirm'

const PAGE = 50

// when says how long ago, in the words a person uses: just now, 5 min ago,
// 3 h ago, then the date.
export function when(at: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - at) / 1000))
  if (s < 45) return 'just now'
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return new Date(at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

const oneLine = (sql: string) => sql.replace(/\s+/g, ' ').trim()

async function copyText(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true } catch { return false }
}

/**
 * The console's history and saved queries (point 8.2): what you ran, to find,
 * open, run again, copy or keep under a name. Your own only, as the engine
 * keeps it (8.1, 8.3); the switches are on the account page.
 *
 * Run means run again where it ran: on the branch the entry came from when that
 * branch still exists, and on the branch in use otherwise. A saved query runs
 * on the branch in use. Running never carries the destructive override.
 */
export default function HistoryPanel({ branch, branches, tick, busy, current, onOpen, onRun }: {
  branch: string
  current: string // what is in the editor, to save as it is
  branches: string[]
  tick: number // changes after each run, so the list shows the new entry
  busy: boolean
  onOpen: (sql: string) => void
  onRun: (sql: string, branch: string) => void
}) {
  const [tab, setTab] = useState<'history' | 'saved'>('history')
  const [search, setSearch] = useState('')
  const [failed, setFailed] = useState(false)
  const [here, setHere] = useState(false) // only this branch
  const [entries, setEntries] = useState<HistoryEntry[]>([])
  const [more, setMore] = useState(false)
  const [saved, setSaved] = useState<SavedQuery[]>([])
  // Loading from the start, so the panel does not say "nothing yet" for the
  // moment before the first answer arrives.
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [off, setOff] = useState(false)
  const [naming, setNaming] = useState<{ sql: string; key: string; name: string; renaming?: number } | null>(null)
  const confirm = useConfirm()
  const seq = useRef(0)

  useEffect(() => {
    historySettings().then(s => setOff(!s.enabled || !s.mine)).catch(() => { /* the list says what is wrong */ })
  }, [])

  const flash = (m: string) => { setNote(m); setTimeout(() => setNote(n => (n === m ? '' : n)), 1800) }

  const load = useCallback(async (append = false, before?: number) => {
    const my = ++seq.current
    setLoading(true); setErr('')
    try {
      if (tab === 'history') {
        const r = await listHistory({ q: search, failed, branch: here ? branch : undefined, limit: PAGE, before })
        if (my !== seq.current) return
        setEntries(e => (append ? [...e, ...r.entries] : r.entries))
        setMore(r.entries.length === PAGE)
      } else {
        const r = await listSaved(search)
        if (my !== seq.current) return
        setSaved(r.queries)
      }
    } catch (e) {
      if (my === seq.current) setErr((e as Error).message)
    } finally {
      if (my === seq.current) setLoading(false)
    }
  }, [tab, search, failed, here, branch])

  // Typing waits a moment before asking, so a search is one request rather
  // than one a keystroke.
  useEffect(() => {
    const t = setTimeout(() => { load() }, search ? 250 : 0)
    return () => clearTimeout(t)
  }, [load, tick, search])

  const runOn = (e: HistoryEntry) => (branches.includes(e.branch) ? e.branch : branch)

  const copy = async (sql: string) => flash((await copyText(sql)) ? 'Copied ✓' : 'The browser refused the clipboard: use Open, then copy from the editor')

  const submitName = async (ev: React.FormEvent) => {
    ev.preventDefault()
    if (!naming) return
    setErr('')
    try {
      if (naming.renaming) await updateSaved(naming.renaming, { name: naming.name })
      else await saveQuery(naming.name, naming.sql)
      flash(naming.renaming ? 'Renamed' : `Saved as “${naming.name.trim()}”`)
      setNaming(null)
      if (tab === 'saved') load()
    } catch (e) { setErr((e as Error).message) }
  }

  const removeEntry = async (e: HistoryEntry) => {
    try { await deleteHistoryEntry(e.id); setEntries(xs => xs.filter(x => x.id !== e.id)) } catch (x) { setErr((x as Error).message) }
  }

  const removeSaved = async (q: SavedQuery) => {
    const ok = await confirm({ title: 'Delete saved query', message: <>Delete <b>{q.name}</b>? This can't be undone.</>, confirmText: 'Delete', danger: true })
    if (!ok) return
    try { await deleteSaved(q.id); setSaved(xs => xs.filter(x => x.id !== q.id)) } catch (x) { setErr((x as Error).message) }
  }

  const nameForm = (key: string) => naming && naming.key === key && (
    <form className="hist-name" onSubmit={submitName}>
      <input autoFocus aria-label="Name for the saved query" placeholder="Name" maxLength={100}
        value={naming.name} onChange={e => setNaming({ ...naming, name: e.target.value })} />
      <button type="submit" className="primary sm" disabled={!naming.name.trim()}>{naming.renaming ? 'Rename' : 'Save'}</button>
      <button type="button" className="ghost sm" onClick={() => setNaming(null)}>Cancel</button>
    </form>
  )

  return (
    <aside className="wb-history" aria-label="Query history">
      <div className="hist-tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'history'} className={tab === 'history' ? 'on' : ''}
          onClick={() => { setTab('history'); setNaming(null) }}>History</button>
        <button role="tab" aria-selected={tab === 'saved'} className={tab === 'saved' ? 'on' : ''}
          onClick={() => { setTab('saved'); setNaming(null) }}>Saved</button>
      </div>
      <div className="hist-filters">
        <input className="obj-filter" type="search" aria-label={tab === 'history' ? 'Search history' : 'Search saved queries'}
          placeholder={tab === 'history' ? 'Search your history…' : 'Search saved queries…'}
          value={search} onChange={e => setSearch(e.target.value)} />
        {tab === 'history' && (
          <div className="hist-checks">
            <label className="check-row"><input type="checkbox" checked={failed} onChange={e => setFailed(e.target.checked)} /> Failed only</label>
            <label className="check-row"><input type="checkbox" checked={here} onChange={e => setHere(e.target.checked)} /> Only {branch}</label>
          </div>
        )}
      </div>
      {note && <div className="ok hist-note" role="status">{note}</div>}
      {err && <div className="err hist-note" role="alert">{err}</div>}

      {tab === 'history' ? (
        <ul className="hist-list">
          {off && entries.length === 0 && !loading && (
            <li className="hist-empty">History is off for you or for this install: turn it on in <a href="/keys">your account</a>.</li>
          )}
          {!off && entries.length === 0 && !loading && (
            <li className="hist-empty">{search || failed || here ? 'Nothing matches.' : 'Nothing yet. The queries you run appear here.'}</li>
          )}
          {entries.map(e => (
            <li key={e.id} className={'hist-item' + (e.ok ? '' : ' bad')}>
              <code className="hist-sql" title={e.sql}>{oneLine(e.sql)}</code>
              <div className="hist-meta">
                <span>{when(e.at)}</span>
                <span>{e.branch}</span>
                <span>{e.duration_ms} ms</span>
                {e.ok ? <span>{e.rows} row{e.rows === 1 ? '' : 's'}</span> : <span className="n-bad" title={e.error}>failed</span>}
                {e.kind === 'export' && <span>export</span>}
                {e.source !== 'console' && <span>{e.source === 'cli' ? 'CLI' : 'API'}</span>}
              </div>
              {e.truncated && <div className="muted hist-meta">Longer than 64 KB, kept cut: it can be copied, not run.</div>}
              <div className="hist-actions">
                <button className="ghost sm" onClick={() => onOpen(e.sql)} disabled={busy}>Open</button>
                <button className="ghost sm" onClick={() => onRun(e.sql, runOn(e))} disabled={busy || e.truncated}
                  title={runOn(e) === e.branch ? `Run again on ${e.branch}` : `${e.branch} is gone: runs on ${branch}`}>Run</button>
                <button className="ghost sm" onClick={() => copy(e.sql)}>Copy</button>
                <button className="ghost sm" onClick={() => setNaming({ sql: e.sql, key: `h${e.id}`, name: '' })} disabled={e.truncated}>Save</button>
                <button className="ghost sm" aria-label="Delete from history" title="Delete from history" onClick={() => removeEntry(e)}>×</button>
              </div>
              {nameForm(`h${e.id}`)}
            </li>
          ))}
          {more && (
            <li><button className="ghost sm hist-more" disabled={loading}
              onClick={() => load(true, entries[entries.length - 1]?.id)}>Load more</button></li>
          )}
          {loading && <li className="hist-empty">Loading…</li>}
        </ul>
      ) : (
        <ul className="hist-list">
          <li className="hist-save-current">
            <button className="ghost sm" disabled={!current.trim()}
              onClick={() => setNaming({ sql: current, key: 'editor', name: '' })}>Save the editor’s query</button>
            {nameForm('editor')}
          </li>
          {saved.length === 0 && !loading && (
            <li className="hist-empty">{search ? 'Nothing matches.' : 'No saved queries. Save one from History.'}</li>
          )}
          {saved.map(q => (
            <li key={q.id} className="hist-item">
              <div className="hist-name-row"><b>{q.name}</b></div>
              <code className="hist-sql" title={q.sql}>{oneLine(q.sql)}</code>
              <div className="hist-actions">
                <button className="ghost sm" onClick={() => onOpen(q.sql)} disabled={busy}>Open</button>
                <button className="ghost sm" onClick={() => onRun(q.sql, branch)} disabled={busy} title={`Run on ${branch}`}>Run</button>
                <button className="ghost sm" onClick={() => copy(q.sql)}>Copy</button>
                <button className="ghost sm" onClick={() => setNaming({ sql: q.sql, key: `s${q.id}`, name: q.name, renaming: q.id })}>Rename</button>
                <button className="ghost sm" aria-label={`Delete ${q.name}`} title="Delete" onClick={() => removeSaved(q)}>×</button>
              </div>
              {nameForm(`s${q.id}`)}
            </li>
          ))}
          {loading && <li className="hist-empty">Loading…</li>}
        </ul>
      )}
    </aside>
  )
}
