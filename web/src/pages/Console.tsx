import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getAdmins, getBranches, runQuery, API, type Branch, type BranchAdmins, type QueryResult } from '../api'

type DbObject = { schema: string; name: string; type: 'table' | 'view' }
type Tab = 'rows' | 'structure' | 'indexes'

const PAGE = 100

const lit = (s: string) => "'" + s.replace(/'/g, "''") + "'"
const qid = (s: string) => '"' + s.replace(/"/g, '""') + '"'
const rel = (o: DbObject) => qid(o.schema) + '.' + qid(o.name)
const key = (o: DbObject) => o.schema + '.' + o.name

const LIST_SQL = `SELECT table_schema, table_name, table_type
FROM information_schema.tables
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_schema, table_type DESC, table_name`

// FoxByte keeps its own bookkeeping (Blackbox, policies, agent sessions) in
// the fox schema of every branch. It is not the user's data, so it is hidden
// whenever the console opens and shown only on request.
const isSystem = (o: DbObject) => o.schema === 'bb' || o.schema.startsWith('key_')

// Statements that can add, remove or rename tables, so the schema list is
// refreshed after they run.
const DDL = /\b(create|drop|alter|truncate|rename|import\s+foreign)\b/i
// Two different refusals, overridden differently (docs/policy-errors.md): the
// guardrail on DROP TABLE / DROP SCHEMA (bb.allow_destructive) and a Blackbox
// policy rule, SQLSTATE BBX01 (bb.policy_allow, per rule).
// Matched without the product's name in it: the database raises this text, the
// product has been renamed twice, and a rename must not quietly stop the
// console recognising a blocked change.
const GUARDRAIL = /guardrail: .* is blocked by policy/
const POLICY_RULE = /BBX01/
const ruleOf = (err: string) => /\(rule ([a-z0-9][a-z0-9-]*)\)/.exec(err)?.[1]

export default function Console() {
  const [branches, setBranches] = useState<Branch[]>([])
  const [branch, setBranch] = useState('main')
  const [offline, setOffline] = useState(false)
  const [objects, setObjects] = useState<DbObject[]>([])
  const [listing, setListing] = useState(false)
  const [listErr, setListErr] = useState('')
  const [reloadTick, setReloadTick] = useState(0)
  const [showSystem, setShowSystem] = useState(false)
  const [filter, setFilter] = useState('')
  const [admins, setAdmins] = useState<BranchAdmins | null>(null)
  const [allowDestructive, setAllowDestructive] = useState(false)

  const [mode, setMode] = useState<'query' | 'browse'>('query')
  const [sel, setSel] = useState<DbObject | null>(null)
  const [tab, setTab] = useState<Tab>('rows')
  const [page, setPage] = useState(0)
  const [total, setTotal] = useState<number | null>(null)

  const [browseRes, setBrowseRes] = useState<QueryResult | null>(null)
  const [sql, setSql] = useState('SELECT version();')
  const [queryRes, setQueryRes] = useState<QueryResult | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    getBranches().then(b => { setBranches(b); setOffline(false) }).catch(() => setOffline(true))
  }, [])

  // The query API reports SQL errors in the body rather than throwing, so both
  // paths are checked — an error used to be shown as an empty schema.
  const loadObjects = useCallback(async (b: string) => {
    setListing(true); setListErr('')
    try {
      const r = await runQuery(b, LIST_SQL)
      if (r.error) { setListErr(r.error); return }
      setObjects((r.rows || []).map(row => ({
        schema: String(row[0]), name: String(row[1]),
        type: /view/i.test(String(row[2])) ? 'view' : 'table',
      })))
    } catch (e) {
      setListErr((e as Error).message)
    } finally {
      setListing(false)
    }
  }, [])

  // Reset when the branch changes.
  useEffect(() => {
    setObjects([]); loadObjects(branch); setSel(null); setMode('query'); setBrowseRes(null); setAllowDestructive(false)
    setAdmins(null)
    getAdmins(branch).then(setAdmins).catch(() => setAdmins(null))
  }, [branch, loadObjects])

  // An open table that no longer exists (dropped, renamed) closes itself.
  useEffect(() => {
    if (sel && !listing && !listErr && !objects.some(o => key(o) === key(sel))) { setSel(null); setMode('query') }
  }, [objects, sel, listing, listErr])

  // Reload refreshes both the list and whatever table is open.
  const reload = () => { loadObjects(branch); setReloadTick(t => t + 1) }

  // Load the active browse tab.
  useEffect(() => {
    if (mode !== 'browse' || !sel) return
    let cancelled = false
    const load = async () => {
      setBusy(true); setBrowseRes(null)
      try {
        let q = ''
        if (tab === 'rows') {
          q = `SELECT * FROM ${rel(sel)} LIMIT ${PAGE} OFFSET ${page * PAGE}`
        } else if (tab === 'structure') {
          q = `SELECT column_name, data_type, is_nullable, column_default
               FROM information_schema.columns
               WHERE table_schema=${lit(sel.schema)} AND table_name=${lit(sel.name)}
               ORDER BY ordinal_position`
        } else {
          q = `SELECT indexname, indexdef FROM pg_indexes
               WHERE schemaname=${lit(sel.schema)} AND tablename=${lit(sel.name)}
               ORDER BY indexname`
        }
        const r = await runQuery(branch, q)
        if (!cancelled) setBrowseRes(r)
        if (tab === 'rows' && !cancelled) {
          const c = await runQuery(branch, `SELECT count(*) FROM ${rel(sel)}`)
          if (!cancelled) setTotal(Number(c.rows?.[0]?.[0] ?? 0))
        }
      } catch (e) {
        if (!cancelled) setBrowseRes({ error: (e as Error).message })
      } finally {
        if (!cancelled) setBusy(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [mode, sel, tab, page, branch, reloadTick])

  const openObject = (o: DbObject) => { setSel(o); setTab('rows'); setPage(0); setTotal(null); setMode('browse') }
  const switchTab = (t: Tab) => { setTab(t); if (t === 'rows') setPage(0) }

  // The override applies to one run and then switches itself off, so a later
  // run can't drop something by accident.
  const runSql = async (override: { allowDestructive?: boolean; allowRules?: string[] } = { allowDestructive }) => {
    setBusy(true); setQueryRes(null); setMode('query')
    try {
      const r = await runQuery(branch, sql, override)
      setQueryRes(r)
      if (!r.error && DDL.test(sql)) loadObjects(branch)
    } catch (e) {
      setQueryRes({ error: (e as Error).message })
    } finally {
      setBusy(false); setAllowDestructive(false)
    }
  }

  if (offline) {
    return (
      <>
        <h1>SQL Console</h1>
        <div className="offline">Can’t reach the API at <code>{API}</code>. Start it with <code>fox start</code>.</div>
      </>
    )
  }

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const f = filter.trim().toLowerCase()
  const match = (o: DbObject) => !f || o.name.toLowerCase().includes(f) || o.schema.toLowerCase().includes(f)
  const tables = objects.filter(o => !isSystem(o) && o.type === 'table' && match(o))
  const views = objects.filter(o => !isSystem(o) && o.type === 'view' && match(o))
  const system = objects.filter(o => isSystem(o) && match(o))
  const label = (o: DbObject) => (o.schema === 'public' ? o.name : o.schema + '.' + o.name)
  const canOverride = admins?.you_are_admin === true
  const err = queryRes?.error || ''
  // A policy-rule block names its rule; without a rule id there's nothing to override.
  const blockedRule = POLICY_RULE.test(err) ? ruleOf(err) : undefined
  const blocked = GUARDRAIL.test(err) || !!blockedRule
  const item = (o: DbObject) => (
    <button key={key(o)} className={'obj-item' + (mode === 'browse' && sel && key(sel) === key(o) ? ' active' : '')} onClick={() => openObject(o)}>
      <i className="ic">{o.type === 'view' ? '◈' : '▦'}</i>{label(o)}
    </button>
  )

  return (
    <div className="fade-up">
      <h1>SQL Console</h1>
      <p className="muted" style={{ marginTop: -2 }}>Browse a branch’s tables &amp; views, or run any SQL — through the control-plane API.</p>

      <div className="row">
        <span className="muted" style={{ fontSize: 13 }}>Branch</span>
        <select value={branch} onChange={e => setBranch(e.target.value)}>
          {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
      </div>

      <div className="console-grid">
        <aside className="obj-panel">
          <div className="obj-head">
            <span>Schema</span>
            <button title={listing ? 'Reloading…' : 'Reload tables'} className={listing ? 'spinning' : ''} disabled={listing} onClick={reload}>↻</button>
          </div>
          <div style={{ padding: 8 }}>
            <input className="obj-filter" placeholder="Filter tables…" value={filter} onChange={e => setFilter(e.target.value)} />
          </div>
          <div className="obj-list">
            <button className={'obj-item special' + (mode === 'query' ? ' active' : '')} onClick={() => setMode('query')}>
              <i className="ic">⌘</i>SQL query
            </button>
            {listErr && <div className="obj-error">Couldn’t load tables: {listErr}</div>}
            {listing && objects.length === 0 && <div className="obj-empty">Loading…</div>}
            {!listing && !listErr && tables.length + views.length === 0 && (
              <div className="obj-empty">
                {f ? 'No tables match.' : <>No tables yet. Create one with <code>CREATE TABLE …</code> in the SQL query.</>}
              </div>
            )}
            {tables.length > 0 && <div className="obj-group">Tables</div>}
            {tables.map(item)}
            {views.length > 0 && <div className="obj-group">Views</div>}
            {views.map(item)}
            {showSystem && system.length > 0 && (
              <>
                <div className="obj-group">FoxByte system</div>
                {system.map(item)}
              </>
            )}
            {system.length > 0 && (
              <button className="obj-show-system" onClick={() => setShowSystem(v => !v)} aria-expanded={showSystem}
                title="Blackbox, policies and agent sessions — kept by FoxByte, not your data">
                {showSystem ? 'Hide system tables' : `Show system tables (${system.length})`}
              </button>
            )}
          </div>
        </aside>

        <div>
          {mode === 'query' ? (
            <>
              <textarea
                className="editor"
                value={sql}
                spellCheck={false}
                onChange={e => setSql(e.target.value)}
                onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') runSql() }}
              />
              <div className="row" style={{ marginTop: 10, flexWrap: 'wrap', gap: 12 }}>
                <button className={'primary' + (allowDestructive ? ' danger' : '')} onClick={() => runSql()} disabled={busy}>
                  {busy ? 'Running…' : 'Run  ⌘/Ctrl+↵'}
                </button>
                <label className={'override-toggle' + (allowDestructive ? ' on' : '')}
                  title={admins && !canOverride
                    ? `Only admins of ${branch} can override the guardrail`
                    : 'Lets DROP TABLE and other blocked changes through, for the next run only'}>
                  <input type="checkbox" checked={allowDestructive} disabled={busy || (admins !== null && !canOverride)}
                    onChange={e => setAllowDestructive(e.target.checked)} />
                  Allow destructive changes <span className="muted">(next run only)</span>
                </label>
              </div>
              {queryRes && <Grid res={queryRes} showCommand />}
              {blocked && (
                <div className="override-help">
                  {canOverride ? (
                    <>
                      <div>
                        <b>{blockedRule ? <>Blocked by policy rule <code>{blockedRule}</code>.</> : 'Blocked by the guardrail.'}</b>{' '}
                        You’re an admin on <code>{branch}</code>, so you can let this change through once.
                      </div>
                      <div className="row" style={{ marginTop: 10 }}>
                        <button className="primary danger" disabled={busy}
                          onClick={() => runSql(blockedRule ? { allowRules: [blockedRule] } : { allowDestructive: true })}>
                          {blockedRule ? <>Allow rule {blockedRule} &amp; run again</> : <>Allow &amp; run again</>}
                        </button>
                      </div>
                    </>
                  ) : (
                    <div>
                      <b>{blockedRule ? <>Blocked by policy rule <code>{blockedRule}</code>.</> : 'Blocked by the guardrail.'}</b> Only admins of <code>{branch}</code> can override it
                      {admins && <> — you’re signed in as <code>{admins.you}</code></>}. Ask an admin to grant you on
                      the <Link to="/policies">Policies</Link> page, or run{' '}
                      <code>fox admin grant {admins?.you || '<email>'} --branch {branch}</code>.
                    </div>
                  )}
                </div>
              )}
            </>
          ) : sel && (
            <>
              <div className="obj-view-head">
                <h2>{sel.name}</h2>
                <span className="path">{sel.schema} · {sel.type}</span>
              </div>
              <div className="db-tabs">
                {(['rows', 'structure', 'indexes'] as Tab[]).map(t => (
                  <button key={t} className={tab === t ? 'active' : ''} onClick={() => switchTab(t)}>
                    {t === 'rows' ? 'Rows' : t === 'structure' ? 'Structure' : 'Indexes'}
                  </button>
                ))}
              </div>
              {busy && !browseRes ? <div className="muted">Loading…</div> : browseRes && <Grid res={browseRes} />}
              {tab === 'rows' && browseRes && !browseRes.error && (
                <div className="pager">
                  <button className="ghost" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>‹ Prev</button>
                  <span>
                    rows {total === 0 ? 0 : page * PAGE + 1}–{page * PAGE + (browseRes.rows?.length || 0)}
                    {total != null && <> of {total}</>}
                  </span>
                  <button className="ghost" onClick={() => setPage(p => p + 1)}
                    disabled={total == null ? (browseRes.rows?.length || 0) < PAGE : (page + 1) * PAGE >= total}>Next ›</button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function Grid({ res, showCommand }: { res: QueryResult; showCommand?: boolean }) {
  const [expanded, setExpanded] = useState<number | null>(null)
  useEffect(() => { setExpanded(null) }, [res]) // reset when new results arrive
  if (res.error) return <div className="err">{res.error}</div>
  const cols = res.columns || []
  const rows = res.rows || []
  const openRow = expanded != null ? rows[expanded] : null
  return (
    <>
      {showCommand && <div className="okmsg">✓ {res.command || 'ok'} · {rows.length} row{rows.length === 1 ? '' : 's'}</div>}
      {cols.length > 0 ? (
        <div className="grid-wrap table-wrap">
          <table>
            <thead><tr><th className="expand-col"></th>{cols.map((c, i) => <th key={i}>{c}</th>)}</tr></thead>
            <tbody>
              {rows.length === 0
                ? <tr><td colSpan={cols.length + 1} className="muted">no rows</td></tr>
                : rows.map((r, i) => (
                  <tr key={i}>
                    <td className="expand-col">
                      <button className="expand-btn" title="View row as JSON" onClick={() => setExpanded(i)}>{'{ }'}</button>
                    </td>
                    {r.map((v, j) => <td key={j}>{v === null ? 'NULL' : String(v)}</td>)}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : !showCommand && (
        <div className="okmsg">✓ {res.command || 'ok'}</div>
      )}
      {openRow && <JsonModal cols={cols} row={openRow} onClose={() => setExpanded(null)} />}
    </>
  )
}

// JsonModal shows one result row as pretty JSON. jsonb cells come back as JSON
// strings, so we parse them into nested structure for a clean document view.
function JsonModal({ cols, row, onClose }: { cols: string[]; row: unknown[]; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const obj: Record<string, unknown> = {}
  cols.forEach((c, i) => {
    const v = row[i]
    if (typeof v === 'string') {
      const t = v.trim()
      if ((t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))) {
        try { obj[c] = JSON.parse(t); return } catch { /* keep as string */ }
      }
    }
    obj[c] = v
  })
  const text = JSON.stringify(obj, null, 2)
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200) } catch { /* ignore */ }
  }

  return (
    <div className="json-modal-backdrop" onClick={onClose}>
      <div className="json-modal" onClick={e => e.stopPropagation()}>
        <div className="json-modal-head">
          <span>Row as JSON</span>
          <div className="row" style={{ gap: 8 }}>
            <button className="ghost" onClick={copy}>{copied ? 'Copied ✓' : 'Copy'}</button>
            <button className="ghost" onClick={onClose} title="Close (Esc)">✕</button>
          </div>
        </div>
        <pre className="json-modal-body">{text}</pre>
      </div>
    </div>
  )
}
