import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { getAdmins, getBranches, getCatalog, getObject, getTracking, runQuery, saveRows, API, type Branch, type BranchAdmins, type CatalogObject, type QueryResult, type Tracking, type StatementResult, type Suggestion } from '../api'
import { BRAND } from '../brand'
import { hintFor } from '../errhint'
import CopyMenu, { cellText } from '../components/CopyMenu'
import ExportMenu from '../components/ExportMenu'
import HistoryPanel from '../components/HistoryPanel'
import { useCompletion } from '../components/Completion'
import { CatalogGroups, ObjectView, TableParts } from '../components/ObjectBrowser'
import { EditGrid, FilterBar, type ColInfo } from '../components/DataGrid'
import { TrackingControl, trackedOf } from '../components/Tracking'
import { countQuery, nextSort, rowsQuery, summary, type Filter, type Sort } from '../gridquery'
import { applySuggestion, schemaFrom, snippets, SCHEMA_SQL, type Rel } from '../sqlcomplete'

type DbObject = { schema: string; name: string; type: 'table' | 'view' }
type Tab = 'rows' | 'structure' | 'indexes' | 'constraints' | 'triggers' | 'ddl'
// Tabs the catalog fills (point 12.1), rather than a query of the console's own.
const CATALOG_TABS: Tab[] = ['constraints', 'triggers', 'ddl']
const TAB_LABEL: Record<Tab, string> = { rows: 'Rows', structure: 'Structure', indexes: 'Indexes', constraints: 'Constraints', triggers: 'Triggers', ddl: 'CREATE script' }

const PAGE = 100
const HISTORY_KEY = 'fox.history.open'

type FixFn = (s: Suggestion, position: number | undefined, run: boolean) => void

const lit = (s: string) => "'" + s.replace(/'/g, "''") + "'"
const qid = (s: string) => '"' + s.replace(/"/g, '""') + '"'
const rel = (o: DbObject) => qid(o.schema) + '.' + qid(o.name)
const key = (o: DbObject) => o.schema + '.' + o.name

const LIST_SQL = `SELECT table_schema, table_name, table_type
FROM information_schema.tables
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_schema, table_type DESC, table_name`

// FoxByte keeps its own bookkeeping (Blackbox, policies, agent sessions) in the
// bb schema of every branch. It is not the user's data, so it is hidden
// whenever the console opens and shown only on request. The name is frozen and
// brand-free (see docs/branding.md), which is why it is not the product's.
const isSystem = (o: DbObject) => o.schema === 'bb' || o.schema.startsWith('bb_')

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
  // Every column the caller can see on this branch, with its type and whether
  // it is in the key: what autocomplete and the snippets read (point 9).
  const [rels, setRels] = useState<Rel[]>([])
  const [listing, setListing] = useState(false)
  const [listErr, setListErr] = useState('')
  const [reloadTick, setReloadTick] = useState(0)
  const [showSystem, setShowSystem] = useState(false)
  const [filter, setFilter] = useState('')
  const [admins, setAdmins] = useState<BranchAdmins | null>(null)
  const [allowDestructive, setAllowDestructive] = useState(false)

  const [mode, setMode] = useState<'query' | 'browse' | 'object'>('query')
  // The rest of what the branch holds, and the one of those open (point 12.1).
  const [catalog, setCatalog] = useState<CatalogObject[]>([])
  const [objSel, setObjSel] = useState<CatalogObject | null>(null)
  // Which tables keep who changed each row and when (points 5.1, 6.1).
  const [tracking, setTracking] = useState<Tracking | null>(null)
  const [sel, setSel] = useState<DbObject | null>(null)
  const [tab, setTab] = useState<Tab>('rows')
  const [page, setPage] = useState(0)
  // The data grid (point 12.2): the open table's sort, filters, and whether
  // its page is being edited.
  const [sort, setSort] = useState<Sort>(null)
  const [filters, setFilters] = useState<Filter[]>([])
  const [editing, setEditing] = useState<ColInfo[] | null>(null)
  const [gridNote, setGridNote] = useState('')
  const [total, setTotal] = useState<number | null>(null)

  const [browseRes, setBrowseRes] = useState<QueryResult | null>(null)
  const [sql, setSql] = useState('SELECT version();')
  const [queryRes, setQueryRes] = useState<QueryResult | null>(null)
  const [ranSql, setRanSql] = useState('')
  // The history panel (point 8.2): open or shut, remembered in this browser,
  // and a count of runs so it can show each new one.
  const [historyOpen, setHistoryOpen] = useState(() => { try { return localStorage.getItem(HISTORY_KEY) === '1' } catch { return false } })
  const [historyTick, setHistoryTick] = useState(0)
  const toggleHistory = () => setHistoryOpen(v => {
    try { localStorage.setItem(HISTORY_KEY, v ? '0' : '1') } catch { /* not kept */ }
    return !v
  })
  // The branch the result came from, which an export of the whole of it reads.
  const [ranBranch, setRanBranch] = useState('main')
  // Workbench state. The rail and the divider are remembered per browser: both
  // are a choice about this person's screen, and re-making it on every visit is
  // the kind of small friction that makes a tool feel borrowed.
  const [railOpen, setRailOpen] = useState(() => localStorage.getItem('wb.rail') !== 'closed')
  const [editorH, setEditorH] = useState(() => Number(localStorage.getItem('wb.editorH')) || 260)
  // Which pane, if either, has the window to itself. Esc returns to the split.
  const [expand, setExpand] = useState<'none' | 'editor' | 'results'>('none')
  useEffect(() => { localStorage.setItem('wb.rail', railOpen ? 'open' : 'closed') }, [railOpen])
  useEffect(() => { localStorage.setItem('wb.editorH', String(editorH)) }, [editorH])
  useEffect(() => {
    if (expand === 'none') return
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setExpand('none') }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [expand])

  // Dragging the divider. Tracked on the window rather than the handle so the
  // pointer can leave it mid-drag without the pane sticking — the usual way a
  // splitter feels broken.
  const gutterRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<HTMLTextAreaElement>(null)

  const dragFrom = useRef<{ y: number; h: number } | null>(null)
  const onSplitDown = (e: React.MouseEvent) => {
    dragFrom.current = { y: e.clientY, h: editorH }
    const move = (ev: MouseEvent) => {
      if (!dragFrom.current) return
      const next = dragFrom.current.h + (ev.clientY - dragFrom.current.y)
      setEditorH(Math.max(90, Math.min(window.innerHeight - 260, next)))
    }
    const up = () => {
      dragFrom.current = null
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseup', up)
      document.body.classList.remove('row-resizing')
    }
    document.body.classList.add('row-resizing')
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }
  const [busy, setBusy] = useState(false)
  // A table's rows loading, kept apart from busy (a query in flight, which
  // locks the editor). Sharing busy left the editor read-only for good when a
  // load was cancelled by switching back to the query: the cancelled load never
  // cleared it, and a reload (tracking a table starts one) made that likely.
  const [loading, setLoading] = useState(false)
  const assist = useCompletion({ editor: editorRef, text: sql, setText: setSql, schema: rels, busy })

  // The branch list is what the picker is made of, and it used to be fetched once:
  // a single failed call — the engine still coming up, a slow answer from the
  // storage listing underneath — left the picker empty for as long as the page
  // stayed open, with no way back but a reload. So it keeps trying until it has a
  // list, then stops.
  useEffect(() => {
    let alive = true
    let timer: number | undefined
    const load = () => {
      getBranches()
        .then(b => {
          if (!alive) return
          setBranches(b)
          setOffline(false)
          if (b.length === 0) timer = window.setTimeout(load, 4000) // nothing at all is not an answer
        })
        .catch(() => {
          if (!alive) return
          setOffline(true)
          timer = window.setTimeout(load, 4000)
        })
    }
    load()
    return () => { alive = false; if (timer) window.clearTimeout(timer) }
  }, [])

  // The query API reports SQL errors in the body rather than throwing, so both
  // paths are checked — an error used to be shown as an empty schema.
  // The console's own reads (the object list, a table's rows and structure)
  // stay out of the user's query history: nobody typed them.
  const loadObjects = useCallback(async (b: string) => {
    setListing(true); setListErr('')
    try {
      const r = await runQuery(b, LIST_SQL, { history: false })
      if (r.error) { setListErr(r.error); return }
      setObjects((r.rows || []).map(row => ({
        schema: String(row[0]), name: String(row[1]),
        type: /view/i.test(String(row[2])) ? 'view' : 'table',
      })))
      // The columns, for suggestions. Not worth an error of its own: without
      // them the editor still offers tables and keywords.
      runQuery(b, SCHEMA_SQL, { history: false })
        .then(c => setRels(c.error ? [] : schemaFrom(c.rows || [])))
        .catch(() => setRels([]))
      // Everything else it holds, for the object browser. Without it the rail
      // still lists tables and views, as it always has.
      getCatalog(b).then(c => setCatalog(c.objects ?? [])).catch(() => setCatalog([]))
      getTracking(b).then(setTracking).catch(() => setTracking(null))
    } catch (e) {
      setListErr((e as Error).message)
    } finally {
      setListing(false)
    }
  }, [])

  // Reset when the branch changes.
  useEffect(() => {
    setObjects([]); setRels([]); setCatalog([]); setObjSel(null); setTracking(null); loadObjects(branch); setSel(null); setMode('query'); setBrowseRes(null); setAllowDestructive(false)
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
    if (CATALOG_TABS.includes(tab)) { setBrowseRes(null); setLoading(false); return }
    let cancelled = false
    const load = async () => {
      setLoading(true); setBrowseRes(null)
      try {
        let q = ''
        if (tab === 'rows') {
          q = rowsQuery(rel(sel), { sort, filters, page, pageSize: PAGE, key: keyOf(sel) })
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
        const r = await runQuery(branch, q, { history: false })
        if (!cancelled) setBrowseRes(r)
        if (tab === 'rows' && !cancelled) {
          const c = await runQuery(branch, countQuery(rel(sel), filters), { history: false })
          if (!cancelled) setTotal(Number(c.rows?.[0]?.[0] ?? 0))
        }
      } catch (e) {
        if (!cancelled) setBrowseRes({ error: (e as Error).message })
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true; setLoading(false) }
  }, [mode, sel, tab, page, branch, reloadTick, sort, filters, rels]) // rels: the key that orders a page

  const openObject = (o: DbObject) => {
    setSel(o); setTab('rows'); setPage(0); setTotal(null); setMode('browse')
    setSort(null); setFilters([]); setEditing(null); setGridNote('')
  }
  // A table's primary key, which orders its pages and names a row in an edit.
  const keyOf = (o: DbObject) => rels.find(r => r.schema === o.schema && r.name === o.name)?.cols.filter(c => c.pk).map(c => c.name) ?? []

  // Edit mode needs to know which columns Postgres fills itself: those come
  // from the catalog, with the key.
  const startEdit = async () => {
    if (!sel) return
    setGridNote('')
    const obj = catalog.find(o => o.kind === 'table' && o.schema === sel.schema && o.name === sel.name)
    const key = keyOf(sel)
    let cols = rels.find(r => r.schema === sel.schema && r.name === sel.name)?.cols.map(c => ({ name: c.name, type: c.type })) ?? []
    const locked = new Map<string, string>()
    // Columns row tracking keeps: Postgres writes them on every change.
    const tr = trackedOf(tracking, sel.schema, sel.name)
    for (const c of [tr?.created, tr?.updated, tr?.by, tr?.for]) if (c) locked.set(c, 'Kept by row tracking: Postgres writes it on every change')
    if (obj) {
      try {
        const d = await getObject(branch, 'table', obj.oid)
        if (d.columns?.length) cols = d.columns.map(c => ({ name: c.name, type: c.type }))
        for (const c of d.columns ?? []) {
          if (locked.has(c.name)) continue
          if (c.generated) locked.set(c.name, `Generated from other columns: ${c.generated}`)
          else if (c.identity === 'always') locked.set(c.name, 'An identity column: Postgres sets it')
        }
      } catch { /* the save still refuses what cannot be set */ }
    }
    setEditing(cols.map(c => ({ ...c, key: key.includes(c.name), locked: locked.get(c.name) })))
  }
  const saveGrid = async (changes: import('../gridquery').RowChange[]) => {
    if (!sel) return
    await saveRows(branch, sel.schema, sel.name, changes)
    setEditing(null)
    setGridNote(`Saved: ${summary(changes)}.`)
    setReloadTick(t => t + 1)
  }
  const switchTab = (t: Tab) => { setTab(t); if (t === 'rows') setPage(0) }

  // The override applies to one run and then switches itself off, so a later
  // run can't drop something by accident.
  //
  // text and on run something other than the editor on another branch: the
  // history panel's Run (point 8.2), which puts the statement in the editor and
  // moves to its branch first, so what is on screen is what ran.
  const runSql = async (override: { allowDestructive?: boolean; allowRules?: string[] } = { allowDestructive }, text?: string, on?: string) => {
    const q = text ?? sql
    const b = on ?? branch
    if (text !== undefined) setSql(text)
    if (b !== branch) setBranch(b)
    setBusy(true); setQueryRes(null); setMode('query')
    // The SQL this run is labelled against. The editor is read-only while a
    // query is in flight, so it should not be able to change underneath — this
    // is the belt to that pair of braces, and it costs one assignment.
    setRanSql(q)
    setRanBranch(b)
    try {
      const r = await runQuery(b, q, override)
      setQueryRes(r)
      if (!r.error && DDL.test(q)) loadObjects(b)
    } catch (e) {
      setQueryRes({ error: (e as Error).message })
    } finally {
      setBusy(false); setAllowDestructive(false); setHistoryTick(t => t + 1)
    }
  }

  // A CREATE script or a snippet into the editor, to read, change or run.
  const openSql = (text: string) => {
    setSql(text); setMode('query')
    requestAnimationFrame(() => editorRef.current?.focus())
  }

  // A "did you mean" fix (point 9.2): the name written into the SQL that ran,
  // where Postgres pointed, and run again on the branch it ran on when asked.
  const [fixNote, setFixNote] = useState('')
  const fix: FixFn = (sg, position, run) => {
    const fixed = applySuggestion(ranSql, sg, position)
    if (fixed === null) { setFixNote(`Couldn’t find ${sg.wrong} in the query: change it by hand.`); return }
    setFixNote('')
    if (run) { runSql({}, fixed, ranBranch); return }
    setSql(fixed); setMode('query')
    requestAnimationFrame(() => editorRef.current?.focus())
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
  // The line Postgres objected to, if it said. For a script the position is an
  // offset into the whole script, which is what was sent, so it lands on the
  // right line even in a long migration.
  const errPos = queryRes?.results?.find(r => r.position)?.position ?? queryRes?.position
  const errLine = errPos ? lineColOf(ranSql || sql, errPos).line : 0
  // Put the caret where it is, once, when a new failure arrives. Jumping on
  // every render would fight whoever is already typing somewhere else.
  useEffect(() => {
    if (!errPos || !editorRef.current || busy) return
    const el = editorRef.current
    el.focus()
    el.setSelectionRange(errPos - 1, errPos - 1)
    const { line } = lineColOf(ranSql || sql, errPos)
    el.scrollTop = Math.max(0, (line - 4) * 21)
    if (gutterRef.current) gutterRef.current.scrollTop = el.scrollTop
  }, [errPos])
  // The row count the status bar shows: the visible result's, which for a script
  // is the statement whose tab is open rather than a total nobody asked for.
  const rowCount = mode === 'browse'
    ? browseRes?.rows?.length ?? null
    : queryRes?.rows?.length ?? null
  // A policy-rule block names its rule; without a rule id there's nothing to override.
  const blockedRule = POLICY_RULE.test(err) ? ruleOf(err) : undefined
  const blocked = GUARDRAIL.test(err) || !!blockedRule
  const item = (o: DbObject) => (
    <button key={key(o)} className={'obj-item' + (mode === 'browse' && sel && key(sel) === key(o) ? ' active' : '')} onClick={() => openObject(o)}>
      <i className="ic">{o.type === 'view' ? '◈' : '▦'}</i>{label(o)}
    </button>
  )

  return (
    <div className="wb">
      {/* The title block became the toolbar below, and took the page's only
          heading with it. A screen reader announces a page by its heading, so
          the heading stays — it just no longer costs any of the window. */}
      <h1 className="sr-only">SQL Console</h1>
      {/* One row where the title block used to be. A heading and a sentence of
          explanation cost about 140px of height on every visit, and this page is
          one someone returns to all day — the controls earn that space and the
          prose does not. */}
      <div className="wb-bar">
        <button className="wb-icon" title={railOpen ? 'Hide schema' : 'Show schema'}
          aria-pressed={railOpen} onClick={() => setRailOpen(v => !v)}>▤</button>
        <label className="field-inline">
          <span>Branch</span>
          <select value={branch} onChange={e => setBranch(e.target.value)}>
            {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
          </select>
        </label>
        <button className={'primary' + (allowDestructive ? ' danger' : '')} onClick={() => runSql()} disabled={busy}>
          {busy ? 'Running…' : 'Run'} <span className="kbd">⌘↵</span>
        </button>
        <label className={'override-toggle' + (allowDestructive ? ' on' : '')}
          title={admins && !canOverride
            ? `Only admins of ${branch} can override the guardrail`
            : 'Lets DROP TABLE and other blocked changes through, for the next run only'}>
          <input type="checkbox" checked={allowDestructive} disabled={busy || (admins !== null && !canOverride)}
            onChange={e => setAllowDestructive(e.target.checked)} />
          Allow destructive <span className="muted">(next run)</span>
        </label>
        <span className="wb-sp" />
        <button className={'ghost' + (historyOpen ? ' on' : '')} aria-pressed={historyOpen} onClick={toggleHistory}
          title="Your query history and saved queries">History</button>
        <span className="wb-meta">{BRAND.product} · {branch}</span>
      </div>

      <div className="wb-body">
        <aside className={'obj-panel wb-rail' + (railOpen ? '' : ' shut')}>
          <div className="obj-head">
            <span>Schema</span>
            <button title={listing ? 'Reloading…' : 'Reload tables'} className={listing ? 'spinning' : ''} disabled={listing} onClick={reload}>↻</button>
          </div>
          <div className="obj-filter-wrap">
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
            <CatalogGroups objects={catalog} filter={filter} showSystem={showSystem}
              active={mode === 'object' ? objSel : null}
              onOpen={o => { setObjSel(o); setMode('object') }} />
            {showSystem && system.length > 0 && (
              <>
                <div className="obj-group">{BRAND.product} system</div>
                {system.map(item)}
              </>
            )}
            {system.length > 0 && (
              <button className="obj-show-system" onClick={() => setShowSystem(v => !v)} aria-expanded={showSystem}
                title={`Blackbox, policies and agent sessions — kept by ${BRAND.product}, not your data`}>
                {showSystem ? 'Hide system tables' : `Show system tables (${system.length})`}
              </button>
            )}
          </div>
        </aside>

        <div className="wb-main">
          {mode === 'query' ? (
            <>
              {expand !== 'results' && (
              <section className="wb-pane wb-ed" style={expand === 'editor' ? undefined : { flex: `0 0 ${editorH}px` }}>
                <div className="pane-h">
                  <span>Query</span>
                  <span className="wb-sp" />
                  <span className="kbd">⌘/Ctrl + ↵</span>
                  <button className="wb-icon sm" title={expand === 'editor' ? 'Back to the split' : 'Give the editor the window'}
                    onClick={() => setExpand(x => (x === 'editor' ? 'none' : 'editor'))}>{expand === 'editor' ? '⤡' : '⤢'}</button>
                </div>
                {/* The gutter is a sibling, not a wrapper: a textarea cannot hold
                    anything, so the numbers are drawn beside it with the same font
                    and line height and scrolled in step. That alignment only holds
                    while the editor does not wrap — a wrapped line is two rows
                    against one number, and every number below it would then be
                    wrong. So the editor scrolls sideways instead, as a code editor
                    does, and the numbers mean what they say. */}
                <div className="wb-edit">
                  <div className="wb-gutter" ref={gutterRef} aria-hidden="true">
                    {sql.split('\n').map((_, i) => (
                      <div key={i} className={i + 1 === errLine ? 'bad' : undefined}>{i + 1}</div>
                    ))}
                  </div>
                <textarea
                  ref={editorRef}
                  onScroll={e => { if (gutterRef.current) gutterRef.current.scrollTop = e.currentTarget.scrollTop; assist.close() }}
                  className={'editor' + (busy ? ' running' : '')}
                  value={sql}
                  spellCheck={false}
                  // Read-only rather than disabled while a query is in flight. A
                  // disabled textarea cannot be selected or copied from in some
                  // browsers and drops out of the tab order; read-only keeps the
                  // text usable and the caret where it was, and only refuses
                  // edits. It is here so the editor cannot drift from the results
                  // underneath it: a script's results are labelled with the
                  // statements they came from, and editing mid-run would leave
                  // those labels disagreeing with what is on screen.
                  readOnly={busy}
                  onChange={e => {
                    setSql(e.target.value)
                    const ne = e.nativeEvent as InputEvent
                    assist.onChange(e.target.value, e.target.selectionStart, ne.inputType === 'insertText' ? ne.data : null)
                  }}
                  onBlur={assist.close}
                  onClick={assist.close}
                  {...assist.aria}
                  // The shortcut needs the same guard the Run button has. Without
                  // it, ⌘↵ during a run started a second query against the same
                  // branch while the first was still going.
                  onKeyDown={e => {
                    if (assist.onKeyDown(e)) return
                    if (!busy && (e.metaKey || e.ctrlKey) && e.key === 'Enter') runSql()
                  }}
                />
                {assist.popup}
                </div>
              </section>
              )}
              {expand === 'none' && (
                <div className="wb-split" role="separator" aria-orientation="horizontal"
                  title="Drag to resize" onMouseDown={onSplitDown} />
              )}
              {expand !== 'editor' && (
              <section className="wb-pane wb-res">
                {fixNote && <div className="err-hint wb-note" role="status">{fixNote}</div>}
                {queryRes
                  ? <QueryOutput res={queryRes} sql={ranSql} branch={ranBranch} onFix={fix}
                      expanded={expand === 'results'}
                      onExpand={() => setExpand(x => (x === 'results' ? 'none' : 'results'))} />
                  : <div className="wb-empty">Results appear here. ⌘↵ runs what is in the editor.</div>}
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
              </section>
              )}
            </>
          ) : mode === 'object' && objSel ? (
            <ObjectView branch={branch} obj={objSel} onOpenSql={openSql} />
          ) : sel && (
            <section className="wb-pane wb-res">
              <div className="obj-view-head">
                <h2>{sel.name}</h2>
                <span className="path">{sel.schema} · {sel.type}</span>
                <span className="wb-sp" />
                {sel.type === 'table' && (
                  <TrackingControl branch={branch} schema={sel.schema} table={sel.name} tracking={tracking}
                    onChange={t => { setTracking(t); loadObjects(branch); setReloadTick(n => n + 1) }} />
                )}
                <SnippetMenu rel={rels.find(r => r.schema === sel.schema && r.name === sel.name)
                  ?? { schema: sel.schema, name: sel.name, kind: sel.type === 'view' ? 'view' : 'table', cols: [] }}
                  onPick={text => {
                    setSql(text); setMode('query')
                    requestAnimationFrame(() => editorRef.current?.focus())
                  }} />
              </div>
              <div className="db-tabs">
                {((sel.type === 'view' ? ['rows', 'structure', 'ddl'] : ['rows', 'structure', 'indexes', 'constraints', 'triggers', 'ddl']) as Tab[]).map(t => (
                  <button key={t} className={tab === t ? 'active' : ''} onClick={() => switchTab(t)}>
                    {TAB_LABEL[t]}
                  </button>
                ))}
              </div>
              {tab === 'rows' && (
                <div className="grid-tools">
                  <FilterBar cols={browseRes?.columns ?? rels.find(r => r.schema === sel.schema && r.name === sel.name)?.cols.map(c => c.name) ?? []}
                    filters={filters} onChange={f => { setFilters(f); setPage(0); setEditing(null) }} />
                  <span className="wb-sp" />
                  {gridNote && <span className="ok" role="status">{gridNote}</span>}
                  {sel.type === 'table' && !editing && (
                    <button type="button" className="ghost" onClick={startEdit}
                      disabled={keyOf(sel).length === 0 || !browseRes || !!browseRes.error}
                      title={keyOf(sel).length === 0 ? 'Only a table with a primary key can be edited here: without one, a row cannot be told apart' : 'Add, change and delete rows on this page, then save them together'}>
                      Edit rows
                    </button>
                  )}
                </div>
              )}
              {CATALOG_TABS.includes(tab)
                ? <TableParts branch={branch} tab={tab as 'constraints' | 'triggers' | 'ddl'} onOpenSql={openSql}
                    obj={catalog.find(o => (o.kind === 'table' || o.kind === 'view') && o.schema === sel.schema && o.name === sel.name) ?? null} />
                : tab === 'rows' && editing && browseRes && !browseRes.error
                  ? <EditGrid cols={browseRes.columns ?? []} rows={browseRes.rows ?? []} info={editing}
                      onSave={saveGrid} onCancel={() => setEditing(null)} />
                  : loading && !browseRes ? <div className="muted">Loading…</div>
                  : browseRes && <Grid res={browseRes} sort={tab === 'rows' ? sort : undefined}
                      onSort={tab === 'rows' ? (c => { setSort(s => nextSort(s, c)); setPage(0) }) : undefined} />}
              {tab === 'rows' && browseRes && !browseRes.error && !editing && (
                <div className="pager">
                  <span className="count">
                    rows {total === 0 ? 0 : page * PAGE + 1}–{page * PAGE + (browseRes.rows?.length || 0)}
                    {total != null && <> of {total}</>}
                  </span>
                  <button className="ghost" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>‹ Prev</button>
                  <button className="ghost" onClick={() => setPage(p => p + 1)}
                    disabled={total == null ? (browseRes.rows?.length || 0) < PAGE : (page + 1) * PAGE >= total}>Next ›</button>
                </div>
              )}
            </section>
          )}
        </div>
        {historyOpen && (
          <HistoryPanel branch={branch} branches={options.map(o => o.name)} tick={historyTick} busy={busy} current={sql}
            onOpen={text => { setSql(text); setMode('query') }}
            onRun={(text, on) => runSql({}, text, on)} />
        )}
      </div>

      {/* The numbers worth glancing at, where a desktop app puts them: out of the
          way, always true, never in the path of the work. */}
      <div className="wb-status">
        <span>{branch}</span>
        {rowCount != null && <><span>·</span><span>{rowCount} row{rowCount === 1 ? '' : 's'}</span></>}
        {queryRes?.command && <><span>·</span><span>{queryRes.command}</span></>}
        <span className="wb-sp" />
        {expand !== 'none' && <span>Esc returns to the split</span>}
      </div>
    </div>
  )
}

// Where a character offset falls, as a line and column.
//
// Postgres hands back a 1-based character offset into the SQL it was sent, and
// that is the only thing it gives — no line, no column. Counting newlines before
// the offset is the whole of the work, and it is worth doing because "line 7"
// is actionable and "position 214" is not.
//
// Both numbers come back 1-based, which is what a gutter shows and what someone
// counting lines in their head expects.
export function lineColOf(sql: string, position: number): { line: number; col: number } {
  const upto = sql.slice(0, Math.max(0, position - 1))
  const line = upto.split('\n').length
  const col = position - (upto.lastIndexOf('\n') + 1)
  return { line, col }
}

// Labels for a script's results: the statement each one came from, so a block of
// grids is readable instead of being a stack you have to count semicolons
// against.
//
// The engine cannot provide these. It sends the whole script in one message and
// Postgres hands back results in order, with a command tag and no statement
// text — deliberately, because splitting SQL properly needs a parser and
// semicolons live inside string literals and dollar-quoted function bodies.
//
// So this splits naively, for display only, and then checks its own work: if the
// number of pieces is not exactly the number of results, the split was wrong and
// it gives up rather than labelling a grid with the wrong statement. A wrong
// label is worse than none — it would have someone reading the result of one
// statement as another's.
function labelsFor(sql: string, n: number): string[] | null {
  const parts = sql.split(';').map(p => p.trim()).filter(Boolean)
  if (parts.length !== n) return null
  return parts.map(p => (p.length > 90 ? p.slice(0, 89) + '…' : p).replace(/\s+/g, ' '))
}

// What a run produced. One statement looks exactly as it always did; a script
// shows a result per statement, labelled with the SQL it came from where that
// can be worked out safely, and numbered where it cannot.
// The statements for a table, written out with its columns and key (point
// 9.3). Picking one puts it in the editor to finish; nothing runs on its own.
function SnippetMenu({ rel, onPick }: { rel: Rel; onPick: (sql: string) => void }) {
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false) }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    window.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDoc); window.removeEventListener('keydown', onKey) }
  }, [open])
  return (
    <div className="copy-menu" ref={box}>
      <button type="button" className="ghost" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(o => !o)}>Snippets ▾</button>
      {open && (
        <div className="copy-pop snippet-pop" role="menu" aria-label={`Snippets for ${rel.name}`}>
          {snippets(rel).map(sn => (
            <button key={sn.label} type="button" role="menuitem" className="ghost snippet-item"
              title={sn.sql} onClick={() => { setOpen(false); onPick(sn.sql) }}>{sn.label}</button>
          ))}
          <p className="muted">Opens in the editor, to finish and run.</p>
        </div>
      )}
    </div>
  )
}

function QueryOutput({ res, sql, branch, expanded, onExpand, onFix }:
  { res: QueryResult; sql: string; branch: string; expanded: boolean; onExpand: () => void; onFix?: FixFn }) {
  const all = res.results && res.results.length > 1 ? res.results : null
  const labels = all ? labelsFor(sql, all.length) : null
  // Which statement's result is on screen. A script that failed opens on the
  // statement that failed, because that is the one being looked for.
  const [active, setActive] = useState(0)
  useEffect(() => {
    const bad = res.results?.findIndex(r => r.error) ?? -1
    setActive(bad >= 0 ? bad : 0)
  }, [res])

  const expander = (
    <button className="wb-icon sm" title={expanded ? 'Back to the split' : 'Give the results the window'}
      onClick={onExpand}>{expanded ? '⤡' : '⤢'}</button>
  )

  // One statement: nothing to choose between, so the strip is only a header.
  // The note still belongs here. A script that fails at its second statement
  // comes back with one completed result, so it lands in this branch and not
  // the tabbed one below — and "nothing was applied" is exactly what someone
  // whose first statement was an INSERT needs to be told.
  if (!all) {
    return (
      <div className="wb-out">
        <div className="res-tabs"><span className="pane-t">Result</span><span className="wb-sp" />{expander}</div>
        {res.note && <div className="err-hint wb-note">{res.note}</div>}
        <div className="res-body"><Grid res={res} showCommand sql={sql} branch={branch} onFix={onFix} /></div>
      </div>
    )
  }

  // A script: one tab per statement, so the open one gets the whole pane rather
  // than ten tables sharing it. The tab carries the statement it came from where
  // that can be worked out safely, and its position where it cannot.
  const shown = all[active]
  return (
    <div className="wb-out">
      <div className="res-tabs">
        {all.map((r, i) => (
          <button key={i} className={'res-tab' + (i === active ? ' on' : '') + (r.error ? ' bad' : '')}
            onClick={() => setActive(i)} title={labels ? labels[i] : `Statement ${i + 1}`}>
            <span className="k">{i + 1}</span>
            <span className="lbl">{labels ? labels[i] : r.command || 'statement'}</span>
            {r.error
              ? <span className="n-bad">failed</span>
              : r.rows?.length
                ? <span className="n-ok">{r.rows.length}</span>
                : null}
          </button>
        ))}
        <span className="wb-sp" />{expander}
      </div>
      {res.note && <div className="err-hint wb-note">{res.note}</div>}
      <div className="res-body"><Grid res={shown} showCommand sql={sql} branch={branch} script onFix={onFix} /></div>
    </div>
  )
}

// branch is set where the whole result can be exported again from the server:
// a statement someone ran, not a page of a table they browsed. script marks a
// result that is one of several, which cannot be.
function Grid({ res, showCommand, sql, branch, script, onFix, sort, onSort }:
  { res: StatementResult; showCommand?: boolean; sql?: string; branch?: string; script?: boolean; onFix?: FixFn
    // A table's rows, sorted by a header click (point 12.2).
    sort?: Sort; onSort?: (col: string) => void }) {
  const [expanded, setExpanded] = useState<number | null>(null)
  // Rows ticked for copying, and one cell picked to copy on its own (⌘C).
  const [picked, setPicked] = useState<Set<number>>(new Set())
  const [cellAt, setCellAt] = useState<[number, number] | null>(null)
  const [cellCopied, setCellCopied] = useState(false)
  useEffect(() => { setExpanded(null); setPicked(new Set()); setCellAt(null) }, [res]) // reset when new results arrive
  useEffect(() => {
    if (!cellAt) return
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'c') return
      // Text someone selected by hand is theirs to copy as they selected it.
      if (window.getSelection()?.toString()) return
      const tag = (document.activeElement?.tagName ?? '').toLowerCase()
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return
      const v = res.rows?.[cellAt[0]]?.[cellAt[1]]
      e.preventDefault()
      navigator.clipboard?.writeText(cellText(v)).then(() => {
        setCellCopied(true); setTimeout(() => setCellCopied(false), 1500)
      }).catch(() => { /* nothing to fall back to for one cell: the grid shows it */ })
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [cellAt, res])
  if (res.error) {
    // The raw message stays: it is what a Postgres user knows how to search for.
    // The hint underneath is what a new one needs (web/src/errhint.ts).
    const hint = hintFor(res.error)
    // Where, when Postgres said. Its own hint comes first — "Perhaps you meant
    // to reference the column t.name" is usually the whole answer, and ours is a
    // general one about a class of failure.
    const at = res.position && sql ? lineColOf(sql, res.position) : null
    return (
      <div className="err">
        {res.error}
        {at && <div className="err-at">line {at.line}, column {at.col}</div>}
        {res.hint && <div className="err-hint">{res.hint}</div>}
        {res.detail && <div className="err-hint">{res.detail}</div>}
        {hint && <div className="err-hint">{hint}</div>}
        {res.suggestion && onFix && (
          // Point 9.2: the name probably meant, put in the editor where
          // Postgres pointed, with or without running it again.
          <div className="err-fix">
            <span>Did you mean <code>{res.suggestion.insert}</code>?</span>
            <button className="ghost sm" onClick={() => onFix(res.suggestion!, res.position, false)}>Fix</button>
            <button className="primary sm" onClick={() => onFix(res.suggestion!, res.position, true)}>Fix and run</button>
          </div>
        )}
      </div>
    )
  }
  const cols = res.columns || []
  const rows = res.rows || []
  const openRow = expanded != null ? rows[expanded] : null
  const toCopy = picked.size > 0 ? rows.filter((_, i) => picked.has(i)) : rows
  const toggle = (i: number) => setPicked(p => { const n = new Set(p); if (n.has(i)) n.delete(i); else n.add(i); return n })
  const all = rows.length > 0 && picked.size === rows.length
  const copyBar = cols.length > 0 && (
    <span className="result-tools">
      {cellCopied && <span className="ok">Cell copied ✓</span>}
      {cellAt && !cellCopied && <span className="muted">Cell selected: press {/Mac|iPhone|iPad/.test(navigator.userAgent) ? '⌘C' : 'Ctrl+C'} to copy it</span>}
      <CopyMenu cols={cols} rows={toCopy} selected={picked.size} sql={sql} />
      <ExportMenu cols={cols} rows={toCopy} selected={picked.size} sql={sql} branch={branch} script={script} />
    </span>
  )
  return (
    <div className="result">
      {showCommand ? (
        <div className="result-bar">
          <span className="ok">✓ Ran</span>
          <span className="tag">{res.command || 'ok'}</span>
          <span>{rows.length} row{rows.length === 1 ? '' : 's'}{cols.length > 0 && <> · {cols.length} column{cols.length === 1 ? '' : 's'}</>}</span>
          {copyBar}
        </div>
      ) : copyBar && <div className="result-bar result-bar-tools">{copyBar}</div>}
      {cols.length > 0 ? (
        <div className="grid-wrap table-wrap">
          <table>
            <thead><tr><th className="expand-col">
              {rows.length > 0 && <input type="checkbox" aria-label="Select all rows" checked={all}
                onChange={() => setPicked(all ? new Set() : new Set(rows.map((_, i) => i)))} />}
            </th>{cols.map((c, i) => onSort
              ? <th key={i} aria-sort={sort?.col === c ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                  <button type="button" className="th-sort" onClick={() => onSort(c)} title={`Sort by ${c}`}>
                    {c}{sort?.col === c && <span aria-hidden="true">{sort.dir === 'asc' ? ' ▲' : ' ▼'}</span>}
                  </button>
                </th>
              : <th key={i}>{c}</th>)}</tr></thead>
            <tbody>
              {rows.length === 0
                ? <tr><td colSpan={cols.length + 1} className="muted">no rows</td></tr>
                : rows.map((r, i) => (
                  <tr key={i} className={picked.has(i) ? 'row-picked' : undefined}>
                    <td className="expand-col">
                      <input type="checkbox" aria-label={`Select row ${i + 1}`} checked={picked.has(i)} onChange={() => toggle(i)} />
                      <button className="expand-btn" title="View row as JSON" onClick={() => setExpanded(i)}>{'{ }'}</button>
                    </td>
                    {r.map((v, j) => (
                      <td key={j} className={cellAt && cellAt[0] === i && cellAt[1] === j ? 'cell-picked' : undefined}
                        onClick={() => setCellAt(cellAt && cellAt[0] === i && cellAt[1] === j ? null : [i, j])}>
                        {v === null ? 'NULL' : String(v)}
                      </td>
                    ))}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : !showCommand && (
        <div className="okmsg">✓ {res.command || 'ok'}</div>
      )}
      {openRow && <JsonModal cols={cols} row={openRow} onClose={() => setExpanded(null)} />}
    </div>
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
