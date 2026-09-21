import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { getBranches, getLedger, verifyLedger, type Branch, type LedgerVerify, type QueryResult } from '../api'

type Row = Record<string, string | null>

const STATUS = ['', 'APPLIED', 'FLAGGED', 'BLOCKED'] as const
const KIND = ['', 'human', 'agent'] as const
// The risk values Blackbox records (internal/ledger/ledger.sql).
const RISK = ['', 'drop', 'drop-column', 'type-change', 'security-definer', 'policy'] as const
const PAGE = 25

// Turn the {columns, rows} query result into keyed objects.
function toRows(res: QueryResult | null): Row[] {
  if (!res || !res.columns || !res.rows) return []
  return res.rows.map(r => {
    const o: Row = {}
    res.columns!.forEach((c, i) => { o[c] = r[i] as string | null })
    return o
  })
}

export default function Ledger() {
  const [branches, setBranches] = useState<Branch[]>([])
  const [branch, setBranch] = useState('main')
  const [status, setStatus] = useState('')
  const [kind, setKind] = useState('')
  const [actor, setActor] = useState('')
  const [table, setTable] = useState('')
  const [risk, setRisk] = useState('')
  const [since, setSince] = useState('') // YYYY-MM-DD
  const [until, setUntil] = useState('')
  const [rows, setRows] = useState<Row[]>([])
  const [open, setOpen] = useState<number | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const [verify, setVerify] = useState<LedgerVerify | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyErr, setVerifyErr] = useState('')
  const offsetRef = useRef(0)   // next offset to fetch
  const loadingRef = useRef(false)
  const seqRef = useRef(0)      // the latest load; older responses are dropped
  const sentinel = useRef<HTMLTableRowElement>(null)

  useEffect(() => { getBranches().then(setBranches).catch(() => {}) }, [])

  // Fetch one page. reset=true starts over (offset 0, replaces rows); otherwise
  // it appends the next 25 at the current offset.
  //
  // A reset always runs, and a response that a newer load has superseded is
  // dropped. Skipping a load while another was in flight used to lose the last
  // keystroke of a filter, leaving the list unfiltered.
  const loadPage = useCallback(async (reset: boolean) => {
    if (!reset && loadingRef.current) return
    const seq = ++seqRef.current
    loadingRef.current = true; setBusy(true); setErr('')
    const offset = reset ? 0 : offsetRef.current
    try {
      const res = await getLedger(branch, {
        status, kind, actor, table, risk,
        since, until: until ? until + ' 23:59:59' : '',
        with: 'session', limit: String(PAGE), offset: String(offset),
      })
      if (seq !== seqRef.current) return
      if (res.error) throw new Error(res.error)
      const page = toRows(res)
      setRows(prev => reset ? page : [...prev, ...page])
      offsetRef.current = offset + page.length
      setHasMore(page.length === PAGE)
    } catch (e) {
      if (seq === seqRef.current) { setErr((e as Error).message); setHasMore(false) }
    } finally {
      if (seq === seqRef.current) { loadingRef.current = false; setBusy(false) }
    }
  }, [branch, status, kind, actor, table, risk, since, until])

  // Reset + load the first page whenever the branch or a filter changes.
  useEffect(() => { offsetRef.current = 0; setRows([]); setOpen(null); setHasMore(true); loadPage(true) }, [loadPage])
  // A verification belongs to the branch it was run on.
  useEffect(() => { setVerify(null); setVerifyErr('') }, [branch])

  // Infinite scroll: load the next page when the sentinel row nears the viewport.
  useEffect(() => {
    const el = sentinel.current
    if (!el || !hasMore) return
    const io = new IntersectionObserver(
      entries => { if (entries[0].isIntersecting && !loadingRef.current) loadPage(false) },
      { rootMargin: '250px' },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [hasMore, loadPage, rows.length])

  const runVerify = async () => {
    setVerifying(true); setVerifyErr(''); setVerify(null)
    try { setVerify(await verifyLedger(branch)) } catch (e) { setVerifyErr((e as Error).message) } finally { setVerifying(false) }
  }

  const filtered = !!(status || kind || actor || table || risk || since || until)
  const clearFilters = () => { setStatus(''); setKind(''); setActor(''); setTable(''); setRisk(''); setSince(''); setUntil('') }
  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])

  return (
    <div className="fade-up">
      <div className="page-head">
        <div>
          <h1>Blackbox</h1>
          <p className="sub">A record the database keeps about itself — every schema change, attributed and policy-checked.</p>
        </div>
        <div className="tools">
          <label className="field-inline">
            <span>Branch</span>
            <select value={branch} onChange={e => setBranch(e.target.value)}>
              {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
            </select>
          </label>
          <button className="ghost" onClick={() => loadPage(true)} disabled={busy}>{busy ? '…' : 'Refresh'}</button>
          <button className="ghost" onClick={runVerify} disabled={verifying} title="Recompute the hash chain">
            {verifying ? 'Verifying…' : 'Verify'}
          </button>
        </div>
      </div>

      {/* One toolbar for every filter: the coarse ones (status, actor kind) as
          segmented controls, the specific ones as fields beside them. */}
      <div className="filterbar">
        <div className="filterbar-row">
          <div className="seg">
            {STATUS.map(s => (
              <button key={s || 'all'} className={status === s ? 'active' : ''} onClick={() => setStatus(s)}>
                {s || 'All'}
              </button>
            ))}
          </div>
          <div className="seg">
            {KIND.map(k => (
              <button key={k || 'all'} className={kind === k ? 'active' : ''} onClick={() => setKind(k)}>
                {k ? k[0].toUpperCase() + k.slice(1) : 'Any actor'}
              </button>
            ))}
          </div>
          {filtered && <button className="ghost clear" onClick={clearFilters}>Clear filters</button>}
        </div>
        <div className="filterbar-row">
          <input placeholder="actor…" value={actor} onChange={e => setActor(e.target.value)} aria-label="Filter by actor" />
          <input placeholder="table or object…" value={table} onChange={e => setTable(e.target.value)} aria-label="Filter by table" />
          <select value={risk} onChange={e => setRisk(e.target.value)} aria-label="Filter by risk">
            {RISK.map(r => <option key={r || 'any'} value={r}>{r || 'any risk'}</option>)}
          </select>
          <label className="field-inline">
            <span>From</span>
            <input type="date" value={since} onChange={e => setSince(e.target.value)} aria-label="From date" />
          </label>
          <label className="field-inline">
            <span>To</span>
            <input type="date" value={until} onChange={e => setUntil(e.target.value)} aria-label="To date" />
          </label>
        </div>
      </div>

      {verify && (verify.broken === 0 ? (
        <div className="okmsg">
          ✓ Hash chain intact on {branch} — {verify.chained} chained entr{verify.chained === 1 ? 'y' : 'ies'}
          {verify.legacy > 0 && <> (plus {verify.legacy} from before the chain existed)</>}. For proof against a
          rewrite of the whole chain, check <Link to="/integrity">Integrity</Link> against the anchors.
        </div>
      ) : (
        <div className="err">
          ✗ {verify.broken} entr{verify.broken === 1 ? 'y fails' : 'ies fail'} verification on {branch}; the first is #{verify.firstBroken}.
          The record was altered — see <Link to="/integrity">Integrity</Link>.
        </div>
      ))}
      {verifyErr && <div className="err">Couldn’t verify: {verifyErr}</div>}
      {err && <div className="err">{err.includes('schema_ledger') ? 'Blackbox is not installed on this branch yet.' : err}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th title="Who made the change: the login role the database saw, which a client cannot change">Actor</th>
              <th title="What the client called itself (application_name) — declared by the client, not verified">Tool <span className="lg-declared">declared</span></th>
              <th>Change</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !busy
              && <tr><td colSpan={5} className="muted">{filtered ? 'no changes match these filters' : 'no changes recorded yet'}</td></tr>}
            {rows.map((r, i) => (
              <Fragment key={i}>
                <tr className="lg-row" onClick={() => setOpen(open === i ? null : i)} title="Show the statement" aria-expanded={open === i}>
                  <td className="mono muted" style={{ whiteSpace: 'nowrap' }}>{r.at}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <span className={'lg-kind ' + (r.actor_kind || 'human')}>{r.actor_kind || 'human'}</span>{' '}
                    <span>{r.actor || '—'}</span>
                  </td>
                  <td className="muted" style={{ whiteSpace: 'nowrap' }}>{r.tool || '—'}</td>
                  <td>
                    <span className="lg-caret">{open === i ? '▾' : '▸'}</span>{' '}
                    <code className="mono">{r.command_tag}</code>
                    {r.object_identity && <span className="muted"> {r.object_identity}</span>}
                    {r.risk && <span className="lg-risk"> · {r.risk}</span>}
                  </td>
                  <td><span className={'lg-status ' + (r.status || '')}>{r.status}</span></td>
                </tr>
                {open === i && (
                  <tr className="lg-detail">
                    <td colSpan={5}>
                      <div className="lg-meta">
                        <span title="Declared by the client (bb.session), not verified">
                          <span className="muted">session</span> <code>{r.session || '—'}</code>
                          <span className="lg-declared">declared</span>
                        </span>
                        <span><span className="muted">branch</span> <code>{r.branch || branch}</code></span>
                      </div>
                      <pre className="lg-statement">{r.statement || '(no statement recorded)'}</pre>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {/* sentinel row — the observer loads the next 25 as it nears the viewport */}
            <tr ref={sentinel}>
              <td colSpan={5} className="muted" style={{ textAlign: 'center', padding: '10px', fontSize: 13 }}>
                {busy ? 'Loading…' : (!hasMore && rows.length > 0) ? 'End of record' : ''}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}
