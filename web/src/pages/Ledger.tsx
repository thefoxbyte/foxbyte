import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { branchBeforeEntry, getLedger, verifyLedger, type Branch, type BranchBeforeResult, type LedgerVerify, type QueryResult } from '../api'
import { useBranches } from '../useBranches'

type Row = Record<string, string | null>

const STATUS = ['', 'APPLIED', 'FLAGGED', 'BLOCKED'] as const
const KIND = ['', 'human', 'agent'] as const
// The risk values Blackbox records (internal/ledger/ledger.sql).
const RISK = ['', 'drop', 'drop-column', 'type-change', 'security-definer', 'policy'] as const
const PAGE = 25
// How often the page looks for new entries. The Dashboard already polls at this
// rate; a record of what just happened has more reason to than a branch list.
const POLL_MS = 3000

// A row's identity for expand/collapse. The entry id when the branch has the
// chain columns; the position otherwise, which is all an older ledger can offer.
function rowKey(r: Row, i: number): string {
  return r.id ? `#${r.id}` : `i${i}`
}

// A hash, short enough to read and whole when copied. Nothing in the product
// showed one before, so "hash-chained" was a claim rather than something a user
// could look at.
function Hash({ value }: { value: string | null | undefined }) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="muted">— (recorded before the chain existed)</span>
  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch { /* a browser that refuses the clipboard still shows the hash */ }
  }
  return (
    <button className="lg-hash" onClick={copy} title={`${value} — click to copy`}>
      <code>{value.slice(0, 12)}…</code>{copied ? ' ✓' : ''}
    </button>
  )
}

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
  const [branch, setBranch] = useState('main')
  const [status, setStatus] = useState('')
  const [kind, setKind] = useState('')
  const [actor, setActor] = useState('')
  const [table, setTable] = useState('')
  const [risk, setRisk] = useState('')
  const [since, setSince] = useState('') // YYYY-MM-DD
  const [until, setUntil] = useState('')
  const [rows, setRows] = useState<Row[]>([])
  const [open, setOpen] = useState<string | null>(null)   // the expanded entry's id
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const [verify, setVerify] = useState<LedgerVerify | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyErr, setVerifyErr] = useState('')
  const [live, setLive] = useState(true)
  const [flash, setFlash] = useState<Set<string>>(new Set())
  const [rewind, setRewind] = useState<Row | null>(null)   // the entry a rewind is being confirmed for
  const [rewindName, setRewindName] = useState('')
  const [rewinding, setRewinding] = useState(false)
  const [rewound, setRewound] = useState<BranchBeforeResult | null>(null)
  const [rewindErr, setRewindErr] = useState('')
  const offsetRef = useRef(0)   // next offset to fetch
  const loadingRef = useRef(false)
  const seqRef = useRef(0)      // the latest load; older responses are dropped
  const sentinel = useRef<HTMLTableRowElement>(null)
  const idsRef = useRef<Set<string>>(new Set())  // ids on screen, so a poll adds only what is new

  const { branches, branchesError, reloadBranches } = useBranches()

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
        with: 'session,chain', limit: String(PAGE), offset: String(offset),
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
  // What is on screen, for the poll below to compare against.
  useEffect(() => { idsRef.current = new Set(rows.map(r => r.id).filter(Boolean) as string[]) }, [rows])

  // Live refresh. The record's whole point is that a change shows up, and until
  // now the page only looked when asked, so a user ran a migration in one tab and
  // saw an empty Blackbox in the other.
  //
  // It only ever adds to the top, and only while the first page is what is on
  // screen: someone who has scrolled into older entries with infinite scroll is
  // reading, and rows appearing under them would move the page.
  const pollTop = useCallback(async () => {
    if (loadingRef.current || document.hidden || offsetRef.current > PAGE) return
    try {
      const res = await getLedger(branch, {
        status, kind, actor, table, risk,
        since, until: until ? until + ' 23:59:59' : '',
        with: 'session,chain', limit: String(PAGE), offset: '0',
      })
      if (res.error) return   // a poll never shows an error; Refresh reports properly
      const fresh = toRows(res).filter(r => r.id && !idsRef.current.has(r.id))
      if (fresh.length === 0) return
      setRows(prev => [...fresh, ...prev])
      offsetRef.current += fresh.length
      const ids = new Set(fresh.map(r => r.id as string))
      setFlash(ids)
      window.setTimeout(() => setFlash(f => (f === ids ? new Set() : f)), 2000)
    } catch { /* a failed poll is not news; the next one will say so */ }
  }, [branch, status, kind, actor, table, risk, since, until])

  useEffect(() => {
    if (!live) return
    const t = window.setInterval(pollTop, POLL_MS)
    return () => window.clearInterval(t)
  }, [live, pollTop])
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

  // Branch from just before an entry — the thing to do when the record shows a
  // change that should not have happened. Only main can be the source: it is the
  // only branch that archives WAL, so it is the only one with a point to go back
  // to (internal/branch/branch_before.go).
  const canRewind = (r: Row) => branch === 'main' && !!r.id && r.status !== 'BLOCKED'
  const askRewind = (r: Row) => {
    setRewind(r); setRewindName(''); setRewound(null); setRewindErr('')
  }
  const doRewind = async () => {
    if (!rewind?.id) return
    setRewinding(true); setRewindErr(''); setRewound(null)
    try {
      const r = await branchBeforeEntry('main', Number(rewind.id), rewindName.trim() || undefined)
      setRewound(r)
      setRewind(null)
      void reloadBranches()
    } catch (e) {
      setRewindErr((e as Error).message)
    } finally {
      setRewinding(false)
    }
  }

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
          <button className={'ghost lg-live' + (live ? ' on' : '')} onClick={() => setLive(v => !v)}
            title={live ? 'New entries appear on their own; click to stop' : 'Look for new entries every few seconds'}
            aria-pressed={live}>
            <span className="lg-dot" />{live ? 'Live' : 'Paused'}
          </button>
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
      {rewound && (
        <div className="okmsg">
          ✓ Branch <b>{rewound.branch}</b> holds <code>main</code> as it was just before entry #{rewound.entry_id}
          {rewound.command_tag ? <> ({rewound.command_tag} {rewound.object_identity})</> : null} — recovered to{' '}
          {rewound.target_kind} {rewound.target} from {rewound.base_backup} in {rewound.seconds}s.{' '}
          {rewound.target_kind === 'time' && 'That entry predates transaction capture, so its timestamp was used. '}
          It is on the <Link to="/dashboard">dashboard</Link> with its connection string.
        </div>
      )}
      {(err || branchesError) && <div className="err">{err.includes('schema_ledger') ? 'Blackbox is not installed on this branch yet.' : (err || branchesError)}</div>}

      {rewind && (
        <div className="modal-overlay" onClick={() => !rewinding && setRewind(null)}>
          <div className="modal fade-up" role="dialog" aria-modal="true" onClick={e => e.stopPropagation()}>
            <h3>Branch from before this change</h3>
            <div className="modal-body">
              <p style={{ marginTop: 0 }}>
                A new branch will hold <code>main</code> exactly as it was just before entry #{rewind.id}:{' '}
                <code>{rewind.command_tag}</code>{rewind.object_identity ? ' ' + rewind.object_identity : ''},
                {' '}{rewind.at} by {rewind.actor || 'an unknown actor'}. <b><code>main</code> is not modified.</b>
              </p>
              <p className="muted">
                It restores a base backup and replays the write-ahead log, so it takes a few minutes, and it needs a
                base backup taken before the change.
              </p>
              <input placeholder={`main-before-${rewind.id}`} value={rewindName}
                onChange={e => setRewindName(e.target.value)} aria-label="New branch name (optional)"
                style={{ width: '100%' }} disabled={rewinding} />
              {rewindErr && <div className="err">{rewindErr}</div>}
            </div>
            <div className="modal-actions">
              <button className="ghost" onClick={() => setRewind(null)} disabled={rewinding}>Cancel</button>
              <button className="primary" onClick={doRewind} disabled={rewinding} autoFocus>
                {rewinding ? 'Restoring… (a few minutes)' : 'Create branch'}
              </button>
            </div>
          </div>
        </div>
      )}

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
              <Fragment key={r.id || i}>
                <tr className={'lg-row' + (r.id && flash.has(r.id) ? ' lg-new' : '')}
                  onClick={() => setOpen(open === rowKey(r, i) ? null : rowKey(r, i))}
                  title="Show the statement" aria-expanded={open === rowKey(r, i)}>
                  <td className="mono muted" style={{ whiteSpace: 'nowrap' }}>{r.at}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <span className={'lg-kind ' + (r.actor_kind || 'human')}>{r.actor_kind || 'human'}</span>{' '}
                    <span>{r.actor || '—'}</span>
                  </td>
                  <td className="muted" style={{ whiteSpace: 'nowrap' }}>{r.tool || '—'}</td>
                  <td>
                    <span className="lg-caret">{open === rowKey(r, i) ? '▾' : '▸'}</span>{' '}
                    <code className="mono">{r.command_tag}</code>
                    {r.object_identity && <span className="muted"> {r.object_identity}</span>}
                    {r.risk && <span className="lg-risk"> · {r.risk}</span>}
                  </td>
                  <td><span className={'lg-status ' + (r.status || '')}>{r.status}</span></td>
                </tr>
                {open === rowKey(r, i) && (
                  <tr className="lg-detail">
                    <td colSpan={5}>
                      <div className="lg-meta">
                        {r.id && <span><span className="muted">entry</span> <code>#{r.id}</code></span>}
                        <span title="Declared by the client (bb.session), not verified">
                          <span className="muted">session</span> <code>{r.session || '—'}</code>
                          <span className="lg-declared">declared</span>
                        </span>
                        <span><span className="muted">branch</span> <code>{r.branch || branch}</code></span>
                      </div>
                      {/* The chain, which the page could not show before: each row's
                          hash covers its own fields and the hash of the row before,
                          so an entry cannot be changed or removed without breaking
                          every entry after it. */}
                      {(r.row_hash || r.prev_hash) && (
                        <div className="lg-chain">
                          <span title="SHA-256 over this entry's fields and the previous entry's hash">
                            <span className="muted">this entry</span> <Hash value={r.row_hash} />
                          </span>
                          <span className="lg-link" aria-hidden="true">↳</span>
                          <span title="The row hash of the entry recorded before this one — by entry id, which is not always the row directly below: the list is ordered by time, and a refused change can carry an earlier timestamp">
                            <span className="muted">links to</span> <Hash value={r.prev_hash} />
                          </span>
                        </div>
                      )}
                      <pre className="lg-statement">{r.statement || '(no statement recorded)'}</pre>
                      {canRewind(r) && (
                        <div className="lg-actions">
                          <button className="ghost" onClick={e => { e.stopPropagation(); askRewind(r) }}>
                            Branch from before this change
                          </button>
                          <span className="muted">
                            A new branch holding <code>main</code> as it was just before this entry. <code>main</code> is not touched.
                          </span>
                        </div>
                      )}
                      {r.status === 'BLOCKED' && (
                        <div className="lg-actions muted">This change was refused, so there is nothing to go back to.</div>
                      )}
                      {branch !== 'main' && r.id && (
                        <div className="lg-actions muted">
                          Branching from before a change works on <code>main</code>: it is the only branch that archives WAL.
                        </div>
                      )}
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
