import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  cutoverReplication, importDBStream, importFileStream, listReplication,
  type ImportEvent, type ImportResult, type Replication,
} from '../api'
import { useConfirm } from '../confirm'

type Line = { text: string; kind?: 'err' | 'ok' }
type Prog = { done: number; total: number; label: string }

export default function Import() {
  const [source, setSource] = useState('')
  const [continuous, setContinuous] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [lines, setLines] = useState<Line[]>([])
  const [progress, setProgress] = useState<Prog | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)
  const consoleRef = useRef<HTMLDivElement>(null)

  const isPg = /^postgres(ql)?:\/\//.test(source.trim())
  const runningContinuous = continuous && isPg

  // Keep the console scrolled to the newest line.
  useEffect(() => {
    consoleRef.current?.scrollTo({ top: consoleRef.current.scrollHeight })
  }, [lines, progress])

  const append = (l: Line) => setLines(prev => [...prev, l])

  const run = async (start: (onEvent: (e: ImportEvent) => void) => Promise<ImportResult>) => {
    setBusy(true); setLines([]); setProgress(null); setResult(null)
    try {
      const r = await start(e => {
        if (e.type === 'log') append({ text: e.line })
        else if (e.type === 'progress') setProgress({ done: e.done, total: e.total, label: e.label })
      })
      setResult(r)
    } catch (e) {
      append({ text: (e as Error).message, kind: 'err' })
    } finally {
      setBusy(false)
    }
  }

  const runDSN = () => { if (source.trim()) run(cb => importDBStream(source.trim(), target.trim(), runningContinuous, cb)) }
  const runFile = () => { if (file) run(cb => importFileStream(file, target.trim(), cb)) }

  const pct = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0
  const idle = lines.length === 0 && !busy

  return (
    <div className="fade-up import-page">
      <h1>Migrate a database</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Move an existing database into a fresh FoxByte instance. Because FoxByte <em>is</em> PostgreSQL,
        a Postgres source migrates with full fidelity.
      </p>

      <div className="import-grid">
        {/* left: the form */}
        <div>
          <label className="fld" style={{ marginBottom: 14 }}>
            <span>New instance name <span className="muted">(optional)</span></span>
            <input placeholder="auto — named from the source" value={target} onChange={e => setTarget(e.target.value)} disabled={busy} />
          </label>

          <div className="panel" style={{ padding: 18 }}>
            <h3 style={{ margin: '0 0 10px' }}>From a live database</h3>
            <label className="fld">
              <span>Source connection string</span>
              <input
                placeholder="postgres:// · mysql:// · mariadb:// · mongodb://"
                value={source}
                onChange={e => setSource(e.target.value)}
                spellCheck={false}
                disabled={busy}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
              />
              <span className="hint">
                Postgres/Postgres-wire (RDS, Neon, Supabase, CockroachDB) with full fidelity;
                MySQL (incl. 8.x) &amp; MariaDB; MongoDB documents relationalized (keys → typed columns).
              </span>
            </label>
            {isPg && (
              <label className="fld" style={{ flexDirection: 'row', alignItems: 'center', gap: 8, marginTop: 10 }}>
                <input type="checkbox" checked={continuous} onChange={e => setContinuous(e.target.checked)} disabled={busy} style={{ width: 'auto' }} />
                <span style={{ margin: 0 }}>
                  Continuous replication <span className="muted">— initial copy + streaming for zero-downtime cutover
                  (source needs <code>wal_level=logical</code>)</span>
                </span>
              </label>
            )}
            <div className="row" style={{ marginTop: 14 }}>
              <button className="primary" onClick={runDSN} disabled={busy || !source.trim()}>
                {busy && <span className="spinner" />}
                {busy ? (runningContinuous ? 'Starting replication…' : 'Migrating…') : (runningContinuous ? 'Start continuous replication' : 'Migrate from connection')}
              </button>
            </div>
          </div>

          <div className="panel" style={{ padding: 18, marginTop: 14 }}>
            <h3 style={{ margin: '0 0 10px' }}>From a file</h3>
            <input type="file" accept=".sql,.csv,.json,.ndjson,.jsonl" disabled={busy} onChange={e => setFile(e.target.files?.[0] || null)} />
            <p className="hint" style={{ marginTop: 8 }}>
              A <code>.sql</code> dump, a <code>.csv</code>, or a <code>.json</code> export (documents → typed columns). Pick a file from anywhere.
            </p>
            <div className="row" style={{ marginTop: 8 }}>
              <button className="primary" onClick={runFile} disabled={busy || !file}>
                {busy && <span className="spinner" />}
                {busy ? 'Migrating…' : 'Upload & migrate'}
              </button>
            </div>
          </div>
        </div>

        {/* right: the live console */}
        <div className="import-console-wrap">
          <div className="console-head">
            <span>Migration console</span>
            {busy && <span className="muted" style={{ fontSize: 12 }}>running…</span>}
          </div>
          <div className="console" ref={consoleRef}>
            {idle && <div className="muted">The live migration log will appear here once you hit Migrate.</div>}
            {lines.map((l, i) => (
              <div key={i} className={l.kind === 'err' ? 'log-err' : l.kind === 'ok' ? 'log-ok' : 'log-line'}>{l.text}</div>
            ))}
          </div>

          {progress && progress.total > 0 && (
            <div className="progress-wrap">
              <div className="progress"><div className="progress-bar" style={{ width: pct + '%' }} /></div>
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{progress.done} / {progress.total} — {progress.label}</div>
            </div>
          )}
          {busy && !progress && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>Working… (this source reports progress by phase)</div>}

          {result && (
            <div className="panel" style={{ marginTop: 12, borderColor: 'var(--green)' }}>
              {result.status === 'replicating' ? (
                <>
                  <b style={{ color: 'var(--green)' }}>✓ Continuous replication active → “{result.target}”</b>
                  <p className="muted" style={{ margin: '6px 0 10px' }}>
                    The initial copy is running and changes now stream continuously. Follow it under{' '}
                    <b>Continuous imports</b> below, and cut over once every table is copied.
                  </p>
                </>
              ) : (
                <>
                  <b style={{ color: 'var(--green)' }}>✓ Migrated into “{result.target}”</b>
                  <p className="muted" style={{ margin: '6px 0 10px' }}>{result.tables} table{result.tables === 1 ? '' : 's'} imported.</p>
                </>
              )}
              <div className="row">
                <Link className="ghost" to="/console">Open in SQL Console →</Link>
                <Link className="ghost" to="/ledger">View the ledger →</Link>
              </div>
            </div>
          )}
        </div>
      </div>

      <p className="muted" style={{ marginTop: 16, fontSize: 13 }}>
        Large or scripted migrations — and SQLite files — can also use the <code>fox import</code> CLI, which streams
        a file from anywhere on your machine into a new instance.
      </p>
      <ContinuousImports />
    </div>
  )
}

// Continuous imports still replicating, on any branch: how far the initial copy
// has got, when the source last sent anything, and the cutover that makes the
// branch standalone. Polls, so it also finds imports started from the CLI or
// before this page was opened.
function ContinuousImports() {
  const confirm = useConfirm()
  const [list, setList] = useState<Replication[] | null>(null)
  const [err, setErr] = useState('')
  const [done, setDone] = useState('')
  const [busy, setBusy] = useState('')

  useEffect(() => {
    let live = true
    const load = () => listReplication().then(l => { if (live) { setList(l); setErr('') } })
      .catch(e => { if (live) setErr((e as Error).message) })
    load()
    const t = setInterval(load, 4000)
    return () => { live = false; clearInterval(t) }
  }, [])

  const cutover = async (r: Replication) => {
    const ok = await confirm({
      title: 'Cut over',
      message: r.tables_ready === r.tables
        ? <>Stop replicating into <b>{r.branch}</b>? Its data stays; later changes on the source won't arrive.</>
        : <>Only {r.tables_ready} of {r.tables} tables have finished copying into <b>{r.branch}</b>. Cutting over now leaves the rest incomplete. Stop replicating anyway?</>,
      confirmText: 'Cut over', danger: r.tables_ready !== r.tables,
    })
    if (!ok) return
    setBusy(r.branch); setErr(''); setDone('')
    try {
      const res = await cutoverReplication(r.branch)
      setDone(`✓ ${res.branch} is now a standalone branch (${res.tables} table${res.tables === 1 ? '' : 's'}).`)
      setList(l => (l || []).filter(x => x.branch !== r.branch))
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="panel" style={{ marginTop: 18 }}>
      <h3 style={{ marginTop: 0 }}>Continuous imports</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Branches still replicating from a PostgreSQL source. Cut over once every table has copied: replication stops and the branch keeps its data.
      </p>
      {err && <div className="err">{err}</div>}
      {done && <div className="okmsg">{done}</div>}
      {list === null && !err && <div className="muted">Loading…</div>}
      {list && list.length === 0 && <div className="muted">Nothing is replicating.</div>}
      {list && list.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Branch</th><th>Initial copy</th><th>Last message from source (UTC)</th><th /></tr></thead>
            <tbody>
              {list.map(r => (
                <tr key={r.branch}>
                  <td><code>{r.branch}</code></td>
                  <td>{r.tables_ready === r.tables ? <span style={{ color: 'var(--green)' }}>done — {r.tables} of {r.tables} tables, streaming</span> : <>{r.tables_ready} of {r.tables} tables</>}</td>
                  <td className="mono muted">{r.last_message_at ? r.last_message_at.replace('T', ' ').replace('Z', '') : '—'}</td>
                  <td style={{ textAlign: 'right' }}>
                    <button className={r.tables_ready === r.tables ? 'primary' : 'ghost'} disabled={busy !== ''} onClick={() => cutover(r)}>
                      {busy === r.branch ? 'Cutting over…' : 'Cut over'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
