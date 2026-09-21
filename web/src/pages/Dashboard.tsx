import { useEffect, useState } from 'react'
import {
  getStatus, getBranches, createBranch, deleteBranch, suspendBranch, resumeBranch,
  listBackups, API, type Status, type Branch, type Backup,
} from '../api'
import { useConfirm } from '../confirm'

function Dot({ up }: { up: boolean }) {
  return <span className={'dot ' + (up ? 'up' : 'down')} />
}

function CopyBtn({ text, what = 'connection string' }: { text: string; what?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      className={'copy-icon' + (done ? ' done' : '')}
      title={done ? 'Copied!' : 'Copy ' + what}
      aria-label={'Copy ' + what}
      onClick={() => { navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200) }}
    >
      {done ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
      )}
    </button>
  )
}

function toBytes(s: string): number {
  const m = /^([\d.]+)\s*([KMGT]?)/i.exec(s || '')
  if (!m) return 0
  const mult: Record<string, number> = { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 }
  return parseFloat(m[1]) * (mult[m[2].toUpperCase()] || 1)
}

function sizeLabel(bytes?: number): string {
  if (!bytes) return '—'
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0, n = bytes
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`
}

function when(ts?: string): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}

// Base backups: a restore can only reach a point that a base backup precedes,
// so the oldest one here is the earliest point in time this install can go
// back to. Read-only on purpose -- a restore runs `fox restore --to`, which
// needs a host port and leaves a disposable container to query.
function Backups() {
  const [backups, setBackups] = useState<Backup[] | null>(null)
  const [err, setErr] = useState('')
  // An install that backs up regularly has hundreds of these; the newest few
  // are what anyone reads, so the rest are a click away.
  const [all, setAll] = useState(false)

  useEffect(() => {
    let live = true
    listBackups()
      .then(b => { if (live) { setBackups(b); setErr('') } })
      .catch(e => { if (live) setErr(String(e.message || e)) })
    return () => { live = false }
  }, [])

  const oldest = backups && backups.length ? backups[backups.length - 1] : null
  const shown = backups ? (all ? backups : backups.slice(0, 6)) : []
  const hidden = backups ? backups.length - shown.length : 0
  return (
    <div className="panel" style={{ marginTop: 22 }}>
      <h3>Base backups</h3>
      <p className="muted" style={{ marginTop: 2 }}>
        A point-in-time restore replays archived WAL from one of these, so the oldest is the
        earliest point this install can go back to.{' '}
        {oldest && <>Right now that is <b>{when(oldest.finished_at)}</b>.</>}
      </p>
      {err && <div className="err">{err}</div>}
      {backups === null && !err && <p className="muted">Reading object storage…</p>}
      {backups && backups.length === 0 && (
        <p className="muted">No base backups yet — take one with <code>fox backup create</code>.</p>
      )}
      {backups && backups.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Finished</th><th>Size</th><th>Restore to any point after it</th></tr></thead>
            <tbody>
              {shown.map(b => {
                const cmd = `fox restore --to '${(b.finished_at || '').replace('T', ' ').replace('Z', '+00')}'`
                return (
                  <tr key={b.name}>
                    <td>{when(b.finished_at)} {b.newest && <span className="badge primary">newest</span>}</td>
                    <td className="cell-mono">{sizeLabel(b.size_bytes)}</td>
                    <td className="dsn-cell">
                      <div className="dsn-row">
                        <span className="dsn" title="Copy restore command">{cmd}</span>
                        <CopyBtn text={cmd} what="restore command" />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {hidden > 0 && (
            <button className="ghost" style={{ marginTop: 10 }} onClick={() => setAll(true)}>
              Show {hidden} older {hidden === 1 ? 'backup' : 'backups'}
            </button>
          )}
          {all && backups.length > 6 && (
            <button className="ghost" style={{ marginTop: 10 }} onClick={() => setAll(false)}>Show fewer</button>
          )}
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const confirm = useConfirm()
  const [status, setStatus] = useState<Status | null>(null)
  const [branches, setBranches] = useState<Branch[]>([])
  const [name, setName] = useState('')
  const [from, setFrom] = useState('main')
  const [err, setErr] = useState('')
  const [offline, setOffline] = useState(false)

  const refresh = async () => {
    try {
      const [s, b] = await Promise.all([getStatus(), getBranches()])
      setStatus(s); setBranches(b); setOffline(false)
    } catch {
      setOffline(true)
    }
  }
  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [])

  const act = async (fn: () => Promise<unknown>) => {
    setErr('')
    try { await fn(); await refresh() } catch (e) { setErr((e as Error).message) }
  }
  const create = () => {
    const n = name.trim()
    if (n) { act(() => createBranch(n, from === 'main' ? undefined : from)); setName('') }
  }

  if (offline) {
    return (
      <>
        <h1>Dashboard</h1>
        <div className="offline">
          Can’t reach the API at <code>{API}</code>. Start it with{' '}
          <code>fox start</code>, or set <code>VITE_API_URL</code>.
        </div>
      </>
    )
  }

  const tiles: [string, React.ReactNode][] = status ? [
    ['Primary', <><Dot up={status.mainReady} /> {status.mainReady ? 'Ready' : 'Down'}</>],
    ['Branches', status.branches],
    ['Agent DBs', status.agents],
    ['Gateway', <><Dot up={status.servers.gateway} /> {status.servers.gateway ? 'Up' : 'Down'}</>],
    ['Replica', status.ha.enabled
      ? <><Dot up={status.ha.streaming} /> {status.ha.streaming ? 'streaming' : status.ha.standby}</>
      : <span style={{ color: 'var(--muted)', fontSize: 18 }}>none</span>],
    ['Storage', status.storage?.used || '—'],
  ] : []

  const maxUsed = Math.max(1, ...branches.map(b => toBytes(b.used)))

  return (
    <div className="fade-up">
      <h1>Dashboard</h1>
      <p className="muted" style={{ marginTop: -2 }}>Live control plane · auto-refreshing every 3s.</p>

      <div className="grid stat-grid">
        {tiles.map(([k, v], i) => (
          <div className="tile" key={i}><div className="k">{k}</div><div className="v">{v}</div></div>
        ))}
      </div>

      <div className="row">
        <input
          placeholder="new branch name (e.g. qa)"
          value={name}
          onChange={e => setName(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') create() }}
          style={{ minWidth: 240 }}
        />
        <span className="muted" style={{ fontSize: 13 }}>from</span>
        <select value={from} onChange={e => setFrom(e.target.value)} title="The branch to copy">
          {(branches.some(b => b.name === 'main') ? branches : [{ name: 'main' } as Branch, ...branches]).map(b => (
            <option key={b.name} value={b.name}>{b.name}</option>
          ))}
        </select>
        <button className="primary" onClick={create} disabled={!name.trim()}>+ Create branch</button>
      </div>
      {err && <div className="err">{err}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Branch</th><th>Type</th><th>State</th><th>Size (CoW)</th><th className="num">Conns</th><th>Connection string</th><th /></tr>
          </thead>
          <tbody>
            {branches
              .slice()
              .sort((a, b) => (a.primary ? -1 : b.primary ? 1 : a.name.localeCompare(b.name)))
              .map(b => {
                const running = b.state === 'running'
                const dsn = `postgres://dbadmin:<API_KEY>@localhost:6432/${b.name}`
                const type = b.primary ? 'primary' : b.agent ? 'agent' : 'branch'
                const pct = Math.max(6, Math.round((toBytes(b.used) / maxUsed) * 100))
                return (
                  <tr key={b.name}>
                    <td className="name-cell"><b>{b.name}</b></td>
                    <td><span className={'badge ' + type}>{type}</span></td>
                    <td><span className={'state ' + (running ? 'running' : 'suspended')}><Dot up={running} /> {running ? 'running' : 'suspended'}</span></td>
                    <td>
                      <div className="meter-row">
                        <div className="cow"><span style={{ width: pct + '%' }} /></div>
                        <span className="cell-mono">{b.used || '—'}</span>
                      </div>
                    </td>
                    <td className="num">{running ? b.connections : '—'}</td>
                    <td className="dsn-cell">
                      <div className="dsn-row">
                        <span className="dsn" title="Copy connection string" onClick={() => navigator.clipboard?.writeText(dsn)}>{dsn}</span>
                        <CopyBtn text={dsn} />
                      </div>
                    </td>
                    <td>
                      <div className="actions">
                        {!b.primary && (running
                          ? <button className="ghost" onClick={() => act(() => suspendBranch(b.name))}>Suspend</button>
                          : <button className="ghost" onClick={() => act(() => resumeBranch(b.name))}>Resume</button>)}
                        {!b.primary && (
                          <button className="ghost danger" onClick={async () => {
                            const ok = await confirm({
                              title: 'Delete branch',
                              message: <>Delete branch <b>{b.name}</b>? This permanently destroys its data and can't be undone.</>,
                              confirmText: 'Delete', danger: true,
                            })
                            if (ok) act(() => deleteBranch(b.name))
                          }}>Delete</button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
          </tbody>
        </table>
      </div>

      <Backups />
    </div>
  )
}
