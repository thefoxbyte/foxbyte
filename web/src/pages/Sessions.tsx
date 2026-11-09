// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import { getSessions, signalSession, type SessionsList } from '../api'
import { useConfirm } from '../confirm'
import { useBranches } from '../useBranches'

// Sessions (point 12.5): who is connected to a branch, what each is running,
// and since when; a running query cancelled, or a session ended. The branch's
// owner and an admin see and stop everyone's; anyone else their own and their
// agent keys': another account's statement can hold values that are not theirs.

const ago = (at: string) => {
  if (!at) return ''
  const s = Math.max(0, Math.round((Date.now() - new Date(at).getTime()) / 1000))
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

export default function Sessions() {
  const confirm = useConfirm()
  const { branches } = useBranches()
  const [branch, setBranch] = useState('main')
  const [list, setList] = useState<SessionsList | null>(null)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const latest = useRef(0)

  const load = useCallback(async (b: string) => {
    const mine = ++latest.current
    try {
      const l = await getSessions(b)
      if (mine === latest.current) { setList(l); setErr('') }
    } catch (e) { if (mine === latest.current) { setList(null); setErr((e as Error).message) } }
  }, [])
  useEffect(() => {
    load(branch)
    const t = setInterval(() => load(branch), 3000)
    return () => clearInterval(t)
  }, [branch, load])

  const signal = async (pid: number, user: string, end: boolean) => {
    if (end && !await confirm({
      title: 'End session',
      message: <>This ends session {pid} ({user}) on {branch}, rolling back whatever it has open. The client sees its connection closed.</>,
      confirmText: 'End it', danger: true,
    })) return
    setErr(''); setMsg('')
    try {
      await signalSession(branch, pid, end)
      setMsg(end ? `Session ${pid} ended.` : `Session ${pid}'s query cancelled.`)
      load(branch)
    } catch (e) { setErr((e as Error).message) }
  }

  return (
    <div className="fade-up">
      <h1>Sessions</h1>
      <p className="muted" style={{ marginTop: -2 }}>
        Who is connected to a branch and what each is running, read again every 3 s. Cancel stops a running query and
        keeps the session; End closes the session and rolls back what it has open.
      </p>
      <div className="row">
        <label className="field">Branch
          <select aria-label="Branch" value={branch} onChange={e => setBranch(e.target.value)}>
            {(branches.some(b => b.name === 'main') ? branches : [{ name: 'main' }, ...branches]).map(b => (
              <option key={b.name} value={b.name}>{b.name}</option>
            ))}
          </select>
        </label>
      </div>
      {list && !list.all && (
        <p className="muted" style={{ fontSize: 13 }} data-testid="sessions-own">
          Your sessions and your agent keys&rsquo; only: the branch&rsquo;s owner and admins see everyone&rsquo;s.
        </p>
      )}
      {msg && <div className="ok" role="status" data-testid="sessions-msg">{msg}</div>}
      {err && <div className="err">{err}</div>}
      <div className="table-wrap">
        <table aria-label="Sessions">
          <thead><tr><th>PID</th><th>User</th><th>State</th><th>For</th><th>Query</th><th /></tr></thead>
          <tbody>
            {(list?.sessions ?? []).map(s => (
              <tr key={s.pid} data-testid={`session-${s.pid}`}>
                <td className="cell-mono">{s.pid}</td>
                <td>{s.user}{s.engine && <span className="muted"> (FoxByte)</span>}{s.app && <div className="muted" style={{ fontSize: 12 }}>{s.app}</div>}</td>
                <td>
                  {s.state}
                  {s.wait && s.state === 'active' && <div className="muted" style={{ fontSize: 12 }}>waits: {s.wait}</div>}
                  {s.blockedBy.length > 0 && <div className="err" style={{ fontSize: 12 }}>blocked by {s.blockedBy.join(', ')}</div>}
                </td>
                <td className="cell-mono">{s.state === 'active' ? ago(s.since) : ''}</td>
                <td><code style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>{s.query}</code></td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  {!s.engine && <>
                    <button type="button" className="ghost sm" disabled={s.state !== 'active'} onClick={() => signal(s.pid, s.user, false)}>Cancel</button>{' '}
                    <button type="button" className="ghost sm danger" onClick={() => signal(s.pid, s.user, true)}>End…</button>
                  </>}
                </td>
              </tr>
            ))}
            {list && list.sessions.length === 0 && <tr><td colSpan={6} className="muted">No client sessions on {branch}.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
