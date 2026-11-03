// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { getAuditLog, type AuditLogReply } from '../api'

// The databases' audit log (F6): pgAudit in default mode. It records who
// changed the schema and roles, and who wrote to the tables an admin marks,
// with no statement text and no values; errors reach the server log as their
// code alone. Turning it on or off restarts main, so it is the CLI's, which
// says what it will do first; this page shows where it stands and names the
// command. Admins only.

function bytes(n: number) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${i === 0 ? v : v.toFixed(1)} ${u[i]}`
}

export default function AuditLog() {
  const [data, setData] = useState<AuditLogReply | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    getAuditLog().then(setData, e => setErr((e as Error).message))
  }, [])

  const pending = data?.pending ?? []
  const pct = data && data.quota > 0 ? Math.floor(data.used * 100 / data.quota) : null

  return (
    <div className="fade-up audit-log">
      <h1>Audit log</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        pgAudit's record of who changed the schema and roles, and who wrote to the tables you mark. It keeps no statement
        text and no values: errors reach the server log as their code alone. It is evidence of those operations, not a
        record of every query.
      </p>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {data && !data.on && (
        <div className="panel" style={{ marginTop: 8 }} data-testid="audit-off">
          <p style={{ marginTop: 0 }}><span className="badge">off</span> No database runs pgAudit.</p>
          <p className="muted" style={{ fontSize: 13 }}>
            It costs capacity, more on busy tables: with every statement audited, writes and reads slowed by a fifth to a
            half on a busy server. Turning it on restarts main; connections drop for a few seconds. Run:
          </p>
          <pre><code data-testid="audit-setup">{data.setup}</code></pre>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>It says what it will do, and asks for <code>--yes</code>.</p>
        </div>
      )}

      {data?.on && (
        <div className="panel" style={{ marginTop: 8 }} data-testid="audit-on">
          <p style={{ marginTop: 0 }}>
            <span className="badge primary">on</span> Default mode: schema and role changes by everyone, and writes to
            marked tables. No statement text, no values.
          </p>
          <div className="table-wrap">
            <table aria-label="Audit log">
              <tbody>
                <tr><th>Log</th><td><code>{data.root}/&lt;branch&gt;</code>, a week of hourly files</td></tr>
                <tr>
                  <th>Space</th>
                  <td data-testid="audit-space">
                    {data.quota > 0 ? `${bytes(data.used)} of ${bytes(data.quota)} (${pct}%)` : `${bytes(data.used)}, no quota on this storage`}
                    {pct !== null && pct >= 80 && <span className="badge" style={{ marginLeft: 8 }}>a full log loses audit lines without a word</span>}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
            Marking tables, reading the log and forwarding it to your SIEM come next. To turn it off: <code>{data.off}</code>.
          </p>
        </div>
      )}

      {pending.length > 0 && (
        <p className="muted" style={{ fontSize: 13 }} data-testid="audit-pending">
          Still running as before the last change, until each is next started: {pending.join(', ')}. A suspended branch
          picks it up when it wakes.
        </p>
      )}
    </div>
  )
}
