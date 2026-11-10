// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { getUpkeep, runMaintenance, type MaintenanceOp, type TableUpkeepStats } from '../api'

// A table's upkeep (point 12.5): how many rows and dead row versions it has,
// and when it was last vacuumed and analysed, by hand and by autovacuum; and
// a vacuum or an analyse run on it. Running one is the branch's owner's or an
// admin's: the engine refuses anyone else, and the message says so.

const when = (at: string) => at ? new Date(at).toLocaleString() : 'never'
const size = (b: number) => b >= 1 << 20 ? `${(b / (1 << 20)).toFixed(1)} MB` : b >= 1024 ? `${(b / 1024).toFixed(1)} kB` : `${b} B`

const OPS: [MaintenanceOp, string, string][] = [
  ['vacuum', 'Vacuum', 'Reclaim the space dead row versions take, for reuse. Reads and writes go on.'],
  ['analyze', 'Analyse', 'Read a sample again, so the planner estimates this table well.'],
  ['vacuum-analyze', 'Vacuum and analyse', 'Both, one after the other.'],
]

export default function TableUpkeep({ branch, schema, table }: { branch: string; schema: string; table: string }) {
  const [st, setSt] = useState<TableUpkeepStats | null>(null)
  const [busy, setBusy] = useState<MaintenanceOp | ''>('')
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setErr('')
    try {
      const r = await getUpkeep(branch, schema, table)
      setSt(r.tables[0] ?? null)
    } catch (e) { setErr((e as Error).message) }
  }, [branch, schema, table])
  useEffect(() => { setSt(null); setMsg(''); load() }, [load])

  const run = async (op: MaintenanceOp, label: string) => {
    setBusy(op); setErr(''); setMsg('')
    try {
      const r = await runMaintenance(branch, schema, table, op)
      setSt(r.table)
      setMsg(`${label}: done in ${r.ms} ms.`)
    } catch (e) { setErr((e as Error).message) }
    finally { setBusy('') }
  }

  return (
    <div className="upkeep" data-testid="upkeep">
      {st ? (
        <table aria-label="Upkeep">
          <tbody>
            <tr><th>Rows (estimated)</th><td data-testid="upkeep-live">{st.live}</td></tr>
            <tr><th>Dead row versions</th><td data-testid="upkeep-dead">{st.dead}</td></tr>
            <tr><th>Size, with indexes</th><td>{size(st.bytes)}</td></tr>
            <tr><th>Last vacuum</th><td data-testid="upkeep-vacuum">{when(st.lastVacuum)}{st.lastAutoVacuum && <span className="muted"> · autovacuum {when(st.lastAutoVacuum)}</span>}</td></tr>
            <tr><th>Last analyse</th><td data-testid="upkeep-analyze">{when(st.lastAnalyze)}{st.lastAutoAnalyze && <span className="muted"> · autovacuum {when(st.lastAutoAnalyze)}</span>}</td></tr>
          </tbody>
        </table>
      ) : !err && <div className="muted">Loading…</div>}
      <div className="row" style={{ marginTop: 10, gap: 8 }}>
        {OPS.map(([op, label, title]) => (
          <button key={op} type="button" className="ghost" title={title} disabled={!!busy} onClick={() => run(op, label)}>
            {busy === op ? `${label}…` : label}
          </button>
        ))}
      </div>
      <p className="muted" style={{ fontSize: 13 }}>
        VACUUM FULL is not offered here: it locks the table against reads and writes for as long as it takes.
      </p>
      {msg && <div className="ok" role="status" data-testid="upkeep-msg">{msg}</div>}
      {err && <div className="err">{err}</div>}
    </div>
  )
}
