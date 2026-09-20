import { useCallback, useEffect, useState } from 'react'
import { branchBeforeEntry, createCheckpoint, exportLedgerUrl, getBranches, getIntegrity, getLedgerEntries, type Branch, type BranchBeforeResult, type IntegrityReport, type LedgerEntry } from '../api'

// Blackbox integrity: checks a branch's Blackbox record against its checkpoint
// anchors — kept outside the database — and creates new checkpoints.
export default function Integrity() {
  const [branches, setBranches] = useState<Branch[]>([])
  const [branch, setBranch] = useState('main')
  const [report, setReport] = useState<IntegrityReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [entryId, setEntryId] = useState('')
  const [beforeName, setBeforeName] = useState('')
  const [restoring, setRestoring] = useState(false)
  const [before, setBefore] = useState<BranchBeforeResult | null>(null)
  const [beforeErr, setBeforeErr] = useState('')
  const [entries, setEntries] = useState<LedgerEntry[]>([])

  useEffect(() => { getBranches().then(setBranches).catch(() => {}) }, [])

  const loadEntries = useCallback(() => {
    getLedgerEntries('main', 20).then(setEntries).catch(() => setEntries([]))
  }, [])
  useEffect(() => { loadEntries() }, [loadEntries])

  const verify = useCallback(async () => {
    setBusy(true); setErr('')
    try { setReport(await getIntegrity(branch)) }
    catch (e) { setReport(null); setErr((e as Error).message) }
    finally { setBusy(false) }
  }, [branch])

  useEffect(() => { setMsg(''); verify() }, [verify])

  const checkpoint = async () => {
    setBusy(true); setErr(''); setMsg('')
    try {
      const r = await createCheckpoint(branch)
      setMsg(r.checkpoint
        ? `Checkpoint #${r.checkpoint.checkpoint_id} anchored entries ${r.checkpoint.from_id}–${r.checkpoint.to_id} (${r.checkpoint.entry_count} entries).`
        : 'Nothing new to checkpoint.')
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
    verify()
  }

  const branchBefore = async () => {
    const id = Number(entryId)
    if (!Number.isInteger(id) || id <= 0) { setBeforeErr('Enter a Blackbox entry id.'); return }
    setRestoring(true); setBefore(null); setBeforeErr('')
    try {
      setBefore(await branchBeforeEntry('main', id, beforeName.trim() || undefined))
      getBranches().then(setBranches).catch(() => {})
      loadEntries()
    } catch (e) {
      setBeforeErr((e as Error).message)
    } finally {
      setRestoring(false)
    }
  }

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const stat = (label: string, value: number) => (
    <div className="panel" style={{ padding: '10px 14px', minWidth: 140 }}>
      <div className="muted" style={{ fontSize: 12 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700 }}>{value}</div>
    </div>
  )

  return (
    <div className="fade-up">
      <h1>Blackbox integrity</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Checkpoints anchor the Blackbox record outside the database, so rewritten, deleted or wiped history is caught — even when
        someone could edit the database itself. Anyone can re-check independently with the open-source <code>fox-verify</code>.
      </p>

      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <span className="muted" style={{ fontSize: 13 }}>Branch</span>
        <select value={branch} onChange={e => setBranch(e.target.value)}>
          {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
        <button className="ghost" onClick={verify} disabled={busy}>{busy ? '…' : 'Verify now'}</button>
        <button className="primary" onClick={checkpoint} disabled={busy}>Create checkpoint</button>
        <a className="btn ghost" href={exportLedgerUrl(branch)} download={`${branch}-ledger.jsonl`}>Export (JSONL)</a>
      </div>

      <div className="panel" style={{ marginTop: 18 }}>
        <h3 style={{ marginTop: 0 }}>Branch from before a change</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Creates a new branch holding <code>main</code> exactly as it was just before a Blackbox entry — select one below,
          or find its id with <code>fox blackbox entries</code>. <code>main</code> is not modified. It restores a base backup and replays WAL, so it takes a
          few minutes, and needs a base backup taken before the change.
        </p>
        <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
          <input placeholder="Entry id" inputMode="numeric" value={entryId}
            onChange={e => setEntryId(e.target.value.replace(/[^0-9]/g, ''))} style={{ width: 150 }} />
          <input placeholder={entryId ? `main-before-${entryId}` : 'New branch name (optional)'} value={beforeName}
            onChange={e => setBeforeName(e.target.value)} style={{ width: 220 }} />
          <button className="primary" onClick={branchBefore} disabled={restoring || !entryId}>
            {restoring ? 'Restoring… (a few minutes)' : 'Create branch'}
          </button>
        </div>
        {beforeErr && <div className="err">{beforeErr}</div>}
        {before && (
          <div className="muted" style={{ marginTop: 10 }}>
            Branch <b>{before.branch}</b> is ready: main as it was just before entry #{before.entry_id}
            {before.command_tag ? <> ({before.command_tag} {before.object_identity})</> : null}, recovered to{' '}
            {before.target_kind} {before.target} from {before.base_backup} in {before.seconds}s.
            {before.target_kind === 'time' && ' This entry predates transaction capture, so its timestamp was used.'}
          </div>
        )}
        {entries.length > 0 && (
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table style={{ width: '100%', fontSize: 13 }}>
              <thead>
                <tr><th align="left">ID</th><th align="left">Time (UTC)</th><th align="left">Actor</th><th align="left">Change</th><th align="left">Status</th><th /></tr>
              </thead>
              <tbody>
                {entries.map(en => (
                  <tr key={en.id}>
                    <td><code>{en.id}</code></td>
                    <td className="muted">{en.at.replace('T', ' ').replace('Z', '')}</td>
                    <td>{en.actor}</td>
                    <td>{en.command_tag} <span className="muted">{en.object_identity}</span></td>
                    <td><span className={'lg-status ' + en.status}>{en.status}</span></td>
                    <td align="right">
                      <button className="ghost" disabled={restoring || en.status === 'BLOCKED'}
                        title={en.status === 'BLOCKED' ? 'A blocked change never happened' : 'Branch from just before this change'}
                        onClick={() => { setEntryId(String(en.id)); setBeforeErr('') }}>Select</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {err && <div className="err">{err}</div>}
      {msg && <div className="muted" style={{ marginTop: 10 }}>{msg}</div>}

      {report && (
        <div style={{ marginTop: 18 }}>
          <div className="row" style={{ gap: 12, alignItems: 'center' }}>
            <span className={'lg-status ' + (report.intact ? 'APPLIED' : 'BLOCKED')} style={{ fontSize: 15 }}>
              {report.intact ? 'INTACT' : 'TAMPERED'}
            </span>
            <span className="muted">
              {report.intact
                ? 'Every anchored entry still matches its anchor.'
                : 'The Blackbox record no longer matches what was anchored — see the problems below.'}
            </span>
          </div>

          <div className="row" style={{ flexWrap: 'wrap', gap: 10, marginTop: 14 }}>
            {stat('Entries', report.rows)}
            {stat('Hash-chained', report.chained_rows)}
            {stat('Checkpoints', report.checkpoints)}
            {stat('Anchored entries', report.anchored_rows)}
            {stat('Not yet anchored', report.unanchored_rows)}
          </div>

          {report.problems.length > 0 && (
            <div className="panel" style={{ marginTop: 14 }}>
              <h3 style={{ marginTop: 0 }}>Problems</h3>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {report.problems.map((p, i) => <li key={i} className="err" style={{ margin: '4px 0' }}>{p}</li>)}
              </ul>
            </div>
          )}
          {report.notes.length > 0 && (
            <div className="panel" style={{ marginTop: 14 }}>
              <h3 style={{ marginTop: 0 }}>Notes</h3>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {report.notes.map((n, i) => <li key={i} className="muted" style={{ margin: '4px 0' }}>{n}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
