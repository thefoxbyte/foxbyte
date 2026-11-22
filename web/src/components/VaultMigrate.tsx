// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { getVaultMigrations, migrateToVault, migrationClean, type VaultMigration } from '../api'
import { useConfirm } from '../confirm'

// Moving a branch's Aadhaar numbers into the vault (point 13, step 13.3), on
// the Aadhaar exposure page: a preview first, then the move, each number
// replaced where it stands by its reference key. On a branch first: main is
// moved only once a branch made from main has moved the same columns with
// nothing left, and only by an admin. The engine decides all of that; this
// shows the plan, the result, and the runs before.

const where = (c: { schema: string; table: string; column: string }) => `${c.schema}.${c.table}.${c.column}`

export default function VaultMigrate({ branch, admin, licensed }: { branch: string; admin: boolean; licensed: boolean }) {
  const [runs, setRuns] = useState<VaultMigration[]>([])
  const [shown, setShown] = useState<VaultMigration | null>(null)
  const [busy, setBusy] = useState<'' | 'preview' | 'move'>('')
  const [err, setErr] = useState('')
  // After a preview, the columns ticked to move: all that can be, at first.
  const [picked, setPicked] = useState<Set<string> | null>(null)
  const confirm = useConfirm()

  const load = useCallback(async () => {
    try {
      const ms = await getVaultMigrations(branch)
      setRuns(ms)
      return ms
    } catch { setRuns([]); return [] }
  }, [branch])
  useEffect(() => { setShown(null); setPicked(null); setErr(''); if (licensed) load() }, [load, licensed])

  const main = branch === 'main'
  const run = async (dryRun: boolean) => {
    if (!dryRun) {
      const ok = await confirm({
        title: main ? 'Move main into the vault' : `Move ${branch} into the vault`,
        message: main
          ? <>Replace every Aadhaar number in main's columns with its reference key, where it stands? The keys are the ones the
            rehearsal branch got, and applications reading these columns read keys from now on. This is refused unless a branch made
            from main has moved the same columns with no number left.</>
          : <>Put every Aadhaar number in <b>{branch}</b>'s columns in the vault, and replace each with its reference key where it stands?
            Check the branch afterwards; main is then moved with the same keys.</>,
        confirmText: 'Move',
        danger: main,
      })
      if (!ok) return
    }
    setBusy(dryRun ? 'preview' : 'move'); setErr('')
    const columns = !dryRun && picked ? [...picked] : undefined
    try {
      const m = await migrateToVault(branch, columns ? { columns, dryRun } : { dryRun })
      setShown(m)
      setPicked(dryRun ? new Set(m.columns.filter(c => !c.skipped).map(where)) : null)
      await load()
    } catch (e) {
      setErr((e as Error).message)
      const ms = await load()
      if (ms.length > 0 && !dryRun) setShown(ms[0])
    } finally { setBusy('') }
  }

  if (!licensed) return null
  const canMove = (!main || admin) && (picked === null || picked.size > 0)
  const toggle = (w: string) => setPicked(p => {
    const n = new Set(p ?? [])
    if (n.has(w)) n.delete(w)
    else n.add(w)
    return n
  })
  return (
    <div className="panel" style={{ marginTop: 16 }} data-testid="vault-migrate">
      <h3 style={{ marginTop: 0 }}>Move into the vault</h3>
      <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
        Each number in the columns this report found goes into the vault, and its reference key takes its place: the whole value,
        or the number inside text or JSON. Columns that only hold numbers get legacy keys (12 digits starting with 1, never a valid
        Aadhaar). {main
          ? 'Main is moved only after a branch made from main has moved the same columns with no number left, and only by an admin.'
          : 'On a branch first: check it, then move main, which gets the same keys.'}
      </p>
      <div className="row" style={{ gap: 10 }}>
        <button onClick={() => run(true)} disabled={busy !== ''}>{busy === 'preview' ? 'Reading…' : 'Preview'}</button>
        <button className={main ? 'danger' : 'primary'} onClick={() => run(false)} disabled={busy !== '' || !canMove}
          title={canMove ? undefined : "Main's numbers are moved by an admin"}>
          {busy === 'move' ? 'Moving…' : main ? 'Move main' : 'Move into the vault'}
        </button>
        {picked && <span className="muted" style={{ fontSize: 13 }}>{picked.size} column(s) ticked in the preview</span>}
      </div>
      {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      {shown && <MigrationResult m={shown} picked={shown.dry ? picked : null} onToggle={toggle} />}
      {runs.length > 0 && (
        <>
          <h4 style={{ marginBottom: 6 }}>Runs on {branch}</h4>
          <div className="table-wrap">
            <table aria-label="Vault migrations">
              <thead>
                <tr><th className="num">Run</th><th>When</th><th>By</th><th>What</th><th>State</th><th className="num">Numbers</th><th className="num">Keys made</th><th className="num">Left</th><th><span className="sr-only">Show</span></th></tr>
              </thead>
              <tbody>
                {runs.map(m => (
                  <tr key={m.id}>
                    <td className="num">{m.id}</td>
                    <td>{new Date(m.started).toLocaleString()}</td>
                    <td>{m.actor}</td>
                    <td>{m.dry ? 'preview' : 'move'}</td>
                    <td>{migrationClean(m) ? 'done, clean' : m.state}</td>
                    <td className="num">{m.distinct}</td>
                    <td className="num">{m.dry ? '–' : m.made}</td>
                    <td className="num">{m.dry ? '–' : m.columns.reduce((n, c) => n + c.left, 0)}</td>
                    <td><button className="ghost sm" aria-label={`Show run ${m.id}`} onClick={() => setShown(m)}>Show</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

function MigrationResult({ m, picked, onToggle }: { m: VaultMigration; picked: Set<string> | null; onToggle: (w: string) => void }) {
  const clean = migrationClean(m)
  return (
    <div style={{ marginTop: 12 }} data-testid="vault-migration">
      <p style={{ margin: '0 0 8px' }} data-testid="vault-migration-summary">
        {m.dry ? 'Preview' : 'Move'} {m.id}{m.state !== 'done' ? ` (${m.state})` : ''}: {m.distinct} distinct number(s) in {m.columns.length} column(s).
        {!m.dry && m.state === 'done' && <> {m.made} key(s) made in the vault, {m.reused} it held already.</>}
        {clean && <b> Every column is moved, with no number left.</b>}
        {(m.rehearsals?.length ?? 0) > 0 && <> Rehearsed by run(s) {m.rehearsals!.join(', ')}.</>}
      </p>
      {m.error && <div className="err" style={{ marginBottom: 8 }}>{m.error}</div>}
      {m.columns.length > 0 && (
        <div className="table-wrap">
          <table aria-label="Columns moved">
            <thead>
              <tr>{picked && <th><span className="sr-only">Move</span></th>}<th>Column</th><th>Type</th><th>Keys</th><th className="num">Rows</th><th className="num">Numbers</th><th className="num">Rewritten</th><th className="num">Left</th></tr>
            </thead>
            <tbody>
              {m.columns.map(c => (
                <tr key={where(c)}>
                  {picked && (
                    <td>
                      {!c.skipped && <input type="checkbox" aria-label={`Move ${where(c)}`} checked={picked.has(where(c))} onChange={() => onToggle(where(c))} />}
                    </td>
                  )}
                  <td><code>{where(c)}</code></td>
                  <td>{c.type || '–'}</td>
                  {c.skipped ? <td colSpan={5} className="muted">skipped: {c.skipped}</td> : (
                    <>
                      <td>{c.format}</td>
                      <td className="num">{c.rows}</td>
                      <td className="num">{c.numbers}</td>
                      <td className="num">{m.dry ? '–' : c.replaced}</td>
                      <td className="num">
                        {m.dry ? '–' : c.left}
                        {Object.entries(c.left_why ?? {}).map(([why, n]) => <div key={why} className="muted" style={{ fontSize: 12 }}>{n}: {why}</div>)}
                      </td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {m.limits.length > 0 && (
        <ul className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
          {m.limits.map(l => <li key={l}>{l}</li>)}
        </ul>
      )}
    </div>
  )
}
