// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import {
  getVault, getVaultGrants, getVaultKinds, getVaultLog, getVaultMine, grantVault, revokeVaultGrant, vaultDetokenise, vaultFind, vaultTokenise,
  type VaultGrant, type VaultKind, type VaultLogEntry, type VaultMine, type VaultState,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'

// The vault (point 13): where it stands, its kinds and keys, its grants and
// access log for admins (13.1, 13.2); putting a value in or finding its key
// for admins and holders of a use grant; reading a value back for holders of a
// detokenise grant, with a purpose, shown masked until revealed. Enterprise.

const WARN = 'color-mix(in srgb, var(--red) 78%, var(--text))'

// How a value read back is shown before it is revealed: Aadhaar by its last
// four digits, text by its length, anything else not at all.
export function masked(kind: string, v: string): string {
  if (kind === 'aadhaar') return v.length >= 4 ? `XXXX XXXX ${v.slice(-4)}` : '****'
  if (kind === 'text') return `(${[...v].length} characters)`
  return '••••'
}

type GrantInput = { email: string; kind: string; permission: 'use' | 'detokenise'; per_hour?: number; expires?: string }

export default function Vault() {
  const { can, edition } = useFeatures()
  const [mine, setMine] = useState<VaultMine | null>(null)
  const [st, setSt] = useState<VaultState | null>(null)
  const [kinds, setKinds] = useState<VaultKind[]>([])
  const [grants, setGrants] = useState<VaultGrant[]>([])
  const [log, setLog] = useState<VaultLogEntry[]>([])
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const confirm = useConfirm()

  const load = useCallback(async () => {
    setBusy(true); setErr('')
    try {
      const m = await getVaultMine()
      setMine(m)
      setKinds(m.kinds ?? [])
      if (m.admin) {
        const s = await getVault()
        setSt(s)
        if (s.set_up) {
          setKinds(await getVaultKinds())
          setGrants(await getVaultGrants())
          try { setLog((await getVaultLog(50)).entries ?? []) } catch { setLog([]) }
        }
      }
    } catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }, [])
  // Asked only once the engine has said what it serves: before that, can()
  // answers yes to everything.
  const known = edition !== null
  const allowed = known && can('vault')
  useEffect(() => { if (allowed) load() }, [load, allowed])

  if (!known) return <div className="fade-up"><h1>Vault</h1></div>
  if (!allowed) {
    return (
      <div className="fade-up">
        <h1>Vault</h1>
        <p className="muted" data-testid="vault-locked">{why(edition, 'The vault')}</p>
      </div>
    )
  }

  const admin = !!mine?.admin
  const myGrants = mine?.grants ?? []
  const useKinds = admin ? kinds.map(k => k.name) : myGrants.filter(g => g.permission === 'use').map(g => g.kind)
  const readKinds = myGrants.filter(g => g.permission === 'detokenise').map(g => g.kind)
  const s = st?.status

  const give = async (g: GrantInput) => {
    setErr(''); setMsg('')
    try {
      const made = await grantVault(g)
      setMsg(`Grant ${made.id}: ${made.email} may ${made.permission === 'detokenise' ? 'read back' : 'put in and find'} ${made.kind} values, up to ${made.per_hour} an hour.`)
      load()
      return true
    } catch (e) { setErr((e as Error).message); return false }
  }
  const revoke = async (g: VaultGrant) => {
    const yes = await confirm({
      title: `Revoke grant ${g.id}?`,
      message: `${g.email} may no longer ${g.permission === 'detokenise' ? 'read back' : 'put in or find'} ${g.kind} values. The grant stays in the record and the access review.`,
      confirmText: 'Revoke',
      danger: true,
    })
    if (!yes) return
    setErr(''); setMsg('')
    try { await revokeVaultGrant(g.id); setMsg(`Grant ${g.id} revoked.`); load() } catch (e) { setErr((e as Error).message) }
  }

  return (
    <div className="fade-up vault">
      <h1>Vault</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        The one place this install keeps its most sensitive values, Aadhaar first. Each value is encrypted inside an HSM;
        applications keep a reference key in its place. Reading a value back is its own permission, granted by an admin.
      </p>
      <div className="row" style={{ gap: 10 }}>
        <button className="ghost" onClick={load} disabled={busy}>{busy ? 'Reading…' : 'Refresh'}</button>
      </div>
      {err && <div className="err" style={{ marginTop: 12 }} data-testid="vault-err">{err}</div>}
      {msg && <p className="ok" style={{ marginTop: 12 }} data-testid="vault-msg">{msg}</p>}

      {mine && !mine.set_up && (
        <div className="panel" style={{ marginTop: 14 }} data-testid="vault-state">
          <p style={{ margin: 0 }}><b>Not set up</b> on this install.</p>
          <p className="muted" style={{ margin: '8px 0 0', fontSize: 13 }}>
            The operator sets it up on the machine: <code>fox vault setup</code>, with FoxByte&rsquo;s own software token for trials,
            or with your HSM.
          </p>
        </div>
      )}

      {mine?.set_up && !admin && (
        <div className="panel" style={{ marginTop: 14 }} data-testid="vault-mine">
          {myGrants.length === 0
            ? <p style={{ margin: 0 }}>You hold no vault grant. An admin gives them.</p>
            : (
              <>
                <p style={{ margin: 0 }}><b>Your vault grants</b></p>
                <ul style={{ margin: '6px 0 0' }}>
                  {myGrants.map(g => (
                    <li key={g.id}>
                      {g.permission === 'detokenise' ? 'Read back' : 'Put in and find'} {g.kind} values, {g.used_last_hour} of {g.per_hour} this hour
                      {g.expires && <>, until {new Date(g.expires).toLocaleDateString()}</>}
                    </li>
                  ))}
                </ul>
              </>
            )}
        </div>
      )}

      {admin && st?.set_up && (
        <div className="panel" style={{ marginTop: 14 }} data-testid="vault-state">
          <p style={{ margin: 0 }}>
            <b>Set up</b> {st.config && new Date(st.config.set_up_at).toLocaleDateString()}
            {' · '}database {st.database_running ? 'running' : <span style={{ color: WARN }}>stopped</span>}
            {' · '}service {st.service_running ? 'running' : <span style={{ color: WARN }}>stopped</span>}
          </p>
          {s && (
            <p style={{ margin: '8px 0 0' }} data-testid="vault-token">
              Token <code>{s.token.label}</code>: {s.token.maker} {s.token.model}, serial {s.token.serial}
              {s.token.software && (
                <span className="badge" style={{ marginLeft: 8, color: WARN }}>Software token: not UIDAI-compliant (trials and testing only)</span>
              )}
            </p>
          )}
          {st.status_error && <p style={{ margin: '8px 0 0', color: WARN }}>The service did not answer: {st.status_error}</p>}
          {s && (
            <p style={{ margin: '8px 0 0' }} data-testid="vault-log">
              Access log: {s.log.entries} entries;{' '}
              {s.log.broken_at === 0 ? 'the chain holds.' : <b style={{ color: WARN }}>the chain breaks at entry {s.log.broken_at}.</b>}{' '}
              {st.anchor.holds ? <>Against the security log: {st.anchor.note}.</> : <b style={{ color: WARN }}>Against the security log: {st.anchor.note}.</b>}
            </p>
          )}
        </div>
      )}

      {admin && s && (
        <>
          <h2 style={{ marginTop: 18 }}>Kinds</h2>
          <div className="table-wrap">
            <table aria-label="Vault kinds">
              <thead><tr><th>Kind</th><th>Reference keys</th><th>Records</th><th>Accepts</th><th>Rules</th></tr></thead>
              <tbody>
                {s.kinds.map(k => {
                  const d = kinds.find(x => x.name === k.name)
                  return (
                    <tr key={k.name} data-testid={`vault-kind-${k.name}`}>
                      <td><b>{k.name}</b></td>
                      <td><code>{k.prefix}…</code>{d?.legacy && <div className="muted" style={{ fontSize: 12 }}>legacy: {d.legacy}</div>}</td>
                      <td>{k.records}</td>
                      <td style={{ fontSize: 13 }}>{d?.check ?? ''}</td>
                      <td style={{ fontSize: 13 }}>
                        {k.rules || 'none mapped'}
                        <div style={{ color: k.compliant.startsWith('no:') ? WARN : undefined }}>{k.compliant}</div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <h2 style={{ marginTop: 18 }}>Keys</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>As the token reports them back. FoxByte never holds a key.</p>
          <div className="table-wrap">
            <table aria-label="Vault keys">
              <thead><tr><th>Key</th><th>Role</th><th>Records</th><th>Uses</th><th>Protected</th></tr></thead>
              <tbody>
                {s.kinds.flatMap(k => k.keys.map(key => (
                  <tr key={key.label}>
                    <td><code>{key.label}</code></td>
                    <td>{key.role}{key.current ? ' (current)' : ''}</td>
                    <td>{key.records}</td>
                    <td>{key.uses}</td>
                    <td>
                      {key.destroyed ? 'destroyed'
                        : key.sensitive && !key.extractable && key.never_extractable && key.local ? 'made in the token, never extractable'
                          : <b style={{ color: WARN }}>not protected: it can leave the token</b>}
                    </td>
                  </tr>
                )))}
              </tbody>
            </table>
          </div>

          <Grants kinds={kinds} grants={grants} onGrant={give} onRevoke={revoke} />
        </>
      )}

      {mine?.set_up && useKinds.length > 0 && <PutIn kinds={kinds.filter(k => useKinds.includes(k.name))} onDone={load} onErr={setErr} />}
      {mine?.set_up && readKinds.length > 0 && <ReadBack kinds={readKinds} onDone={load} onErr={setErr} />}

      {admin && st?.set_up && (
        <>
          <h2 style={{ marginTop: 18 }}>Access log</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>The newest 50 calls: who, what, which reference keys and why. Never a value.</p>
          <div className="table-wrap">
            <table aria-label="Vault access log">
              <thead><tr><th className="num">#</th><th>When</th><th>Who</th><th>Call</th><th>Kind</th><th className="num">N</th><th>Purpose</th><th>Result</th></tr></thead>
              <tbody>
                {log.map(e => (
                  <tr key={e.seq}>
                    <td className="num">{e.seq}</td>
                    <td style={{ fontSize: 13 }}>{new Date(e.at).toLocaleString()}</td>
                    <td>{e.actor}</td>
                    <td>{e.action}</td>
                    <td>{e.kind}</td>
                    <td className="num">{e.n}</td>
                    <td style={{ fontSize: 13 }}>{e.purpose}</td>
                    <td style={{ fontSize: 13 }}>{e.result}</td>
                  </tr>
                ))}
                {log.length === 0 && <tr><td colSpan={8} className="muted">No calls yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

function Grants({ kinds, grants, onGrant, onRevoke }: {
  kinds: VaultKind[]; grants: VaultGrant[]
  onGrant: (g: GrantInput) => Promise<boolean>
  onRevoke: (g: VaultGrant) => void
}) {
  const [email, setEmail] = useState('')
  const [kind, setKind] = useState(kinds[0]?.name ?? 'aadhaar')
  const [permission, setPermission] = useState<'use' | 'detokenise'>('use')
  const [perHour, setPerHour] = useState('')
  const [expires, setExpires] = useState('')
  return (
    <>
      <h2 style={{ marginTop: 18 }}>Grants</h2>
      <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
        Admins put values in and find keys without a grant. Reading values back needs a grant, admins included: grant it to yourself when you need it.
        A masked account is never given it.
      </p>
      <div className="table-wrap">
        <table aria-label="Vault grants">
          <thead><tr><th className="num">#</th><th>Account</th><th>Kind</th><th>May</th><th>This hour</th><th>Expires</th><th>Last used</th><th>Given by</th><th /></tr></thead>
          <tbody>
            {grants.map(g => (
              <tr key={g.id} data-testid={`grant-${g.email}-${g.kind}-${g.permission}`}>
                <td className="num">{g.id}</td>
                <td>{g.email}</td>
                <td>{g.kind}</td>
                <td>{g.permission === 'detokenise' ? 'read back' : 'put in, find'}</td>
                <td>{g.used_last_hour} of {g.per_hour}</td>
                <td>{g.expires ? new Date(g.expires).toLocaleDateString() : 'never'}</td>
                <td>{g.last_used ? new Date(g.last_used).toLocaleString() : 'never'}</td>
                <td>{g.granted_by}</td>
                <td><button className="ghost" onClick={() => onRevoke(g)}>Revoke…</button></td>
              </tr>
            ))}
            {grants.length === 0 && <tr><td colSpan={9} className="muted">No grants.</td></tr>}
          </tbody>
        </table>
      </div>
      <form className="row" aria-label="Give a vault grant" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end', marginTop: 10 }}
        onSubmit={async e => {
          e.preventDefault()
          if (!email.trim()) return
          const ok = await onGrant({
            email: email.trim(), kind, permission,
            ...(perHour ? { per_hour: Number(perHour) } : {}), ...(expires.trim() ? { expires: expires.trim() } : {}),
          })
          if (ok) { setEmail(''); setPerHour(''); setExpires('') }
        }}>
        <label className="field">Account<input aria-label="Account" value={email} onChange={e => setEmail(e.target.value)} placeholder="name@example.com" /></label>
        <label className="field">Kind
          <select aria-label="Grant kind" value={kind} onChange={e => setKind(e.target.value)}>
            {kinds.map(k => <option key={k.name} value={k.name}>{k.name}</option>)}
          </select>
        </label>
        <label className="field">May
          <select aria-label="Permission" value={permission} onChange={e => setPermission(e.target.value as 'use' | 'detokenise')}>
            <option value="use">put in, find</option>
            <option value="detokenise">read back</option>
          </select>
        </label>
        <label className="field">An hour<input aria-label="Limit an hour" inputMode="numeric" value={perHour} onChange={e => setPerHour(e.target.value)} placeholder={permission === 'detokenise' ? '100' : '100000'} style={{ width: 90 }} /></label>
        <label className="field">Expires<input aria-label="Expires" value={expires} onChange={e => setExpires(e.target.value)} placeholder="30d or 2026-12-31" style={{ width: 150 }} /></label>
        <button className="primary" type="submit" disabled={!email.trim()}>Give the grant</button>
      </form>
    </>
  )
}

function PutIn({ kinds, onDone, onErr }: { kinds: VaultKind[]; onDone: () => void; onErr: (s: string) => void }) {
  const [kind, setKind] = useState(kinds[0]?.name ?? 'aadhaar')
  const [value, setValue] = useState('')
  const [legacy, setLegacy] = useState(false)
  const [busy, setBusy] = useState(false)
  const [answer, setAnswer] = useState<{ ref?: string; note: string } | null>(null)
  const act = async (what: 'tokenise' | 'find') => {
    const v = value.trim()
    if (!v) return
    setBusy(true); onErr(''); setAnswer(null)
    try {
      const r = what === 'tokenise' ? await vaultTokenise(kind, [v], legacy ? 'legacy' : undefined) : await vaultFind(kind, [v])
      const res = r.results?.[0] ?? ''
      const ref = r.refs?.[0] || undefined
      let note = ''
      if (res === 'refused') note = `Refused: not a ${kind} value, so nothing was made.`
      else if (res === 'not found') note = 'Not in the vault.'
      else if (what === 'tokenise') note = r.new?.[0] ? 'Put in the vault: this is its reference key.' : 'Already in the vault: this is the reference key it has.'
      else note = 'In the vault: this is its reference key.'
      setAnswer({ ref, note })
      // The value is not kept on the page once it has been sent.
      setValue('')
      onDone()
    } catch (e) { onErr((e as Error).message) }
    finally { setBusy(false) }
  }
  return (
    <>
      <h2 style={{ marginTop: 18 }}>Put a value in, or find its reference key</h2>
      <div className="panel" data-testid="vault-tool">
        <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
          <label className="field">Kind
            <select aria-label="Kind" value={kind} onChange={e => { setKind(e.target.value); setLegacy(false) }}>
              {kinds.map(k => <option key={k.name} value={k.name}>{k.name}</option>)}
            </select>
          </label>
          <label className="field" style={{ flex: 1, minWidth: 220 }}>Value
            <input aria-label="Value" type="password" autoComplete="off" value={value} onChange={e => setValue(e.target.value)} />
          </label>
          {kinds.find(x => x.name === kind)?.legacy && (
            <label className="row" style={{ gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={legacy} onChange={e => setLegacy(e.target.checked)} /> Legacy format
            </label>
          )}
          <button className="primary" onClick={() => act('tokenise')} disabled={busy || !value.trim()}>Put in the vault</button>
          <button className="ghost" onClick={() => act('find')} disabled={busy || !value.trim()}>Find</button>
        </div>
        {answer && (
          <p style={{ margin: '10px 0 0' }} data-testid="vault-answer">
            {answer.note} {answer.ref && <code data-testid="vault-ref">{answer.ref}</code>}
          </p>
        )}
        <p className="muted" style={{ margin: '10px 0 0', fontSize: 13 }}>
          The value is sent once and not kept on this page; the vault&rsquo;s log and the security log record the call, never the value.
        </p>
      </div>
    </>
  )
}

function ReadBack({ kinds, onDone, onErr }: { kinds: string[]; onDone: () => void; onErr: (s: string) => void }) {
  const [kind, setKind] = useState(kinds[0])
  const [ref, setRef] = useState('')
  const [purpose, setPurpose] = useState('')
  const [busy, setBusy] = useState(false)
  const [got, setGot] = useState<{ kind: string; value?: string; note: string } | null>(null)
  const [shown, setShown] = useState(false)
  const read = async () => {
    if (!ref.trim() || !purpose.trim()) return
    setBusy(true); onErr(''); setGot(null); setShown(false)
    try {
      const r = await vaultDetokenise(kind, [ref.trim()], purpose.trim())
      const res = r.results?.[0] ?? ''
      if (res === 'done') setGot({ kind, value: r.values?.[0] ?? '', note: 'Read back.' })
      else if (res === 'not found') setGot({ kind, note: 'No such reference key in the vault.' })
      else setGot({ kind, note: `The record ${res}: it was changed, or moved to another record. The read is in the log.` })
      onDone()
    } catch (e) { onErr((e as Error).message) }
    finally { setBusy(false) }
  }
  return (
    <>
      <h2 style={{ marginTop: 18 }}>Read a value back</h2>
      <div className="panel" data-testid="vault-read">
        <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
          <label className="field">Kind
            <select aria-label="Read kind" value={kind} onChange={e => { setKind(e.target.value); setGot(null) }}>
              {kinds.map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </label>
          <label className="field" style={{ minWidth: 260 }}>Reference key
            <input aria-label="Reference key" autoComplete="off" value={ref} onChange={e => setRef(e.target.value)} />
          </label>
          <label className="field" style={{ flex: 1, minWidth: 220 }}>Purpose
            <input aria-label="Purpose" value={purpose} onChange={e => setPurpose(e.target.value)} placeholder="Why it is read: kept in the vault's log" />
          </label>
          <button className="primary" onClick={read} disabled={busy || !ref.trim() || !purpose.trim()}>Read back</button>
        </div>
        {got && (
          <p style={{ margin: '10px 0 0' }} data-testid="vault-read-answer">
            {got.note}{' '}
            {got.value !== undefined && (
              <>
                <code data-testid="vault-value">{shown ? got.value : masked(got.kind, got.value)}</code>{' '}
                <button className="ghost" onClick={() => setShown(v => !v)}>{shown ? 'Hide' : 'Reveal'}</button>
              </>
            )}
          </p>
        )}
        <p className="muted" style={{ margin: '10px 0 0', fontSize: 13 }}>
          Each read states its purpose, counts against your grant&rsquo;s limit an hour, and is in the vault&rsquo;s log and the security log, never with the value.
        </p>
      </div>
    </>
  )
}
