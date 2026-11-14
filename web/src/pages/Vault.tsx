// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { getVault, getVaultKinds, vaultFind, vaultTokenise, type VaultKind, type VaultState } from '../api'
import { useFeatures, why } from '../features'

// The vault (point 13, step 13.1): where it stands, its kinds and keys, and
// putting a value in or finding its reference key. Admins; Enterprise.
// Reading values back is not here: it needs a grant (13.2), and until then
// only the operator can, on the machine.

const WARN = 'color-mix(in srgb, var(--red) 78%, var(--text))'

export default function Vault() {
  const { can, edition } = useFeatures()
  const [st, setSt] = useState<VaultState | null>(null)
  const [kinds, setKinds] = useState<VaultKind[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [kind, setKind] = useState('aadhaar')
  const [value, setValue] = useState('')
  const [legacy, setLegacy] = useState(false)
  const [answer, setAnswer] = useState<{ what: string; ref?: string; note: string } | null>(null)

  const load = useCallback(async () => {
    setBusy(true); setErr('')
    try {
      const s = await getVault()
      setSt(s)
      if (s.set_up) setKinds(await getVaultKinds())
    } catch (e) { setSt(null); setErr((e as Error).message) }
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

  const act = async (what: 'tokenise' | 'find') => {
    const v = value.trim()
    if (!v) return
    setBusy(true); setErr(''); setAnswer(null)
    try {
      const r = what === 'tokenise' ? await vaultTokenise(kind, [v], legacy ? 'legacy' : undefined) : await vaultFind(kind, [v])
      const res = r.results?.[0] ?? ''
      const ref = r.refs?.[0] || undefined
      let note = ''
      if (res === 'refused') note = `Refused: not a ${kind} value, so nothing was made.`
      else if (res === 'not found') note = 'Not in the vault.'
      else if (what === 'tokenise') note = r.new?.[0] ? 'Put in the vault: this is its reference key.' : 'Already in the vault: this is the reference key it has.'
      else note = 'In the vault: this is its reference key.'
      setAnswer({ what, ref, note })
      // The value is not kept on the page once it has been sent.
      setValue('')
      load()
    } catch (e) { setErr((e as Error).message) }
    finally { setBusy(false) }
  }

  const s = st?.status
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

      {st && !st.set_up && (
        <div className="panel" style={{ marginTop: 14 }} data-testid="vault-state">
          <p style={{ margin: 0 }}><b>Not set up</b> on this install.</p>
          <p className="muted" style={{ margin: '8px 0 0', fontSize: 13 }}>
            The operator sets it up on the machine: <code>fox vault setup</code>, with FoxByte&rsquo;s own software token for trials,
            or with your HSM.
          </p>
        </div>
      )}

      {st?.set_up && (
        <>
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

          {s && (
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

              <h2 style={{ marginTop: 18 }}>Put a value in, or find its reference key</h2>
              <div className="panel" data-testid="vault-tool">
                <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
                  <label className="field">Kind
                    <select aria-label="Kind" value={kind} onChange={e => { setKind(e.target.value); setLegacy(false) }}>
                      {s.kinds.map(k => <option key={k.name} value={k.name}>{k.name}</option>)}
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
                  Reading a value back needs a grant from an admin.
                </p>
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
