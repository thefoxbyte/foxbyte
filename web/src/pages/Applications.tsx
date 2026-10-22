// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { addAppKey, listApps, registerApp, removeApp, revokeAppKey, type AppKey, type AppsReply, type RegisteredApp } from '../api'
import { useConfirm } from '../confirm'

// Application identity (F1): the applications that may say which of their
// users a transaction acts for. An application calls bb.act_for($1) with a
// short-lived token signed by its own key, and the Blackbox records each change
// as made by the application's account and for the user the token names.
// Admins only: a registration decides who may put a name on a record.

const when = (unix?: number | null) => (unix ? new Date(unix * 1000).toLocaleString() : '')

function keyState(k: AppKey) {
  if (!k.revoked) return <span className="badge primary">active</span>
  return (
    <span className="badge" title={k.compromised_since ? `reported compromised since ${when(k.compromised_since)}` : undefined}>
      revoked {when(k.revoked)}{k.compromised_since ? ', reported compromised' : ''}
    </span>
  )
}

function unsyncedNote(u?: Record<string, string> | null) {
  const names = Object.keys(u ?? {})
  return names.length ? `Not yet copied to ${names.join(', ')}: it is when they are next woken or restarted.` : ''
}

export default function Applications() {
  const confirm = useConfirm()
  const [data, setData] = useState<AppsReply | null>(null)
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [account, setAccount] = useState('')
  const [pub, setPub] = useState('')
  const [kid, setKid] = useState('')
  const [life, setLife] = useState('300')
  const [onInvalid, setOnInvalid] = useState<'none' | 'refuse'>('none')
  const [adding, setAdding] = useState<string | null>(null)
  const [newKey, setNewKey] = useState('')

  const refresh = useCallback(async () => {
    try { setData(await listApps()); setErr('') } catch (e) { setErr((e as Error).message) }
  }, [])
  useEffect(() => { refresh() }, [refresh])

  const act = async (fn: () => Promise<{ unsynced?: Record<string, string> | null }>, done: string) => {
    setBusy(true); setErr(''); setNote('')
    try {
      const r = await fn()
      setNote([done, unsyncedNote(r.unsynced)].filter(Boolean).join(' '))
      await refresh()
      return true
    } catch (e) { setErr((e as Error).message); return false } finally { setBusy(false) }
  }

  const register = async () => {
    const n = name.trim()
    if (!n || !account.trim()) { setErr('An application needs a name and the account its connections use.'); return }
    const ok = await act(() => registerApp({
      name: n, account: account.trim(), max_life_seconds: Number(life) || 300, on_invalid: onInvalid,
      public_key: pub.trim() || undefined, kid: kid.trim() || undefined,
    }), `Registered ${n}.`)
    if (ok) { setName(''); setAccount(''); setPub(''); setKid('') }
  }

  const addKey = async (a: RegisteredApp) => {
    if (!newKey.trim()) return
    const ok = await act(() => addAppKey(a.name, newKey.trim()), `Added a key to ${a.name}. Both keys are accepted until you revoke the old one.`)
    if (ok) { setAdding(null); setNewKey('') }
  }

  const revoke = async (a: RegisteredApp, k: AppKey, compromised: boolean) => {
    const ok = await confirm({
      title: compromised ? 'Report key compromised' : 'Revoke key',
      message: compromised
        ? <>Revoke <code>{k.kid}</code> of <b>{a.name}</b> and report it compromised from now? Its tokens are refused from the next transaction, and what it asserts from now on is shown as <i>key reported compromised</i>. For an earlier moment, use <code>fox app key revoke {a.name} {k.kid} --compromised-since &lt;time&gt;</code>.</>
        : <>Revoke <code>{k.kid}</code> of <b>{a.name}</b>? Its tokens are refused from the next transaction. What it asserted before stays as it was recorded.</>,
      confirmText: compromised ? 'Revoke and report' : 'Revoke',
      danger: true,
    })
    if (!ok) return
    await act(() => revokeAppKey(a.name, k.kid, compromised ? 'now' : ''), `Revoked ${k.kid}.`)
  }

  const remove = async (a: RegisteredApp) => {
    const ok = await confirm({
      title: 'Remove application',
      message: <>Remove <b>{a.name}</b> and its keys? Its tokens are refused from the next transaction. What it asserted stays in every Blackbox, under its name.</>,
      confirmText: 'Remove',
      danger: true,
    })
    if (!ok) return
    await act(() => removeApp(a.name), `Removed ${a.name}.`)
  }

  const notReady = Object.entries(data?.readiness ?? {}).filter(([, v]) => v !== 'checked')
  const apps = data?.apps ?? []

  return (
    <div className="fade-up applications">
      <h1>Applications</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Applications that may say which of their users a transaction acts for. The Blackbox records each change as made
        by the application's account and <i>for</i> the user its token names, &ldquo;asserted by&rdquo; the application:
        it vouched for the user, which is not proof the user was there.
      </p>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}
      {note && <div className="ok" role="status" style={{ marginTop: 12 }}>{note}</div>}

      {data && (
        <div className="panel" style={{ marginTop: 8 }}>
          <div className="muted" style={{ fontSize: 13 }}>Every token for this install names</div>
          <div><code data-testid="install-id">"aud": "{data.install_id}"</code></div>
          {notReady.length > 0 && (
            <p className="muted" style={{ margin: '8px 0 0', fontSize: 13 }} data-testid="not-ready">
              Not ready to check tokens: {notReady.map(([b, v]) => `${b} (${v === 'unavailable'
                ? 'its container predates the image that checks them: restart the engine'
                : v === 'not installed' ? `fox ledger upgrade ${b}` : v})`).join('; ')}.
            </p>
          )}
        </div>
      )}

      <h2 style={{ marginTop: 22 }}>Registered</h2>
      {data && apps.length === 0 && <p className="muted">No application is registered.</p>}
      {apps.map(a => (
        <div key={a.name} className="panel" style={{ marginTop: 10 }} data-testid={`app-${a.name}`}>
          <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
            <div>
              <b>{a.name}</b>{' '}
              <span className="muted">
                {a.account ? <>account <code>{a.account}</code></> : 'its account was deleted: nothing can assert for it'}
                {' · '}tokens live at most {Math.round(a.max_life_seconds / 60 * 10) / 10} min
                {' · '}an invalid token {a.on_invalid === 'refuse' ? 'refuses the transaction' : 'is recorded for nobody, with the reason'}
              </span>
            </div>
            <div className="row" style={{ gap: 6 }}>
              <button className="ghost" disabled={busy} onClick={() => { setAdding(adding === a.name ? null : a.name); setNewKey('') }}>Add key</button>
              <button className="ghost danger" disabled={busy} onClick={() => remove(a)}>Remove</button>
            </div>
          </div>
          {a.keys.length === 0 ? <p className="muted" style={{ margin: '8px 0 0' }}>No key yet: add one to accept its tokens.</p> : (
            <div className="table-wrap" style={{ marginTop: 8 }}>
              <table aria-label={`Keys of ${a.name}`}>
                <thead><tr><th>Key id (<code>kid</code>)</th><th>Added</th><th>State</th><th></th></tr></thead>
                <tbody>
                  {a.keys.map(k => (
                    <tr key={k.kid}>
                      <td><code>{k.kid}</code></td>
                      <td>{when(k.created)}</td>
                      <td>{keyState(k)}</td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        {!k.revoked && <>
                          <button className="ghost" disabled={busy} onClick={() => revoke(a, k, false)}>Revoke</button>{' '}
                          <button className="ghost danger" disabled={busy} onClick={() => revoke(a, k, true)}>Report compromised</button>
                        </>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {adding === a.name && (
            <div className="row" style={{ marginTop: 8, gap: 8, alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <textarea aria-label={`New public key for ${a.name}`} rows={3} style={{ flex: 1, minWidth: 260, fontFamily: 'var(--font-mono)' }}
                placeholder="-----BEGIN PUBLIC KEY----- … (or a JWK, or the 32 bytes in hex)" value={newKey} onChange={e => setNewKey(e.target.value)} />
              <button className="primary" disabled={busy || !newKey.trim()} onClick={() => addKey(a)}>Add</button>
            </div>
          )}
        </div>
      ))}

      <h2 style={{ marginTop: 22 }}>Register an application</h2>
      <div className="panel">
        <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
          <label className="field">Name (its tokens' <code>iss</code>)
            <input value={name} onChange={e => setName(e.target.value)} placeholder="shop" />
          </label>
          <label className="field">Account its connections use
            <input value={account} onChange={e => setAccount(e.target.value)} placeholder="shop-service@example.com" />
          </label>
          <label className="field">Token life
            <select value={life} onChange={e => setLife(e.target.value)}>
              <option value="60">1 minute</option>
              <option value="300">5 minutes</option>
              <option value="900">15 minutes</option>
              <option value="3600">60 minutes</option>
            </select>
          </label>
          <label className="field">An invalid token
            <select value={onInvalid} onChange={e => setOnInvalid(e.target.value as 'none' | 'refuse')}>
              <option value="none">is recorded for nobody</option>
              <option value="refuse">refuses the transaction</option>
            </select>
          </label>
        </div>
        <label className="field" style={{ display: 'block', marginTop: 10 }}>Public key (Ed25519)
          <textarea rows={3} style={{ width: '100%', fontFamily: 'var(--font-mono)' }} value={pub} onChange={e => setPub(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY----- … (openssl pkey -in key.pem -pubout), a JWK, or the 32 bytes in hex" />
        </label>
        <label className="field" style={{ display: 'block', marginTop: 10 }}>Key id (optional; the key's thumbprint if empty)
          <input value={kid} onChange={e => setKid(e.target.value)} placeholder="2026-10" />
        </label>
        <p className="muted" style={{ fontSize: 13 }}>
          Use an account of the application's own, never a person's: anyone who can log in as it can assert any user.
          Its agent keys cannot assert.
        </p>
        <button className="primary" disabled={busy} onClick={register}>{busy ? 'Working…' : 'Register'}</button>
      </div>

      <div className="panel" style={{ marginTop: 14 }}>
        <h3 style={{ marginTop: 0 }}>How an application asserts its user</h3>
        <ol style={{ margin: 0, paddingLeft: 20 }}>
          <li>Sign a token with its private key, with any JWT library that does EdDSA: header <code>{'{"alg":"EdDSA","typ":"JWT","kid":"<key id>"}'}</code>, claims <code>iss</code> (its name), <code>sub</code> (the user), <code>aud</code> (above), <code>iat</code> and <code>exp</code>; optionally <code>tenant</code> and <code>branch</code>.</li>
          <li>In each transaction, before its changes: <code>SELECT bb.act_for($1)</code>, with the token as the parameter, never in the SQL text.</li>
          <li>The Blackbox shows each change as made by its account, and for that user.</li>
        </ol>
      </div>
    </div>
  )
}
