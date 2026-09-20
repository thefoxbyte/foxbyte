import { useEffect, useState } from 'react'
import { listKeys, createKey, revokeKey, type ApiKey } from '../api'
import { useConfirm } from '../confirm'

// The gateway listens beside the control plane, so the host the console was
// opened on is the host to connect to.
const dsn = (key: string) =>
  `postgresql://dbadmin:${key}@${window.location.hostname || 'localhost'}:6432/main?sslmode=require`

export default function ApiKeys() {
  const confirm = useConfirm()
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [name, setName] = useState('')
  const [fresh, setFresh] = useState<string | null>(null)
  const [err, setErr] = useState('')

  const refresh = () => listKeys().then(r => setKeys(r.keys || [])).catch(e => setErr((e as Error).message))
  useEffect(() => { refresh() }, [])

  const create = async () => {
    const n = name.trim()
    if (!n) return
    setErr('')
    try {
      const r = await createKey(n)
      setFresh(r.key)
      setName('')
      await refresh()
    } catch (e) { setErr((e as Error).message) }
  }
  const revoke = async (k: ApiKey) => {
    const ok = await confirm({
      title: 'Revoke API key',
      message: <>Revoke <b>{k.name}</b> (<code>{k.prefix}…</code>)? Anything using it stops working immediately. This can't be undone.</>,
      confirmText: 'Revoke',
      danger: true,
    })
    if (!ok) return
    setErr('')
    try { await revokeKey(k.id); await refresh() } catch (e) { setErr((e as Error).message) }
  }

  return (
    <div className="fade-up">
      <div className="page-head">
        <div>
          <h1>API keys</h1>
          <p className="sub">
            A key is the password for a connection: send it as a <code>Bearer</code> token to the
            API and agent endpoints, or as the password when you connect through the gateway.
          </p>
        </div>
        <div className="tools">
          <input placeholder="key name (e.g. ci, laptop)" value={name} onChange={e => setName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') create() }} style={{ minWidth: 220 }} />
          <button className="primary" onClick={create} disabled={!name.trim()}>Create key</button>
        </div>
      </div>
      {err && <div className="err">{err}</div>}

      {/* Shown once, and with the connection string already assembled: this is
          the moment someone actually needs it, right after signing in. */}
      {fresh && (
        <div className="panel key-fresh">
          <b>New key — copy it now, it won’t be shown again.</b>
          <pre><code>{fresh}</code>
            <button className="copy" onClick={() => navigator.clipboard?.writeText(fresh)}>copy</button>
          </pre>
          <p className="muted">Connect to the <code>main</code> branch with it:</p>
          <pre><code>{dsn(fresh)}</code>
            <button className="copy" onClick={() => navigator.clipboard?.writeText(dsn(fresh))}>copy</button>
          </pre>
        </div>
      )}

      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Prefix</th><th>Created</th><th /></tr></thead>
          <tbody>
            {keys.length === 0
              ? <tr><td colSpan={4} className="muted">No keys yet — name one above and create it.</td></tr>
              : keys.map(k => (
                <tr key={k.id}>
                  <td><b>{k.name}</b></td>
                  <td className="mono muted">{k.prefix}…</td>
                  <td className="muted">{new Date(k.created * 1000).toLocaleString()}</td>
                  <td><div className="actions"><button className="ghost danger" onClick={() => revoke(k)}>Revoke</button></div></td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
