// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { activateLicense, getLicense, type License, type LicenseActivation } from '../api'
import { BRAND } from '../brand'

// Activating a licence, from the console.
//
// The CLI has done this since licensing landed, and it is the wrong place for
// the person who needs it: somebody meets a locked feature in the console, and
// the way out was a terminal, a file saved to disk, and a command they had to
// be told about. This is the page the lock can point at.
//
// What it deliberately does not do: pretend the licence is a secret. It is
// signed, not confidential — anyone holding it can read what it grants — so it
// goes in an ordinary textarea rather than a password field, and the state it
// produces is shown in full. Treating public data as secret teaches people to
// mistrust the places that really are.
export default function LicensePage() {
  const [lic, setLic] = useState<License | null>(null)
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [done, setDone] = useState<LicenseActivation | null>(null)

  const load = useCallback(async () => {
    try { setLic(await getLicense()) } catch { setLic(null) }
  }, [])
  useEffect(() => { void load() }, [load])

  const activate = async () => {
    setBusy(true)
    setErr('')
    setDone(null)
    try {
      const r = await activateLicense(text)
      setDone(r)
      setText('')
      await load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fade-up">
      <h1>Licence</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        {BRAND.product} Enterprise unlocks the paid features. Paste the licence you were sent;
        it is signed, so this engine can tell a real one from a forged one.
      </p>

      <Current lic={lic} />

      {/* A Standard build has nothing to activate: the paid code is not in it,
          so no licence can turn anything on. Saying that here is kinder than
          accepting a licence and leaving somebody to wonder why nothing
          changed. */}
      {lic?.edition === 'standard' ? (
        <section className="panel" style={{ marginTop: 18 }}>
          <h2 style={{ marginTop: 0 }}>This is the Standard edition</h2>
          <p style={{ marginBottom: 6 }}>
            A licence cannot unlock anything here — the paid features are not part of this
            build at all, which is what keeps it freely redistributable.
          </p>
          <p className="muted" style={{ marginBottom: 0, fontSize: 13 }}>
            Install the Enterprise edition first:{' '}
            <code>install.sh --edition enterprise</code>, then come back to this page.
          </p>
        </section>
      ) : (
        <section className="panel" style={{ marginTop: 18 }}>
          <h2 style={{ marginTop: 0, marginBottom: 6 }}>Activate a licence</h2>
          <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
            Paste the whole file, including the braces. Only an admin may activate one.
          </p>
          <textarea
            aria-label="Licence"
            value={text}
            onChange={e => setText(e.target.value)}
            spellCheck={false}
            rows={10}
            placeholder={'{\n  "format": "foxbyte-license/1",\n  "id": "…",\n  …\n}'}
            style={{ width: '100%', fontFamily: 'var(--mono, monospace)', fontSize: 12 }}
          />
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <button className="primary" onClick={() => void activate()} disabled={busy || !text.trim()}>
              {busy ? 'Activating…' : 'Activate'}
            </button>
            {text.trim() && !busy && (
              <button className="ghost" onClick={() => { setText(''); setErr(''); }}>Clear</button>
            )}
          </div>

          {err && <div className="err" style={{ marginTop: 12 }} data-testid="licence-error">{err}</div>}

          {done && (
            <div className="panel" style={{ marginTop: 12 }} data-testid="licence-activated">
              <p style={{ marginTop: 0, marginBottom: done.notes?.length ? 8 : 0 }}>
                <strong>Activated {done.activated}</strong> for {done.customer}.
                {done.unlocks ? ' The paid features are available.' : ` ${done.reason}`}
              </p>
              {/* What is still left to do, and only when there is something.
                  A licence that works until the next repair, with nothing
                  having mentioned it, is a surprise that arrives months later
                  with no way to connect it to this moment. */}
              {done.notes?.map((n, i) => (
                <p key={i} className="muted" style={{ fontSize: 13, margin: '4px 0 0' }}>{n}</p>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  )
}

function Current({ lic }: { lic: License | null }) {
  if (!lic) {
    return (
      <section className="panel" style={{ marginTop: 18 }}>
        <p className="muted" style={{ margin: 0 }}>Asking the engine…</p>
      </section>
    )
  }
  const tone = !lic.present ? '' : lic.state === 'active' ? 'ok' : lic.state === 'warning' ? 'warn' : 'bad'
  return (
    <section className="panel" style={{ marginTop: 18 }}>
      <div className="row" style={{ gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
        <h2 style={{ marginTop: 0, marginBottom: 0 }}>Installed</h2>
        <span className={`tag ${tone}`} data-testid="licence-state">
          {lic.present ? lic.state : 'none'}
        </span>
        <span className="muted" style={{ fontSize: 13 }}>{lic.edition} edition</span>
      </div>

      {lic.present ? (
        <div className="table-wrap" style={{ marginTop: 12 }}>
          <table>
            <tbody>
              {lic.id && <tr><td className="muted">Licence</td><td><code>{lic.id}</code></td></tr>}
              {lic.customer && <tr><td className="muted">Issued to</td><td>{lic.customer}</td></tr>}
              {lic.expires && (
                <tr>
                  <td className="muted">Expires</td>
                  <td>{new Date(lic.expires).toLocaleDateString()}</td>
                </tr>
              )}
              {/* An empty fingerprint is a site licence — not tied to a
                  machine — which is a different thing from one bound here, and
                  the difference matters the first time a standby is promoted
                  on another machine. */}
              {lic.issuedFor !== undefined && (
                <tr>
                  <td className="muted">Machine</td>
                  <td>{lic.issuedFor ? <code>{lic.issuedFor}</code> : 'any — this is a site licence'}</td>
                </tr>
              )}
              <tr><td className="muted">Unlocks</td><td>{lic.features.join(', ') || '—'}</td></tr>
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted" style={{ marginBottom: 0, marginTop: 10 }}>
          {lic.reason || 'No licence is installed.'}
        </p>
      )}

      {/* Said once, where it can be acted on, rather than repeated on every
          locked page. */}
      {lic.present && lic.reason && (
        <p className="muted" style={{ marginTop: 10, marginBottom: 0, fontSize: 13 }}>
          {lic.reason}{lic.action ? ` — ${lic.action}` : ''}
        </p>
      )}
    </section>
  )
}
