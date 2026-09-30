import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { login, register, providers, oauthUrl, type Providers } from '../api'
import { useAuth } from '../auth-context'
import { Mark, Wordmark } from '../components/brand'
import { BRAND } from '../brand'

export default function Login() {
  const { user, setUser } = useAuth()
  const nav = useNavigate()
  // `fox start` opens this page as /login?setup=<token> on a first run, so the
  // token is already here and nobody has to copy it out of a terminal.
  const [params] = useSearchParams()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(params.get('setup') ?? '')
  // Read once: the token is taken out of the address bar below, and the wording
  // should not change when it goes.
  const [tokenFromLink] = useState(() => (params.get('setup') ?? '') !== '')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [prov, setProv] = useState<Providers | null>(null)

  useEffect(() => { if (user) nav('/dashboard') }, [user, nav])
  // A one-time token does not belong in the address bar or in history; it is in
  // the form now.
  useEffect(() => {
    if (tokenFromLink) window.history.replaceState({}, '', '/login')
  }, [tokenFromLink])
  useEffect(() => {
    providers().then(p => {
      setProv(p)
      // A fresh install has no account yet: the only thing to do is create it.
      if (p.setup) setMode('register')
    }).catch(() => {})
  }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr(''); setBusy(true)
    try {
      const r = mode === 'login' ? await login(email, password) : await register(email, password, setup ? token : undefined)
      setUser(r.user)
      nav('/dashboard')
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const setup = prov?.setup === true
  const signupOpen = prov?.signup === true

  return (
    <div className="authcard fade-up">
      <div className="auth-brand"><Mark size={30} /><b><Wordmark /></b></div>
      {setup ? (
        <h1>Create the first account</h1>
      ) : signupOpen ? (
        <div className="authtabs" role="tablist">
          <button className={mode === 'login' ? 'active' : ''} onClick={() => { setMode('login'); setErr('') }}>Log in</button>
          <button className={mode === 'register' ? 'active' : ''} onClick={() => { setMode('register'); setErr('') }}>Sign up</button>
        </div>
      ) : (
        <h1>Log in</h1>
      )}
      <p className="muted">
        {setup
          ? tokenFromLink
            ? 'This install has no account yet. The first one is its admin; its setup token came in with this link, so just choose an email and a password.'
            : 'This install has no account yet. The first one is its admin, so it needs the setup token that fox start printed (fox setup-token shows it again).'
          : mode === 'register'
          ? 'Create a FoxByte account to get a dashboard, SQL console, and API keys.'
          : 'Access your FoxByte dashboard, SQL console, and API keys.'}
      </p>

      {prov && !setup && (prov.github || prov.google) && (
        <div className="oauth">
          {prov.github && <a className="btn ghost" href={oauthUrl('github')}>Continue with GitHub</a>}
          {prov.google && <a className="btn ghost" href={oauthUrl('google')}>Continue with Google</a>}
          <div className="divider"><span>or</span></div>
        </div>
      )}

      <form onSubmit={submit} className="form">
        <input type="email" placeholder="you@example.com" value={email} onChange={e => setEmail(e.target.value)} required />
        <input type="password" placeholder="password" value={password} onChange={e => setPassword(e.target.value)} required />
        {setup && (
          <input type="text" placeholder="setup token" autoComplete="off" spellCheck={false}
            value={token} onChange={e => setToken(e.target.value)} required />
        )}
        {err && <div className="err">{err}</div>}
        <button className="primary" disabled={busy}>{busy ? '…' : mode === 'login' ? 'Log in' : 'Create account'}</button>
      </form>

      {!signupOpen && !setup && (
        <p className="hint">
          Signups are closed on this instance. An admin can create your account with{' '}
          <code>{BRAND.cli} user create you@example.com</code>.
        </p>
      )}

      {/* The one place someone locked out actually looks. A password cannot be
          recovered — only a hash of it is stored — so the honest answer is how to
          set a new one, and it needs the machine rather than an inbox: there is no
          mail server in a local install, and access to the machine is what owning
          the install means. */}
      {mode === 'login' && !setup && (
        <p className="hint">
          Forgotten your password? It cannot be recovered, but a new one can be set on
          the machine {BRAND.product} runs on:{' '}
          <code>{BRAND.cli} user passwd {email.trim() || 'you@example.com'}</code>.
          That signs the account out everywhere and is recorded in the security log.
        </p>
      )}
    </div>
  )
}
