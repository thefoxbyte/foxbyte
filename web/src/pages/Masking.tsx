// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  applyMaskSetup, dropMaskRule, getMaskKeys, getMaskedBranches, getMasking, getPersonalData, maskAccount, maskKey, planMaskRule, planMaskSetup,
  setMaskRule, unmaskAccount, type MaskKeysStatus, type MaskedBranch, type MaskPlace, type MaskRule, type MaskRuleName, type MaskStatus, type PIIFinding,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'
import { useBranches } from '../useBranches'

// Masking (F5, point 4.6): rules on confirmed personal data, and the accounts
// an admin masks. A masked account reads the masks of marked tables and
// ordinary tables as they are, on every branch it does not own. Admins only;
// reading it is free, setting it is Enterprise.

const RULES: MaskRuleName[] = ['partial', 'hash', 'fake', 'empty']
const WHAT: Record<MaskRuleName, string> = {
  partial: 'all but the last four characters as X',
  hash: 'a keyed hash: the same value, the same mask, so it still joins',
  fake: 'a made-up value of its kind, the same for the same value',
  empty: 'nothing',
}

// The category's default (as the engine's DefaultMaskRule), and what it may be:
// Aadhaar is masked by display only, never hashed or faked.
const defaultRule = (category: string): MaskRuleName => {
  const c = category.toLowerCase()
  if (['aadhaar', 'pan', 'card', 'mobile', 'gstin', 'ifsc'].includes(c)) return 'partial'
  if (c === 'email') return 'hash'
  if (c === 'name') return 'fake'
  return 'empty'
}
const allowed = (category: string): MaskRuleName[] =>
  category.toLowerCase() === 'aadhaar' ? ['partial', 'empty'] : RULES

const where = (p: MaskPlace) => `${p.schema}.${p.table}.${p.column}${p.path ? ' ' + p.path : ''}`
const key = (p: MaskPlace) => `${p.schema}\u0000${p.table}\u0000${p.column}\u0000${p.path ?? ''}`
const WARN = 'color-mix(in srgb, var(--red) 78%, var(--text))'
const viewOf = (r: MaskRule) => (r.schema === 'public' ? r.table : `${r.schema}__${r.table}`)

export default function Masking() {
  const { branches } = useBranches()
  const [branch, setBranch] = useState('main')
  const [st, setSt] = useState<MaskStatus | null>(null)
  const [confirmed, setConfirmed] = useState<PIIFinding[]>([])
  const [choice, setChoice] = useState<Record<string, MaskRuleName>>({})
  const [email, setEmail] = useState('')
  const [keys, setKeys] = useState<MaskKeysStatus | null>(null)
  const [mbs, setMbs] = useState<MaskedBranch[]>([])
  const [domain, setDomain] = useState('')
  const [move, setMove] = useState({ table: '', domain: '' })
  const [unmaskFor, setUnmaskFor] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const confirm = useConfirm()
  const { can, edition } = useFeatures()
  const setting = can('masking')

  // Only the latest load is shown: one for main started when the page opened
  // must not land after the branch the person picked since.
  const latest = useRef(0)
  const load = useCallback(async (b: string) => {
    const mine = ++latest.current
    const stale = () => mine !== latest.current
    setBusy(true); setErr('')
    try {
      const s = await getMasking(b)
      if (stale()) return
      setSt(s)
      try { const k = await getMaskKeys(); if (!stale()) setKeys(k) } catch { if (!stale()) setKeys(null) }
      try { const m = await getMaskedBranches(); if (!stale()) setMbs(m) } catch { if (!stale()) setMbs([]) }
      try {
        const pd = await getPersonalData(b)
        if (!stale()) setConfirmed((pd.findings ?? []).filter(f => f.state === 'confirmed'))
      } catch { if (!stale()) setConfirmed([]) }
    } catch (e) { if (!stale()) { setSt(null); setErr((e as Error).message) } }
    finally { if (!stale()) setBusy(false) }
  }, [])
  useEffect(() => { load('main') }, [load])
  // While a masked branch is being made, its progress is read again.
  useEffect(() => {
    if (!mbs.some(m => m.state === 'making')) return
    const t = setInterval(async () => { try { setMbs(await getMaskedBranches()) } catch { /* kept */ } }, 3000)
    return () => clearInterval(t)
  }, [mbs])

  const run = async (f: () => Promise<string>) => {
    setErr(''); setMsg('')
    try { setMsg(await f()); await load(branch) } catch (e) { setErr((e as Error).message) }
  }

  const setup = () => run(async () => {
    const p = await planMaskSetup(branch)
    const ok = await confirm({
      title: `Set masking up on ${branch}`,
      message: <>
        <p>This makes the install&rsquo;s masking key if it has none: 32 random bytes in <code>{p.keyDir}</code>, readable only
          by the database server and mounted read-only into each database. FoxByte never reads it back.</p>
        <p>Then the masked readers&rsquo; role, schema and rights on {branch}. Nobody is masked until you mask an account.</p>
        {p.restart && <p><b>{branch} restarts</b> to mount the key: connections drop for 5–15 seconds; nothing is lost.</p>}
      </>,
      confirmText: 'Set it up',
    })
    if (!ok) return ''
    setBusy(true)
    try { await applyMaskSetup(branch) } finally { setBusy(false) }
    return `Masking is set up on ${branch}.`
  })

  const mask = (f: PIIFinding) => run(async () => {
    const at: MaskPlace = { schema: f.schema, table: f.table, column: f.column, path: f.path || undefined }
    const rule = choice[key(at)] ?? defaultRule(f.category)
    const p = await planMaskRule(branch, at, rule)
    const ok = await confirm({
      title: `Mask ${p.where} as ${rule}`,
      message: <>
        <p>Every masked account sees {WHAT[rule]}, on every branch it does not own.</p>
        <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }} data-testid="mask-cost">{p.cost}</pre>
      </>,
      confirmText: 'Set the rule',
    })
    if (!ok) return ''
    await setMaskRule(branch, at, rule)
    return `${p.where} is masked as ${rule}.`
  })

  const drop = (r: MaskRule) => run(async () => {
    const at: MaskPlace = { schema: r.schema, table: r.table, column: r.column, path: r.path }
    const ok = await confirm({ title: `Take the rule off ${where(at)}`, message: 'Masked accounts see its real values again.', confirmText: 'Take it off' })
    if (!ok) return ''
    await dropMaskRule(branch, at)
    return `${where(at)} is no longer masked.`
  })

  const account = (e: string, off: boolean) => run(async () => {
    const ok = await confirm({
      title: off ? `Unmask ${e}` : `Mask ${e}`,
      message: off
        ? 'They see real values again on every branch. Their open sessions end.'
        : 'They read the masks of marked tables, ordinary tables as they are, and cannot write to marked tables, on every branch, their own included, and so do their agent keys. Their open sessions end. An admin is never masked.',
      confirmText: off ? 'Unmask' : 'Mask',
    })
    if (!ok) return ''
    await maskAccount(e, off)
    if (!off) setEmail('')
    return off ? `${e} is unmasked.` : `${e} is masked.`
  })

  const createDomain = (d: string) => run(async () => {
    const ok = await confirm({
      title: `Make key domain ${d}`,
      message: <>
        <p>A key of its own: 32 random bytes beside the default key, never read back and never shown.</p>
        <p>Tables put under it hash apart from every other domain&rsquo;s, so their masks cannot be joined with them: for data
          that must never be matched up, such as two tenants&rsquo;. Joins work within one domain.</p>
      </>,
      confirmText: 'Make it',
    })
    if (!ok) return ''
    await maskKey('create', d, true)
    setDomain('')
    return `Key domain ${d} is made.`
  })

  const rotate = (d: string) => run(async () => {
    const p = await maskKey('rotate', d, false)
    const u = keys?.keys.find(k => k.domain === d)
    const keyed = (u?.tables ?? []).filter(t => t.keyed)
    const ok = await confirm({
      title: `Rotate ${d}'s key`,
      message: <>
        <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }} data-testid="rotate-cost">{p.cost}</pre>
        <p>Written again: {keyed.length ? keyed.map(t => `${t.branch}: ${t.schema}.${t.table}`).join(', ') : 'no table on a running branch'}.</p>
        {(keys?.stopped.length ?? 0) > 0 && <p>Not running, so not rotated: {keys!.stopped.join(', ')}. Set masking up on each again once it starts.</p>}
      </>,
      confirmText: 'Rotate the key',
    })
    if (!ok) return ''
    setBusy(true)
    try { await maskKey('rotate', d, true) } finally { setBusy(false) }
    return `${d}'s key is rotated, and the old one deleted.`
  })

  const dropDomain = (d: string) => run(async () => {
    const ok = await confirm({
      title: `Delete key domain ${d}`,
      message: 'Its key is deleted. Refused while a table on any branch uses it, or while a branch stopped since it was made, whose tables cannot be read.',
      confirmText: 'Delete it',
    })
    if (!ok) return ''
    await maskKey('drop', d, true)
    return `Key domain ${d} is deleted.`
  })

  const moveTable = (t: string, d: string) => run(async () => {
    const [schema, table] = t.split('.')
    const ok = await confirm({
      title: `Put ${t} under ${d}`,
      message: `Only ${t}'s hashed and faked masks on ${branch} are written again, under ${d}'s key; masked accounts read the old ones until it is done. Its masks then join only with tables in ${d}.`,
      confirmText: 'Move it',
    })
    if (!ok) return ''
    await maskKey('use', d, true, { branch, schema, table })
    return `${t} on ${branch} is under key domain ${d}.`
  })

  const unmask = (e: string, off: boolean) => run(async () => {
    const ok = await confirm({
      title: off ? `Take unmask on ${branch} from ${e}` : `Unmask ${e} on ${branch}`,
      message: off
        ? `They read masks on ${branch} again. Their open sessions there end.`
        : <>
          <p>They see real values on {branch}, as its owner does. Every read they make there of a marked table is audited: their
            role&rsquo;s audit role becomes <code>bb_audit_read</code>, which only a superuser can change. Listed in the access review.</p>
          {!st?.auditOn && <p data-testid="unmask-audit-off"><b>The audit log is off</b>, so their reads are not logged until it is turned on.</p>}
          <p>Their open sessions on {branch} end.</p>
        </>,
      confirmText: off ? 'Take it off' : 'Unmask',
    })
    if (!ok) return ''
    await unmaskAccount(e, branch, off)
    if (!off) setUnmaskFor('')
    return off ? `${e} reads masks on ${branch} again.` : `${e} sees real values on ${branch}, every read audited.`
  })

  const ruled = new Set((st?.rules ?? []).map(r => key(r)))
  const ruleTables = [...new Set((st?.rules ?? []).map(r => `${r.schema}.${r.table}`))]
  const domainOf = (t: string) => keys?.keys.find(k => k.tables.some(x => x.branch === branch && `${x.schema}.${x.table}` === t))?.domain ?? 'default'
  const ready = new Set(st?.ready ?? [])
  const open = confirmed.filter(f => !ruled.has(key({ schema: f.schema, table: f.table, column: f.column, path: f.path || undefined })))

  return (
    <div className="fade-up masking">
      <h1>Masking</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Who sees the real values of personal data. A masked account reads masks of the columns a reviewer confirmed, and
        everything else as it is. Admins, and a branch&rsquo;s owner, always see real values.
      </p>

      <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
        <label className="field">Branch
          <select aria-label="Branch" value={branch} onChange={e => { setBranch(e.target.value); load(e.target.value) }}>
            {(branches.length ? branches.map(b => b.name) : ['main']).map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <button className="ghost" onClick={() => load(branch)} disabled={busy}>{busy ? 'Reading…' : 'Refresh'}</button>
      </div>

      {err && <div className="err" style={{ marginTop: 12 }} data-testid="mask-err">{err}</div>}
      {msg && <p className="ok" style={{ marginTop: 12 }} data-testid="mask-msg">{msg}</p>}

      {st && (
        <>
          <div className="panel" style={{ marginTop: 14 }} data-testid="mask-state">
            <p style={{ margin: 0 }}>
              {st.on ? <><b>On.</b> {st.rules.length} rule(s) on {st.branch}; {st.accounts.length} account(s) masked.</> : <><b>Not set up</b> on this install.</>}
            </p>
            {st.pending.length > 0 && (
              <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
                Started before masking was set up, so masking nothing until they start again: {st.pending.join(', ')}.
              </p>
            )}
            {setting
              ? <button className="primary" style={{ marginTop: 10 }} onClick={setup} disabled={busy}>Set up on {branch}…</button>
              : <p className="muted" style={{ margin: '8px 0 0', fontSize: 13 }}>{why(edition, 'Setting masking up, its rules and masked accounts,')}</p>}
          </div>

          <h2 style={{ marginTop: 18 }}>Rules</h2>
          <div className="table-wrap">
            <table aria-label="Masking rules">
              <thead><tr><th>Where</th><th>Rule</th><th>Category</th><th>Masks</th><th>Set by</th><th /></tr></thead>
              <tbody>
                {st.rules.map(r => (
                  <tr key={key(r)} data-testid={`rule-${r.table}-${r.column}${r.path ? '-' + r.path : ''}`}>
                    <td><code>{where(r)}</code></td>
                    <td><span className="badge">{r.rule}</span></td>
                    <td>{r.category}</td>
                    <td>{ready.has(viewOf(r)) ? 'made' : <span style={{ color: WARN }}>not made: masked accounts are refused the table</span>}</td>
                    <td className="muted" style={{ fontSize: 13 }}>{r.by}, {new Date(r.at).toLocaleString()}</td>
                    <td>{setting && <button className="ghost" onClick={() => drop(r)}>Take off…</button>}</td>
                  </tr>
                ))}
                {st.rules.length === 0 && <tr><td colSpan={6} className="muted">No rules on {st.branch}.</td></tr>}
              </tbody>
            </table>
          </div>

          <h2 style={{ marginTop: 18 }}>Confirmed personal data without a rule</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
            A rule is set on what a reviewer confirmed, on the Personal data page. Aadhaar is masked by display only, never hashed or faked.
          </p>
          <div className="table-wrap">
            <table aria-label="Confirmed personal data without a rule">
              <thead><tr><th>Where</th><th>Category</th><th>Rule</th><th /></tr></thead>
              <tbody>
                {open.map(f => {
                  const at: MaskPlace = { schema: f.schema, table: f.table, column: f.column, path: f.path || undefined }
                  const r = choice[key(at)] ?? defaultRule(f.category)
                  return (
                    <tr key={f.id} data-testid={`open-${f.table}-${f.column}`}>
                      <td><code>{where(at)}</code></td>
                      <td>{f.category}</td>
                      <td>
                        <select aria-label={`Rule for ${where(at)}`} value={r} disabled={!setting}
                          onChange={e => setChoice({ ...choice, [key(at)]: e.target.value as MaskRuleName })}>
                          {allowed(f.category).map(x => <option key={x} value={x}>{x}</option>)}
                        </select>
                        <div className="muted" style={{ fontSize: 12 }}>{WHAT[r]}</div>
                      </td>
                      <td>{setting && st.on && <button className="ghost" onClick={() => mask(f)}>Mask…</button>}</td>
                    </tr>
                  )
                })}
                {open.length === 0 && <tr><td colSpan={4} className="muted">None.</td></tr>}
              </tbody>
            </table>
          </div>

          <h2 style={{ marginTop: 18 }}>Masked accounts</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
            Install-wide: masked on every branch, their own included. Nobody is masked until an admin masks them.
          </p>
          <div className="table-wrap">
            <table aria-label="Masked accounts">
              <thead><tr><th>Account</th><th>Masked by</th><th /></tr></thead>
              <tbody>
                {st.accounts.map(a => (
                  <tr key={a.email} data-testid={`account-${a.email}`}>
                    <td>{a.email}</td>
                    <td className="muted" style={{ fontSize: 13 }}>{a.by}, {new Date(a.at).toLocaleString()}</td>
                    <td>{setting && <button className="ghost" onClick={() => account(a.email, true)}>Unmask…</button>}</td>
                  </tr>
                ))}
                {st.accounts.length === 0 && <tr><td colSpan={3} className="muted">None.</td></tr>}
              </tbody>
            </table>
          </div>
          {setting && st.on && (
            <form className="row" style={{ gap: 10, marginTop: 10, alignItems: 'flex-end' }} aria-label="Mask an account"
              onSubmit={e => { e.preventDefault(); if (email.trim()) account(email.trim().toLowerCase(), false) }}>
              <label className="field">Account&rsquo;s email
                <input aria-label="Account to mask" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@example.com" />
              </label>
              <button className="primary" type="submit" disabled={!email.trim()}>Mask…</button>
            </form>
          )}

          {st.on && (
            <>
              <h2 style={{ marginTop: 18 }}>Unmask on {st.branch}</h2>
              <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
                A masked account given unmask on a branch sees real values there, and every read it makes of a marked table is audited.
                {!st.auditOn && <> The audit log is off, so those reads are not being logged.</>}
              </p>
              <div className="table-wrap">
                <table aria-label="Unmask rights">
                  <thead><tr><th>Account</th><th>Given by</th><th /></tr></thead>
                  <tbody>
                    {st.unmasks.map(g => (
                      <tr key={g.email} data-testid={`unmask-${g.email}`}>
                        <td>{g.email}</td>
                        <td className="muted" style={{ fontSize: 13 }}>{g.by}, {new Date(g.at).toLocaleString()}</td>
                        <td>{setting && <button className="ghost" onClick={() => unmask(g.email, true)}>Take off…</button>}</td>
                      </tr>
                    ))}
                    {st.unmasks.length === 0 && <tr><td colSpan={3} className="muted">Nobody: masked accounts read masks on {st.branch}.</td></tr>}
                  </tbody>
                </table>
              </div>
              {setting && st.accounts.length > 0 && (
                <form className="row" style={{ gap: 10, marginTop: 10, alignItems: 'flex-end' }} aria-label="Unmask an account"
                  onSubmit={e => { e.preventDefault(); if (unmaskFor) unmask(unmaskFor, false) }}>
                  <label className="field">Masked account
                    <select aria-label="Account to unmask" value={unmaskFor} onChange={e => setUnmaskFor(e.target.value)}>
                      <option value="">…</option>
                      {st.accounts.filter(a => !st.unmasks.some(g => g.email === a.email)).map(a => <option key={a.email} value={a.email}>{a.email}</option>)}
                    </select>
                  </label>
                  <button className="primary" type="submit" disabled={!unmaskFor}>Unmask…</button>
                </form>
              )}

              <h2 style={{ marginTop: 18 }}>Lookups on {st.branch}</h2>
              <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
                A masked account finds a person by an exact value without unmasking: <code>SELECT * FROM bb_mask.find(&#39;table&#39;, &#39;column&#39;, &#39;value&#39;)</code>,
                which returns the rows masked, 30 a minute. Each call is recorded here; the value never is.
              </p>
              <div className="table-wrap">
                <table aria-label="Lookups">
                  <thead><tr><th>When</th><th>Who</th><th>Column</th><th>Found</th></tr></thead>
                  <tbody>
                    {st.lookups.map((l, i) => (
                      <tr key={i} data-testid="lookup">
                        <td className="muted" style={{ fontSize: 13 }}>{new Date(l.at).toLocaleString()}</td>
                        <td>{l.who}</td>
                        <td><code>{l.table}.{l.column}</code></td>
                        <td>{l.found}</td>
                      </tr>
                    ))}
                    {st.lookups.length === 0 && <tr><td colSpan={4} className="muted">None.</td></tr>}
                  </tbody>
                </table>
              </div>

              {(st.closed ?? []).length > 0 && (
                <>
                  <h2 style={{ marginTop: 18 }}>Closed to masked accounts</h2>
                  <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
                    Masked accounts would read real values through these, so their rights on them were taken away. They
                    come back when the rule that closed them is taken off.
                  </p>
                  <div className="table-wrap">
                    <table aria-label="Closed to masked accounts">
                      <thead><tr><th>Object</th><th>Taken</th><th>Why</th></tr></thead>
                      <tbody>
                        {(st.closed ?? []).map(c => (
                          <tr key={c.relation} data-testid={`closed-${c.relation}`}>
                            <td><code>{c.relation}</code></td>
                            <td>{c.privs}</td>
                            <td className="muted" style={{ fontSize: 13 }}>
                              {c.kind === 'refs'
                                ? 'A foreign key into a masked column: a write would say whether a value is there.'
                                : 'A view reading a masked column, as its owner.'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}

              {(st.definers ?? []).length > 0 && (
                <>
                  <h2 style={{ marginTop: 18 }}>Definer functions that can leak</h2>
                  <p className="muted" style={{ marginTop: -4, fontSize: 13 }} data-testid="definers-note">
                    Masked accounts can run these, and each runs as a role that reads real values of a masked table. Take
                    EXECUTE from PUBLIC on each, or make it SECURITY INVOKER.
                  </p>
                  <div className="table-wrap">
                    <table aria-label="Definer functions that can leak">
                      <thead><tr><th>Function</th><th>Runs as</th><th>Names</th></tr></thead>
                      <tbody>
                        {(st.definers ?? []).map(d => (
                          <tr key={d.function} data-testid={`definer-${d.function}`}>
                            <td><code>{d.function}</code></td>
                            <td>{d.owner}</td>
                            <td>{d.tables.join(', ')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </>
          )}

          <h2 style={{ marginTop: 18 }}>Masked branches</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
            A masked branch&rsquo;s marked columns hold their masks, so nobody is masked on it: a copy for people and agents
            who should never see the real values. It is closed until it is masked and verified. Make one on the
            Dashboard (<i>masked</i>), or with <code>fox branch create &lt;name&gt; --masked</code>.
          </p>
          <div className="table-wrap">
            <table aria-label="Masked branches">
              <thead><tr><th>Branch</th><th>Of</th><th>State</th><th>Masked</th></tr></thead>
              <tbody>
                {mbs.map(m => (
                  <tr key={m.name} data-testid={`maskedbranch-${m.name}`}>
                    <td><b>{m.name}</b></td>
                    <td>{m.from}</td>
                    <td>
                      {m.state === 'open' ? (m.inherited ? 'open: a copy of a masked branch' : 'open: masked and verified')
                        : m.state === 'making' ? `being masked: ${m.step ?? ''}` : `closed, not masked: ${m.error ?? ''}`}
                      {(m.problems ?? []).length > 0 && (
                        <ul style={{ margin: '4px 0 0', fontSize: 13 }}>{(m.problems ?? []).map((p, i) => <li key={i}>{p}</li>)}</ul>
                      )}
                    </td>
                    <td className="muted" style={{ fontSize: 13 }}>{m.state === 'open' && !m.inherited ? `${m.tables} table(s), ${m.rows} row(s)` : '—'}</td>
                  </tr>
                ))}
                {mbs.length === 0 && <tr><td colSpan={4} className="muted">None.</td></tr>}
              </tbody>
            </table>
          </div>

          {keys && keys.keys.length > 0 && (
            <>
              <h2 style={{ marginTop: 18 }}>Keys</h2>
              <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>
                Hashes and fakes are made with a key domain&rsquo;s key, so the same value masks alike in every table of a
                domain, and tables in different domains never join. The keys themselves are never shown.
              </p>
              <div className="table-wrap">
                <table aria-label="Masking keys">
                  <thead><tr><th>Domain</th><th>Key</th><th>Tables on running branches</th><th /></tr></thead>
                  <tbody>
                    {keys.keys.map(k => (
                      <tr key={k.domain} data-testid={`key-${k.domain}`}>
                        <td><code>{k.domain}</code></td>
                        <td>
                          key {Math.max(k.gen, 1)}
                          <div className="muted" style={{ fontSize: 12 }}>
                            {k.made ? `made ${new Date(k.made).toLocaleString()}${k.by ? ' by ' + k.by : ''}` : 'made before key records were kept'}
                            {k.rotated && <>; rotated {new Date(k.rotated).toLocaleString()} by {k.rotatedBy}</>}
                          </div>
                          {k.next && <div style={{ fontSize: 12, color: WARN }}>A rotation was cut short: rotate again to finish it.</div>}
                        </td>
                        <td style={{ fontSize: 13 }}>
                          {k.tables.length ? k.tables.map(t => `${t.branch}: ${t.schema}.${t.table}`).join(', ') : <span className="muted">none</span>}
                          {k.stale.length > 0 && <div style={{ fontSize: 12, color: WARN }} data-testid={`stale-${k.domain}`}>
                            Made under an older key: {k.stale.map(t => `${t.branch}: ${t.schema}.${t.table}`).join(', ')}. Set masking up on that branch again.
                          </div>}
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          {setting && <button className="ghost" onClick={() => rotate(k.domain)} disabled={busy}>Rotate…</button>}
                          {setting && k.domain !== 'default' && <button className="ghost" onClick={() => dropDomain(k.domain)}>Delete…</button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {keys.stopped.length > 0 && <p className="muted" style={{ fontSize: 13 }}>Not running, so not read: {keys.stopped.join(', ')}.</p>}
              {setting && (
                <div className="row" style={{ gap: 16, marginTop: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                  <form className="row" style={{ gap: 10, alignItems: 'flex-end' }} aria-label="Make a key domain"
                    onSubmit={e => { e.preventDefault(); if (domain.trim()) createDomain(domain.trim()) }}>
                    <label className="field">New key domain
                      <input aria-label="New key domain" value={domain} onChange={e => setDomain(e.target.value)} placeholder="tenant_a" />
                    </label>
                    <button className="primary" type="submit" disabled={!domain.trim()}>Make…</button>
                  </form>
                  {ruleTables.length > 0 && keys.keys.length > 1 && (
                    <form className="row" style={{ gap: 10, alignItems: 'flex-end' }} aria-label="Put a table under a key domain"
                      onSubmit={e => { e.preventDefault(); if (move.table && move.domain) moveTable(move.table, move.domain) }}>
                      <label className="field">Table on {branch}
                        <select aria-label="Table to move" value={move.table} onChange={e => setMove({ ...move, table: e.target.value })}>
                          <option value="">…</option>
                          {ruleTables.map(t => <option key={t} value={t}>{t} ({domainOf(t)})</option>)}
                        </select>
                      </label>
                      <label className="field">Under
                        <select aria-label="Key domain for the table" value={move.domain} onChange={e => setMove({ ...move, domain: e.target.value })}>
                          <option value="">…</option>
                          {keys.keys.map(k => <option key={k.domain} value={k.domain}>{k.domain}</option>)}
                        </select>
                      </label>
                      <button className="primary" type="submit" disabled={!move.table || !move.domain}>Move…</button>
                    </form>
                  )}
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  )
}
