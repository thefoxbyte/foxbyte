// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import { auditEvidenceUrl, getAuditLog, getAuditMarks, getAuditRecords, getBranches, getUnauditedPersonal, markPersonalTables, purgeAuditText, sendAuditForward, setAuditForward, setAuditMode, setAuditRetention, stopAuditForward, unmarkAudited, type AuditAnchors, type AuditEntry, type AuditFor, type AuditLogReply, type AuditMarks, type Branch } from '../api'
import { useConfirm } from '../confirm'
import { BRAND } from '../brand'
import { useFeatures, why } from '../features'

// The databases' audit log (F6): pgAudit in default mode. It records who
// changed the schema and roles, and who wrote to the tables an admin marks,
// with no statement text and no values; errors reach the server log as their
// code alone. Turning it on or off restarts main, so it is the CLI's, which
// says what it will do first; this page shows where it stands and names the
// command. Admins only.

function bytes(n: number) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${i === 0 ? v : v.toFixed(1)} ${u[i]}`
}

function outcomeOf(e: AuditEntry) {
  if (e.kind === 'outcome') return e.sqlstate ?? ''
  if (e.txn_outcome && e.error) return `${e.txn_outcome.toLowerCase()} (${e.error})`
  if (e.txn_outcome) return e.txn_outcome.toLowerCase()
  return e.error ? `error ${e.error}` : '–'
}

function forOf(f?: AuditFor | null) {
  if (!f || !f.state || f.state === 'none') return '–'
  return f.state === 'asserted' ? `${f.actor}, asserted by ${f.issuer}` : `${f.actor} (${f.state})`
}

// The records, newest first, with how each statement's transaction ended and
// whom it was for. Reading them is recorded in the security log.
function Records({ branches }: { branches: Branch[] }) {
  const [q, setQ] = useState({ branch: '', table: '', user: '', since: '24h', errors: false })
  const [rows, setRows] = useState<AuditEntry[] | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const show = async () => {
    setBusy(true); setErr('')
    try {
      const r = await getAuditRecords({ ...q, since: q.since === 'all' ? '' : q.since, limit: 200 })
      setRows(r.records)
    } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <>
      <h2 style={{ marginTop: 22 }}>Records</h2>
      <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
        Who did what to which object, how it ended, and whom it was for. Never what a statement held. Reading them is
        recorded in the security log.
      </p>
      <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
        <label className="field">Branch
          <select aria-label="Records branch" value={q.branch} onChange={e => setQ({ ...q, branch: e.target.value })}>
            <option value="">every branch</option>
            {branches.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
          </select>
        </label>
        <label className="field">Table<input aria-label="Records table" value={q.table} onChange={e => setQ({ ...q, table: e.target.value })} placeholder="orders" /></label>
        <label className="field">Login<input aria-label="Records login" value={q.user} onChange={e => setQ({ ...q, user: e.target.value })} placeholder="alice@example.com" /></label>
        <label className="field">Since
          <select aria-label="Records since" value={q.since} onChange={e => setQ({ ...q, since: e.target.value })}>
            <option value="1h">the last hour</option>
            <option value="24h">the last day</option>
            <option value="168h">the last week</option>
            <option value="all">ever</option>
          </select>
        </label>
        <label className="check-row"><input type="checkbox" checked={q.errors} onChange={e => setQ({ ...q, errors: e.target.checked })} /> Errors only</label>
        <button className="primary" onClick={show} disabled={busy}>{busy ? 'Reading…' : 'Show'}</button>
      </div>
      {err && <div className="err" style={{ marginTop: 8 }}>{err}</div>}
      {rows && rows.length === 0 && <p className="muted" data-testid="no-records">No record matches.</p>}
      {rows && rows.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 8 }}>
          <table aria-label="Audit records">
            <thead><tr><th>Time</th><th>Branch</th><th>Login</th><th>What</th><th>Object</th><th>Outcome</th><th>For</th></tr></thead>
            <tbody>
              {rows.map(e => (
                <tr key={e.seq}>
                  <td style={{ whiteSpace: 'nowrap' }}>{new Date(e.time).toLocaleString()}</td>
                  <td>{e.branch}</td>
                  <td>{e.login || '–'}</td>
                  <td>{e.kind === 'outcome' ? e.outcome : e.command}{e.class && <span className="muted"> · {e.class}</span>}</td>
                  <td>{e.object ? <code>{e.object}</code> : '–'}</td>
                  <td>{outcomeOf(e)}</td>
                  <td>{forOf(e.txn_for)}</td>
                </tr>
              )).flatMap((row, i) => {
                const e = rows[i]
                if (!e.text && !e.text_gone) return [row]
                return [row, (
                  <tr key={`${e.seq}-text`} className="audit-text">
                    <td colSpan={7}>
                      {e.text
                        ? <><span className="muted">Statement (forensic mode): </span><code data-testid={`text-${e.seq}`}>{e.text}</code></>
                        : <span className="muted" data-testid={`text-${e.seq}`}>Statement text removed: past its retention, or purged.</span>}
                    </td>
                  </tr>
                )]
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

// What the audit log keeps: forensic mode (statement text, values and all,
// with a reason), how long records and text are kept, and a person's text
// purged. Admins only; each change is in the security log.
function Settings({ data, branches, onChange }: { data: AuditLogReply; branches: Branch[]; onChange: () => void }) {
  const confirm = useConfirm()
  const [where, setWhere] = useState('')
  const [reason, setReason] = useState('')
  const [days, setDays] = useState(String(data.retention?.days ?? 365))
  const [textDays, setTextDays] = useState(String(data.retention?.forensic_days ?? 30))
  const [purgeUser, setPurgeUser] = useState('')
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const grants = Object.entries(data.forensic ?? {})
  const act = async (f: () => Promise<string>) => {
    setErr(''); setNote('')
    try { setNote(await f()); onChange() } catch (e) { setErr((e as Error).message) }
  }
  const forensicOn = async () => {
    const ok = await confirm({
      title: 'Turn on forensic mode',
      message: <>Keep each audited statement's text on <b>{where || 'every branch'}</b>, literals and all, which can include personal
        data, for {data.retention?.forensic_days ?? 30} days? It is kept beside the records, read by admins only, and every read is
        recorded. Your reason is recorded with your name.</>,
      confirmText: 'Turn on',
      danger: true,
    })
    if (ok) act(async () => { await setAuditMode(true, where, reason); setReason(''); return `Forensic mode is on for ${where || 'every branch'}.` })
  }
  const purge = async () => {
    const ok = await confirm({
      title: 'Purge statement text',
      message: <>Remove every statement text forensic mode kept from <b>{purgeUser}</b>'s statements? Their records stay.</>,
      confirmText: 'Purge',
      danger: true,
    })
    if (ok) act(async () => { const r = await purgeAuditText(purgeUser); setPurgeUser(''); return `Removed ${r.purged} statement text(s).` })
  }
  return (
    <>
      <h2 style={{ marginTop: 22 }}>What it keeps</h2>
      {err && <div className="err" style={{ marginTop: 8 }}>{err}</div>}
      {note && <div className="ok" role="status" style={{ marginTop: 8 }}>{note}</div>}
      <div className="panel" data-testid="audit-mode">
        {grants.length === 0
          ? <p style={{ marginTop: 0 }}><span className="badge">default mode</span> No statement text, no values, on every branch.</p>
          : grants.map(([b, g]) => (
              <p key={b} style={{ marginTop: 0 }}>
                <span className="badge primary">forensic</span> on <b>{b || 'every branch'}</b> since {new Date(g.since).toLocaleString()}, by {g.by}: &ldquo;{g.reason}&rdquo;{' '}
                <button className="ghost sm" onClick={() => act(async () => { await setAuditMode(false, b, ''); return `Default mode for ${b || 'every branch'}.` })}>Back to default</button>
              </p>
            ))}
        <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
          <label className="field">Forensic mode on
            <select aria-label="Forensic branch" value={where} onChange={e => setWhere(e.target.value)}>
              <option value="">every branch</option>
              {branches.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
            </select>
          </label>
          <label className="field" style={{ flex: 1, minWidth: 220 }}>Why
            <input aria-label="Forensic reason" value={reason} onChange={e => setReason(e.target.value)} placeholder="Incident 2026-11-04: who changed the orders?" />
          </label>
          <button className="ghost danger" disabled={!reason.trim()} onClick={forensicOn}>Turn on forensic mode</button>
        </div>
      </div>
      <div className="panel" style={{ marginTop: 10 }}>
        <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
          <label className="field">Records kept (days)
            <input aria-label="Records kept days" type="number" min={1} max={3650} value={days} onChange={e => setDays(e.target.value)} style={{ width: 110 }} />
          </label>
          <button className="ghost" onClick={() => act(async () => { const r = await setAuditRetention(Number(days), false); return `Records are kept ${r.days} days.` })}>Save</button>
          <label className="field">Statement text kept (days)
            <input aria-label="Text kept days" type="number" min={1} max={3650} value={textDays} onChange={e => setTextDays(e.target.value)} style={{ width: 110 }} />
          </label>
          <button className="ghost" onClick={() => act(async () => { const r = await setAuditRetention(Number(textDays), true); return `Statement text is kept ${r.forensic_days} days.` })}>Save</button>
        </div>
        <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end', marginTop: 10 }}>
          <label className="field">Purge a person's statement text
            <input aria-label="Purge login" value={purgeUser} onChange={e => setPurgeUser(e.target.value)} placeholder="alice@example.com" />
          </label>
          <button className="ghost danger" disabled={!purgeUser.trim()} onClick={purge}>Purge</button>
        </div>
      </div>
    </>
  )
}

// Forwarding to a SIEM: a copy of every record, over TLS, as it is collected.
// The token and CA bundle are sent once and never shown again. Admins only;
// each change is in the security log.
function Forwarding({ data, onChange }: { data: AuditLogReply; onChange: () => void }) {
  const confirm = useConfirm()
  const f = data.forward ?? null
  const [url, setUrl] = useState('')
  const [token, setToken] = useState('')
  const [ca, setCa] = useState('')
  const [text, setText] = useState(false)
  const [fromStart, setFromStart] = useState(false)
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const act = async (fn: () => Promise<string>) => {
    setErr(''); setNote('')
    try { setNote(await fn()); onChange() } catch (e) { setErr((e as Error).message) }
  }
  const save = async () => {
    const ok = await confirm({
      title: 'Forward the audit log',
      message: <>Send a copy of every audit record to <b>{url}</b>, {fromStart ? 'starting with every record the store still holds' : 'from the next record collected'}?
        Each says who did what to which object, how it ended and whom for, with its place in the chain. No values.{' '}
        {text
          ? <b>Statement text is sent too, values and all: once there, retention and purge here no longer reach it.</b>
          : 'Statement text is not sent.'}</>,
      confirmText: 'Forward',
      danger: text,
    })
    if (ok) act(async () => {
      await setAuditForward({ url, token: token || undefined, ca_pem: ca || undefined, text, from_start: fromStart })
      setToken(''); setCa('')
      return `Forwarding to ${url}.`
    })
  }
  const stop = async () => {
    const ok = await confirm({
      title: 'Stop forwarding',
      message: <>Stop sending records to <b>{f?.host}</b>, and remove the token and CA bundle kept for it? The records stay in the store.</>,
      confirmText: 'Stop forwarding',
    })
    if (ok) act(async () => { await stopAuditForward(); return 'Forwarding stopped.' })
  }
  const send = () => act(async () => {
    const r = await sendAuditForward()
    if (r.error) throw new Error(`Forwarding failed after ${r.sent} record(s): ${r.error}. The rest wait in the store.`)
    return `${r.sent} record(s) sent; ${r.waiting} waiting.`
  })
  return (
    <>
      <h2 style={{ marginTop: 22 }}>Forwarding to a SIEM</h2>
      <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
        A copy of every record, over TLS: <code>https://…</code> as JSON lines, or <code>syslog://host:6514</code> as RFC 5424.
        Each record carries its place in the chain, so the copy there shows a record changed or removed here later.
      </p>
      {err && <div className="err" style={{ marginTop: 8 }}>{err}</div>}
      {note && <div className="ok" role="status" style={{ marginTop: 8 }}>{note}</div>}
      <div className="panel" data-testid="audit-forward">
        {f
          ? <>
              <p style={{ marginTop: 0 }}>
                <span className="badge primary">forwarding</span> to <code>{f.url}</code>, since {new Date(f.since).toLocaleString()}, by {f.by}.{' '}
                {f.text ? <b>Statement text included.</b> : 'No statement text.'} TLS checked against {f.ca ? 'its own CA bundle' : "the system's CAs"}.
              </p>
              <p data-testid="forward-position">
                Delivered up to record {f.position} of {f.head} ({f.waiting} waiting), {f.sent} sent in all
                {f.last_ok && <span className="muted">; last delivered {new Date(f.last_ok).toLocaleString()}</span>}.
              </p>
              {f.last_err && <div className="err" data-testid="forward-error">Failing since {f.err_since ? new Date(f.err_since).toLocaleString() : 'now'}: {f.last_err}. The records wait in the store.</div>}
              {(f.skipped ?? 0) > 0 && <p className="muted">{f.skipped} record(s) were removed by retention before they could be sent.</p>}
              <div className="row" style={{ gap: 10 }}>
                <button className="ghost" onClick={send}>Send now</button>
                <button className="ghost danger" onClick={stop}>Stop forwarding</button>
              </div>
            </>
          : <p style={{ marginTop: 0 }} className="muted">Not forwarded.</p>}
        <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end', marginTop: 10 }}>
          <label className="field" style={{ flex: 1, minWidth: 260 }}>{f ? 'Forward somewhere else' : 'Forward to'}
            <input aria-label="Forward URL" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://siem.example.com/ingest" />
          </label>
          <label className="field">Token (https only)
            <input aria-label="Forward token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} />
          </label>
        </div>
        <label className="field" style={{ marginTop: 10 }}>CA bundle (PEM), if the server's certificate is not one the system trusts
          <textarea aria-label="Forward CA" rows={3} value={ca} onChange={e => setCa(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        </label>
        <div className="row" style={{ flexWrap: 'wrap', gap: 14, alignItems: 'center', marginTop: 10 }}>
          <label className="check-row"><input type="checkbox" checked={fromStart} onChange={e => setFromStart(e.target.checked)} /> Every record still kept, not just new ones</label>
          <label className="check-row"><input type="checkbox" checked={text} onChange={e => setText(e.target.checked)} /> Statement text too (forensic mode)</label>
          <button className="primary" disabled={!url.trim()} onClick={save}>Forward</button>
        </div>
      </div>
    </>
  )
}

// anchorText is where anchoring the chain has got (step 6).
function anchorText(a?: AuditAnchors) {
  if (!a) return '–'
  if (a.anchors === 0) {
    return a.writes
      ? 'none yet: the first comes within 10 minutes of the first record'
      : 'none: anchoring the chain outside the store is part of Enterprise'
  }
  let s = `${a.anchors}, up to record ${a.anchored} (${a.unanchored} since)`
  if (a.locked > 0) s += `; ${a.locked} locked in the anchor target`
  if (!a.writes) s += '; no more are written in this edition'
  return s
}

// PersonalTables names the tables holding confirmed personal data whose writes
// are not audited, and marks them all where the licence covers it (step 6).
function PersonalTables({ branch, onMarked }: { branch: string; onMarked: (m: AuditMarks) => void }) {
  const { can } = useFeatures()
  const [tables, setTables] = useState<string[] | null>(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    setTables(null); setMsg('')
    getUnauditedPersonal(branch).then(r => setTables(r.tables), () => setTables(null))
  }, [branch])
  if (!tables || (tables.length === 0 && !msg)) return null
  const mark = async () => {
    setBusy(true); setMsg('')
    try {
      const m = await markPersonalTables(branch)
      onMarked(m)
      setTables(m.personal_unmarked ?? [])
      setMsg(`Marked: ${(m.marked ?? []).join(', ') || 'nothing new'}.`)
    } catch (e) { setMsg((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <div className="panel" style={{ marginTop: 10 }} data-testid="personal-unmarked">
      {tables.length > 0 && <>
        <p style={{ marginTop: 0 }}>
          <b>Confirmed personal data, writes not audited:</b> {tables.map(t => <code key={t} style={{ marginRight: 6 }}>{t}</code>)}
        </p>
        {can('personal-data')
          ? <button className="primary" onClick={mark} disabled={busy}>{busy ? 'Marking…' : 'Audit tables with personal data'}</button>
          : <p className="muted" style={{ margin: 0, fontSize: 13 }}>Marking them on their own is part of Enterprise; mark each with <b>Audit…</b>.</p>}
      </>}
      {msg && <p className="muted" style={{ marginBottom: 0, fontSize: 13 }}>{msg}</p>}
    </div>
  )
}

// Evidence: the document an auditor is handed for a period (step 6b): what was
// audited and what was not, integrity and anchors, delivery, and who changed
// any of it. A file to save; the engine records each one produced.
function Evidence() {
  const { can, edition } = useFeatures()
  const [since, setSince] = useState('90d')
  const [records, setRecords] = useState(false)
  const licensed = can('export')
  return (
    <>
      <h2 style={{ marginTop: 22 }}>Evidence</h2>
      <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
        One document for an auditor: what the log covered and what it did not, the chain and its anchors checked, delivery
        to the SIEM, what was found wrong, and every change to the audit log in the period. With the records, the chain can
        be checked without {BRAND.product}. Never a statement&rsquo;s text.
      </p>
      <div className="row" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }} data-testid="audit-evidence">
        <label className="field">Period
          <select aria-label="Evidence period" value={since} onChange={e => setSince(e.target.value)}>
            <option value="30d">the last 30 days</option>
            <option value="90d">the last 90 days</option>
            <option value="365d">the last year</option>
          </select>
        </label>
        <label className="check-row"><input type="checkbox" checked={records} onChange={e => setRecords(e.target.checked)} /> With the records</label>
        {licensed
          ? <a className="btn primary" href={auditEvidenceUrl(since, '', records)} download>Download evidence</a>
          : <span className="muted" style={{ fontSize: 13 }}>{why(edition, 'The evidence export')}</span>}
      </div>
    </>
  )
}

export default function AuditLog() {
  const confirm = useConfirm()
  const [data, setData] = useState<AuditLogReply | null>(null)
  const [err, setErr] = useState('')
  const [branches, setBranches] = useState<Branch[]>([])
  const [branch, setBranch] = useState('main')
  const [marks, setMarks] = useState<AuditMarks | null>(null)
  const [markErr, setMarkErr] = useState('')

  useEffect(() => {
    getAuditLog().then(setData, e => setErr((e as Error).message))
    getBranches().then(setBranches, () => setBranches([]))
  }, [])
  // Only the latest load is shown: main's, asked for when the page opened,
  // must not land after the branch the person picked since.
  const latestMarks = useRef(0)
  const loadMarks = useCallback((b: string) => {
    const mine = ++latestMarks.current
    setMarks(null); setMarkErr('')
    getAuditMarks(b).then(
      m => { if (mine === latestMarks.current) setMarks(m) },
      e => { if (mine === latestMarks.current) setMarkErr((e as Error).message) })
  }, [])
  useEffect(() => { loadMarks(branch) }, [branch, loadMarks])

  const stop = async (schema: string, name: string) => {
    const ok = await confirm({
      title: 'Stop auditing',
      message: <>Stop recording who writes to <b>{schema}.{name}</b> on {branch}? What the log already holds stays.</>,
      confirmText: 'Stop auditing',
    })
    if (!ok) return
    try { setMarks(await unmarkAudited(branch, schema, name)) } catch (e) { setMarkErr((e as Error).message) }
  }

  const pending = data?.pending ?? []
  const pct = data && data.quota > 0 ? Math.floor(data.used * 100 / data.quota) : null

  return (
    <div className="fade-up audit-log">
      <h1>Audit log</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        pgAudit's record of who changed the schema and roles, and who wrote to the tables you mark. It keeps no statement
        text and no values: errors reach the server log as their code alone. It is evidence of those operations, not a
        record of every query.
      </p>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {data && !data.on && (
        <div className="panel" style={{ marginTop: 8 }} data-testid="audit-off">
          <p style={{ marginTop: 0 }}><span className="badge">off</span> No database runs pgAudit.</p>
          <p className="muted" style={{ fontSize: 13 }}>
            It costs capacity, more on busy tables: with every statement audited, writes and reads slowed by a fifth to a
            half on a busy server. Turning it on restarts main; connections drop for a few seconds. Run:
          </p>
          <pre><code data-testid="audit-setup">{data.setup}</code></pre>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>It says what it will do, and asks for <code>--yes</code>.</p>
        </div>
      )}

      {data?.on && (
        <div className="panel" style={{ marginTop: 8 }} data-testid="audit-on">
          <p style={{ marginTop: 0 }}>
            <span className="badge primary">on</span> Default mode: schema and role changes by everyone, and writes to
            marked tables. No statement text, no values.
          </p>
          <div className="table-wrap">
            <table aria-label="Audit log">
              <tbody>
                <tr><th>Log</th><td><code>{data.root}/&lt;branch&gt;</code>, a week of hourly files</td></tr>
                <tr>
                  <th>Space</th>
                  <td data-testid="audit-space">
                    {data.quota > 0 ? `${bytes(data.used)} of ${bytes(data.quota)} (${pct}%)` : `${bytes(data.used)}, no quota on this storage`}
                    {pct !== null && pct >= 80 && <span className="badge" style={{ marginLeft: 8 }}>a full log loses audit lines without a word</span>}
                  </td>
                </tr>
                <tr><th>Anchors</th><td data-testid="audit-anchors">{anchorText(data.anchors)}</td></tr>
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ fontSize: 13, marginBottom: 0 }}>
            To turn it off: <code>{data.off}</code>.
          </p>
        </div>
      )}

      {data && <Records branches={branches} />}
      {data && <Settings data={data} branches={branches} onChange={() => getAuditLog().then(setData, () => {})} />}
      {data && <Forwarding data={data} onChange={() => getAuditLog().then(setData, () => {})} />}
      {data && <Evidence />}

      <h2 style={{ marginTop: 22 }}>Marked tables</h2>
      <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
        Writes to these tables, and reads where marked, are lines in the log, by every login. Mark a table from its view in
        the console (<b>Audit…</b>), or with <code>fox audit-log table &lt;table&gt; [--reads]</code>. A branch made from this
        one has the same marks.
      </p>
      <label className="field" style={{ display: 'inline-block' }}>Branch{' '}
        <select aria-label="Branch" value={branch} onChange={e => setBranch(e.target.value)}>
          {(branches.length ? branches.map(b => b.name) : ['main']).map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
      {markErr && <div className="err" style={{ marginTop: 8 }}>{markErr}</div>}
      {marks && marks.tables.length === 0 && <p className="muted" data-testid="no-marks">No table on {branch} is marked.</p>}
      {marks && marks.tables.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 8 }}>
          <table aria-label={`Marked tables on ${branch}`}>
            <thead><tr><th>Table</th><th>Audited</th><th></th></tr></thead>
            <tbody>
              {marks.tables.map(m => (
                <tr key={`${m.schema}.${m.name}`}>
                  <td><code>{m.schema}.{m.name}</code></td>
                  <td>{m.writes && m.reads ? 'writes and reads' : m.reads ? 'reads' : 'writes'}</td>
                  <td style={{ textAlign: 'right' }}><button className="ghost" onClick={() => stop(m.schema, m.name)}>Stop auditing</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(marks?.definers ?? []).length > 0 && (
        <div className="panel" style={{ marginTop: 10 }} data-testid="audit-definers">
          <p style={{ marginTop: 0 }}>
            <b>Not audited:</b> these SECURITY DEFINER functions name marked tables, and pgAudit does not see the statements
            inside a definer function. Made SECURITY INVOKER, they are audited.
          </p>
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            {marks!.definers!.map(f => <li key={f.function}><code>{f.function}</code>, as {f.owner}: {f.tables.join(', ')}</li>)}
          </ul>
        </div>
      )}
      <PersonalTables branch={branch} onMarked={setMarks} />

      {data?.on && (
        <div className="panel" style={{ marginTop: 10 }} data-testid="audit-findings">
          {(data.findings ?? []).length === 0
            ? <p style={{ margin: 0 }} className="muted">Nothing found wrong: lines are arriving, none are missing, every mark is in place.</p>
            : <>
                <p style={{ marginTop: 0 }}><b>Found</b></p>
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  {(data.findings ?? []).map((f, i) => (
                    <li key={i}>
                      <span className="badge">{f.kind}</span>{' '}
                      {f.branch && <b>{f.branch}: </b>}{f.detail}
                      {f.since && <span className="muted"> (since {new Date(f.since).toLocaleString()})</span>}
                    </li>
                  ))}
                </ul>
              </>}
        </div>
      )}

      {pending.length > 0 && (
        <p className="muted" style={{ fontSize: 13 }} data-testid="audit-pending">
          Still running as before the last change, until each is next started: {pending.join(', ')}. A suspended branch
          picks it up when it wakes.
        </p>
      )}
    </div>
  )
}
