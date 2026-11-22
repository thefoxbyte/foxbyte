// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  declareVault, getVaultDeclarations, getVaultEvidence, getVaultKinds, vaultEvidenceUrl,
  type VaultDeclaration, type VaultDeclItem, type VaultEvidence, type VaultKind, type VaultRule,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'

// The vault's evidence (point 13, step 13.4b): rule by rule, for a kind with
// rules mapped (UIDAI's for Aadhaar), what FoxByte checked on this machine,
// what it does by how it is built, and what the customer declared, which
// FoxByte cannot check. Declarations are made here, each kept with who and
// when. The whole document downloads as JSON for an auditor. Admins;
// Enterprise.

const WARN = 'color-mix(in srgb, var(--red) 78%, var(--text))'
const GOOD = 'color-mix(in srgb, var(--green, #2f9e44) 80%, var(--text))'

const verdictColour: Record<string, string | undefined> = { 'met': GOOD, 'not met': WARN, 'open': undefined, 'not applicable': undefined }

export default function VaultEvidencePage() {
  const { can, edition } = useFeatures()
  const [kinds, setKinds] = useState<VaultKind[]>([])
  const [kind, setKind] = useState('aadhaar')
  const [since, setSince] = useState('90d')
  const [ev, setEv] = useState<VaultEvidence | null>(null)
  const [items, setItems] = useState<VaultDeclItem[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [editing, setEditing] = useState('')

  const load = useCallback(async (k: string, s: string) => {
    setBusy(true); setErr('')
    try {
      const [e, d] = await Promise.all([getVaultEvidence(k, s), getVaultDeclarations(k)])
      setEv(e); setItems(d.items ?? [])
    } catch (e) { setErr((e as Error).message); setEv(null) }
    finally { setBusy(false) }
  }, [])
  const known = edition !== null
  const allowed = known && can('vault')
  useEffect(() => {
    if (!allowed) return
    getVaultKinds().then(setKinds).catch(() => setKinds([]))
  }, [allowed])
  useEffect(() => { if (allowed) load(kind, since) }, [allowed, kind, since, load])

  if (!known) return <div className="fade-up"><h1>Vault evidence</h1></div>
  if (!allowed) {
    return (
      <div className="fade-up">
        <h1>Vault evidence</h1>
        <p className="muted" data-testid="vault-evidence-locked">{why(edition, 'The vault')}</p>
      </div>
    )
  }

  const k = ev?.kinds.find(x => x.kind === kind)
  const save = async (item: string, value: string) => {
    setErr(''); setMsg('')
    try {
      await declareVault(kind, item, value)
      setMsg(value ? `Declared ${item}. The evidence shows it as declared, not checked.` : `Withdrawn: ${item} is open again.`)
      setEditing('')
      load(kind, since)
      return true
    } catch (e) { setErr((e as Error).message); return false }
  }

  return (
    <div className="fade-up vault-evidence">
      <p className="muted" style={{ margin: 0, fontSize: 13 }}><Link to="/vault">← Vault</Link></p>
      <h1>Vault evidence</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Rule by rule: what FoxByte checked on this machine just now, what it does by how it is built, and what you declared, which it cannot check.
        Nothing here runs a scan; the branches are read from their latest Aadhaar exposure reports.
      </p>
      <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label className="field">Kind
          <select aria-label="Evidence kind" value={kind} onChange={e => { setKind(e.target.value); setEditing('') }}>
            {(kinds.length ? kinds.map(x => x.name) : ['aadhaar']).map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label className="field">Activity since
          <select aria-label="Activity since" value={since} onChange={e => setSince(e.target.value)}>
            <option value="30d">30 days</option>
            <option value="90d">90 days</option>
            <option value="365d">a year</option>
          </select>
        </label>
        <button className="ghost" onClick={() => load(kind, since)} disabled={busy}>{busy ? 'Reading…' : 'Read it again'}</button>
        <a className="btn primary" href={vaultEvidenceUrl(kind, since)} download={`vault-evidence-${kind}.json`}>Download (JSON)</a>
        <a className="btn ghost" href={vaultEvidenceUrl(kind, since, true)} download={`vault-evidence-${kind}-with-log.json`}>With the access log</a>
      </div>
      {err && <div className="err" style={{ marginTop: 12 }} data-testid="evidence-err">{err}</div>}
      {msg && <p className="ok" style={{ marginTop: 12 }} data-testid="evidence-msg">{msg}</p>}

      {ev && (
        <div className="panel" style={{ marginTop: 14 }} data-testid="evidence-head">
          <p style={{ margin: 0 }}>
            Token <code>{ev.token.label}</code>: {ev.token.maker} {ev.token.model}, serial {ev.token.serial}
            {ev.token.software && <span className="badge" style={{ marginLeft: 8, color: WARN }}>Software token: not UIDAI-compliant (trials and testing only)</span>}
          </p>
          <p style={{ margin: '8px 0 0' }}>
            Access log: {ev.log.entries} entries; {ev.log.broken_at === 0 ? 'the chain holds' : <b style={{ color: WARN }}>the chain breaks at entry {ev.log.broken_at}</b>};
            {' '}{ev.log.anchor.holds ? <>against the security log: {ev.log.anchor.note}.</> : <b style={{ color: WARN }}>against the security log: {ev.log.anchor.note}.</b>}
          </p>
          <p className="muted" style={{ margin: '8px 0 0', fontSize: 13 }}>Made {new Date(ev.generated).toLocaleString()} for {ev.by}; {ev.product} {ev.version}, {ev.edition}.</p>
        </div>
      )}

      {k && k.rows.length === 0 && (
        <p className="muted" style={{ marginTop: 14 }} data-testid="evidence-no-rules">No rules are mapped for {k.kind}, so there is nothing to judge. Its keys and activity are in the download.</p>
      )}

      {k && k.rows.length > 0 && (
        <>
          <p style={{ marginTop: 16 }} data-testid="evidence-summary">
            <b>{k.rules}</b>: {k.summary['met'] ?? 0} met, {k.summary['not met'] ?? 0} not met, {k.summary['open'] ?? 0} open (waiting for your declaration),
            {' '}{k.summary['not applicable'] ?? 0} not applicable.
          </p>
          <div className="table-wrap">
            <table aria-label="Rules">
              <thead><tr><th>Para</th><th>Requirement</th><th>Whose</th><th>Verdict</th><th>What stands behind it</th></tr></thead>
              <tbody>
                {k.rows.map((r, i) => (
                  <Row key={`${r.para}-${i}`} r={r} items={items} editing={editing} setEditing={setEditing} onSave={save} />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {k?.branches && k.branches.length > 0 && (
        <>
          <h2 style={{ marginTop: 18 }}>Branches</h2>
          <p className="muted" style={{ marginTop: -4, fontSize: 13 }}>By their latest Aadhaar exposure report. A report older than 30 days, or none, is flagged: it cannot show a branch is clean.</p>
          <div className="table-wrap">
            <table aria-label="Branches by their latest exposure report">
              <thead><tr><th>Branch</th><th>Scanned</th><th className="num">Numbers in tables</th><th className="num">In logs</th><th>Shows</th></tr></thead>
              <tbody>
                {k.branches.map(b => (
                  <tr key={b.branch} data-testid={`evidence-branch-${b.branch}`}>
                    <td><b>{b.branch}</b></td>
                    <td style={{ fontSize: 13 }}>{b.ran ? new Date(b.ran).toLocaleDateString() : 'never'}</td>
                    <td className="num">{b.numbers}</td>
                    <td className="num">{b.log_numbers}</td>
                    <td style={{ fontSize: 13, color: b.flag ? WARN : undefined }}>{b.flag || 'clean'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {k && (
        <>
          <h2 style={{ marginTop: 18 }}>Keys and activity</h2>
          <p style={{ margin: 0, fontSize: 13 }} data-testid="evidence-activity">
            {k.records} record(s). Since {ev ? new Date(ev.since).toLocaleDateString() : ''}:{' '}
            {Object.entries(k.activity.calls).map(([a, n]) => `${a} ${n}`).join(', ') || 'no calls'}; {k.activity.refused} refusal(s).
            {' '}{k.activity.changed_since_data_key} value(s) deleted or replaced since the current data key was made, readable from the vault database&rsquo;s history until it is rotated.
          </p>
          <div className="table-wrap" style={{ marginTop: 8 }}>
            <table aria-label="Evidence keys">
              <thead><tr><th>Key</th><th>Role</th><th>Made</th><th>Destroyed</th><th className="num">Records</th></tr></thead>
              <tbody>
                {k.keys.map(key => (
                  <tr key={key.label}>
                    <td><code>{key.label}</code>{key.current ? ' (current)' : ''}</td>
                    <td>{key.role}</td>
                    <td style={{ fontSize: 13 }}>{key.created ? new Date(key.created).toLocaleDateString() : ''}</td>
                    <td style={{ fontSize: 13 }}>{key.destroyed_at ? new Date(key.destroyed_at).toLocaleDateString() : ''}</td>
                    <td className="num">{key.records}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {ev && (
        <>
          <h2 style={{ marginTop: 18 }}>What this cannot show</h2>
          <ul style={{ fontSize: 13 }} data-testid="evidence-limits">{ev.limits.map(l => <li key={l}>{l}</li>)}</ul>
        </>
      )}
    </div>
  )
}

function Row({ r, items, editing, setEditing, onSave }: {
  r: VaultRule; items: VaultDeclItem[]; editing: string; setEditing: (s: string) => void; onSave: (item: string, value: string) => Promise<boolean>
}) {
  const declared = new Map<string, VaultDeclaration>((r.declared ?? []).map(d => [d.item, d]))
  return (
    <tr data-testid={`rule-${r.para}`}>
      <td><b>{r.para}</b></td>
      <td style={{ fontSize: 13 }}>{r.requirement}{r.note && <div className="muted">{r.note}</div>}</td>
      <td style={{ fontSize: 13 }}>{r.whose}</td>
      <td><b style={{ color: verdictColour[r.verdict] }}>{r.verdict}</b></td>
      <td style={{ fontSize: 13 }}>
        <ul style={{ margin: 0, paddingLeft: 16 }}>
          {r.checks.map((c, i) => (
            <li key={i} style={{ color: c.ok ? undefined : WARN }}>
              {c.ok ? '✓' : '✗'} {c.what} <span className="muted">({c.basis}: {c.detail})</span>
            </li>
          ))}
          {(r.items ?? []).map(it => {
            const d = declared.get(it)
            return (
              <li key={it}>
                {d
                  ? <>Declared <b>{it}</b> by {d.declared_by} on {new Date(d.declared_at).toLocaleDateString()}: &ldquo;{d.value}&rdquo;{' '}</>
                  : <><b>{it}</b>: not declared{' '}</>}
                {editing !== it && <button className="ghost" style={{ fontSize: 12, padding: '1px 8px' }} onClick={() => setEditing(it)}>{d ? 'Change…' : 'Declare…'}</button>}
                {editing === it && <Declare item={it} asks={items.find(x => x.item === it)?.asks ?? ''} current={d?.value ?? ''} onSave={onSave} onCancel={() => setEditing('')} />}
              </li>
            )
          })}
        </ul>
      </td>
    </tr>
  )
}

function Declare({ item, asks, current, onSave, onCancel }: {
  item: string; asks: string; current: string; onSave: (item: string, value: string) => Promise<boolean>; onCancel: () => void
}) {
  const [value, setValue] = useState(current)
  const [busy, setBusy] = useState(false)
  const confirm = useConfirm()
  const withdraw = async () => {
    const yes = await confirm({ title: `Withdraw ${item}?`, message: 'The statement stays in the record; the evidence shows the rule open again until someone declares it.', confirmText: 'Withdraw', danger: true })
    if (!yes) return
    setBusy(true); await onSave(item, ''); setBusy(false)
  }
  return (
    <div className="panel" style={{ marginTop: 6 }} data-testid="vault-declare">
      <p className="muted" style={{ margin: 0 }}>{asks}</p>
      <textarea aria-label={`Declaration: ${item}`} rows={3} style={{ width: '100%', marginTop: 6 }} value={value} onChange={e => setValue(e.target.value)} maxLength={2000} />
      <div className="row" style={{ gap: 8, marginTop: 6 }}>
        <button className="primary" disabled={busy || !value.trim()} onClick={async () => { setBusy(true); await onSave(item, value.trim()); setBusy(false) }}>Save the declaration</button>
        {current && <button className="ghost" style={{ color: WARN }} disabled={busy} onClick={withdraw}>Withdraw…</button>}
        <button className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  )
}
