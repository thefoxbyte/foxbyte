// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import {
  declareSafeguard, getSafeguards, safeguardsUrl,
  type SafeguardItem, type SafeguardRule, type SafeguardsEvidence, type VaultDeclaration,
} from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'

// The safeguards evidence (point 11.4): Rule 6 of the DPDP Rules, clause by
// clause, against what FoxByte checked on this machine just now, what it
// does by how it is built, and what you declared, which it cannot check;
// each clause with what it guards against and what it does not. The whole
// document downloads as JSON for an auditor. Admins; Enterprise.

const WARN = 'color-mix(in srgb, var(--red) 78%, var(--text))'
const GOOD = 'color-mix(in srgb, var(--green, #2f9e44) 80%, var(--text))'
const colour: Record<string, string | undefined> = { 'met': GOOD, 'not met': WARN, 'open': undefined }

export default function Safeguards() {
  const { can, edition } = useFeatures()
  const allowed = edition !== null && can('dpdp')
  const [ev, setEv] = useState<SafeguardsEvidence | null>(null)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState('')
  const load = useCallback(async () => {
    setBusy(true); setErr('')
    try { setEv(await getSafeguards()) } catch (e) { setErr((e as Error).message); setEv(null) } finally { setBusy(false) }
  }, [])
  useEffect(() => { if (allowed) load() }, [allowed, load])

  if (edition === null) return <div className="fade-up"><h1>Safeguards evidence</h1></div>
  if (!allowed) {
    return (
      <div className="fade-up">
        <h1>Safeguards evidence</h1>
        <p className="muted" data-testid="safeguards-locked">{why(edition, 'The safeguards evidence')}</p>
      </div>
    )
  }
  const save = async (item: string, value: string) => {
    setErr(''); setMsg('')
    try {
      await declareSafeguard(item, value)
      setMsg(value ? `Declared ${item}. The evidence shows it as declared, not checked.` : `Withdrawn: ${item} is open again.`)
      setEditing(''); await load()
      return true
    } catch (e) { setErr((e as Error).message); return false }
  }
  return (
    <div className="fade-up">
      <h1>Safeguards evidence</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Rule 6 of the DPDP Rules, clause by clause: what FoxByte checked on this machine just now, what it does by how it is built, and what you declared,
        which it cannot check.
      </p>
      <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
        <button className="ghost" onClick={load} disabled={busy}>{busy ? 'Reading…' : 'Read it again'}</button>
        <a className="btn primary" href={safeguardsUrl} download="safeguards-evidence.json" data-testid="safeguards-download">Download (JSON)</a>
      </div>
      {err && <div className="err" style={{ marginTop: 12 }} data-testid="safeguards-err">{err}</div>}
      {msg && <p className="ok" style={{ marginTop: 12 }} data-testid="safeguards-msg">{msg}</p>}
      {ev && (
        <>
          <p style={{ marginTop: 16 }} data-testid="safeguards-summary">
            <b>{ev.rule}</b>, in force {ev.inForce}: {ev.summary['met'] ?? 0} met, {ev.summary['not met'] ?? 0} not met, {ev.summary['open'] ?? 0} open (waiting for your declaration).
          </p>
          <div className="table-wrap">
            <table aria-label="Rule 6">
              <thead><tr><th>Clause</th><th>Requirement</th><th>Verdict</th><th>What stands behind it</th></tr></thead>
              <tbody>
                {ev.rules.map(r => <Row key={r.clause} r={r} items={ev.items} editing={editing} setEditing={setEditing} onSave={save} />)}
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ fontSize: 13 }}>Made {new Date(ev.generated).toLocaleString()} for {ev.by}; {ev.product} {ev.version}, {ev.edition}.</p>
          <h2 style={{ marginTop: 18 }}>What this cannot show</h2>
          <ul style={{ fontSize: 13 }} data-testid="safeguards-limits">{ev.limits.map(l => <li key={l}>{l}</li>)}</ul>
        </>
      )}
    </div>
  )
}

function Row({ r, items, editing, setEditing, onSave }: {
  r: SafeguardRule; items: SafeguardItem[]; editing: string; setEditing: (s: string) => void; onSave: (item: string, value: string) => Promise<boolean>
}) {
  const declared = new Map<string, VaultDeclaration>((r.declared ?? []).map(d => [d.item, d]))
  return (
    <tr data-testid={`safeguard-${r.clause}`}>
      <td><b>{r.clause}</b></td>
      <td style={{ fontSize: 13 }}>{r.requirement}</td>
      <td><b style={{ color: colour[r.verdict] }}>{r.verdict}</b></td>
      <td style={{ fontSize: 13 }}>
        <ul style={{ margin: 0, paddingLeft: 16, display: 'grid', gap: 6 }}>
          {(r.checks ?? []).map((c, i) => (
            <li key={i} style={{ color: c.ok ? undefined : WARN }}>{c.ok ? '✓' : '✗'} {c.what} <span className="muted">({c.basis}: {c.detail})</span></li>
          ))}
          {(r.items ?? []).map(it => {
            const d = declared.get(it)
            return (
              <li key={it}>
                {d ? <>Declared <b>{it}</b> by {d.declared_by} on {new Date(d.declared_at).toLocaleDateString()}: &ldquo;{d.value}&rdquo;{' '}</> : <><b>{it}</b>: not declared{' '}</>}
                {editing !== it && <button className="ghost" style={{ fontSize: 12, padding: '1px 8px' }} onClick={() => setEditing(it)}>{d ? 'Change…' : 'Declare…'}</button>}
                {editing === it && <Declare item={it} asks={items.find(x => x.item === it)?.asks ?? ''} current={d?.value ?? ''} onSave={onSave} onCancel={() => setEditing('')} />}
              </li>
            )
          })}
          <li className="muted">Guards against: {r.guards} Not against: {r.notAgainst}</li>
          {(r.notes ?? []).map((n, i) => <li key={`n${i}`} className="muted">{n}</li>)}
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
  return (
    <div className="panel" style={{ marginTop: 6 }} data-testid="safeguard-declare">
      <p className="muted" style={{ margin: 0 }}>{asks}</p>
      <textarea aria-label={`Declaration: ${item}`} rows={3} style={{ width: '100%', marginTop: 6 }} value={value} onChange={e => setValue(e.target.value)} maxLength={2000} />
      <div className="row" style={{ gap: 8, marginTop: 6 }}>
        <button className="primary" disabled={busy || !value.trim()} onClick={async () => { setBusy(true); await onSave(item, value.trim()); setBusy(false) }}>Save the declaration</button>
        {current && <button className="ghost" style={{ color: WARN }} disabled={busy} onClick={async () => {
          if (!await confirm({ title: `Withdraw ${item}?`, message: 'The statement stays in the record; its clause shows open again until someone declares it.', confirmText: 'Withdraw', danger: true })) return
          setBusy(true); await onSave(item, ''); setBusy(false)
        }}>Withdraw…</button>}
        <button className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  )
}
