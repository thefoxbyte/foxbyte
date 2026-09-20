import { useCallback, useEffect, useState } from 'react'
import {
  addPolicyRule, checkPolicy, getAdmins, getBranches, getPolicyEvaluations, getPolicyRules, grantAdmin, removePolicyRule,
  revokeAdmin, updatePolicyRule,
  type Branch, type BranchAdmins, type PolicyAction, type PolicyCheckResult, type PolicyEvaluation, type PolicyRule,
} from '../api'

// Blackbox policy gate: rules checked on every schema change before it runs.
// A warn rule lets the change through with a notice (SQLSTATE BBX02); a block
// rule refuses it (BBX01). Reading and previewing are open to everyone; changing
// rules needs db_admin on the branch.
const emptyDraft = { rule_id: '', command_tag: 'ALTER TABLE', pattern: '', action: 'warn' as PolicyAction, reason: '', hint: '' }

export default function Policies() {
  const [branches, setBranches] = useState<Branch[]>([])
  const [branch, setBranch] = useState('main')
  const [rules, setRules] = useState<PolicyRule[]>([])
  const [evals, setEvals] = useState<PolicyEvaluation[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [sql, setSql] = useState('')
  const [check, setCheck] = useState<PolicyCheckResult | null>(null)
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState(emptyDraft)
  const [admins, setAdmins] = useState<BranchAdmins | null>(null)
  const [newAdmin, setNewAdmin] = useState('')

  useEffect(() => { getBranches().then(setBranches).catch(() => {}) }, [])

  const loadAdmins = useCallback(async () => {
    try { setAdmins(await getAdmins(branch)) } catch { setAdmins(null) }
  }, [branch])
  useEffect(() => { setAdmins(null); setNewAdmin(''); loadAdmins() }, [loadAdmins])

  const load = useCallback(async () => {
    try {
      const [r, e] = await Promise.all([getPolicyRules(branch), getPolicyEvaluations(branch, 20)])
      setRules(r); setEvals(e)
    } catch (e) {
      setRules([]); setEvals([]); setErr((e as Error).message)
    }
  }, [branch])
  useEffect(() => { setErr(''); setCheck(null); load() }, [load])

  const act = async (f: () => Promise<unknown>) => {
    setBusy(true); setErr('')
    try { await f(); await load() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }

  const runCheck = async () => {
    setBusy(true); setErr('')
    try { setCheck(await checkPolicy(branch, sql)) } catch (e) { setCheck(null); setErr((e as Error).message) } finally { setBusy(false) }
  }

  const add = () => act(async () => {
    await addPolicyRule(branch, {
      rule_id: draft.rule_id.trim(), command_tag: draft.command_tag.trim().toUpperCase(), pattern: draft.pattern || null,
      action: draft.action, reason: draft.reason, hint: draft.hint || null,
    })
    setAdding(false); setDraft(emptyDraft)
  })

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const badge = (action: string) => (
    <span className={'lg-status ' + (action === 'block' ? 'BLOCKED' : action === 'allowed' ? 'APPLIED' : 'FLAGGED')}>{action.toUpperCase()}</span>
  )

  return (
    <div className="fade-up">
      <div className="page-head">
        <div>
          <h1>Policies</h1>
          <p className="sub">
            Blackbox checks every schema change against these rules before it runs. <b>Warn</b> lets it through with a notice;{' '}
            <b>block</b> refuses it with SQLSTATE <code>BBX01</code> and records the attempt. Changing rules, and overriding a
            block, needs <code>db_admin</code> — manage who has it under <a href="#who-can-override">Who can override</a>.
          </p>
        </div>
        <div className="tools">
          <label className="field-inline">
            <span>Branch</span>
            <select value={branch} onChange={e => setBranch(e.target.value)}>
              {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
            </select>
          </label>
          <button className="ghost" onClick={() => setAdding(a => !a)} disabled={busy}>{adding ? 'Cancel' : 'Add rule'}</button>
        </div>
      </div>

      {err && <div className="err">{err}</div>}

      {adding && (
        <div className="panel" style={{ marginTop: 14 }}>
          <h3 style={{ marginTop: 0 }}>New rule</h3>
          <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
            <input placeholder="rule-id" value={draft.rule_id} onChange={e => setDraft({ ...draft, rule_id: e.target.value })} style={{ width: 180 }} />
            <input placeholder="Command, e.g. ALTER TABLE" value={draft.command_tag} onChange={e => setDraft({ ...draft, command_tag: e.target.value })} style={{ width: 200 }} />
            <input placeholder="Pattern (regex, optional)" value={draft.pattern} onChange={e => setDraft({ ...draft, pattern: e.target.value })} style={{ width: 240 }} />
            <div className="seg">
              {(['warn', 'block'] as PolicyAction[]).map(a => (
                <button key={a} className={draft.action === a ? 'active' : ''} onClick={() => setDraft({ ...draft, action: a })}>{a}</button>
              ))}
            </div>
          </div>
          <div className="row" style={{ flexWrap: 'wrap', gap: 10, marginTop: 10 }}>
            <input placeholder="Why this rule exists" value={draft.reason} onChange={e => setDraft({ ...draft, reason: e.target.value })} style={{ flex: '1 1 280px' }} />
            <input placeholder="Next step to suggest (optional)" value={draft.hint} onChange={e => setDraft({ ...draft, hint: e.target.value })} style={{ flex: '1 1 280px' }} />
            <button className="primary" onClick={add} disabled={busy || !draft.rule_id || !draft.reason}>Add</button>
          </div>
        </div>
      )}

      <div className="table-wrap" style={{ marginTop: 14 }}>
        <table>
          <thead><tr><th>Rule</th><th>Applies to</th><th>Why</th><th>Action</th><th>On</th><th /></tr></thead>
          <tbody>
            {rules.length === 0 && <tr><td colSpan={6} className="muted">no rules on this branch</td></tr>}
            {rules.map(r => (
              <tr key={r.rule_id} style={{ opacity: r.enabled ? 1 : 0.55 }}>
                <td style={{ whiteSpace: 'nowrap' }}><code>{r.rule_id}</code>{r.builtin && <span className="muted"> · built-in</span>}</td>
                <td>
                  <code className="mono">{r.command_tag}</code>
                  {r.pattern && <div className="muted mono" style={{ fontSize: 12 }}>{r.pattern}</div>}
                </td>
                <td className="muted">{r.reason}</td>
                <td>
                  <div className="seg">
                    {(['warn', 'block'] as PolicyAction[]).map(a => (
                      <button key={a} className={r.action === a ? 'active' : ''} disabled={busy || r.action === a}
                        onClick={() => act(() => updatePolicyRule(branch, r.rule_id, { action: a }))}>{a}</button>
                    ))}
                  </div>
                </td>
                <td>
                  <input type="checkbox" checked={r.enabled} disabled={busy}
                    onChange={e => act(() => updatePolicyRule(branch, r.rule_id, { enabled: e.target.checked }))} />
                </td>
                <td>
                  {!r.builtin && <button className="ghost" disabled={busy} onClick={() => act(() => removePolicyRule(branch, r.rule_id))}>Remove</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel" id="who-can-override" style={{ marginTop: 18 }}>
        <h3 style={{ marginTop: 0 }}>Who can override</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Admins of <code>{branch}</code> may run a blocked change — tick <b>Allow destructive changes</b> in the SQL
          console — and may grant or revoke this here. A grant on <code>main</code> is copied into branches created
          after it; branches that already exist need their own.
        </p>
        {admins && !admins.you_are_admin && (
          <div className="muted" style={{ marginBottom: 10 }}>
            You (<code>{admins.you}</code>) aren’t an admin on <code>{branch}</code>, so you can’t change this list. An admin can
            grant you here, or run <code>fox admin grant {admins.you} --branch {branch}</code>.
          </div>
        )}
        <div className="table-wrap">
          <table>
            <thead><tr><th>Admin</th><th /></tr></thead>
            <tbody>
              {!admins && <tr><td colSpan={2} className="muted">loading…</td></tr>}
              {admins && admins.admins.length === 0 && (
                <tr><td colSpan={2} className="muted">no admins — only superusers can override on this branch</td></tr>
              )}
              {admins?.admins.map(email => (
                <tr key={email}>
                  <td>{email}{email === admins.you && <span className="muted"> · you</span>}</td>
                  <td style={{ textAlign: 'right' }}>
                    <button className="ghost danger" disabled={busy || !admins.you_are_admin || admins.admins.length === 1}
                      title={admins.admins.length === 1 ? 'The last admin can’t be removed here — grant someone else first' : ''}
                      onClick={() => act(async () => { await revokeAdmin(branch, email); await loadAdmins() })}>Revoke</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {admins?.you_are_admin && (
          <form className="row" style={{ marginTop: 10, flexWrap: 'wrap', gap: 10 }}
            onSubmit={e => { e.preventDefault(); act(async () => { await grantAdmin(branch, newAdmin.trim()); setNewAdmin(''); await loadAdmins() }) }}>
            <input type="email" placeholder="user@example.com" value={newAdmin} onChange={e => setNewAdmin(e.target.value)} style={{ flex: '1 1 240px' }} />
            <button className="primary" type="submit" disabled={busy || !newAdmin.trim()}>Grant</button>
          </form>
        )}
      </div>

      <div className="panel" style={{ marginTop: 18 }}>
        <h3 style={{ marginTop: 0 }}>Check a statement</h3>
        <p className="muted" style={{ marginTop: 0 }}>See which rules a schema change would trigger, without running it.</p>
        <textarea rows={3} style={{ width: '100%' }} placeholder="ALTER TABLE orders DROP COLUMN note"
          value={sql} onChange={e => setSql(e.target.value)} />
        <div className="row" style={{ marginTop: 8 }}>
          <button className="primary" onClick={runCheck} disabled={busy || !sql.trim()}>Check</button>
        </div>
        {check && (
          <div style={{ marginTop: 10 }}>
            <div className="muted" style={{ fontSize: 13 }}>Command: <code>{check.command}</code></div>
            {check.matches.length === 0
              ? <div style={{ marginTop: 6 }}>No rule matches — this change would run without a warning.</div>
              : check.matches.map(m => (
                <div key={m.rule_id} style={{ marginTop: 6 }}>
                  {badge(m.action)} <code>{m.rule_id}</code> — {m.reason}
                  <div className="muted" style={{ fontSize: 13 }}>{m.hint}</div>
                </div>
              ))}
          </div>
        )}
      </div>

      <h3 style={{ marginTop: 22 }}>Recent evaluations</h3>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Time (UTC)</th><th>Rule</th><th>Result</th><th>Command</th><th>Actor</th><th>Blackbox entry</th></tr></thead>
          <tbody>
            {evals.length === 0 && <tr><td colSpan={6} className="muted">nothing yet</td></tr>}
            {evals.map(e => (
              <tr key={e.id}>
                <td className="mono muted" style={{ whiteSpace: 'nowrap' }}>{e.at.replace('T', ' ').replace('Z', '')}</td>
                <td><code>{e.rule_id}</code></td>
                <td>{badge(e.action)}</td>
                <td className="mono">{e.command_tag || '—'}</td>
                <td>{e.actor || '—'}</td>
                <td className="mono">{e.blackbox_id ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
