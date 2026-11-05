// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { applyHardeningFix, applyHardeningProfile, getHardening, hardeningJsonUrl, planHardeningFix, planHardeningProfile, type HardeningCheck, type HardeningFix, type HardeningReport } from '../api'
import { useConfirm } from '../confirm'
import { useFeatures, why } from '../features'
import { useBranches } from '../useBranches'

// The hardening report (point 3.2): how a branch's PostgreSQL, and the install
// around it, stand against FoxByte's hardening checks. Pass, fail, manual (a
// person judges, from the evidence) or not applicable; each with why it
// matters and the fix. Admins only, every edition. The page prints, for a PDF.

const LABEL: Record<HardeningCheck['status'], string> = { pass: 'pass', fail: 'fail', manual: 'manual', 'n/a': 'n/a' }

// What a fix will change and run, for the confirmation before it is made.
function FixPlan({ f }: { f: HardeningFix }) {
  return (
    <div data-testid={`plan-${f.id}`}>
      <b>{f.title}</b> <span className="muted">({f.level})</span>
      <ul style={{ margin: '4px 0', paddingLeft: 20 }}>{f.changes.map(c => <li key={c}>{c}</li>)}</ul>
      {(f.sql ?? []).length > 0 && <pre style={{ margin: '4px 0', whiteSpace: 'pre-wrap' }}><code>{(f.sql ?? []).join(';\n')}</code></pre>}
      {f.note && <p className="muted" style={{ fontSize: 13, margin: 0 }}>{f.note}</p>}
    </div>
  )
}

export default function Hardening() {
  const { branches } = useBranches()
  const [branch, setBranch] = useState('main')
  const [report, setReport] = useState<HardeningReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [level, setLevel] = useState<'' | 'basic' | 'strict'>('')
  const [open, setOpen] = useState(false) // only what did not pass
  const [msg, setMsg] = useState('')
  const [profile, setProfile] = useState('baseline')
  const [preview, setPreview] = useState<{ fixes: HardeningFix[]; manual: HardeningCheck[] } | null>(null)
  const confirm = useConfirm()
  const { can, edition } = useFeatures()
  const fixing = can('hardening')

  const load = useCallback(async (b: string) => {
    setBusy(true); setErr('')
    try { setReport(await getHardening(b)) }
    catch (e) { setReport(null); setErr((e as Error).message) }
    finally { setBusy(false) }
  }, [])
  useEffect(() => { load('main') }, [load])

  const fix = async (c: HardeningCheck) => {
    if (!report) return
    setErr(''); setMsg('')
    try {
      const { fix: f } = await planHardeningFix(report.branch, c.id)
      const ok = await confirm({ title: `Fix ${c.id} on ${report.branch}`, message: <FixPlan f={f} />, confirmText: 'Make this change' })
      if (!ok) return
      const { result } = await applyHardeningFix(report.branch, c.id)
      setMsg(result.error ? `${c.id}: not fixed: ${result.error}` : `${c.id}: ${result.before.status} → ${result.after.status}.`)
      await load(report.branch)
    } catch (e) { setErr((e as Error).message) }
  }
  const previewProfile = async () => {
    if (!report) return
    setErr(''); setMsg('')
    try { setPreview(await planHardeningProfile(report.branch, profile)) } catch (e) { setErr((e as Error).message) }
  }
  const applyProfile = async () => {
    if (!report || !preview) return
    const ok = await confirm({ title: `Apply the ${profile} profile to ${report.branch}`,
      message: <>{preview.fixes.map(f => <FixPlan key={f.id} f={f} />)}</>, confirmText: `Make ${preview.fixes.length} change(s)` })
    if (!ok) return
    try {
      const { results } = await applyHardeningProfile(report.branch, profile)
      const failed = results.filter(r => r.error)
      setMsg(`The ${profile} profile: ${results.length - failed.length} fix(es) made` +
        (failed.length ? `; not fixed: ${failed.map(r => `${r.fix.id} (${r.error})`).join(', ')}` : '.'))
      setPreview(null)
      await load(report.branch)
    } catch (e) { setErr((e as Error).message) }
  }

  const shown = (report?.checks ?? []).filter(c =>
    (!level || c.level === level) && (!open || c.status === 'fail' || c.status === 'manual'))
  const sections = [...new Set(shown.map(c => c.section))]
  const s = report?.summary

  return (
    <div className="fade-up hardening">
      <h1>Hardening</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        How a branch&rsquo;s PostgreSQL, and this install around it, stand against hardening checks: what passes, what
        fails and how to fix it, and what needs a person to judge.
      </p>

      <div className="row no-print" style={{ flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
        <label className="field">Branch
          <select aria-label="Branch" value={branch} onChange={e => setBranch(e.target.value)}>
            {(branches.length ? branches.map(b => b.name) : ['main']).map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <button className="primary" onClick={() => load(branch)} disabled={busy}>{busy ? 'Checking…' : 'Check'}</button>
        <label className="field">Level
          <select aria-label="Level" value={level} onChange={e => setLevel(e.target.value as typeof level)}>
            <option value="">basic and strict</option>
            <option value="basic">basic</option>
            <option value="strict">strict</option>
          </select>
        </label>
        <label className="check-row"><input type="checkbox" checked={open} onChange={e => setOpen(e.target.checked)} /> Only what did not pass</label>
        {report && (
          <>
            <a className="btn ghost" href={hardeningJsonUrl(report.branch)} download={`hardening-${report.branch}.json`}>JSON</a>
            <button className="ghost" onClick={() => window.print()}>Print or save as PDF</button>
          </>
        )}
      </div>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}
      {msg && <p className="ok" style={{ marginTop: 12 }} data-testid="hardening-msg">{msg}</p>}

      {report && s && (
        <>
          <p className="muted" style={{ marginTop: 14 }} data-testid="hardening-summary">
            {report.branch}, PostgreSQL {report.postgres}, checked {new Date(report.generated).toLocaleString()}:{' '}
            <b>{s.pass}</b> pass, <b>{s.fail}</b> fail, <b>{s.manual}</b> manual, {s['n/a']} not applicable.
            {report.profile && <> The {report.profile.profile} profile was applied by {report.profile.by}, {new Date(report.profile.at).toLocaleString()}.</>}
          </p>

          <div className="panel no-print" style={{ marginTop: 10 }} data-testid="hardening-profiles">
            <p style={{ marginTop: 0 }}>
              <b>Profiles.</b> <i>baseline</i> fixes every basic check that fails and is safe to fix; <i>strict</i> the strict ones too.
              The preview shows each change, and what is left to a person.
            </p>
            {fixing ? (
              <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <label className="field">Profile
                  <select aria-label="Profile" value={profile} onChange={e => { setProfile(e.target.value); setPreview(null) }}>
                    <option value="baseline">baseline</option>
                    <option value="strict">strict</option>
                  </select>
                </label>
                <button className="ghost" onClick={previewProfile}>Preview</button>
                {preview && preview.fixes.length > 0 && <button className="primary" onClick={applyProfile}>Apply {profile}</button>}
              </div>
            ) : <p className="muted" style={{ margin: 0, fontSize: 13 }}>{why(edition, 'Fixing checks, and profiles,')}</p>}
            {preview && (
              <div style={{ marginTop: 10 }} data-testid="profile-preview">
                {preview.fixes.length === 0
                  ? <p className="muted" style={{ margin: 0 }}>Nothing for the {profile} profile to fix on {report.branch}.</p>
                  : preview.fixes.map(f => <FixPlan key={f.id} f={f} />)}
                {preview.manual.length > 0 && (
                  <p className="muted" style={{ fontSize: 13 }}>
                    Failing, and left to a person: {preview.manual.map(c => c.id).join(', ')}.
                  </p>
                )}
              </div>
            )}
          </div>
          {sections.map(sec => (
            <div key={sec}>
              <h2 style={{ marginTop: 18, textTransform: 'capitalize' }}>{sec}</h2>
              <div className="table-wrap">
                <table aria-label={`Hardening: ${sec}`}>
                  <thead><tr><th>Status</th><th>Check</th><th>Found</th><th>Fix</th></tr></thead>
                  <tbody>
                    {shown.filter(c => c.section === sec).map(c => (
                      <tr key={c.id} data-testid={`check-${c.id}`}>
                        <td><span className={'badge' + (c.status === 'pass' ? ' primary' : '')}>{LABEL[c.status]}</span></td>
                        <td>
                          {c.title} <span className="muted" style={{ fontSize: 12 }}>({c.level})</span>
                          <div className="muted" style={{ fontSize: 12 }}>{c.why}</div>
                        </td>
                        <td style={{ fontSize: 13 }}>{c.evidence}</td>
                        <td style={{ fontSize: 13 }}>
                          {c.fixable && fixing
                            ? <button className="ghost" onClick={() => fix(c)}>Fix…</button>
                            : c.fix ? <code>{c.fix}</code> : '–'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
          {shown.length === 0 && <p className="muted" data-testid="hardening-none">Nothing to show with these filters.</p>}
          <div className="panel" style={{ marginTop: 16 }}>
            <p style={{ marginTop: 0 }}>{report.basis}</p>
            <ul style={{ margin: 0 }}>{report.limits.map(l => <li key={l}>{l}</li>)}</ul>
          </div>
        </>
      )}
    </div>
  )
}
