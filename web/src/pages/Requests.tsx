import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { createRequest, decideRequest, listRequests, type ChangeRequest } from '../api'
import { useFeatures, why } from '../features'
import { useConfirm } from '../confirm'
import { useBranches } from '../useBranches'

// Change requests: a branch's schema changes, offered for review, then applied to
// another branch. Branching was only half a workflow until this — you could take
// a copy, change it, and prove what changed, and then there was no way back.
//
// What is applied is the Blackbox's own record of what ran on the source, so the
// target ends up holding the same statements, attributed to whoever wrote them.
// Schema only: no data is moved, and the page says so rather than letting "merge"
// be read as more than it is.

const STATUS = ['open', 'approved', 'rejected', 'failed'] as const

export default function Requests() {
  const { can, edition } = useFeatures()
  // Rejecting is deliberately not gated, so a request left open when an install
  // changed edition can still be closed rather than stranded.
  const canApply = can('promotion')
  const [requests, setRequests] = useState<ChangeRequest[]>([])
  const [filter, setFilter] = useState<string>('open')
  const [open, setOpen] = useState<number | null>(null)
  const [source, setSource] = useState('')
  const [target, setTarget] = useState('main')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const confirm = useConfirm()

  const load = useCallback(async () => {
    try {
      setRequests(await listRequests(filter))
      setErr('')
    } catch (e) {
      setErr((e as Error).message)
    }
  }, [filter])

  useEffect(() => { load() }, [load])
  const { branches, branchesError } = useBranches()

  const ask = async () => {
    if (!source) return
    setBusy(true); setErr(''); setMsg('')
    try {
      const c = await createRequest(source, target)
      setMsg(`Request #${c.id} holds ${c.entries.length} statement(s) from ${c.source}. Nothing has been applied to ${c.target}.`)
      setFilter('open'); setOpen(c.id)
      await load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const decide = async (c: ChangeRequest, decision: 'approve' | 'reject') => {
    const ok = await confirm({
      title: decision === 'approve' ? `Apply ${c.entries.length} statement(s) to ${c.target}?` : `Reject request #${c.id}?`,
      message: decision === 'approve'
        ? <>Every statement below runs on <code>{c.target}</code> in one transaction, recorded in its Blackbox
            and attributed to whoever wrote it on <code>{c.source}</code>. Schema only — no data is moved.</>
        : <>Nothing will be applied to <code>{c.target}</code>. A rejected request cannot be reopened.</>,
      confirmText: decision === 'approve' ? 'Apply' : 'Reject',
      danger: decision === 'reject',
    })
    if (!ok) return
    setBusy(true); setErr(''); setMsg('')
    try {
      const done = await decideRequest(c.id, decision)
      setMsg(decision === 'approve'
        ? `Applied ${done.applied} statement(s) to ${done.target}.`
        : `Request #${done.id} rejected; ${done.target} is unchanged.`)
      await load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const branchNames = branches.length ? branches.map(b => b.name) : ['main']
  const sources = branchNames.filter(n => n !== target)

  return (
    <div className="fade-up">
      <div className="page-head">
        <div>
          <h1>Change requests</h1>
          <p className="sub">A branch's schema changes, reviewed, then applied to another branch. Schema only — no data is moved.</p>
        </div>
        <div className="tools">
          <div className="seg">
            {(['', ...STATUS] as const).map(s => (
              <button key={s || 'all'} className={filter === s ? 'active' : ''} onClick={() => setFilter(s)}>
                {s ? s[0].toUpperCase() + s.slice(1) : 'All'}
              </button>
            ))}
          </div>
          <button className="ghost" onClick={load} disabled={busy}>Refresh</button>
        </div>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Offer a branch's changes</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Its Blackbox entries since the two branches split, in the order they ran. Entries the guardrail refused are
          left out — a blocked change never happened.
        </p>
        <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
          <label className="field-inline">
            <span>From</span>
            <select value={source} onChange={e => setSource(e.target.value)}>
              <option value="">choose a branch…</option>
              {sources.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <label className="field-inline">
            <span>To</span>
            <select value={target} onChange={e => setTarget(e.target.value)}>
              {branchNames.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <button className="primary" onClick={ask} disabled={busy || !source}>Ask for review</button>
        </div>
      </div>

      {msg && <div className="okmsg">{msg}</div>}
      {(err || branchesError) && <div className="err">{err || branchesError}</div>}

      {requests.length === 0 && !err && !branchesError && (
        <p className="muted" style={{ marginTop: 18 }}>
          No {filter || ''} change requests. Make one above, or with <code>fox branch request &lt;source&gt;</code>.
        </p>
      )}

      {requests.map(c => (
        <div className="panel" key={c.id} style={{ marginTop: 14 }}>
          <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <b>#{c.id}</b> <span className={'lg-status ' + (c.status === 'open' ? '' : c.status === 'failed' ? 'BLOCKED' : 'APPLIED')}>{c.status}</span>{' '}
              <code>{c.source}</code> → <code>{c.target}</code>{' '}
              <span className="muted">
                · {c.entries.length} statement(s) · asked by {c.created_by}
                {c.decided_by && <> · decided by {c.decided_by}</>}
                {c.status === 'approved' && c.applied > 0 && <> · {c.applied} applied</>}
              </span>
            </div>
            <div className="row" style={{ gap: 8 }}>
              <button className="ghost" onClick={() => setOpen(open === c.id ? null : c.id)}>
                {open === c.id ? 'Hide' : 'Review'}
              </button>
              {c.status === 'open' && (
                <>
                  <button className="ghost" onClick={() => decide(c, 'reject')} disabled={busy}>Reject</button>
                  <button className="primary" onClick={() => decide(c, 'approve')} disabled={busy || !canApply}
                    title={canApply ? undefined : why(edition, 'Applying a change request')}>
                    {canApply ? `Apply to ${c.target}` : `Apply to ${c.target} (Enterprise)`}
                  </button>
                </>
              )}
            </div>
          </div>
          {c.note && <div className="muted" style={{ marginTop: 8 }}>{c.status === 'failed' ? 'It did not apply: ' : 'Note: '}{c.note}</div>}
          {open === c.id && (
            <div style={{ marginTop: 12 }}>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Entry</th><th>Actor</th><th>Change</th><th>Statement</th></tr>
                  </thead>
                  <tbody>
                    {c.entries.map(e => (
                      <tr key={e.id}>
                        <td className="mono muted">#{e.id}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span className={'lg-kind ' + (e.kind || 'human')}>{e.kind || 'human'}</span> {e.actor || '—'}
                        </td>
                        <td>
                          <code className="mono">{e.command}</code>{' '}
                          <span className="muted">{e.object}</span>
                          {e.risk && <span className="lg-risk"> · {e.risk}</span>}
                        </td>
                        <td><pre className="lg-statement" style={{ maxHeight: 140 }}>{e.sql}</pre></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {c.status === 'approved' && (
                <p className="muted" style={{ marginTop: 10 }}>
                  These are in <Link to="/blackbox">{c.target}'s Blackbox</Link> now, each attributed to whoever wrote it,
                  with this request's id in the entry's session.
                </p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
