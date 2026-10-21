// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useId, useState } from 'react'
import { getFinding, getSamples, markFinding, type PIIDecision, type PIIFinding, type PIISamples } from '../api'

// Reviewing one finding (point 4.6): what the scan saw, masked samples to
// decide by, and the decision, with every earlier one listed.
//
// The samples are read by the engine as the reviewer's own role and masked
// there, so this component never holds a value; it shows what it is given.

export const where = (f: PIIFinding) => `${f.schema}.${f.table}.${f.column}${f.path ? ' ' + f.path : ''}`

export function PIIReview({ branch, finding, label, canDecide, onDecided, onClose }: {
  branch: string
  finding: PIIFinding
  label: string // the category, as people say it
  canDecide: boolean // licensed: deciding and reading samples are Enterprise
  onDecided: (f: PIIFinding) => void
  onClose: () => void
}) {
  const titleId = useId()
  const [samples, setSamples] = useState<PIISamples | null>(null)
  const [samplesErr, setSamplesErr] = useState('')
  const [history, setHistory] = useState<PIIDecision[]>([])
  const [note, setNote] = useState(finding.note ?? '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    getFinding(branch, finding.id).then(d => setHistory(d.decisions ?? [])).catch(() => setHistory([]))
    if (!canDecide) return
    getSamples(branch, finding.id).then(setSamples).catch(e => setSamplesErr((e as Error).message))
  }, [branch, finding.id, canDecide])

  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])

  const decide = async (state: PIIFinding['state']) => {
    setBusy(true); setErr('')
    try {
      const d = await markFinding(branch, finding.id, state, note.trim())
      setHistory(d.decisions ?? [])
      onDecided(d.finding)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal fade-up" role="dialog" aria-modal="true" aria-labelledby={titleId}
        style={{ maxWidth: 620, width: '100%' }} onClick={e => e.stopPropagation()}>
        <h3 id={titleId}>Review {where(finding)}</h3>
        <p className="modal-body" style={{ marginTop: 0 }}>
          The scan suggests <b>{label}</b>, with {finding.confidence} confidence: {finding.why}.
        </p>

        <h4 style={{ margin: '14px 0 6px' }}>Masked samples</h4>
        {!canDecide ? (
          <p className="muted" style={{ margin: 0 }}>Reading samples and deciding are part of Enterprise.</p>
        ) : samplesErr ? (
          <div className="err">{samplesErr}</div>
        ) : !samples ? (
          <p className="muted" style={{ margin: 0 }}>Reading…</p>
        ) : (samples.samples ?? []).length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>Nothing there to show now.</p>
        ) : (
          <>
            <ul aria-label="Masked samples" style={{ margin: 0, paddingLeft: 18 }}>
              {samples.samples!.map((s, i) => (
                <li key={i}>
                  <code>{s.masked}</code>{' '}
                  <span className="muted" style={{ fontSize: 12 }}>{s.matches ? `looks like ${label.toLowerCase()}` : 'does not look like it'}</span>
                </li>
              ))}
            </ul>
            <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
              Read as {samples.as}, so only what that role may read; masked before they left the engine, and not kept.
            </p>
          </>
        )}

        {canDecide && (
          <>
            <label htmlFor={titleId + '-note'} style={{ display: 'block', marginTop: 14, fontSize: 13 }}>Note (optional)</label>
            <textarea id={titleId + '-note'} rows={2} value={note} maxLength={1000} onChange={e => setNote(e.target.value)}
              style={{ width: '100%' }} />
          </>
        )}
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}

        {history.length > 0 && (
          <>
            <h4 style={{ margin: '14px 0 6px' }}>Decisions</h4>
            <ol aria-label="Decisions" style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
              {history.map(h => (
                <li key={h.id}>
                  {h.state} by {h.actor}, {new Date(h.at).toLocaleString()}{h.note ? `: ${h.note}` : ''}
                </li>
              ))}
            </ol>
          </>
        )}

        <div className="row" style={{ justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button className="ghost" onClick={onClose}>Close</button>
          {canDecide && finding.state !== 'suggested' && (
            <button className="ghost" disabled={busy} onClick={() => decide('suggested')}>Reopen</button>
          )}
          {canDecide && (
            <>
              <button className="ghost" disabled={busy || finding.state === 'rejected'} onClick={() => decide('rejected')}>
                Reject
              </button>
              <button className="primary" disabled={busy || finding.state === 'confirmed'} onClick={() => decide('confirmed')}>
                Confirm
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
