// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useId, useRef, useState, type DragEvent } from 'react'
import { activateLicense, getEditionSwitch, startEditionSwitch, type EditionSwitch, type License, type LicenseActivation } from '../api'
import { BRAND } from '../brand'
import { refreshEntitlement } from '../features'

// Upgrading to Enterprise, from wherever somebody happens to be.
//
// Two different things are both called "upgrading", and this says which one
// applies before asking for anything. An Enterprise build needs a licence: a
// file, uploaded or pasted, and the engine unlocks the paid features the moment
// it has verified it. A Standard build cannot be upgraded by any licence — the
// paid code is not in that binary, which is what keeps the free build purely
// AGPL — so it is shown the one command that installs the Enterprise build,
// rather than a form that would accept a licence and change nothing.

/** What activating produced, which decides what the modal says next. */
export type Outcome = 'activated' | 'warning' | 'locked'

// Three outcomes, not two. The engine installs a licence that has expired or
// that names another machine, because those are states a real customer is in
// and each has its own way out — so "it worked" has to be told apart from "it
// worked, and something wants doing" and from "it is installed and unlocks
// nothing". A green tick on an expired licence would be the one lie in here.
export function outcomeOf(r: LicenseActivation): Outcome {
  if (r.unlocks && r.state === 'active') return 'activated'
  if (r.unlocks) return 'warning'
  return 'locked'
}

// A licence is a few hundred bytes. Anything far larger is the wrong file, and
// reading it whole into a textarea would be a strange way to find out.
const maxLicenceBytes = 64 * 1024

type Mode = 'upload' | 'paste'

export default function UpgradeModal({ lic, onClose }: { lic: License; onClose: (changed: boolean) => void }) {
  const titleId = useId()
  const [mode, setMode] = useState<Mode>('upload')
  const [text, setText] = useState('')
  const [file, setFile] = useState<{ name: string; size: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [result, setResult] = useState<LicenseActivation | null>(null)
  const [dragging, setDragging] = useState(false)
  const closeRef = useRef<HTMLButtonElement>(null)

  // Closing tells the page whether anything changed, so it can ask every lock
  // to look again; dismissing without activating changes nothing.
  const close = () => { if (!busy) onClose(result !== null) }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })
  // The result is the thing to read next, and Close the thing to press.
  useEffect(() => { if (result) closeRef.current?.focus() }, [result])

  const readFile = async (f: File) => {
    setErr('')
    if (f.size > maxLicenceBytes) {
      setFile(null); setText('')
      setErr(`${f.name} is ${Math.round(f.size / 1024)} KB — a licence is a few hundred bytes, so this is not one.`)
      return
    }
    const body = await f.text()
    setFile({ name: f.name, size: f.size })
    setText(body)
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files?.[0]
    if (f) void readFile(f)
  }

  const activate = async () => {
    setBusy(true)
    setErr('')
    try {
      setResult(await activateLicense(text))
    } catch (e) {
      // The engine's own words: it says what was wrong with the licence and
      // that nothing was installed, which is better than anything generic.
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={close}>
      <div className="modal upgrade-modal fade-up" role="dialog" aria-modal="true" aria-labelledby={titleId}
        onClick={e => e.stopPropagation()}>
        {lic.edition === 'standard'
          ? <StandardBuild titleId={titleId} onClose={close} />
          : result
            ? <Result r={result} titleId={titleId} closeRef={closeRef} onClose={close}
                onAgain={() => { setResult(null); setText(''); setFile(null) }} />
            : (
              <>
                <h3 id={titleId}>Activate {BRAND.product} Enterprise</h3>
                <p className="modal-body">
                  Upload the licence file you were sent, or paste what is in it. It is signed, so this
                  engine can tell a real one from a forged one before it installs anything.
                </p>

                <div className="seg" role="tablist" aria-label="How to provide the licence">
                  <button role="tab" aria-selected={mode === 'upload'} className={mode === 'upload' ? 'active' : ''}
                    onClick={() => { setMode('upload'); setErr('') }} disabled={busy}>Upload file</button>
                  <button role="tab" aria-selected={mode === 'paste'} className={mode === 'paste' ? 'active' : ''}
                    onClick={() => { setMode('paste'); setErr('') }} disabled={busy}>Paste licence</button>
                </div>

                {mode === 'upload' ? (
                  <label className={'drop' + (dragging ? ' dragging' : '') + (file ? ' has-file' : '')}
                    onDragOver={e => { e.preventDefault(); setDragging(true) }}
                    onDragLeave={() => setDragging(false)} onDrop={onDrop}>
                    <input type="file" accept=".json,.lic,.txt,application/json,text/plain" disabled={busy}
                      aria-label="Licence file"
                      onChange={e => { const f = e.target.files?.[0]; if (f) void readFile(f) }} />
                    {file
                      ? <span><b>{file.name}</b> <span className="muted">· {file.size} bytes · choose another</span></span>
                      : <span><b>Choose a licence file</b> <span className="muted">or drop it here</span></span>}
                  </label>
                ) : (
                  <textarea className="lic-paste" rows={7} value={text} disabled={busy} autoFocus
                    aria-label="Licence text" spellCheck={false}
                    placeholder='{"id":"FB-…","customer":"…","signature":"…"}'
                    onChange={e => { setText(e.target.value); setFile(null); setErr('') }} />
                )}

                {err && <p className="err" role="alert">{err}</p>}

                <div className="modal-actions">
                  <button className="ghost" onClick={close} disabled={busy}>Cancel</button>
                  <button className="primary" onClick={activate} disabled={busy || !text.trim()}>
                    {busy ? <><span className="spinner" aria-hidden />Activating…</> : 'Activate'}
                  </button>
                </div>
              </>
            )}
      </div>
    </div>
  )
}

function Result({ r, titleId, closeRef, onClose, onAgain }: {
  r: LicenseActivation
  titleId: string
  closeRef: React.RefObject<HTMLButtonElement | null>
  onClose: () => void
  onAgain: () => void
}) {
  const o = outcomeOf(r)
  const title = o === 'activated' ? 'Enterprise activated'
    : o === 'warning' ? 'Enterprise activated, with a warning'
      : 'Licence installed, but nothing is unlocked'
  return (
    <div className="upgrade-result" role="status">
      <StatusMark outcome={o} />
      <h3 id={titleId}>{title}</h3>
      {o === 'activated' && (
        <p className="modal-body">
          Licence <b>{r.activated}</b> for <b>{r.customer}</b>. The paid features are unlocked now —
          close this and they are ready.
        </p>
      )}
      {o !== 'activated' && (
        <p className="modal-body">
          {r.reason && <>{r.reason}. </>}
          {r.action}
        </p>
      )}
      {r.notes && r.notes.length > 0 && (
        <ul className="upgrade-notes">
          {r.notes.map(n => <li key={n}>{n}</li>)}
        </ul>
      )}
      <div className="modal-actions centered">
        {o === 'locked' && <button className="ghost" onClick={onAgain}>Try another licence</button>}
        <button ref={closeRef} className="primary" onClick={onClose}>Close</button>
      </div>
    </div>
  )
}

/** The circle at the top of a result: a tick, or a mark that asks for attention. */
function StatusMark({ outcome }: { outcome: Outcome }) {
  return (
    <svg className={'status-mark ' + outcome} width="56" height="56" viewBox="0 0 56 56" aria-hidden>
      <circle cx="28" cy="28" r="26" />
      {outcome === 'activated'
        ? <path d="M17 29l7.5 7.5L39.5 21" />
        : <><path d="M28 16v15" /><path d="M28 39.5v.5" /></>}
    </svg>
  )
}

/**
 * A command to run, with a button that copies it. Long ones wrap rather than
 * run off the edge. The clipboard can refuse (an older browser, a page not
 * served over HTTPS), so the text is then selected for a manual copy instead.
 */
function Cmd({ text }: { text: string }) {
  // 'selected' says what to do next, so a refused clipboard does not look like
  // a button that did nothing.
  const [state, setState] = useState<'idle' | 'copied' | 'selected'>('idle')
  const ref = useRef<HTMLElement>(null)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setState('copied')
    } catch {
      const sel = window.getSelection()
      if (sel && ref.current) {
        const r = document.createRange()
        r.selectNodeContents(ref.current)
        sel.removeAllRanges()
        sel.addRange(r)
      }
      setState('selected')
    }
    setTimeout(() => setState('idle'), 2500)
  }
  const keys = /Mac|iPhone|iPad/.test(navigator.userAgent) ? '⌘C' : 'Ctrl+C'
  return (
    <pre className="cmd">
      <code ref={ref}>{text}</code>
      <button type="button" className="copy" onClick={copy} aria-label={`Copy: ${text}`}>
        {state === 'copied' ? 'copied' : state === 'selected' ? `press ${keys}` : 'copy'}
      </button>
    </pre>
  )
}

// Where the Enterprise licence is published. The free build carries the
// address and nothing from enterprise/ itself.
const enterpriseLicenseURL = `https://github.com/${BRAND.repo}/blob/main/enterprise/LICENSE`

// How often a running switch is asked about. Answers stop for a few seconds
// while the servers restart onto the new edition; that is expected, not failure.
const switchPollMs = 2000

function StandardBuild({ titleId, onClose }: { titleId: string; onClose: () => void }) {
  const upgrade = `${BRAND.cli} upgrade --edition enterprise`
  const unix = `curl -fsSL ${BRAND.installSh} | ${BRAND.envPrefix}EDITION=enterprise sh`
  const win = `$env:${BRAND.envPrefix}EDITION = 'enterprise'; irm ${BRAND.installPs1} | iex`
  const [accepted, setAccepted] = useState(false)
  const [sw, setSw] = useState<EditionSwitch | null>(null)
  const [starting, setStarting] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const [err, setErr] = useState('')

  // Opened again while a switch runs: carry on showing it.
  useEffect(() => {
    getEditionSwitch().then(s => { if (s.state === 'running') setSw(s) }).catch(() => { /* not an admin, or an older engine */ })
  }, [])

  // While it runs, ask how it is going. When it is done, every lock on the page
  // asks again — and this page, now on an Enterprise engine, turns this modal
  // into the licence form by itself.
  useEffect(() => {
    if (sw?.state !== 'running') return
    const id = setInterval(async () => {
      try {
        const s = await getEditionSwitch()
        setRestarting(false)
        setSw(s)
        if (s.state === 'done') refreshEntitlement()
      } catch {
        setRestarting(true)
      }
    }, switchPollMs)
    return () => clearInterval(id)
  }, [sw?.state])

  const install = async () => {
    setStarting(true)
    setErr('')
    try {
      await startEditionSwitch('enterprise', true)
      setSw({ state: 'running', edition: 'enterprise', log: [] })
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setStarting(false)
    }
  }

  if (sw && sw.state !== 'none') {
    return (
      <>
        <h3 id={titleId}>Installing {BRAND.product} Enterprise</h3>
        {sw.state === 'running' && (
          <p className="modal-body" role="status">
            <span className="spinner" aria-hidden />
            {restarting
              ? 'The servers are restarting onto the Enterprise edition…'
              : 'Downloading the signed Enterprise build and checking it. The servers restart for a few seconds; your data is not touched.'}
          </p>
        )}
        {sw.state === 'done' && (
          <p className="modal-body" role="status">Enterprise is installed. Opening licence activation…</p>
        )}
        {sw.state === 'failed' && (
          <>
            <p className="err" role="alert">{sw.error || 'The switch did not finish.'}</p>
            <p className="modal-body">
              You can also run it from a terminal, which shows every step:
            </p>
            <Cmd text={upgrade} />
          </>
        )}
        {!!sw.log?.length && <pre className="switch-log"><code>{sw.log.join('\n')}</code></pre>}
        <p className="modal-note">
          On macOS and Windows, <code>{BRAND.cli}</code> on your computer updates itself to match the next
          time you run it.
        </p>
        <div className="modal-actions">
          <button className="primary" onClick={onClose} autoFocus>Close</button>
        </div>
      </>
    )
  }

  return (
    <>
      <h3 id={titleId}>Moving to {BRAND.product} Enterprise</h3>
      <p className="modal-body">
        This is the standard edition, and a licence cannot change that: the paid features are not
        in this build at all, which is what keeps it free to share. Install the Enterprise build of
        the same version over it. That replaces the <code>{BRAND.cli}</code> program and nothing else,
        so your databases, accounts and settings stay where they are.
      </p>
      <label className="accept">
        <input type="checkbox" checked={accepted} onChange={e => setAccepted(e.target.checked)} disabled={starting}
          aria-label={`I accept the ${BRAND.product} Enterprise License`} />
        <span>
          I accept the{' '}
          <a href={enterpriseLicenseURL} target="_blank" rel="noreferrer">{BRAND.product} Enterprise License</a>.
          {' '}It is not open source, and its paid features need a licence key, which you activate next.
        </span>
      </label>
      {err && <p className="err" role="alert">{err}</p>}
      <div className="modal-actions">
        <button className="ghost" onClick={onClose} disabled={starting}>Cancel</button>
        <button className="primary" onClick={install} disabled={!accepted || starting}>
          {starting ? <><span className="spinner" aria-hidden />Starting…</> : 'Install Enterprise'}
        </button>
      </div>
      <details className="modal-more">
        <summary>Or install it from a terminal</summary>
        <p className="modal-body">
          On the computer where {BRAND.product} is installed (on Linux, put <code>sudo</code> in front):
        </p>
        <Cmd text={upgrade} />
        <p className="modal-body">
          If it says “unknown command: upgrade”, your <code>{BRAND.cli}</code> is older than that command:
          run <code>{BRAND.cli} update</code> first, or use the installer — macOS and Linux:
        </p>
        <Cmd text={unix} />
        <p className="modal-body">Windows (PowerShell):</p>
        <Cmd text={win} />
        <p className="modal-body">
          Then restart onto it: <code>{BRAND.cli} stop</code> and <code>{BRAND.cli} setup</code> on macOS or
          Windows, or <code>sudo {BRAND.cli} start</code> on Linux.
        </p>
      </details>
    </>
  )
}
