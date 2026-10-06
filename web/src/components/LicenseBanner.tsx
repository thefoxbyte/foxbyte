// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The one place the console says something about the licence.
//
// Four decisions, because a banner is the easiest thing in an application to
// get wrong:
//
// It says nothing when there is nothing to say. An active licence shows no
// banner at all — a notice that is always there is wallpaper, and the next one
// that matters goes unread.
//
// It says nothing in the Standard edition either. A Standard user is not a
// failed Enterprise user, and a permanent strip advertising what they have not
// bought is an advert, not a notice. Paid features are shown locked on their
// own pages, where there is room to say what they do.
//
// A warning can be dismissed; a lapse cannot. Grace exists so that a licence
// expiring does not interrupt anyone, and a strip that cannot be closed
// interrupts them for a fortnight. It comes back for a *different* problem,
// because the dismissal is keyed to what it said.
//
// And it never blocks the page. An engine too old to have /api/license, or one
// that cannot answer, leaves the console exactly as it was.
import { useEffect, useState } from 'react'
import { getLicense, type License } from '../api'
import { BRAND } from '../brand'

// Dismissals last for the browser session, not forever: a new day's work should
// see a licence that is still expiring. Storage can be unavailable (private
// windows) or throw, in which case the banner simply stays shown.
const DISMISS_KEY = 'bb.license.dismissed'
function readDismissed() {
  try { return sessionStorage.getItem(DISMISS_KEY) ?? '' } catch { return '' }
}
function writeDismissed(value: string) {
  try { sessionStorage.setItem(DISMISS_KEY, value) } catch { /* not persisted */ }
}

// tone is how loudly to say it. `warning` still unlocks everything, so it is
// amber and closable; lapsed and invalid have taken the paid features away, so
// they are red and stay.
function tone(l: License): 'warn' | 'stop' | null {
  if (l.edition !== 'enterprise') return null
  if (!l.present) return 'warn'
  switch (l.state) {
    case 'active': return null
    case 'warning': return 'warn'
    default: return 'stop'
  }
}

function headline(l: License) {
  if (!l.present) return 'No licence is installed'
  switch (l.state) {
    case 'warning': return 'This licence needs attention'
    case 'lapsed': return 'The paid features are locked'
    default: return 'This licence was refused'
  }
}

export default function LicenseBanner() {
  const [lic, setLic] = useState<License | null>(null)
  const [dismissed, setDismissed] = useState(readDismissed)

  useEffect(() => {
    let live = true
    getLicense().then(l => { if (live) setLic(l) }).catch(() => { /* older engine, or none */ })
    return () => { live = false }
  }, [])

  if (!lic) return null
  const t = tone(lic)
  if (!t) return null

  // Keyed to what it says, so dismissing "expires in 9 days" does not also
  // silence "activated on a different machine".
  const key = `${lic.state}:${lic.reason}`
  if (t === 'warn' && dismissed === key) return null

  const close = () => { writeDismissed(key); setDismissed(key) }
  return (
    <div className={'lic-banner ' + t} role={t === 'stop' ? 'alert' : 'status'}>
      <div className="lic-text">
        <b>{headline(lic)}</b>
        {lic.present && lic.reason && <span className="lic-reason">{lic.reason}</span>}
        {lic.action && <span className="lic-action">{lic.action}</span>}
        {lic.expires && lic.state === 'active' && (
          <span className="lic-reason">Runs to {new Date(lic.expires).toLocaleDateString()}</span>
        )}
      </div>
      <div className="lic-side">
        <code>{BRAND.cli} license show</code>
        {t === 'warn' && (
          <button className="icon-btn" onClick={close} aria-label="Dismiss this notice">×</button>
        )}
      </div>
    </div>
  )
}
