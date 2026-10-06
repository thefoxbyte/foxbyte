// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { getStatus, has, type Feature, type Status } from './api'

// Which paid features this engine can actually serve, for the pages that show a
// control locked rather than hidden.
//
// Two rules live here so no page has to remember them.
//
// **Unknown is not refused.** Until /api/status answers — and on an engine too
// old to have the field at all — every feature reads as available. A newer
// console must not disable the controls of an older engine; the engine refuses
// for itself, with a message, and that is the authority.
//
// **The edition is reported too**, because the two reasons a feature is missing
// need different sentences: a Standard install needs a different binary, an
// Enterprise one needs a licence. One is a download, the other a purchase.
export function useFeatures() {
  const [status, setStatus] = useState<Status | null>(null)
  useEffect(() => { getStatus().then(setStatus).catch(() => setStatus(null)) }, [])
  return {
    can: (f: Feature) => !status || has(status, f),
    // null until the engine answers, so a page can wait before saying anything.
    edition: status?.edition ?? null,
  }
}

// why explains a locked control in one sentence, naming the way out.
export function why(edition: 'standard' | 'enterprise' | null, what: string) {
  if (edition === 'enterprise') return `${what} needs a licence covering it — run \`fox license activate <file>\`.`
  return `${what} is part of Enterprise, and this is the standard edition.`
}
