// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import { getBranches, type Branch } from './api'

// The branch list, for the pages whose controls are built from it.
//
// Every one of them used to load it once and swallow the failure:
//
//   useEffect(() => { getBranches().then(setBranches).catch(() => {}) }, [])
//
// One dropped request then left the page permanently unusable and said nothing
// about it — the selectors stayed empty, the buttons did nothing, and only a
// manual reload fixed it. That is not hypothetical: the engine runs short-lived
// containers on a Docker bridge, and Chromium aborts requests in flight when the
// host's network interfaces change (net::ERR_NETWORK_CHANGED), which is exactly
// how the console's own promotion test failed in CI on 29 Sep 2026.
//
// So a dropped list is retried, and a list that truly cannot be loaded says so
// rather than leaving a page that looks fine and is not.
const attempts = 3
const backoffMs = [300, 1200]

export function useBranches() {
  const [branches, setBranches] = useState<Branch[]>([])
  const [error, setError] = useState('')
  // A page can be left before the retries finish; setting state then is a leak
  // and a React warning.
  const live = useRef(true)
  useEffect(() => () => { live.current = false }, [])

  const reload = useCallback(async () => {
    let last: unknown
    for (let i = 0; i < attempts; i++) {
      try {
        const bs = await getBranches()
        if (!live.current) return
        setBranches(bs)
        setError('')
        return
      } catch (e) {
        last = e
        if (i < attempts - 1) {
          await new Promise(r => setTimeout(r, backoffMs[i] ?? backoffMs[backoffMs.length - 1]))
          if (!live.current) return
        }
      }
    }
    if (!live.current) return
    setError(`Could not load the branch list: ${(last as Error)?.message ?? 'unknown error'}. Reload the page.`)
  }, [])

  useEffect(() => { void reload() }, [reload])

  return { branches, branchesError: error, reloadBranches: reload }
}
