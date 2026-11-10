// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef } from 'react'

// Run fn now and then every ms, for a page showing something that changes.
//
// setInterval does not know whether the last request came back: with a slow
// server the requests stack up, which makes the server slower, and every open
// tab did this whether anyone was looking at it or not. So the next poll is
// timed from the end of the last one, and a hidden tab does not poll at all and
// catches up the moment it is shown again.
//
// fn reports its own errors; one that throws anyway does not stop the polling.
export function usePolling(fn: () => unknown, ms: number) {
  const latest = useRef(fn)
  latest.current = fn

  useEffect(() => {
    let stopped = false
    let running = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const tick = async () => {
      if (stopped || running || document.hidden) return
      running = true
      try {
        await latest.current()
      } catch {
        // fn's to report
      }
      running = false
      if (!stopped && !document.hidden) timer = setTimeout(tick, ms)
    }
    const onVisibility = () => {
      if (document.hidden) return
      clearTimeout(timer)
      tick()
    }

    document.addEventListener('visibilitychange', onVisibility)
    tick()
    return () => {
      stopped = true
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [ms])
}
