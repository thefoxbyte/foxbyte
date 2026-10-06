// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import { streamChanges, type RealtimeEvent } from '../api'
import { useBranches } from '../useBranches'
import { useFeatures, why } from '../features'

// The change feed, watched live.
//
// A viewer rather than a tool: it answers "is the feed working, and what is it
// saying", which is the question somebody has while wiring a subscriber up.
// Tables are chosen with `fox realtime enable`, because that is a decision with
// refusals attached — a table with no primary key, or with row-level security —
// and a console button would have to reproduce every one of them.

const MAX_ROWS = 200

export default function Realtime() {
  const { branches } = useBranches()
  const { can, edition } = useFeatures()
  const licensed = can('realtime')

  const [branch, setBranch] = useState('main')
  const [events, setEvents] = useState<RealtimeEvent[]>([])
  const [live, setLive] = useState(false)
  const [note, setNote] = useState('')
  const stop = useRef<(() => void) | null>(null)

  const disconnect = useCallback(() => {
    stop.current?.()
    stop.current = null
    setLive(false)
  }, [])

  // Always let go of the stream when the page does: a connection left open
  // holds a replication slot, and a slot holds WAL.
  useEffect(() => disconnect, [disconnect])

  const connect = () => {
    disconnect()
    setEvents([])
    setNote('')
    setLive(true)
    stop.current = streamChanges(branch, e => {
      setEvents(prev => {
        // Newest first, and bounded: a busy table would otherwise grow the DOM
        // until the tab gives up.
        const next = [e, ...prev]
        return next.length > MAX_ROWS ? next.slice(0, MAX_ROWS) : next
      })
      if (e.type === 'resync' || e.type === 'error') setNote(e.detail || e.code || '')
    }, {
      onClose: reason => {
        setLive(false)
        if (reason) setNote(reason)
      },
    })
  }

  const options = branches.length ? branches : [{ name: 'main' } as { name: string }]

  return (
    <div className="fade-up">
      <h1>Change feed</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Row-level changes as they are committed, decoded from the write-ahead log. Choose which
        tables are streamed with <code>fox realtime enable</code>, which refuses the ones a feed
        cannot carry safely.
      </p>

      {edition && !licensed && (
        <p className="muted" style={{ marginTop: -6, fontSize: 13 }}>
          {why(edition, 'The change feed')} Everything else on this install is unaffected.
        </p>
      )}

      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <span className="muted" style={{ fontSize: 13 }}>Branch</span>
        <select value={branch} onChange={e => setBranch(e.target.value)} disabled={live}>
          {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
        {live
          ? <button className="ghost" onClick={disconnect}>Stop</button>
          : <button className="primary" onClick={connect} disabled={!licensed}
              title={licensed ? undefined : why(edition, 'The change feed')}>
              {licensed ? 'Watch' : 'Watch (Enterprise)'}
            </button>}
        {live && <span className="muted" style={{ fontSize: 13 }}>listening…</span>}
      </div>

      {note && <div className="err" style={{ marginTop: 14 }}>{note}</div>}

      <div className="panel" style={{ marginTop: 18 }}>
        {events.length === 0
          ? <p className="muted" style={{ margin: 0 }}>
              {live
                ? 'Connected. Nothing has changed yet — run an INSERT or UPDATE on a streamed table.'
                : 'Not watching.'}
            </p>
          : <table className="tbl">
              <thead><tr><th>Table</th><th>Action</th><th>Identity</th><th>Changed</th><th>Position</th></tr></thead>
              <tbody>
                {events.map((e, i) => <EventRow key={i} e={e} />)}
              </tbody>
            </table>}
      </div>
    </div>
  )
}

function EventRow({ e }: { e: RealtimeEvent }) {
  if (e.type === 'schema') {
    return (
      <tr>
        <td><code>{e.table}</code></td>
        <td colSpan={4} className="muted">
          shape: {e.columns.map(c => c.name + (c.key ? ' (key)' : '')).join(', ')}
        </td>
      </tr>
    )
  }
  if (e.type !== 'change') {
    return <tr><td colSpan={5} className="muted">{e.type}: {e.detail || e.code}</td></tr>
  }
  return (
    <tr>
      <td><code>{e.table}</code></td>
      <td>{e.action}</td>
      <td><code>{Object.entries(e.identity).map(([k, v]) => `${k}=${v ?? 'NULL'}`).join(' ')}</code></td>
      <td>
        {e.changed?.join(', ')}
        {/* Named rather than guessed: a large column an update did not touch is
            absent from `new`, and a client must leave its own copy alone. */}
        {e.unchanged?.length ? <span className="muted"> (not sent: {e.unchanged.join(', ')})</span> : null}
      </td>
      <td><code className="muted">{e.commit_lsn}</code></td>
    </tr>
  )
}
