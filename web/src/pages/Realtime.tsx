// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError, createRealtimeKey, disableRealtimeTable, enableRealtimeTable,
  getRealtimeActivity, listRealtimeKeys, listRealtimeTables, prepareRealtimeTable,
  revokeRealtimeKey, streamChanges,
  type RealtimeActivity, type RealtimeEvent, type RealtimeKey, type RealtimeVerdict,
} from '../api'
import { useBranches } from '../useBranches'
import { useFeatures, why } from '../features'
import { useConfirm } from '../confirm'

// Realtime, as a place rather than a viewer.
//
// This page used to say, in a comment, that tables are chosen with
// `fox realtime enable` "because that is a decision with refusals attached — and
// a console button would have to reproduce every one of them". That was true of
// a gate. The readiness work turned each refusal into a verdict carrying the
// exact statements and their cost, so a button reproduces nothing: it runs what
// the verdict already says, and shows the one statement that has a price before
// running it.
//
// Three questions, in the order somebody actually has them:
//
//   1. what can stream, and what would it take        — Tables
//   2. how does my application connect                — Keys
//   3. is it working, and what is it saying            — Feed
//
// The last of those is the old page, unchanged in behaviour.

const MAX_ROWS = 200

export default function Realtime() {
  const { branches } = useBranches()
  const { can, edition } = useFeatures()
  const licensed = can('realtime')
  const [branch, setBranch] = useState('main')

  return (
    <div className="fade-up">
      <h1>Realtime</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Row-level changes as they are committed, decoded from the write-ahead log. Choose what
        streams, hand an application a connection string, and watch it work.
      </p>

      {edition && !licensed && (
        <p className="muted" style={{ marginTop: -6, fontSize: 13 }}>
          {why(edition, 'The change feed')} Everything else on this install is unaffected.
        </p>
      )}

      <div className="row" style={{ flexWrap: 'wrap', gap: 10, marginBottom: 4 }}>
        <span className="muted" style={{ fontSize: 13 }}>Branch</span>
        <select aria-label="Branch" value={branch} onChange={e => setBranch(e.target.value)}>
          {(branches.length ? branches : [{ name: 'main' } as { name: string }])
            .map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
      </div>

      <Activity branch={branch} licensed={licensed} />
      <Tables branch={branch} licensed={licensed} edition={edition} />
      <Keys branch={branch} licensed={licensed} />
      <Feed branch={branch} licensed={licensed} edition={edition} />
    </div>
  )
}

// ---------------------------------------------------------------- activity

// What staying warm has cost.
//
// The feed chose the warm model over a cold start, because a cold start defeats
// the point of realtime — a subscribed branch is therefore never suspended. That
// was the right trade and it is not a free one, and until now nothing in the
// product said for how long a branch had been up or whether anything had used
// it in that time. A forgotten tab and a busy application looked identical.
function Activity({ branch, licensed }: { branch: string; licensed: boolean }) {
  const [a, setA] = useState<RealtimeActivity | null>(null)
  const [cost, setCost] = useState('')
  const [maxSubs, setMaxSubs] = useState(0)
  const [missing, setMissing] = useState(false)

  const load = useCallback(async () => {
    try {
      const r = await getRealtimeActivity(branch)
      if (!r?.activity) throw new Error('no activity in the response')
      setA(r.activity)
      setCost(r.cost ?? '')
      setMaxSubs(typeof r.max_subscribers === 'number' ? r.max_subscribers : 0)
      setMissing(false)
    } catch {
      // Quiet on purpose. The licence and the not-set-up cases are already
      // explained by the Tables panel below, and a second copy of the same
      // sentence on the same screen is noise.
      setA(null)
      setMissing(true)
    }
  }, [branch])

  useEffect(() => { if (licensed) void load() }, [load, licensed])

  if (!licensed || missing || !a) return null

  return (
    <section className="panel" style={{ marginTop: 18 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h2 style={{ marginTop: 0, marginBottom: 6 }}>What this is costing</h2>
        <button className="ghost" onClick={() => void load()}>Refresh</button>
      </div>

      <p style={{ marginTop: 0 }} data-testid="realtime-cost">{cost}</p>

      {/* Each figure is one text node rather than a number wrapped in <strong>
          inside a sentence. Splitting a sentence across elements for emphasis
          makes it unreadable to anything that reads text — a screen reader, a
          test — for the sake of a bold digit. */}
      <div className="row" style={{ gap: 24, flexWrap: 'wrap', fontSize: 13 }}>
        {a.warm && <span data-testid="rt-subscribers">{subscriberLine(a, maxSubs)}</span>}
        <span data-testid="rt-tables">
          {a.tables_streaming} table{a.tables_streaming === 1 ? '' : 's'} streaming
        </span>
        {a.warm && <span data-testid="rt-events">{a.events_delivered.toLocaleString()} events delivered</span>}
      </div>

      {/* Transactions, said as transactions. Without pg_stat_statements — not
          loaded, and loading it costs a restart — this is what Postgres counts,
          and calling it "queries" would be a word that is not true about a
          number somebody may bill from. */}
      <p className="muted" data-testid="rt-measured" style={{ marginBottom: 0, marginTop: 10, fontSize: 13 }}>
        {a.measured
          ? measuredLine(a.measured)
          : 'Not enough readings yet to say how much work happened — they are taken on a timer.'}
      </p>

      {a.slots && a.slots.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 14 }}>
          <table>
            <thead><tr><th>Bookmark</th><th>State</th><th>Holding</th><th>Before it is dropped</th></tr></thead>
            <tbody>
              {a.slots.map(s => (
                <tr key={s.slot}>
                  <td><code>{s.slot}</code></td>
                  <td>{s.status === 'lost' ? 'lost' : s.active ? 'streaming' : 'idle'}</td>
                  <td>{bytes(s.held_bytes)}</td>
                  {/* The number that turns "a subscriber went away" into
                      something to act on before the disk does it for you. */}
                  <td>{s.safe_bytes > 0 ? bytes(s.safe_bytes) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {a.notes?.map((n, i) => (
        <p key={i} className="muted" style={{ marginBottom: 0, marginTop: 8, fontSize: 13 }}>Note: {n}</p>
      ))}
    </section>
  )
}

function subscriberLine(a: RealtimeActivity, maxSubs: number) {
  const of = maxSubs ? ` of ${maxSubs}` : ''
  const peak = a.peak_subscribers > a.subscribers ? ` (${a.peak_subscribers} at most so far)` : ''
  return `${a.subscribers}${of} subscribers${peak}`
}

// Transactions, said as transactions. Without pg_stat_statements — not loaded,
// and loading it costs a restart — this is what Postgres counts, and calling it
// "queries" would be a word that is not true about a number somebody may bill
// from.
function measuredLine(m: NonNullable<RealtimeActivity['measured']>) {
  return `Over the last ${m.over} (${m.samples} readings): `
    + `${m.transactions.toLocaleString()} transactions `
    + `(${Math.round(m.transactions_per_day).toLocaleString()}/day), `
    + `${m.rows_returned.toLocaleString()} rows returned.`
}

function bytes(n: number) {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GB`
  if (n >= 1 << 20) return `${Math.round(n / (1 << 20))} MB`
  if (n >= 1 << 10) return `${Math.round(n / (1 << 10))} kB`
  return `${n} B`
}

// ---------------------------------------------------------------- tables

function Tables({ branch, licensed, edition }: {
  branch: string; licensed: boolean; edition: 'standard' | 'enterprise' | null
}) {
  const confirm = useConfirm()
  const [rows, setRows] = useState<RealtimeVerdict[] | null>(null)
  const [withheld, setWithheld] = useState(0)
  const [err, setErr] = useState('')
  // The engine not being set up is not an error to apologise for, it is a
  // single command away — kept apart from err so it can be said differently.
  const [setup, setSetup] = useState('')
  const [busy, setBusy] = useState('')

  const load = useCallback(async () => {
    setErr('')
    setSetup('')
    try {
      const r = await listRealtimeTables(branch)
      // Checked rather than trusted. `rows` is rendered with `rows.length`, so
      // anything that is not an array crashes the page — and the engine is not
      // the only thing that can answer: a route missing from this build falls
      // through to the console's own catch-all. req() now refuses that, and
      // this is the second line of defence, because a page that cannot render
      // is a worse failure than a page that says it found nothing.
      setRows(Array.isArray(r?.tables) ? r.tables : [])
      setWithheld(typeof r?.withheld === 'number' ? r.withheld : 0)
    } catch (e) {
      setRows([])
      if (e instanceof ApiError && e.status === 409) {
        setSetup(e.message)
      } else if (e instanceof ApiError && e.status === 403) {
        // Expected, and already explained. useFeatures treats an unanswered
        // /api/status as "available" on purpose — a newer console must not
        // disable an older engine's controls — so the first render of this
        // panel asks before it knows, and on a Standard install the answer is
        // a refusal. Showing it as an error would put a raw 403 next to the
        // sentence that already says why the feature is locked.
      } else {
        setErr((e as Error).message)
      }
    }
  }, [branch])

  useEffect(() => { if (licensed) void load() }, [load, licensed])

  // act runs one table's change and redraws just that row from the verdict the
  // server returns, so the list cannot disagree with what happened.
  const act = async (v: RealtimeVerdict, fn: () => Promise<{ table?: RealtimeVerdict }>) => {
    const key = qualified(v)
    setBusy(key)
    setErr('')
    try {
      const res = await fn()
      if (res.table) {
        setRows(prev => (prev ?? []).map(p => (qualified(p) === key ? res.table! : p)))
      } else {
        await load()
      }
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy('')
    }
  }

  const start = (v: RealtimeVerdict) =>
    act(v, () => enableRealtimeTable(branch, { schema: v.table.schema, table: v.table.name }))

  const stop = (v: RealtimeVerdict) =>
    act(v, () => disableRealtimeTable(branch, { schema: v.table.schema, table: v.table.name }))

  // The only action that asks first, and it asks with the number in it.
  //
  // A free fix is a grant or an index-backed identity: running it is the whole
  // decision, and a dialog would be ceremony. A costly one is REPLICA IDENTITY
  // FULL, which doubles what a table writes to the WAL for as long as it
  // exists — a bill, not a step — so the cost the engine measured goes in the
  // dialog, and cancelling is the default.
  const prepare = async (v: RealtimeVerdict) => {
    const costly = (v.fixes ?? []).filter(f => f.cost)
    if (costly.length) {
      const ok = await confirm({
        title: `Prepare ${qualified(v)}?`,
        danger: true,
        confirmText: 'Run it anyway',
        message: (
          <div>
            <p style={{ marginTop: 0 }}>
              One of these changes has an ongoing cost, not a one-off one:
            </p>
            {costly.map((f, i) => (
              <p key={i} style={{ margin: '6px 0' }}>
                <code>{f.sql}</code><br />
                <span className="muted">{f.cost}</span>
              </p>
            ))}
            {v.alternatives?.length ? (
              <p className="muted" style={{ marginBottom: 0 }}>
                Instead: {v.alternatives.join('; ')}
              </p>
            ) : null}
          </div>
        ),
      })
      if (!ok) return
    }
    await act(v, async () => {
      const r = await prepareRealtimeTable(branch, {
        schema: v.table.schema, table: v.table.name, apply: true,
      })
      return { table: r.table }
    })
  }

  if (!licensed) {
    return (
      <section className="panel" style={{ marginTop: 18 }}>
        <h2 style={{ marginTop: 0 }}>Tables</h2>
        <p className="muted" style={{ margin: 0 }}>{why(edition, 'Choosing what streams')}</p>
      </section>
    )
  }

  return (
    <section className="panel" style={{ marginTop: 18 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h2 style={{ marginTop: 0, marginBottom: 8 }}>Tables</h2>
        <button className="ghost" onClick={() => void load()}>Refresh</button>
      </div>

      {setup && (
        <div className="panel" style={{ marginBottom: 12 }}>
          <p style={{ marginTop: 0 }}>{setup}</p>
          <p className="muted" style={{ marginBottom: 0, fontSize: 13 }}>
            It turns on logical decoding and restarts <code>main</code>, which drops connections
            for a few seconds. Nothing else on this install changes, and{' '}
            <code>fox realtime teardown</code> undoes it.
          </p>
        </div>
      )}
      {err && <div className="err" style={{ marginBottom: 12 }}>{err}</div>}

      {rows === null
        ? <p className="muted" style={{ margin: 0 }}>Looking…</p>
        : rows.length === 0 && !setup
          ? <p className="muted" style={{ margin: 0 }}>No application tables on this branch yet.</p>
          : rows.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Table</th><th>State</th><th>Detail</th><th /></tr>
                </thead>
                <tbody>
                  {rows.map(v => (
                    <TableRow key={qualified(v)} v={v} busy={busy === qualified(v)}
                      onStart={() => void start(v)} onStop={() => void stop(v)}
                      onPrepare={() => void prepare(v)} />
                  ))}
                </tbody>
              </table>
            </div>
          )}

      {/* Withheld, not silently absent: "nothing else is here" and "tables are
          here and they are not yours to stream" are different answers. */}
      {withheld > 0 && (
        <p className="muted" style={{ marginBottom: 0, marginTop: 10, fontSize: 13 }}>
          {withheld} table{withheld === 1 ? '' : 's'} not shown — they belong to FoxByte, to
          Postgres or to an extension, and a subscriber is never offered them.
        </p>
      )}
    </section>
  )
}

const qualified = (v: RealtimeVerdict) => `${v.table.schema}.${v.table.name}`

function TableRow({ v, busy, onStart, onStop, onPrepare }: {
  v: RealtimeVerdict; busy: boolean
  onStart: () => void; onStop: () => void; onPrepare: () => void
}) {
  const fixes = v.fixes ?? []
  const costly = fixes.some(f => f.cost)
  return (
    <tr>
      <td><code>{qualified(v)}</code></td>
      <td><span className={`tag ${stateClass(v.status)}`}>{v.status}</span></td>
      <td className="muted" style={{ fontSize: 13 }}>
        {v.status === 'needs changes' && (
          <>
            {fixes.length} change{fixes.length === 1 ? '' : 's'} needed
            {costly && <strong> — one has an ongoing cost</strong>}
            <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
              {fixes.map((f, i) => (
                <li key={i}><code>{f.sql}</code>{f.cost ? <> <span className="warn">({f.cost})</span></> : null}</li>
              ))}
            </ul>
          </>
        )}
        {v.status === 'cannot stream' && (v.reason || '')}
        {v.status === 'streaming' && 'subscribers receive its changes'}
        {v.status === 'ready' && (v.table.has_primary_key
          ? 'has a primary key'
          : v.table.unique_index
            ? `identified by ${v.table.unique_index}`
            : 'ready')}
      </td>
      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
        {busy && <span className="muted" style={{ fontSize: 13 }}>working…</span>}
        {!busy && v.status === 'ready' && <button className="primary" onClick={onStart}>Start streaming</button>}
        {!busy && v.status === 'streaming' && <button className="ghost" onClick={onStop}>Stop</button>}
        {!busy && v.status === 'needs changes' && (
          <button className={costly ? 'ghost' : 'primary'} onClick={onPrepare}>
            {costly ? 'Prepare…' : 'Prepare'}
          </button>
        )}
      </td>
    </tr>
  )
}

function stateClass(status: RealtimeVerdict['status']) {
  switch (status) {
    case 'streaming': return 'ok'
    case 'ready': return 'ok'
    case 'needs changes': return 'warn'
    default: return 'bad'
  }
}

// ---------------------------------------------------------------- keys

function Keys({ branch, licensed }: { branch: string; licensed: boolean }) {
  const confirm = useConfirm()
  const [keys, setKeys] = useState<RealtimeKey[]>([])
  const [label, setLabel] = useState('')
  const [url, setUrl] = useState('')
  const [err, setErr] = useState('')
  const [copied, setCopied] = useState(false)

  const load = useCallback(async () => {
    try {
      const r = await listRealtimeKeys(branch)
      setKeys(Array.isArray(r?.keys) ? r.keys : [])
    } catch { setKeys([]) }
  }, [branch])

  // A branch change must not leave the previous branch's connection string on
  // screen: it is a secret, and it is the wrong one.
  useEffect(() => { setUrl(''); setCopied(false); if (licensed) void load() }, [load, licensed])

  const mint = async () => {
    setErr('')
    try {
      const r = await createRealtimeKey(branch, label.trim() || 'app')
      setUrl(r.url)
      setCopied(false)
      setLabel('')
      await load()
    } catch (e) { setErr((e as Error).message) }
  }

  const revoke = async (k: RealtimeKey) => {
    const ok = await confirm({
      title: `Revoke ${k.name}?`,
      danger: true,
      confirmText: 'Revoke',
      message: 'Anything subscribing with this key stops at its next connection. This cannot be undone.',
    })
    if (!ok) return
    setErr('')
    try { await revokeRealtimeKey(branch, k.id); await load() } catch (e) { setErr((e as Error).message) }
  }

  if (!licensed) return null

  return (
    <section className="panel" style={{ marginTop: 18 }}>
      <h2 style={{ marginTop: 0, marginBottom: 4 }}>Connecting an application</h2>
      <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
        A realtime key subscribes to this branch and does nothing else: not the control plane, not
        SQL through the gateway, not another branch. Put the connection string where your
        application reads secrets from.
      </p>

      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <input aria-label="Key name" placeholder="what will use it (e.g. checkout-service)"
          value={label} onChange={e => setLabel(e.target.value)} style={{ minWidth: 260 }} />
        <button className="primary" onClick={() => void mint()}>Create key</button>
      </div>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {/* Shown once, and said to be. The secret is hashed on the way in, so
          this is the only moment it exists anywhere but the subscriber's own
          configuration — a page that implied otherwise would cost somebody a
          re-mint at the wrong time. */}
      {url && (
        <div className="panel" style={{ marginTop: 12 }}>
          <p style={{ marginTop: 0, marginBottom: 6 }}>
            <strong>Copy this now — it is shown once.</strong>
          </p>
          <code data-testid="realtime-dsn" style={{ wordBreak: 'break-all', display: 'block', marginBottom: 8 }}>{url}</code>
          <button className="ghost" onClick={() => {
            void navigator.clipboard?.writeText(url).then(() => setCopied(true)).catch(() => setCopied(false))
          }}>{copied ? 'Copied' : 'Copy'}</button>
        </div>
      )}

      {keys.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 14 }}>
          <table>
            <thead><tr><th>Name</th><th>Key</th><th>Created</th><th /></tr></thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td><code className="muted">{k.prefix}…</code></td>
                  <td className="muted">{new Date(k.created * 1000).toLocaleString()}</td>
                  <td style={{ textAlign: 'right' }}>
                    <button className="ghost" onClick={() => void revoke(k)}>Revoke</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------- feed

function Feed({ branch, licensed, edition }: {
  branch: string; licensed: boolean; edition: 'standard' | 'enterprise' | null
}) {
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
  // And when the branch changes, or the feed would still be the old one's.
  useEffect(() => { disconnect(); setEvents([]); setNote('') }, [branch, disconnect])

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
      // Asked for, so the boundaries are visible here. A person checking that
      // two rows moved together has no other way to see it, and the feed is
      // where they would look.
      transactions: true,
      onClose: reason => {
        setLive(false)
        if (reason) setNote(reason)
      },
    })
  }

  return (
    <section className="panel" style={{ marginTop: 18 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap' }}>
        <h2 style={{ marginTop: 0, marginBottom: 8 }}>Feed</h2>
        <div className="row" style={{ gap: 10 }}>
          {live && <span className="muted" style={{ fontSize: 13 }}>listening…</span>}
          {live
            ? <button className="ghost" onClick={disconnect}>Stop</button>
            : <button className="primary" onClick={connect} disabled={!licensed}
                title={licensed ? undefined : why(edition, 'The change feed')}>
                {licensed ? 'Watch' : 'Watch (Enterprise)'}
              </button>}
        </div>
      </div>

      {note && <div className="err" style={{ marginBottom: 12 }}>{note}</div>}

      {events.length === 0
        ? <p className="muted" style={{ margin: 0 }}>
            {live
              ? 'Connected. Nothing has changed yet — run an INSERT or UPDATE on a streaming table.'
              : 'Not watching.'}
          </p>
        : <div className="table-wrap">
            <table>
              <thead><tr><th>Table</th><th>Action</th><th>Identity</th><th>Changed</th><th>Position</th></tr></thead>
              <tbody>
                {events.map((e, i) => <EventRow key={i} e={e} />)}
              </tbody>
            </table>
          </div>}
    </section>
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
  // The frames. Rendered as boundaries rather than as rows of data, because
  // what they carry is "these changes belong together" — the one thing a list
  // of changes cannot say on its own.
  //
  // No box-drawing characters, and the rule sits on the commit. This list is
  // newest-first, so a transaction arrives as commit, then its changes, then
  // its begin: a ┌ above and a └ below would have been upside down, and a rule
  // on the begin would have separated a transaction from its own changes
  // instead of from the newer ones above it. The xid ties the pair together
  // without relying on their order.
  if (e.type === 'commit') {
    return (
      <tr data-testid="tx-commit">
        <td colSpan={5} className="muted" style={{ fontSize: 12, borderTop: '2px solid var(--border)' }}>
          transaction {e.xid} committed {e.changes} change{e.changes === 1 ? '' : 's'}
          {' '}· resume from <code>{e.commit_lsn}</code>
          {e.at ? ` · ${new Date(e.at).toLocaleTimeString()}` : ''}
        </td>
      </tr>
    )
  }
  if (e.type === 'begin') {
    return (
      <tr data-testid="tx-begin">
        <td colSpan={5} className="muted" style={{ fontSize: 12 }}>
          transaction {e.xid} began
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
