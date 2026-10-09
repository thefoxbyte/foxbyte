// SPDX-License-Identifier: Apache-2.0

/** Subscribing to a FoxByte branch's change feed.
 *
 * The feed is server-sent events over HTTP, which is simple enough to consume
 * by hand — and there are four things a hand-written subscriber tends to get
 * wrong, each of which costs real data:
 *
 *  1. **A column missing from `new` is not null.** Postgres omits a large
 *     (TOASTed) value an update did not touch, and names it in `unchanged`.
 *     A client that copies `new` over its own row writes null across a value
 *     that never changed. `applyChange` below exists for this.
 *  2. **Resume from a commit, not from a change.** Every change in a
 *     transaction carries the same `commit_lsn`, which is the transaction's
 *     boundary; resuming from it cannot land halfway through a transaction
 *     already applied. This client tracks it and reconnects with `?since=`.
 *  3. **`resync` means start again.** The server says it when a bookmark went
 *     past the write-ahead-log budget. Carrying on from the last position
 *     would leave a silent hole, so the position is dropped and the caller is
 *     told to refetch.
 *  4. **Values are strings.** A bigint or a numeric does not survive a
 *     JavaScript number, so every value arrives as a string, and `null` means
 *     SQL NULL. `""` and `null` are different.
 *
 * Dependency-free, and works anywhere `fetch` does: Node 18+, Deno, Bun, and
 * browsers. */

/** A row, as the feed sends it: Postgres text, or null for SQL NULL. */
export type RealtimeRow = Record<string, string | null>

export interface RealtimeSchema {
  type: "schema"
  table: string
  columns: { name: string; type_oid: number; key: boolean }[]
}

export interface RealtimeChange {
  type: "change"
  table: string
  action: "insert" | "update" | "delete" | "truncate"
  /** The transaction's commit position: the same on every change in it, and
   * the only safe place to resume from. */
  commit_lsn: string
  /** This record's own position, for ordering within a transaction. */
  lsn?: string
  xid?: number
  /** The replica-identity columns — the only row locator promised under every
   * identity setting. Always present. */
  identity: RealtimeRow
  /** The row after the change, for insert and update. A column absent here may
   * be in `unchanged` rather than null. */
  new?: RealtimeRow
  /** The row before it, and only when Postgres sent one: an update or delete
   * under REPLICA IDENTITY FULL. */
  old?: RealtimeRow
  /** The columns whose value differs, and only under FULL where it can be
   * computed truthfully. */
  changed?: string[]
  /** Large columns the update did not touch, which are therefore absent from
   * `new`. Leave your own copy of these alone. */
  unchanged?: string[]
}

export interface RealtimeBegin {
  type: "begin"
  xid: number
  commit_lsn: string
  at?: string
}

export interface RealtimeCommit {
  type: "commit"
  xid: number
  commit_lsn: string
  at?: string
  changes: number
}

export interface RealtimeNotice {
  type: "resync" | "error"
  code?: string
  detail?: string
}

export type RealtimeEvent =
  | RealtimeSchema
  | RealtimeChange
  | RealtimeBegin
  | RealtimeCommit
  | RealtimeNotice

/** One transaction's changes, delivered together. */
export interface RealtimeTransaction {
  xid: number
  /** Where to resume from once this transaction has been applied. */
  commitLsn: string
  /** When it committed, as Postgres recorded it. */
  at?: string
  changes: RealtimeChange[]
}

/** A parsed `fox-realtime://` connection string. */
export interface RealtimeUrl {
  host: string
  branch: string
  key: string
  /** `require` (the default: encrypted, certificate not verified — which is
   * what a default install serves), `verify-full`, or `disable`. */
  sslmode: "require" | "verify-full" | "disable"
}

export class RealtimeError extends Error {}

const SCHEME = "fox-realtime"

/** Parse a connection string.
 *
 * The key is carried in userinfo, where a Postgres URL puts its password, and
 * this client turns it into an `Authorization` header. It never goes in a path
 * or a query string: a URL reaches access logs, browser history and `Referer`,
 * and a key that lands in any of those has to be treated as disclosed. */
export function parseRealtimeUrl(raw: string): RealtimeUrl {
  const text = raw.trim()
  if (!text) throw new RealtimeError("empty realtime URL")
  // Checked before the URL parser, which fails on a bare host:port with a
  // message about path segments and colons that tells nobody anything.
  if (!text.startsWith(`${SCHEME}://`)) {
    throw new RealtimeError(`a realtime URL starts with ${SCHEME}:// (got ${JSON.stringify(raw)})`)
  }
  let u: URL
  try {
    // Re-schemed to http: so the URL parser treats the authority the way it
    // does for a known scheme. Nothing from this is used except its parts.
    u = new URL("http://" + text.slice(`${SCHEME}://`.length))
  } catch {
    throw new RealtimeError(`not a realtime URL: ${JSON.stringify(raw)}`)
  }
  if (!u.port) {
    throw new RealtimeError(
      `no port in ${JSON.stringify(u.hostname || raw)}: expected ${SCHEME}://<key>@host:port/<branch>`,
    )
  }
  // The key may be the username (what `fox realtime key create` prints) or the
  // password (what somebody transcribing a Postgres URL is likely to type).
  const key = decodeURIComponent(u.password || u.username || "")
  const branch = decodeURIComponent(u.pathname.replace(/^\/+|\/+$/g, ""))
  if (!branch) {
    throw new RealtimeError(`no branch in ${JSON.stringify(raw)}: expected ${SCHEME}://<key>@host:port/<branch>`)
  }
  if (branch.includes("/")) {
    throw new RealtimeError(`${JSON.stringify(u.pathname)} names more than one path segment; a realtime URL ends at the branch`)
  }
  const mode = u.searchParams.get("sslmode") ?? "require"
  if (mode !== "require" && mode !== "verify-full" && mode !== "disable") {
    throw new RealtimeError(`sslmode=${JSON.stringify(mode)} is not one of require, verify-full, disable`)
  }
  return { host: u.host, branch, key, sslmode: mode }
}

export interface SubscribeOptions {
  /** Resume from here instead of from now: the `commitLsn` of the last
   * transaction fully applied. Omit to receive only what happens next. */
  since?: string
  /** Receive whole transactions through `onTransaction` as well as individual
   * changes. On by default when `onTransaction` is given. */
  transactions?: boolean
  /** Every event, including the frames and notices, exactly as sent. */
  onEvent?: (e: RealtimeEvent) => void
  /** One change at a time. */
  onChange?: (c: RealtimeChange) => void
  /** One whole transaction at a time, so related changes can be applied
   * together or not at all. Requires the frames, which this turns on. */
  onTransaction?: (tx: RealtimeTransaction) => void
  /** A table's shape, re-sent whenever it changes. */
  onSchema?: (s: RealtimeSchema) => void
  /** The feed could not continue from where this subscriber was: everything
   * held locally is now of unknown age and has to be refetched. The stream
   * carries on from the present moment afterwards. */
  onResync?: (n: RealtimeNotice) => void
  /** A stream ended. Reconnection is automatic; this is for visibility. */
  onError?: (err: Error) => void
  /** Stop reconnecting after this many consecutive failures. 0 means never
   * stop. Default 0. */
  maxRetries?: number
  /** Use this instead of the global `fetch`.
   *
   * The reason it exists: a default install serves a self-signed certificate,
   * which is what `sslmode=require` describes — encrypted, identity not
   * verifiable. A browser's trust store is the user's business and this client
   * does not touch it, but in Node the choice is the caller's to make
   * explicitly. Either set NODE_TLS_REJECT_UNAUTHORIZED=0 for the process, or
   * pass a fetch bound to an undici Agent with
   * `connect: { rejectUnauthorized: false }`. This client will not quietly
   * disable certificate checking on anybody's behalf. */
  fetch?: typeof fetch
}

/** A running subscription. */
export interface Subscription {
  /** Stop, and stop reconnecting. */
  close(): void
  /** Where a reconnect would resume from — the last transaction fully
   * delivered. Persist it to survive a restart of your own process. */
  position(): string | undefined
  /** Resolves when the subscription stops for good. */
  done: Promise<void>
}

/** Subscribe to a branch's change feed.
 *
 * Reconnects on its own, resuming from the last transaction it delivered, so a
 * network blip does not lose changes. It gives up only when `close()` is called
 * or `maxRetries` is reached. */
export function subscribe(url: string | RealtimeUrl, opts: SubscribeOptions = {}): Subscription {
  const dsn = typeof url === "string" ? parseRealtimeUrl(url) : url
  const frames = opts.transactions ?? !!opts.onTransaction
  const ctrl = new AbortController()

  // The resume position, and the rule that makes it safe: it moves to a
  // transaction's boundary only once that transaction has been handed to the
  // caller in full. A position taken mid-transaction would skip the rest of it
  // after a reconnect.
  let position = opts.since
  let stopped = false
  let open: RealtimeTransaction | undefined

  const base = `${dsn.sslmode === "disable" ? "http" : "https"}://${dsn.host}`

  const deliver = (e: RealtimeEvent) => {
    opts.onEvent?.(e)
    switch (e.type) {
      case "schema":
        opts.onSchema?.(e)
        return
      case "begin":
        open = { xid: e.xid, commitLsn: e.commit_lsn, at: e.at, changes: [] }
        return
      case "change":
        opts.onChange?.(e)
        if (open && e.xid === open.xid) open.changes.push(e)
        // Without frames there is no transaction to wait for, so the change's
        // own boundary is the position. With frames the position moves at the
        // commit instead.
        else if (!frames) position = e.commit_lsn
        return
      case "commit":
        if (open && open.xid === e.xid) {
          opts.onTransaction?.({ ...open, at: e.at ?? open.at })
        }
        open = undefined
        position = e.commit_lsn
        return
      case "resync":
        // Everything held locally is of unknown age. Carrying on from the old
        // position would leave a hole that nothing would ever report, so the
        // position is dropped and the caller is told to refetch.
        position = undefined
        open = undefined
        opts.onResync?.(e)
        return
      case "error":
        opts.onError?.(new RealtimeError(e.detail || e.code || "the feed stopped"))
        return
    }
  }

  const done = (async () => {
    let failures = 0
    while (!stopped) {
      try {
        await readStream(base, dsn, frames, position, ctrl.signal, deliver, opts.fetch)
        failures = 0 // a stream that ended cleanly is not a failure
      } catch (err) {
        if (ctrl.signal.aborted) return
        failures++
        opts.onError?.(err instanceof Error ? err : new Error(String(err)))
        if (opts.maxRetries && failures >= opts.maxRetries) return
      }
      if (stopped) return
      // Backoff, capped. A branch that is suspended wakes on the next
      // connection, so retrying is the right move — just not in a tight loop.
      const wait = Math.min(1000 * 2 ** Math.min(failures, 5), 30_000)
      await sleep(wait, ctrl.signal)
    }
  })()

  return {
    close() {
      stopped = true
      ctrl.abort()
    },
    position: () => position,
    done: done.then(() => undefined),
  }
}

async function readStream(
  base: string,
  dsn: RealtimeUrl,
  frames: boolean,
  since: string | undefined,
  signal: AbortSignal,
  deliver: (e: RealtimeEvent) => void,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const q = new URLSearchParams()
  if (since) q.set("since", since)
  if (frames) q.set("transactions", "1")
  const url = `${base}/api/branches/${encodeURIComponent(dsn.branch)}/realtime${q.size ? `?${q}` : ""}`

  const res = await fetchImpl(url, {
    signal,
    headers: {
      // The key goes here and nowhere else.
      Authorization: `Bearer ${dsn.key}`,
      Accept: "text/event-stream",
    },
  })
  if (!res.ok) {
    const body = await res.text().catch(() => "")
    throw new RealtimeError(`${res.status}: ${body || res.statusText}`)
  }
  if (!res.body) throw new RealtimeError("the response carried no stream")

  const reader = res.body.getReader()
  const dec = new TextDecoder()
  let buf = ""
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += dec.decode(value, { stream: true })
    // Frames are separated by a blank line. A partial frame stays in the
    // buffer: splitting on every newline would hand half a JSON object to the
    // parser the moment a message spans two TCP reads, which is routine for a
    // wide row.
    let cut: number
    while ((cut = buf.indexOf("\n\n")) >= 0) {
      const frame = buf.slice(0, cut)
      buf = buf.slice(cut + 2)
      for (const line of frame.split("\n")) {
        if (!line.startsWith("data:")) continue
        const data = line.slice(5).trim()
        if (!data) continue
        let parsed: RealtimeEvent
        try {
          parsed = JSON.parse(data) as RealtimeEvent
        } catch {
          continue // not ours, or truncated: skip rather than kill the stream
        }
        deliver(parsed)
      }
    }
  }
}

/** Apply a change to a row you are keeping, correctly.
 *
 * This is the function the whole module exists for. Postgres omits a large
 * column an update did not touch, so `new` has a hole in it and `unchanged`
 * names it. Copying `new` over your row writes null across a value that never
 * changed — and nothing reports it, because the feed did exactly what it
 * promised.
 *
 * Returns the row after the change, or `undefined` for a delete. */
export function applyChange(row: RealtimeRow | undefined, c: RealtimeChange): RealtimeRow | undefined {
  if (c.action === "delete" || c.action === "truncate") return undefined
  const next: RealtimeRow = { ...(row ?? {}) }
  for (const [k, v] of Object.entries(c.new ?? {})) next[k] = v
  // The identity columns are always sent, and are the row's locator.
  for (const [k, v] of Object.entries(c.identity)) next[k] = v
  // Anything named in `unchanged` keeps the value already held: it was not in
  // `new` because it did not change, not because it became null.
  for (const k of c.unchanged ?? []) {
    if (row && k in row) next[k] = row[k]
    else delete next[k]
  }
  return next
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    const t = setTimeout(resolve, ms)
    const stop = () => {
      clearTimeout(t)
      resolve()
    }
    if (signal.aborted) stop()
    else signal.addEventListener("abort", stop, { once: true })
  })
}
