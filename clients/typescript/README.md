# FoxByte — TypeScript client

A thin, dependency-free client for the FoxByte control-plane REST API (uses the
built-in `fetch`). Apache-2.0.

```bash
npm install @foxbyte/client
```

Node 18 or newer, a browser, Deno or Bun — anything with `fetch`.

```ts
import { FoxByte } from "@foxbyte/client"

const db = new FoxByte("key_…")            // API key
await db.createBranch("qa")
console.log(await db.query("qa", "select 1"))
console.log(await db.verifyBlackbox("qa"))   // tamper-evidence check (verifyLedger() still works)
```

> The engine serves a self-signed cert by default. In Node, point at a host with
> a real cert, or set `NODE_TLS_REJECT_UNAUTHORIZED=0` for local development only.

## Acting for your application's users

When your application changes data on behalf of one of its users, it can say
which: register the application once (`fox app register shop --account
shop-svc@example.com --key shop.pub`), sign a short-lived Ed25519 token for each
user with its private key (any JWT library that does EdDSA, such as `jose`), and
pass it with the change. The Blackbox and row tracking then record the change as
made by your application's account **for** that user, "asserted by" your
application.

```ts
const db = new FoxByte(process.env.FOX_KEY!)   // your application's account key
await db.withActor(token, async (as) => {
  await as.query("main", "UPDATE orders SET status = 'paid' WHERE id = 7")
})
```

Each query in `withActor` is its own transaction that asserts the token first. A
token the engine does not take (expired, another install's, a revoked key) is
refused and nothing runs. `db.query(branch, sql, { actFor: token })` does the
same for one query without refusing: its result's `act_for` says whom it ran
for, or why the token was not taken.

The token travels in the request body and the engine binds it as a parameter,
so it is never in a URL, the SQL text, query history or `pg_stat_statements`.

### With your own Postgres connection

An application connected through the Gateway with a driver of its own (here
node-postgres) can use `withActorTransaction`, which works with any client whose
`query(text, params)` binds parameters:

```ts
import { withActorTransaction } from "@foxbyte/client"
const client = await pool.connect()
try {
  await withActorTransaction(client, token, (c) => c.query("UPDATE orders SET status = $1 WHERE id = $2", ["paid", 7]))
} finally {
  client.release()
}
```

It sends `BEGIN`, `SELECT bb.act_for($1)` with the token as the parameter, your
statements, then `COMMIT`, or `ROLLBACK` if anything throws.

## The change feed (Enterprise)

Subscribe to a branch and be told when rows change. Give an application a
**realtime key** — `fox realtime key create <branch>` — which subscribes to that
one branch and can do nothing else: not the control plane, not SQL through the
gateway, not another branch.

```ts
import { subscribe, applyChange } from "@foxbyte/client"

const rows = new Map<string, Record<string, string | null>>()

const sub = subscribe(process.env.FOX_REALTIME_URL!, {
  since: loadPosition(),          // resume where this process left off
  onTransaction(tx) {
    // One commit, whole. Two rows moved by one transaction arrive together,
    // so nothing you derive from the feed passes through a state where one
    // side moved and the other had not.
    for (const c of tx.changes) {
      const id = c.identity.id!
      const next = applyChange(rows.get(id), c)
      next ? rows.set(id, next) : rows.delete(id)
    }
    savePosition(tx.commitLsn)    // only after the whole commit is applied
  },
  onResync() {
    // The feed could not continue from where we were: everything held is of
    // unknown age, so refetch rather than carry on with a hole.
    rows.clear()
    refetchEverything()
  },
})
```

Four things this handles so you do not have to:

- **A column missing from `new` is not null.** Postgres omits a large (TOASTed)
  value an update did not touch and names it in `unchanged`. Copying `new` over
  your row writes null across a value that never changed, and nothing reports
  it — which is why `applyChange` exists. Use it.
- **Resume from a commit, not a change.** Every change in a transaction carries
  the same `commit_lsn`; `position()` moves only once a whole transaction has
  been handed to you.
- **Reconnects.** The server ends a stream every hour by design; this comes back
  on its own, resuming from the last transaction delivered.
- **Values are strings.** A `bigint` or `numeric` does not survive a JavaScript
  number, so every value is a string and `null` means SQL NULL — `""` and `null`
  are different.

Already holding an API key? `db.subscribe("main", { onChange })` uses it. A
realtime key is the better choice for anything that should only ever read.

> In Node, a default install's self-signed certificate needs a decision from
> you: set `NODE_TLS_REJECT_UNAUTHORIZED=0` for local development, or pass
> `fetch:` bound to an undici `Agent` with `rejectUnauthorized: false`. This
> client will not quietly disable certificate checking on your behalf.

The full API is described by the OpenAPI spec at `GET /api/openapi.yaml`.
