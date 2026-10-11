# FoxByte — TypeScript client

A thin, dependency-free client for the FoxByte control-plane REST API (uses the
built-in `fetch`). Apache-2.0.

```bash
npm install ./clients/typescript    # from a checkout
```

Node 18 or newer, a browser, Deno or Bun — anything with `fetch`. Not on the
npm registry: install it from the repository.

```ts
import { FoxByte } from "@foxbyte/client"

const db = new FoxByte("key_…")            // API key
await db.createBranch("qa")
console.log(await db.query("qa", "select 1"))
console.log(await db.verifyBlackbox("qa"))   // tamper-evidence check (verifyLedger() still works)
```

> The engine serves a self-signed cert by default. In Node, point at a host with
> a real cert, or set `NODE_TLS_REJECT_UNAUTHORIZED=0` for local development only.

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
