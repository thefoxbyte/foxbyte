# FoxByte — TypeScript client

A thin, dependency-free client for the FoxByte control-plane REST API (uses the
built-in `fetch`). Apache-2.0.

```ts
import { FoxByte } from "@foxbyte/client"

const db = new FoxByte("key_…")            // API key
await db.createBranch("qa")
console.log(await db.query("qa", "select 1"))
console.log(await db.verifyBlackbox("qa"))   // tamper-evidence check (verifyLedger() still works)
```

> The engine serves a self-signed cert by default. In Node, point at a host with
> a real cert, or set `NODE_TLS_REJECT_UNAUTHORIZED=0` for local development only.

The full API is described by the OpenAPI spec at `GET /api/openapi.yaml`.
