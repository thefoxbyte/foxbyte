// Commit-to-subscriber latency, in one process, using the official client.
//
// "After the gateway returned" starts when the INSERT comes back, which is
// after the commit, and stops when subscribe() delivers the transaction.
// If the feed wins that race the sample is 0, and "from sending" still shows
// the time from just before the statement to the same delivery, which includes
// the commit.
//
// A default install's certificate is self-signed. This file trusts it for the
// local engine only, the same decision the client leaves to the caller.

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

import pg from "pg"
import { subscribe } from "@foxbyte/client"

const n = Number(process.env.N || 50)
const branch = process.env.FOX_BRANCH || "main"
const key = process.env.FOX_REALTIME_KEY
const apiKey = process.env.FOX_API_KEY
if (!key || !apiKey) {
  console.error("FOX_API_KEY and FOX_REALTIME_KEY are required")
  process.exit(1)
}

const pool = new pg.Pool({
  host: process.env.FOX_GATEWAY_HOST || "127.0.0.1",
  port: Number(process.env.FOX_GATEWAY_PORT || 6432),
  user: process.env.FOX_DB_USER || "dbadmin",
  password: apiKey,
  database: branch,
  max: 2,
  ssl: { rejectUnauthorized: false },
})

const fox = new URL(process.env.FOX_API || "https://127.0.0.1:8080")
const realtimeUrl = `fox-realtime://${encodeURIComponent(key)}@${fox.host}/${encodeURIComponent(branch)}`

const pending = new Map()
const sub = subscribe(realtimeUrl, {
  onTransaction(tx) {
    for (const c of tx.changes) {
      const title = c.new && c.new.title
      const hit = title && pending.get(title)
      if (!hit) continue
      pending.delete(title)
      hit(process.hrtime.bigint())
    }
  },
  onError(err) { console.error("stream:", err.message) },
})

await new Promise((r) => setTimeout(r, 800))

const after = []
const fromSend = []
for (let i = 1; i <= n; i++) {
  const title = `probe ${i} ${Math.random().toString(36).slice(2, 8)}`
  const seen = new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      pending.delete(title)
      reject(new Error("no event for " + title))
    }, 8000)
    pending.set(title, (at) => { clearTimeout(t); resolve(at) })
  })
  const sent = process.hrtime.bigint()
  await pool.query(`INSERT INTO public.todos (title) VALUES ($1)`, [title])
  const acked = process.hrtime.bigint()
  const at = await seen
  after.push(ms(at - acked))
  fromSend.push(ms(at - sent))
}

sub.close()
await pool.end()

function ms(ns) { return Math.max(0, Number(ns) / 1e6) }

function pct(sorted, p) {
  const rank = Math.ceil((p / 100) * sorted.length)
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))]
}

function report(label, samples) {
  const s = [...samples].sort((a, b) => a - b)
  const line = {
    n: s.length,
    p50_ms: round(pct(s, 50)),
    p95_ms: round(pct(s, 95)),
    min_ms: round(s[0]),
    max_ms: round(s[s.length - 1]),
  }
  console.log(`${label}: n=${line.n} p50=${line.p50_ms}ms p95=${line.p95_ms}ms min=${line.min_ms}ms max=${line.max_ms}ms`)
  return line
}

function round(n) { return Math.round(n * 10) / 10 }

const out = {
  branch,
  after_gateway_returned_commit: report("after the gateway returned the commit", after),
  from_sending_the_statement: report("from sending the statement, which includes the commit", fromSend),
}
console.log(JSON.stringify(out))
