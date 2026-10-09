// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the change-feed subscriber, against the compiled output.
//
//   npm test        (in clients/typescript)
//
// Node's own test runner, so the client stays dependency-free: a library this
// thin should not oblige anyone to install a framework to verify it.
//
// Two of these matter more than the rest, because they are the mistakes the
// module exists to stop a user making:
//
//  * applyChange must leave an unchanged TOASTed column alone. Postgres omits a
//    large value an update did not touch, so `new` has a hole in it — and a
//    client that copies `new` over its row writes null across a value that
//    never changed, with nothing to report it.
//  * the key must never reach a URL. It goes in an Authorization header; a URL
//    reaches access logs, browser history and Referer.
import { test } from "node:test"
import assert from "node:assert/strict"
import { applyChange, parseRealtimeUrl, subscribe, RealtimeError } from "../dist/realtime.js"

test("parses what the CLI prints", () => {
  const u = parseRealtimeUrl("fox-realtime://rtk_abc@127.0.0.1:8080/app")
  assert.equal(u.host, "127.0.0.1:8080")
  assert.equal(u.branch, "app")
  assert.equal(u.key, "rtk_abc")
  assert.equal(u.sslmode, "require")
})

test("accepts the key in the password position too", () => {
  // What somebody transcribing a Postgres URL is likely to type.
  assert.equal(parseRealtimeUrl("fox-realtime://ignored:rtk_abc@127.0.0.1:8080/app").key, "rtk_abc")
})

test("trims whitespace a copy-paste leaves", () => {
  assert.equal(parseRealtimeUrl("  fox-realtime://rtk_abc@127.0.0.1:8080/app\n").branch, "app")
})

test("refuses what cannot be a realtime URL", () => {
  for (const [raw, expect] of [
    ["", "empty"],
    ["postgres://u@h:5432/db", "starts with fox-realtime://"],
    ["127.0.0.1:8080/app", "starts with fox-realtime://"],
    // A port is required rather than defaulted: the control plane's port is
    // configurable, so a guess produces a connection refused somewhere the
    // user never asked to connect.
    ["fox-realtime://k@127.0.0.1/app", "no port"],
    ["fox-realtime://k@127.0.0.1:8080/", "no branch"],
    ["fox-realtime://k@127.0.0.1:8080/app/orders", "more than one path segment"],
    ["fox-realtime://k@127.0.0.1:8080/app?sslmode=prefer", "not one of"],
  ]) {
    assert.throws(() => parseRealtimeUrl(raw), e => {
      assert.ok(e instanceof RealtimeError, `${raw}: ${e}`)
      assert.match(e.message, new RegExp(expect.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))
      return true
    }, `${raw} was accepted`)
  }
})

test("applyChange builds a row from an insert", () => {
  const got = applyChange(undefined, {
    type: "change", table: "t", action: "insert", commit_lsn: "0/1",
    identity: { id: "1" }, new: { id: "1", note: "hello" },
  })
  assert.deepEqual(got, { id: "1", note: "hello" })
})

test("applyChange leaves an unchanged TOASTed column alone", () => {
  // The trap. `body` is a large value the update did not touch, so the server
  // omitted it from `new` and named it in `unchanged`. Copying `new` over the
  // held row would write null across it.
  const held = { id: "1", note: "old", body: "a very large value" }
  const got = applyChange(held, {
    type: "change", table: "t", action: "update", commit_lsn: "0/1",
    identity: { id: "1" }, new: { id: "1", note: "new" }, unchanged: ["body"],
  })
  assert.equal(got.body, "a very large value", "an untouched large column was overwritten")
  assert.equal(got.note, "new")
})

test("applyChange does not invent a value it has never seen", () => {
  const got = applyChange(undefined, {
    type: "change", table: "t", action: "update", commit_lsn: "0/1",
    identity: { id: "1" }, new: { id: "1" }, unchanged: ["body"],
  })
  assert.ok(!("body" in got), "claimed a value the client has never held")
})

test("applyChange keeps empty string and null apart", () => {
  const got = applyChange({ id: "1", a: "x", b: "y" }, {
    type: "change", table: "t", action: "update", commit_lsn: "0/1",
    identity: { id: "1" }, new: { id: "1", a: "", b: null },
  })
  assert.equal(got.a, "")
  assert.equal(got.b, null)
})

test("applyChange removes the row on delete and truncate", () => {
  for (const action of ["delete", "truncate"]) {
    const got = applyChange({ id: "1" }, {
      type: "change", table: "t", action, commit_lsn: "0/1", identity: { id: "1" },
    })
    assert.equal(got, undefined, action)
  }
})

// --- the stream, over a fetch of our own ------------------------------------

function sse(...events) {
  return events.map(e => `event: message\ndata: ${JSON.stringify(e)}\n\n`).join("")
}

/** Run a subscription until `until()` is true, then stop it.
 *
 * A subscription reconnects after a stream ends, on purpose: the server closes
 * one every hour by design and a client that did not come back would simply
 * stop receiving changes. So `done` resolves only after `close()`, and a test
 * that awaited it without closing would wait for ever — which is exactly what
 * the first version of this file did. */
async function run(sub, until, ms = 2000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline && !until()) await new Promise(r => setTimeout(r, 5))
  sub.close()
  await sub.done
  return until()
}

/** A fetch that serves one canned body and records the request. */
function fetchOf(body, seen = {}) {
  return async (url, init) => {
    seen.url = String(url)
    seen.headers = init?.headers ?? {}
    const chunks = typeof body === "string" ? [body] : body
    let i = 0
    return {
      ok: true,
      status: 200,
      body: {
        getReader: () => ({
          read: async () =>
            i < chunks.length
              ? { value: new TextEncoder().encode(chunks[i++]), done: false }
              : { value: undefined, done: true },
        }),
      },
      text: async () => "",
    }
  }
}

test("the key goes in a header and never in the URL", async () => {
  const seen = {}
  const sub = subscribe("fox-realtime://rtk_secret@127.0.0.1:8080/app", {
    fetch: fetchOf(sse({ type: "change", table: "t", action: "insert", commit_lsn: "0/AB", identity: { id: "1" } }), seen),
  })
  await run(sub, () => !!seen.url)
  assert.ok(!seen.url.includes("rtk_secret"), `the key is in the URL: ${seen.url}`)
  assert.equal(seen.headers.Authorization, "Bearer rtk_secret")
})

test("a transaction is delivered whole", async () => {
  // The case framing exists for: two rows moved in one transaction.
  const txs = []
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onTransaction: tx => txs.push(tx),
    fetch: fetchOf(sse(
      { type: "begin", xid: 42, commit_lsn: "0/FF", at: "2026-10-09T12:00:00Z" },
      { type: "change", table: "t", action: "update", xid: 42, commit_lsn: "0/FF", identity: { id: "1" }, new: { id: "1", bal: "90" } },
      { type: "change", table: "t", action: "update", xid: 42, commit_lsn: "0/FF", identity: { id: "2" }, new: { id: "2", bal: "110" } },
      { type: "commit", xid: 42, commit_lsn: "0/FF", changes: 2 },
    )),
  })
  assert.ok(await run(sub, () => txs.length > 0), "no transaction was delivered")
  assert.equal(txs.length, 1)
  assert.equal(txs[0].xid, 42)
  assert.equal(txs[0].changes.length, 2)
  assert.equal(txs[0].commitLsn, "0/FF")
  // Asking for transactions turns the frames on by itself.
  assert.equal(sub.position(), "0/FF")
})

test("the position moves only at the commit", async () => {
  // Mid-transaction it must not move: a reconnect from there would skip the
  // rest of the transaction.
  const changes = []
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onChange: () => changes.push(1),
    onTransaction: () => {},
    fetch: fetchOf(sse(
      { type: "begin", xid: 7, commit_lsn: "0/FF" },
      { type: "change", table: "t", action: "update", xid: 7, commit_lsn: "0/FF", identity: { id: "1" } },
    )),
  })
  await run(sub, () => changes.length > 0)
  assert.equal(sub.position(), undefined, "the position moved before the commit arrived")
})

test("a resync drops the position", async () => {
  // Everything held is of unknown age; resuming from the old position would
  // leave a hole nothing would ever report.
  const notices = []
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onTransaction: () => {},
    onResync: n => notices.push(n),
    fetch: fetchOf(sse(
      { type: "begin", xid: 1, commit_lsn: "0/AA" },
      { type: "change", table: "t", action: "insert", xid: 1, commit_lsn: "0/AA", identity: { id: "1" } },
      { type: "commit", xid: 1, commit_lsn: "0/AA", changes: 1 },
      { type: "resync", code: "slot_invalidated", detail: "refetch" },
    )),
  })
  assert.ok(await run(sub, () => notices.length > 0), "no resync was reported")
  assert.equal(sub.position(), undefined, "a resync left a stale resume position behind")
})

test("a payload split across reads is not truncated", async () => {
  // A wide row crosses a packet boundary routinely.
  const big = "x".repeat(9000)
  const whole = sse({ type: "change", table: "t", action: "insert", commit_lsn: "0/AB", identity: { id: "1" }, new: { body: big } })
  const changes = []
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onChange: c => changes.push(c),
    // Cut in the middle of the JSON.
    fetch: fetchOf([whole.slice(0, 120), whole.slice(120)]),
  })
  assert.ok(await run(sub, () => changes.length > 0), "the split payload never arrived")
  assert.equal(changes.length, 1)
  assert.equal(changes[0].new.body, big)
})

test("an unframed subscriber tracks the position from the change", async () => {
  const changes = []
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onChange: c => changes.push(c),
    fetch: fetchOf(sse({ type: "change", table: "t", action: "insert", commit_lsn: "0/AB", identity: { id: "1" } })),
  })
  await run(sub, () => changes.length > 0)
  assert.equal(sub.position(), "0/AB")
})

test("since is sent when resuming", async () => {
  const seen = {}
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    since: "0/1234", onChange: () => {}, fetch: fetchOf("", seen),
  })
  await run(sub, () => !!seen.url)
  assert.match(seen.url, /since=0%2F1234/)
  assert.ok(!seen.url.includes("transactions"), "frames were asked for without being wanted")
})

test("asking for transactions sets the parameter", async () => {
  const seen = {}
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onTransaction: () => {}, fetch: fetchOf("", seen),
  })
  await run(sub, () => !!seen.url)
  assert.match(seen.url, /transactions=1/)
})

test("a refused stream is reported and not retried past maxRetries", async () => {
  const errors = []
  const sub = subscribe("fox-realtime://k@127.0.0.1:8080/app", {
    onError: e => errors.push(e),
    maxRetries: 1,
    fetch: async () => ({ ok: false, status: 429, statusText: "Too Many Requests", text: async () => "already serving 8" }),
  })
  await sub.done
  assert.equal(errors.length, 1, "a refusal was not reported")
  assert.match(errors[0].message, /429/)
  assert.match(errors[0].message, /already serving 8/)
})
