// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for application identity in the client: a query that acts for a
// user, withActor, and withActorTransaction. Against the compiled output, with
// a local HTTP server standing in for the engine.
//
// The one that matters most: the token goes in the request body, never in the
// URL, where access logs and browser history would keep it.
import { test } from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { FoxByte, withActorTransaction } from "../dist/index.js"

async function engine(reply) {
  const seen = []
  const server = createServer((req, res) => {
    let body = ""
    req.on("data", (c) => (body += c))
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : null })
      res.setHeader("Content-Type", "application/json")
      res.end(JSON.stringify(reply(seen[seen.length - 1])))
    })
  })
  await new Promise((r) => server.listen(0, "127.0.0.1", r))
  const url = `http://127.0.0.1:${server.address().port}`
  return { url, seen, close: () => new Promise((r) => server.close(r)) }
}

test("a query sends act_for in the body, and only when asked", async () => {
  const e = await engine(() => ({ columns: ["n"], rows: [[1]], act_for: { user: "alice" } }))
  try {
    const db = new FoxByte("key_x", e.url)
    const r = await db.query("main", "SELECT 1", { actFor: "tok.en.sig" })
    assert.deepEqual(e.seen[0].body, { sql: "SELECT 1", act_for: "tok.en.sig" })
    assert.equal(e.seen[0].url, "/api/branches/main/query")
    assert.ok(!e.seen[0].url.includes("tok"))
    assert.equal(r.act_for.user, "alice")
    await db.query("main", "SELECT 2")
    assert.deepEqual(e.seen[1].body, { sql: "SELECT 2" })
  } finally {
    await e.close()
  }
})

test("withActor's queries all act for the user, and require the token to be taken", async () => {
  const e = await engine(() => ({ columns: [], rows: [], act_for: { user: "alice" } }))
  try {
    const db = new FoxByte("key_x", e.url)
    const out = await db.withActor("tok.en.sig", async (as) => {
      await as.query("main", "UPDATE a SET x = 1")
      await as.query("qa", "UPDATE b SET y = 2")
      return "done"
    })
    assert.equal(out, "done")
    assert.equal(e.seen.length, 2)
    for (const s of e.seen) {
      assert.equal(s.body.act_for, "tok.en.sig")
      assert.equal(s.body.act_for_required, true)
      assert.equal(s.auth, "Bearer key_x")
    }
    assert.equal(e.seen[1].url, "/api/branches/qa/query")
  } finally {
    await e.close()
  }
})

test("withActor refuses an empty token before sending anything", async () => {
  const db = new FoxByte("key_x", "http://127.0.0.1:9")
  await assert.rejects(db.withActor("", async () => "never"), /needs a token/)
})

test("withActorTransaction asserts first with the token as a parameter, and commits", async () => {
  const calls = []
  const client = { query: async (text, params) => { calls.push([text, params]); return {} } }
  const out = await withActorTransaction(client, "tok.en.sig", async (c) => {
    await c.query("UPDATE orders SET paid = true WHERE id = $1", [7])
    return 42
  })
  assert.equal(out, 42)
  assert.deepEqual(calls, [
    ["BEGIN", undefined],
    ["SELECT bb.act_for($1)", ["tok.en.sig"]],
    ["UPDATE orders SET paid = true WHERE id = $1", [7]],
    ["COMMIT", undefined],
  ])
  for (const [text] of calls) assert.ok(!text.includes("tok.en.sig"), "the token is never in SQL text")
})

test("withActorTransaction rolls back and rethrows when fn throws", async () => {
  const calls = []
  const client = { query: async (text) => { calls.push(text); return {} } }
  await assert.rejects(
    withActorTransaction(client, "tok", async () => { throw new Error("boom") }),
    /boom/,
  )
  assert.deepEqual(calls, ["BEGIN", "SELECT bb.act_for($1)", "ROLLBACK"])
})

test("withActorTransaction rolls back when the engine refuses the token", async () => {
  const calls = []
  const client = {
    query: async (text) => {
      calls.push(text)
      if (text.startsWith("SELECT bb.act_for")) throw new Error("application identity refused: expired")
      return {}
    },
  }
  await assert.rejects(withActorTransaction(client, "tok", async () => "never"), /refused: expired/)
  assert.deepEqual(calls, ["BEGIN", "SELECT bb.act_for($1)", "ROLLBACK"])
})
