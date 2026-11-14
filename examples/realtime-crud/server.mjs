// A small on-prem backend for the realtime todo demo.
//
// Writes go through the FoxByte gateway (:6432) with an account API key, the
// same way any Postgres client would. The browser subscribes with the official
// TypeScript client. That client speaks HTTPS to the engine; a default install
// serves a self-signed certificate, which a page on another port cannot accept
// on the engine's behalf. This process proxies only the change-feed stream to
// loopback HTTP so the page can use the client unchanged. The SQL key never
// leaves this process. The browser is given the realtime key, which can
// subscribe to one branch and do nothing else.

import { createServer } from "node:http"
import { readFile } from "node:fs/promises"
import { request as httpsRequest } from "node:https"
import { fileURLToPath } from "node:url"
import path from "node:path"
import pg from "pg"

const here = path.dirname(fileURLToPath(import.meta.url))
const clientDist = path.resolve(here, "../../clients/typescript/dist")

const port = Number(process.env.PORT || 8787)
const branch = process.env.FOX_BRANCH || "main"
const apiKey = required("FOX_API_KEY")
const realtimeKey = required("FOX_REALTIME_KEY")
const foxAPI = (process.env.FOX_API || "https://127.0.0.1:8080").replace(/\/$/, "")
const dbUser = process.env.FOX_DB_USER || "dbadmin"

const pool = new pg.Pool({
  host: process.env.FOX_GATEWAY_HOST || "127.0.0.1",
  port: Number(process.env.FOX_GATEWAY_PORT || 6432),
  user: dbUser,
  password: apiKey,
  database: branch,
  max: 4,
  ssl: { rejectUnauthorized: false },
})

function required(name) {
  const v = (process.env[name] || "").trim()
  if (!v) {
    console.error(`${name} is not set. See .env.example.`)
    process.exit(1)
  }
  return v
}

async function initTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.todos (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      title text NOT NULL,
      done boolean NOT NULL DEFAULT false
    )`)
  // The feed reads as db_client. Without this grant, \`fox realtime enable\`
  // refuses the table.
  await pool.query(`GRANT SELECT ON public.todos TO db_client`)
}

function send(res, code, body, type = "application/json; charset=utf-8") {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body))
  res.writeHead(code, {
    "Content-Type": type,
    "Content-Length": buf.length,
    "Cache-Control": "no-store",
  })
  res.end(buf)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on("data", (c) => chunks.push(c))
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8")
      if (!raw) return resolve({})
      try { resolve(JSON.parse(raw)) } catch (e) { reject(e) }
    })
    req.on("error", reject)
  })
}

function rowOf(r) {
  return { id: String(r.id), title: r.title, done: r.done === true }
}

// Proxy one change-feed request to the engine, streaming the response.
// Only this path is forwarded: the page does not gain the control plane.
function proxyFeed(req, res) {
  const incoming = new URL(req.url, "http://127.0.0.1")
  const target = new URL(foxAPI + incoming.pathname + incoming.search)
  const headers = {
    Accept: "text/event-stream",
    Authorization: req.headers.authorization || "",
  }
  const up = httpsRequest({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || 443,
    path: target.pathname + target.search,
    method: "GET",
    headers,
    rejectUnauthorized: false,
  }, (upRes) => {
    const out = {
      "Content-Type": upRes.headers["content-type"] || "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    }
    res.writeHead(upRes.statusCode || 502, out)
    if (typeof res.flushHeaders === "function") res.flushHeaders()
    upRes.pipe(res)
  })
  up.on("error", (err) => {
    if (!res.headersSent) send(res, 502, { error: "the change feed could not be reached: " + err.message })
    else res.end()
  })
  // A GET has no body, so the incoming request emits "close" as soon as its
  // headers are in. Only the response closing means the browser went away.
  res.on("close", () => up.destroy())
  up.end()
}

async function foxHello() {
  const target = new URL(`${foxAPI}/realtime/v1/branches/${encodeURIComponent(branch)}/hello`)
  return new Promise((resolve) => {
    const up = httpsRequest({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: target.pathname,
      method: "GET",
      headers: { Authorization: `Bearer ${realtimeKey}`, Accept: "application/json" },
      rejectUnauthorized: false,
    }, (upRes) => {
      const chunks = []
      upRes.on("data", (c) => chunks.push(c))
      upRes.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8")
        resolve({ status: upRes.statusCode || 0, body: text })
      })
    })
    up.on("error", (err) => resolve({ status: 0, body: err.message }))
    up.end()
  })
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://127.0.0.1")
    if (req.method === "GET" && url.pathname.startsWith("/api/branches/") && url.pathname.endsWith("/realtime")) {
      proxyFeed(req, res)
      return
    }
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      const html = await readFile(path.join(here, "public/index.html"))
      send(res, 200, html, "text/html; charset=utf-8")
      return
    }
    if (req.method === "GET" && url.pathname === "/app.js") {
      const js = await readFile(path.join(here, "public/app.js"))
      send(res, 200, js, "text/javascript; charset=utf-8")
      return
    }
    if (req.method === "GET" && url.pathname.startsWith("/vendor/")) {
      const rel = url.pathname.slice("/vendor/".length)
      if (rel.includes("..") || !rel.endsWith(".js")) {
        send(res, 404, { error: "not found" })
        return
      }
      const js = await readFile(path.join(clientDist, rel))
      send(res, 200, js, "text/javascript; charset=utf-8")
      return
    }
    if (req.method === "GET" && url.pathname === "/config") {
      // The browser subscribes to this process (sslmode=disable). The proxy
      // above carries the stream to the engine. The key stays in userinfo of
      // the connection string, which the client turns into a header.
      const host = req.headers.host || `127.0.0.1:${port}`
      send(res, 200, {
        branch,
        realtimeUrl: `fox-realtime://${encodeURIComponent(realtimeKey)}@${host}/${encodeURIComponent(branch)}?sslmode=disable`,
      })
      return
    }
    if (req.method === "GET" && url.pathname === "/status") {
      const hello = await foxHello()
      send(res, 200, { branch, fox: hello.status, detail: hello.body.slice(0, 400) })
      return
    }
    if (req.method === "GET" && url.pathname === "/items") {
      const q = await pool.query(`SELECT id, title, done FROM public.todos ORDER BY id`)
      send(res, 200, { items: q.rows.map(rowOf) })
      return
    }
    if (req.method === "POST" && url.pathname === "/items") {
      const body = await readBody(req)
      const title = String(body.title || "").trim()
      if (!title) { send(res, 400, { error: "title is required" }); return }
      const q = await pool.query(
        `INSERT INTO public.todos (title) VALUES ($1) RETURNING id, title, done`,
        [title],
      )
      send(res, 201, rowOf(q.rows[0]))
      return
    }
    const item = url.pathname.match(/^\/items\/(\d+)$/)
    if (item && req.method === "PATCH") {
      const body = await readBody(req)
      const sets = []
      const params = []
      if (body.title !== undefined) {
        const title = String(body.title).trim()
        if (!title) { send(res, 400, { error: "title is required" }); return }
        params.push(title)
        sets.push(`title = $${params.length}`)
      }
      if (body.done !== undefined) {
        params.push(Boolean(body.done))
        sets.push(`done = $${params.length}`)
      }
      if (!sets.length) { send(res, 400, { error: "nothing to change" }); return }
      params.push(item[1])
      const q = await pool.query(
        `UPDATE public.todos SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING id, title, done`,
        params,
      )
      if (!q.rows.length) { send(res, 404, { error: "no such item" }); return }
      send(res, 200, rowOf(q.rows[0]))
      return
    }
    if (item && req.method === "DELETE") {
      const q = await pool.query(`DELETE FROM public.todos WHERE id = $1 RETURNING id`, [item[1]])
      if (!q.rows.length) { send(res, 404, { error: "no such item" }); return }
      send(res, 200, { id: String(q.rows[0].id), deleted: true })
      return
    }
    send(res, 404, { error: "not found" })
  } catch (err) {
    send(res, 500, { error: err.message || String(err) })
  }
})

await initTable()
server.listen(port, "127.0.0.1", () => {
  console.log(`todo demo on http://127.0.0.1:${port}  branch ${branch}`)
  console.log(`gateway ${process.env.FOX_GATEWAY_HOST || "127.0.0.1"}:${process.env.FOX_GATEWAY_PORT || 6432}  feed ${foxAPI}`)
})
