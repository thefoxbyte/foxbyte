// The page subscribes with the official client. Writes go to this demo's
// backend, which commits them through the gateway. The list is updated only
// from the feed, so a second window — and a psql session — move the same rows.

import { subscribe, applyChange } from "/vendor/index.js"

const params = new URLSearchParams(location.search)
const who = (params.get("as") || "A").slice(0, 12)
document.getElementById("who").textContent = "Window " + who
document.title = "Todos — window " + who
if (who.toUpperCase() === "B") {
  document.documentElement.style.setProperty("--accent", "#9a3412")
  document.documentElement.style.setProperty("--accent-ink", "#7c2d12")
}

const listEl = document.getElementById("list")
const eventsEl = document.getElementById("events")
const statusEl = document.getElementById("status")
const posEl = document.getElementById("pos")
const statsEl = document.getElementById("stats")
const pauseBtn = document.getElementById("pause")
const resumeBtn = document.getElementById("resume")

const rows = new Map()
const waiting = new Map()
const titleWaiters = new Map()
const pendingLatency = new Map()
let sub = null
let branch = "main"
let realtimeUrl = ""
// Each tab keeps its own cursor. localStorage is shared by every tab on this
// origin, and one tab writing the position it just applied would move the
// other tab's saved resume point.
let tabId = sessionStorage.getItem("fox-tab")
if (!tabId) {
  tabId = Math.random().toString(36).slice(2)
  sessionStorage.setItem("fox-tab", tabId)
}
const posKey = () => "fox-rt-pos:" + branch + ":" + tabId

function setStatus(text, kind) {
  statusEl.textContent = text
  statusEl.className = "status" + (kind ? " " + kind : "")
}

function showPos() {
  const saved = localStorage.getItem(posKey())
  const live = sub ? sub.position() : undefined
  const held = live || saved
  const where = live ? " (this subscription)" : (saved ? " (saved)" : "")
  posEl.textContent = held
    ? "Resume position " + held + where
    : "No position saved yet. A position is the last commit the feed delivered, and it is the only safe place to resume."
  resumeBtn.disabled = Boolean(sub) || !saved
  pauseBtn.disabled = !sub
}

function render() {
  listEl.replaceChildren()
  if (rows.size === 0) {
    const li = document.createElement("li")
    li.className = "empty"
    li.textContent = "Nothing here yet."
    listEl.append(li)
    return
  }
  for (const row of rows.values()) {
    const li = document.createElement("li")
    li.className = "row" + (row.done ? " done" : "") + (row.flash ? " flash" : "")
    li.dataset.id = row.id
    const box = document.createElement("input")
    box.type = "checkbox"
    box.checked = row.done
    box.addEventListener("change", () => patch(row.id, { done: box.checked }))
    const text = document.createElement("div")
    const title = document.createElement("div")
    title.className = "title"
    title.textContent = row.title
    const meta = document.createElement("div")
    meta.className = "meta"
    meta.textContent = row.note || ("#" + row.id)
    text.append(title, meta)
    const ops = document.createElement("div")
    ops.className = "ops"
    const edit = document.createElement("button")
    edit.type = "button"
    edit.className = "ghost"
    edit.textContent = "Rename"
    edit.addEventListener("click", () => rename(row))
    const del = document.createElement("button")
    del.type = "button"
    del.className = "warn"
    del.textContent = "Delete"
    del.addEventListener("click", () => remove(row.id))
    ops.append(edit, del)
    li.append(box, text, ops)
    listEl.append(li)
  }
}

function note(id, text) {
  const row = rows.get(id)
  if (!row) return
  row.note = text
  row.flash = true
  render()
  setTimeout(() => {
    const cur = rows.get(id)
    if (cur) cur.flash = false
    render()
  }, 1200)
}

function logEvent(text) {
  const li = document.createElement("li")
  const t = new Date()
  const stamp = [t.getHours(), t.getMinutes(), t.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":")
    + "." + String(t.getMilliseconds()).padStart(3, "0")
  li.textContent = stamp + "  " + text
  eventsEl.prepend(li)
  while (eventsEl.children.length > 12) eventsEl.lastChild.remove()
}

function asFeedRow(row) {
  if (!row) return undefined
  return { id: row.id, title: row.title, done: row.done ? "t" : "f" }
}

function applyTx(tx) {
  for (const c of tx.changes) {
    if (c.table !== "public.todos") continue
    const id = c.identity.id
    const prev = rows.get(id)
    const next = applyChange(asFeedRow(prev), c)
    if (next) {
      rows.set(id, {
        id,
        title: next.title ?? "",
        done: next.done === "t" || next.done === "true" || next.done === true,
        flash: true,
        note: prev && prev.note,
      })
    } else {
      rows.delete(id)
    }
    const title = c.new && c.new.title
    if (title && titleWaiters.has(title)) {
      const done = titleWaiters.get(title)
      titleWaiters.delete(title)
      done(performance.now())
    }
    const started = pendingLatency.get(id)
    let extra = ""
    if (started) {
      const ms = Math.round(performance.now() - started)
      pendingLatency.delete(id)
      extra = " · " + ms + " ms from commit to this window"
      const row = rows.get(id)
      if (row) row.note = "#" + id + extra
    }
    logEvent(c.action + " #" + (id || "") + (c.new && c.new.title ? " “" + c.new.title + "”" : "") + extra)
    const wait = waiting.get(id + ":" + c.action) || waiting.get(id)
    if (wait) {
      waiting.delete(id + ":" + c.action)
      waiting.delete(id)
      wait()
    }
  }
  localStorage.setItem(posKey(), tx.commitLsn)
  showPos()
  render()
  setTimeout(() => {
    let changed = false
    for (const row of rows.values()) if (row.flash) { row.flash = false; changed = true }
    if (changed) render()
  }, 1200)
}

function connect(since) {
  if (sub) sub.close()
  setStatus(since ? "resuming" : "connecting", "")
  sub = subscribe(realtimeUrl, {
    since,
    // The feed sends nothing until a commit. The stream being open is already
    // "live": the first row is not required to know the subscription worked.
    async fetch(url, opts) {
      const res = await fetch(url, opts)
      if (res.ok) setStatus("live", "live")
      return res
    },
    onTransaction(tx) {
      setStatus("live", "live")
      applyTx(tx)
    },
    onResync() {
      rows.clear()
      localStorage.removeItem(posKey())
      logEvent("resync — refetching, the saved position can no longer be replayed")
      refresh()
    },
    onError(err) {
      setStatus("reconnecting", "paused")
      logEvent("stream: " + err.message)
    },
  })
  showPos()
}

async function refresh() {
  const res = await fetch("/items")
  const data = await res.json()
  rows.clear()
  for (const item of data.items || []) rows.set(item.id, { ...item, done: Boolean(item.done) })
  render()
}

function waitFor(id, action, ms = 8000) {
  return new Promise((resolve, reject) => {
    const key = action ? id + ":" + action : id
    const t = setTimeout(() => {
      waiting.delete(key)
      reject(new Error("the feed did not deliver " + key + " within " + ms + " ms"))
    }, ms)
    waiting.set(key, () => { clearTimeout(t); resolve() })
  })
}

// Registered before the write, because the feed can deliver the row before
// the HTTP response that acknowledges the commit.
function waitForTitle(title, ms = 8000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      titleWaiters.delete(title)
      reject(new Error("the feed did not deliver “" + title + "” within " + ms + " ms"))
    }, ms)
    titleWaiters.set(title, (at) => { clearTimeout(t); resolve(at) })
  })
}

async function write(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || res.statusText)
  return data
}

document.getElementById("add").addEventListener("submit", async (ev) => {
  ev.preventDefault()
  const input = document.getElementById("title")
  const title = input.value.trim()
  if (!title) return
  input.value = ""
  try {
    const created = await write("POST", "/items", { title })
    pendingLatency.set(created.id, performance.now())
  } catch (err) {
    logEvent("add failed: " + err.message)
  }
})

async function rename(row) {
  const title = prompt("New title", row.title)
  if (!title || title.trim() === row.title) return
  pendingLatency.set(row.id, performance.now())
  try {
    await write("PATCH", "/items/" + row.id, { title: title.trim() })
  } catch (err) {
    pendingLatency.delete(row.id)
    logEvent("rename failed: " + err.message)
  }
}

async function patch(id, body) {
  pendingLatency.set(id, performance.now())
  try {
    await write("PATCH", "/items/" + id, body)
  } catch (err) {
    pendingLatency.delete(id)
    logEvent("update failed: " + err.message)
  }
}

async function remove(id) {
  pendingLatency.set(id, performance.now())
  try {
    await write("DELETE", "/items/" + id)
  } catch (err) {
    pendingLatency.delete(id)
    logEvent("delete failed: " + err.message)
  }
}

function percentile(sorted, p) {
  if (!sorted.length) return 0
  const rank = Math.ceil((p / 100) * sorted.length)
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))]
}

document.getElementById("measure").addEventListener("click", async () => {
  const btn = document.getElementById("measure")
  btn.disabled = true
    const afterAck = []
    const fromSend = []
    statsEl.textContent = "Measuring…"
    try {
      for (let i = 1; i <= 50; i++) {
        const title = "measure " + i + " " + Math.random().toString(36).slice(2, 8)
        const seen = waitForTitle(title)
        const sent = performance.now()
        const created = await write("POST", "/items", { title })
        const acked = performance.now()
        pendingLatency.set(created.id, acked)
        const at = await seen
        afterAck.push(Math.max(0, at - acked))
        fromSend.push(Math.max(0, at - sent))
        statsEl.textContent = i + " / 50"
      }
      const ack = [...afterAck].sort((a, b) => a - b)
      const sent = [...fromSend].sort((a, b) => a - b)
      const fmt = (n) => (Math.round(n * 10) / 10).toFixed(1) + " ms"
      const summary = "50 inserts. After the gateway returned the commit: p50 " + fmt(percentile(ack, 50))
        + ", p95 " + fmt(percentile(ack, 95))
        + ". From sending the write (includes the commit): p50 " + fmt(percentile(sent, 50))
        + ", p95 " + fmt(percentile(sent, 95)) + "."
    statsEl.textContent = summary
    logEvent(summary)
    console.log(summary)
  } catch (err) {
    statsEl.textContent = "Measure stopped: " + err.message
    logEvent("measure stopped: " + err.message)
  } finally {
    btn.disabled = false
  }
})

pauseBtn.addEventListener("click", () => {
  if (!sub) return
  const pos = sub.position()
  if (pos) localStorage.setItem(posKey(), pos)
  sub.close()
  sub = null
  setStatus("paused", "paused")
  logEvent("disconnected" + (pos ? " at " + pos : ""))
  showPos()
})

resumeBtn.addEventListener("click", () => {
  const since = localStorage.getItem(posKey()) || undefined
  logEvent("resuming" + (since ? " from " + since : " from now"))
  connect(since)
})

const cfg = await (await fetch("/config")).json()
branch = cfg.branch
realtimeUrl = cfg.realtimeUrl
document.getElementById("branch").textContent = "branch " + branch + " · changes arrive from the feed, not from a refresh"
const hello = await (await fetch("/status")).json()
if (hello.fox !== 200) {
  setStatus("feed " + hello.fox, "paused")
  logEvent("the engine did not accept the realtime key (" + hello.fox + ")")
}
await refresh()
connect()
showPos()
