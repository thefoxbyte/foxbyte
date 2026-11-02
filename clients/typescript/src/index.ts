// SPDX-License-Identifier: Apache-2.0

/** A thin, dependency-free client for the FoxByte control-plane REST API.
 * The full API is described by the OpenAPI spec at GET /api/openapi.yaml. */

export interface QueryResult {
  columns?: string[]
  rows?: unknown[][]
  error?: string
  /** With actFor: whom the query ran for, or why the token was not taken. */
  act_for?: { user: string | null; refused?: string }
}

/** Options for one query. */
export interface QueryOptions {
  /** An application identity token (`fox app`): the query runs in one
   * transaction that first says which of your users it acts for, so the
   * Blackbox and row tracking record each change for them. Sent in the body,
   * bound as a parameter by the engine, never in the SQL. */
  actFor?: string
  /** With actFor: refuse the query, running nothing, when the token is not
   * taken, rather than run it for nobody. */
  actForRequired?: boolean
}

/** What withActor hands its function: queries that all act for one user. */
export interface ActingClient {
  query(branch: string, sql: string): Promise<QueryResult>
}

/** The smallest thing withActorTransaction needs of a Postgres client: a
 * query method taking parameters, as node-postgres's Client and PoolClient
 * have. */
export interface ParameterisedClient {
  query(text: string, params?: unknown[]): Promise<unknown>
}

/** Runs fn in one transaction on a Postgres connection of your own (through
 * the Gateway, logged in with your application's account key), after saying
 * which of your users it acts for: `SELECT bb.act_for($1)`, with the token as
 * the parameter, never in the SQL. Commits when fn resolves, rolls back when it
 * throws. Every change fn makes is recorded for that user.
 *
 *     const client = await pool.connect()
 *     try {
 *       await withActorTransaction(client, token, c => c.query("UPDATE orders SET …"))
 *     } finally { client.release() }
 *
 * The token must be one the engine takes, or the change is recorded for
 * nobody (or refused, if your application was registered with
 * --on-invalid refuse): check what `SELECT bb.act_for($1)` returns with a
 * client of your own if you need to know first. */
export async function withActorTransaction<C extends ParameterisedClient, T>(
  client: C,
  token: string,
  fn: (client: C) => Promise<T>,
): Promise<T> {
  await client.query("BEGIN")
  try {
    await client.query("SELECT bb.act_for($1)", [token])
    const out = await fn(client)
    await client.query("COMMIT")
    return out
  } catch (e) {
    try { await client.query("ROLLBACK") } catch { /* the original error matters more */ }
    throw e
  }
}

export interface Branch {
  name: string
  state?: string
  primary?: boolean
  agent?: boolean
  used?: string
  connections?: number
}

/** The change feed. See ./realtime.ts — a subscriber has several details to
 * get right, and they are handled there rather than left to the caller. */
export * from "./realtime.js"
import { subscribe, type SubscribeOptions, type Subscription } from "./realtime.js"

export class FoxByteError extends Error {}

export class FoxByte {
  constructor(
    private readonly apiKey: string,
    private readonly baseUrl: string = "https://localhost:8080",
  ) {
    this.baseUrl = this.baseUrl.replace(/\/$/, "")
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.baseUrl + path, {
      method,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
    if (!res.ok) {
      throw new FoxByteError(`${res.status} ${res.statusText}: ${await res.text()}`)
    }
    const text = await res.text()
    return (text ? JSON.parse(text) : null) as T
  }

  status(): Promise<unknown> {
    return this.request("GET", "/api/status")
  }
  branches(): Promise<Branch[]> {
    return this.request("GET", "/api/branches")
  }
  createBranch(name: string): Promise<unknown> {
    return this.request("POST", "/api/branches", { name })
  }
  deleteBranch(name: string): Promise<unknown> {
    return this.request("DELETE", `/api/branches/${name}`)
  }
  suspend(name: string): Promise<unknown> {
    return this.request("POST", `/api/branches/${name}/suspend`)
  }
  resume(name: string): Promise<unknown> {
    return this.request("POST", `/api/branches/${name}/resume`)
  }
  query(branch: string, sql: string, opts: QueryOptions = {}): Promise<QueryResult> {
    return this.request("POST", `/api/branches/${branch}/query`, {
      sql,
      ...(opts.actFor ? { act_for: opts.actFor } : {}),
      ...(opts.actFor && opts.actForRequired ? { act_for_required: true } : {}),
    })
  }

  /** Runs fn with a client whose every query acts for the user a token names
   * (application identity: register your application with `fox app register`,
   * and sign a short-lived token for each user with its key). Each query is
   * its own transaction, asserted afresh; one the engine does not take is
   * refused, with nothing run, so a change is never recorded for nobody by
   * mistake.
   *
   *     await db.withActor(token, async (as) => {
   *       await as.query("main", "UPDATE orders SET status = 'paid' WHERE id = 7")
   *     })
   */
  async withActor<T>(token: string, fn: (as: ActingClient) => Promise<T>): Promise<T> {
    if (!token) throw new FoxByteError("withActor needs a token")
    return fn({ query: (branch, sql) => this.query(branch, sql, { actFor: token, actForRequired: true }) })
  }
  /** The branch's DDL history — who changed what. */
  ledger(branch = "main", filters: Record<string, string | number> = {}): Promise<QueryResult> {
    const qs = new URLSearchParams(
      Object.entries(filters).map(([k, v]) => [k, String(v)]),
    ).toString()
    return this.request("GET", `/api/branches/${branch}/ledger${qs ? `?${qs}` : ""}`)
  }
  /** Recompute the Blackbox hash chain (tamper-evidence). */
  verifyLedger(branch = "main"): Promise<QueryResult> {
    return this.request("GET", `/api/branches/${branch}/ledger/verify`)
  }
  /** Blackbox: the branch's DDL history. Same as ledger(). */
  blackbox(branch = "main", filters: Record<string, string | number> = {}): Promise<QueryResult> {
    return this.ledger(branch, filters)
  }
  /** Recompute the Blackbox hash chain. Same as verifyLedger(). */
  verifyBlackbox(branch = "main"): Promise<QueryResult> {
    return this.verifyLedger(branch)
  }

  /** Subscribe to a branch's change feed using this client's credentials.
   *
   * For a program that already holds an API key. An application that should
   * only ever read the feed is better given a realtime key — `fox realtime key
   * create <branch>` — which cannot reach the control plane and cannot run
   * SQL; pass its connection string to `subscribe()` directly. */
  subscribe(branch: string, opts: SubscribeOptions = {}): Subscription {
    const u = new URL(this.baseUrl)
    return subscribe(
      { host: u.host, branch, key: this.apiKey, sslmode: u.protocol === "http:" ? "disable" : "require" },
      opts,
    )
  }
}
