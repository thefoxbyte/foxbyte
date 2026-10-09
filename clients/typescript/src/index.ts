// SPDX-License-Identifier: Apache-2.0

/** A thin, dependency-free client for the FoxByte control-plane REST API.
 * The full API is described by the OpenAPI spec at GET /api/openapi.yaml. */

export interface QueryResult {
  columns?: string[]
  rows?: unknown[][]
  error?: string
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
  query(branch: string, sql: string): Promise<QueryResult> {
    return this.request("POST", `/api/branches/${branch}/query`, { sql })
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
