// Typed client for the FoxByte control-plane API (cookie/session auth).
// When the UI is served by the control-plane itself (the embedded production
// build sets VITE_API_URL=""), API is "" — i.e. same-origin, relative requests.
// The dev server (`make web-dev`, VITE_API_URL unset) falls back to :8080.
import { splitFrames } from './sse'

export const API = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8080'
export const AGENT_API = (import.meta.env.VITE_AGENT_API_URL as string | undefined) ?? 'http://localhost:8088'

export type User = { id: number; email: string }
export type HAState = { enabled: boolean; standby: string; streaming: boolean; primary: string }
export type StorageInfo = { used: string; avail: string }
// Which paid features this engine can serve. A Standard build reports none, and
// so does an Enterprise build with no licence — so a page asks `features` rather
// than `edition` before deciding it may load, and uses `edition` only to explain
// why something is locked.
export type Feature =
  | 'realtime'
  | 'anchors'
  | 'policy'
  | 'impact'
  | 'promotion'
  | 'export'
  | 'pipelines'
  | 'personal-data'

export type Status = {
  mainReady: boolean
  branches: number
  agents: number
  edition: 'standard' | 'enterprise'
  features: Feature[]
  ha: HAState
  storage: StorageInfo
  servers: { gateway: boolean; api: boolean }
}

// has answers "may this run here?". Older engines predate these fields, so an
// absent list means no paid features rather than a crash.
export const has = (s: Status | null | undefined, f: Feature) => !!s?.features?.includes(f)
export type Branch = {
  name: string; primary: boolean; agent: boolean; state: string
  used: string; refer: string; connections: number; port: string
}
// One statement's outcome. `results` always holds at least one, so a caller can
// read one shape whether the SQL was a single statement or a script; the fields
// beside it are the last statement's, kept for callers that predate scripts.
export type StatementResult = {
  columns?: string[]
  rows?: unknown[][]
  command?: string
  error?: string
  // Where Postgres says the trouble is: a 1-based character offset into the SQL
  // that was sent. Absent when it could not locate it — a deadlock has no
  // position, and sending 0 would point at line 1 and be wrong.
  position?: number
  detail?: string
  hint?: string
  // The name probably meant, when the error is a table or a column that does
  // not exist (point 9.2): insert is how to write it.
  suggestion?: Suggestion
}
export type Suggestion = { kind: 'table' | 'column'; wrong: string; right: string; insert: string }
export type QueryResult = StatementResult & {
  results?: StatementResult[]
  // Set when a script failed: Postgres runs one in a single transaction unless
  // the script opens its own, so nothing it did survives.
  note?: string
}
// kind is empty for an account key; 'agent' for a key to give an AI agent, which
// the Gateway logs in as an agent and the console refuses; 'realtime' for a
// change-feed key. scope names the one branch a scoped key opens.
export type ApiKey = { id: string; name: string; prefix: string; created: number; kind?: string; scope?: string }
export type Providers = { github: boolean; google: boolean; signup: boolean; setup?: boolean }

export class ApiError extends Error {
  status: number
  constructor(status: number, msg: string) {
    super(msg)
    this.status = status
  }
}

async function req(method: string, url: string, body?: unknown) {
  const r = await fetch(url, {
    method,
    credentials: 'include',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await r.text()
  let data: unknown = {}
  let parsed = true
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      parsed = false
    }
  }
  if (!r.ok) {
    // Session expired mid-use → bounce to login (except when probing /auth/me).
    if (r.status === 401 && !url.endsWith('/auth/me')) {
      if (location.pathname !== '/login') location.assign('/login')
    }
    throw new ApiError(r.status, (data && (data as any).error) || `HTTP ${r.status}`)
  }
  // A 200 whose body is not JSON is not a success, and must not be handed back
  // as an empty object.
  //
  // This used to be `r.json().catch(() => ({}))`, and the empty object it
  // produced was indistinguishable from a real response with missing fields.
  // When a route is absent — a Standard build, where the paid routes are not
  // compiled in — the request falls through to the console's own catch-all and
  // comes back as index.html with status 200. Every caller then read undefined
  // out of `{}`: the Realtime page crashed on `rows.length`, having been handed
  // `undefined` where an array was promised, and the error named a property
  // rather than the missing route.
  //
  // An empty body stays `{}`, which is what a handler that writes nothing
  // means. Only a non-empty body that is not JSON is an error.
  if (!parsed) {
    throw new ApiError(r.status, `${url} did not return JSON — the route may not exist on this engine`)
  }
  return data
}

// --- auth ---
export const me = () => req('GET', `${API}/auth/me`) as Promise<{ user: User | null }>
export const providers = () => req('GET', `${API}/auth/providers`) as Promise<Providers>
export const login = (email: string, password: string) => req('POST', `${API}/auth/login`, { email, password }) as Promise<{ user: User }>
export const register = (email: string, password: string, setup_token?: string) => req('POST', `${API}/auth/register`, { email, password, setup_token }) as Promise<{ user: User }>
export const logout = () => req('POST', `${API}/auth/logout`)
export const oauthUrl = (provider: 'github' | 'google') => `${API}/auth/oauth/${provider}`

// --- api keys ---
export const changePassword = (current: string, next: string) =>
  req('POST', `${API}/api/account/password`, { current, new: next }) as Promise<{ status: string; note: string }>
export const listKeys = () => req('GET', `${API}/api/keys`) as Promise<{ keys: ApiKey[] }>
export const createKey = (name: string, kind: '' | 'agent' = '') =>
  req('POST', `${API}/api/keys`, kind ? { name, kind } : { name }) as Promise<{ key: string; info: ApiKey }>
export const revokeKey = (id: string) => req('DELETE', `${API}/api/keys/${encodeURIComponent(id)}`)

// --- the change feed (Enterprise) ---

// One event from the feed. Values are Postgres text, so a bigint and a numeric
// survive the trip; null means SQL NULL, and a column missing from `new` means
// it was a large value the update did not touch — leave your own copy alone
// rather than treating it as null. `unchanged` names those explicitly.
export type RealtimeRow = Record<string, string | null>
export type RealtimeEvent =
  | { type: 'schema'; table: string; columns: { name: string; type_oid: number; key: boolean }[] }
  | {
      type: 'change'; table: string; action: 'insert' | 'update' | 'delete' | 'truncate'
      // The transaction's commit position, shared by every change in it, and
      // the only safe place to resume from. `lsn` is the record's own position,
      // for ordering within the transaction.
      commit_lsn: string; lsn?: string; xid?: number
      identity: RealtimeRow
      new?: RealtimeRow; old?: RealtimeRow; changed?: string[]; unchanged?: string[]
    }
  // The frames around a transaction, sent only when asked for with
  // transactions: true. Without them a subscriber cannot tell two changes that
  // belong to one commit from two unrelated ones.
  | { type: 'begin'; xid: number; commit_lsn: string; at?: string }
  | { type: 'commit'; xid: number; commit_lsn: string; at?: string; changes: number }
  | { type: 'resync' | 'error'; code?: string; detail?: string }

// --- what can stream, and making it so (Enterprise) ---

// A table as the catalog describes it, and what that means for streaming.
//
// `status` is the verdict in words — streaming, ready, needs changes, cannot
// stream — and is what the console renders. `fixes` are exact statements; a
// fix with a `cost` has an ongoing price rather than a one-off one, and is the
// only kind a person must be shown before it runs.
export type RealtimeTable = {
  schema: string; name: string; kind: string
  has_primary_key: boolean; rls_enabled: boolean
  client_can_select: boolean; client_can_use_schema: boolean
  is_system: boolean; is_extension_owned: boolean
  unique_index?: string
  inserts: number; updates: number; deletes: number
  stats_days: number; avg_row_bytes: number
}
export type RealtimeFix = { sql: string; why: string; cost?: string }
export type RealtimeVerdict = {
  table: RealtimeTable
  status: 'streaming' | 'ready' | 'needs changes' | 'cannot stream'
  fixes?: RealtimeFix[]
  alternatives?: string[]
  reason?: string
}

// The front door, not /api/ — the same endpoint an application calls, so the
// console cannot drift from what a subscriber is told. A session is accepted
// there; reading verdicts needs only Use.
export const listRealtimeTables = (name: string) =>
  req('GET', `${API}/realtime/v1/branches/${encodeURIComponent(name)}/tables`) as
    Promise<{ branch: string; tables: RealtimeVerdict[]; withheld: number }>

export const enableRealtimeTable = (
  name: string, t: { schema: string; table: string; events?: string[]; full_identity?: boolean },
) => req('POST', `${API}/api/branches/${encodeURIComponent(name)}/realtime/enable`, t) as
  Promise<{ table?: RealtimeVerdict; ok?: boolean }>

export const disableRealtimeTable = (name: string, t: { schema: string; table: string }) =>
  req('POST', `${API}/api/branches/${encodeURIComponent(name)}/realtime/disable`, t) as
    Promise<{ table?: RealtimeVerdict; ok?: boolean }>

// apply defaults to false on the server, so calling this without it shows the
// statements instead of running them.
export const prepareRealtimeTable = (
  name: string, t: { schema: string; table: string; apply?: boolean },
) => req('POST', `${API}/api/branches/${encodeURIComponent(name)}/realtime/prepare`, t) as
  Promise<{ applied: boolean; statements: RealtimeFix[]; table: RealtimeVerdict }>

// --- what staying warm has cost (Enterprise) ---

// A branch with a subscriber attached is never suspended — that is what makes
// the feed continuous, and it is not free. This is where that bill is legible.
//
// `measured` is absent until two readings exist: the counters are cumulative,
// so a single one cannot say how much work happened. `transactions` rather than
// queries, because without pg_stat_statements loaded that is what Postgres
// counts. `notes` carries the caveats a number would otherwise hide.
export type RealtimeSlotLag = {
  slot: string; active: boolean; status: string
  held_bytes: number
  // How much further the bookmark may fall behind before Postgres drops it.
  safe_bytes: number
}
export type RealtimeMeasured = {
  from: string; to: string; over: string
  transactions: number; rows_returned: number
  transactions_per_day: number; samples: number
}
export type RealtimeActivity = {
  branch: string; warm: boolean
  warm_since?: string; warm_for?: string
  subscribers: number; events_delivered: number; peak_subscribers: number
  tables_streaming: number
  measured?: RealtimeMeasured
  slots?: RealtimeSlotLag[]
  notes?: string[]
}

export const getRealtimeActivity = (name: string, window = '24h') =>
  req('GET', `${API}/api/branches/${encodeURIComponent(name)}/realtime/activity?window=${encodeURIComponent(window)}`) as
    Promise<{ activity: RealtimeActivity; cost: string; max_subscribers: number }>

// --- realtime keys (Enterprise) ---

// A stream-only credential for one branch. `prefix` is the visible head of the
// key, which is all that is kept — the secret is hashed, and `url` below is the
// only time it exists outside the subscriber's own configuration.
export type RealtimeKey = { id: string; name: string; prefix: string; created: number; scope: string; kind: string }

export const listRealtimeKeys = (name: string) =>
  req('GET', `${API}/api/branches/${encodeURIComponent(name)}/realtime/keys`) as Promise<{ keys: RealtimeKey[] }>

// The response carries the whole connection string, key included, once.
export const createRealtimeKey = (name: string, label: string) =>
  req('POST', `${API}/api/branches/${encodeURIComponent(name)}/realtime/keys`, { name: label }) as
    Promise<{ key: RealtimeKey; url: string }>

export const revokeRealtimeKey = (name: string, id: string) =>
  req('DELETE', `${API}/api/branches/${encodeURIComponent(name)}/realtime/keys/${encodeURIComponent(id)}`) as
    Promise<{ revoked: string }>

// streamChanges opens the feed and calls onEvent for each one, until the
// returned function is called or the stream ends.
//
// A fetch reader rather than EventSource, for the same reason consumeSSE is
// one: EventSource cannot set a request header, which would force the API key
// into the URL where it lands in logs and history.
export function streamChanges(
  name: string,
  onEvent: (e: RealtimeEvent) => void,
  opts: { since?: string; transactions?: boolean; onClose?: (reason?: string) => void } = {},
): () => void {
  const ctrl = new AbortController()
  const q = new URLSearchParams()
  if (opts.since) q.set('since', opts.since)
  if (opts.transactions) q.set('transactions', '1')
  const url = `${API}/api/branches/${encodeURIComponent(name)}/realtime`
    + (q.size ? `?${q}` : '')
  ;(async () => {
    let reason: string | undefined
    try {
      // Cookie/session auth, like every other call here. A branch-scoped
      // API key reaches this route too, but that is for a program using
      // the API directly; the console is a signed-in person.
      const res = await fetch(url, { credentials: 'include', signal: ctrl.signal })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new ApiError(res.status, (data as { error?: string }).error || `HTTP ${res.status}`)
      }
      const reader = res.body!.getReader()
      const dec = new TextDecoder()
      let buf = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buf += dec.decode(value, { stream: true })
        const { frames, rest } = splitFrames(buf)
        buf = rest
        for (const f of frames) {
          if (!f.data) continue
          try { onEvent(JSON.parse(f.data) as RealtimeEvent) } catch { /* not ours */ }
        }
      }
    } catch (e) {
      if ((e as Error).name !== 'AbortError') reason = (e as Error).message
    } finally {
      opts.onClose?.(reason)
    }
  })()
  return () => ctrl.abort()
}

// --- control plane ---
export const getStatus = () => req('GET', `${API}/api/status`) as Promise<Status>

// What the engine is honouring, and why. /api/status says which features are
// usable; this says what to do when they are not. The fields after `action` are
// admin-only, because who bought the licence and which machine it is tied to
// are the account's details rather than the product's.
export type License = {
  edition: 'standard' | 'enterprise'
  present: boolean                                   // is a licence installed at all
  state: 'active' | 'warning' | 'lapsed' | 'invalid'
  unlocks: boolean                                   // are the paid features usable right now
  features: Feature[]
  reason: string                                     // empty when there is nothing wrong
  action: string                                     // what would fix it
  you_are_admin?: boolean                            // may this viewer activate one (absent on an older engine)
  expires?: string                                   // RFC 3339
  id?: string
  customer?: string
  licensed?: Feature[]                               // what the licence names, vs what this build serves
  issuedAt?: string
  issuedFor?: string
  boundTo?: string
  rebinds?: number
}
export const getLicense = () => req('GET', `${API}/api/license`) as Promise<License>

// What came back from activating one. `notes` is what is still left to do and
// is empty when there is nothing. Every engine process now picks a licence up by
// itself, so the one note left is for macOS and Windows: only the VM's copy was
// written, and the host keeps its own at the next `fox start`.
export type LicenseActivation = {
  activated: string
  customer: string
  edition: 'standard' | 'enterprise'
  state: License['state']
  unlocks: boolean
  reason: string
  action: string
  notes?: string[]
}

/** Activate a licence. Admin only; the engine refuses a forgery outright. */
export const activateLicense = (text: string) =>
  req('POST', `${API}/api/license`, { license: text }) as Promise<LicenseActivation>

// The Upgrade modal's Install button: the engine switches itself to the other
// edition in the background, and says how it went (admins only).
export interface EditionSwitch {
  state: 'none' | 'running' | 'done' | 'failed'
  edition: string
  by?: string
  started_at?: string
  finished_at?: string
  error?: string
  log?: string[]
}
export const startEditionSwitch = (edition: 'enterprise' | 'standard', acceptLicense: boolean) =>
  req('POST', `${API}/api/edition/switch`, { edition, accept_license: acceptLicense }) as Promise<{ state: string }>
export const getEditionSwitch = () => req('GET', `${API}/api/edition/switch`) as Promise<EditionSwitch>
export const getBranches = () => req('GET', `${API}/api/branches`) as Promise<Branch[]>
// from: the branch to copy (default main).
export const createBranch = (name: string, from?: string) =>
  req('POST', `${API}/api/branches`, from ? { name, from } : { name })
export const deleteBranch = (name: string) => req('DELETE', `${API}/api/branches/${name}`)
export const suspendBranch = (name: string) => req('POST', `${API}/api/branches/${name}/suspend`)
export const resumeBranch = (name: string) => req('POST', `${API}/api/branches/${name}/resume`)
// allowDestructive applies SET bb.allow_destructive=on to this one run. The
// query runs as the signed-in user, so it counts only for admins of the branch.
// allowRules applies SET bb.policy_allow: the per-rule override for a Blackbox
// policy block (BBX01), which allowDestructive does not cover.
// history: false keeps the query out of the signed-in user's query history
// (point 8.1): the console's own reads of a table, which nobody typed.
export const runQuery = (name: string, sql: string, opts: { allowDestructive?: boolean; allowRules?: string[]; history?: boolean } = {}) =>
  req('POST', `${API}/api/branches/${name}/query`, {
    sql,
    ...(opts.allowDestructive ? { allow_destructive: true } : {}),
    ...(opts.allowRules?.length ? { allow_rules: opts.allowRules } : {}),
    ...(opts.history === false ? { history: false } : {}),
  }) as Promise<QueryResult>

// Query history (points 8.1, 8.3): your own, and the switches. The engine
// keeps the SQL, branch, time, duration, row count and outcome, never a result.
export type HistoryEntry = {
  id: number; branch: string; source: 'console' | 'api' | 'cli'; kind: 'query' | 'export'
  sql: string; truncated?: boolean; at: number; duration_ms: number; rows: number; ok: boolean; error?: string
}
export type HistorySettings = { enabled: boolean; retention_days: number; mine: boolean; count: number; admin: boolean }
export const listHistory = (opts: { branch?: string; limit?: number; before?: number; q?: string; failed?: boolean } = {}) => {
  const q = new URLSearchParams()
  if (opts.branch) q.set('branch', opts.branch)
  if (opts.limit) q.set('limit', String(opts.limit))
  if (opts.before) q.set('before', String(opts.before))
  if (opts.q) q.set('q', opts.q)
  if (opts.failed) q.set('failed', '1')
  const qs = q.toString()
  return req('GET', `${API}/api/history${qs ? `?${qs}` : ''}`) as Promise<{ entries: HistoryEntry[] }>
}
export const historySettings = () => req('GET', `${API}/api/history/settings`) as Promise<HistorySettings>
export const setHistorySettings = (p: { mine?: boolean; enabled?: boolean; retention_days?: number }) =>
  req('PUT', `${API}/api/history/settings`, p) as Promise<HistorySettings>
export const deleteMyHistory = () => req('DELETE', `${API}/api/history`) as Promise<{ deleted: number }>
export const deleteHistoryEntry = (id: number) => req('DELETE', `${API}/api/history/${id}`)
// The object browser (point 12.1): what a branch holds, read as you, and each
// object's CREATE script.
export type CatalogKind = 'schema' | 'table' | 'view' | 'sequence' | 'function' | 'procedure' | 'type' | 'extension'
export type CatalogObject = {
  kind: CatalogKind; oid: number; schema?: string; name: string; args?: string; sub?: string; system?: boolean
}
export type CatalogPart = { name: string; kind?: string; def: string; constraint?: boolean; system?: boolean; disabled?: boolean }
export type CatalogCol = { name: string; type: string; not_null?: boolean; default?: string; identity?: string; generated?: string; comment?: string }
export type ObjectDetail = CatalogObject & {
  comment?: string; columns?: CatalogCol[]; constraints?: CatalogPart[]; indexes?: CatalogPart[]; triggers?: CatalogPart[]
  facts?: [string, string][]; values?: string[]; members?: { Kind: string; Name: string }[]; ddl: string
}
export const getCatalog = (branch: string) =>
  req('GET', `${API}/api/branches/${branch}/schema`) as Promise<{ objects: CatalogObject[] | null }>
export const getObject = (branch: string, kind: CatalogKind, oid: number) =>
  req('GET', `${API}/api/branches/${branch}/schema/${kind}/${oid}`) as Promise<ObjectDetail>

// Row tracking (points 5.1, 6.1): who changed each row and when, kept by
// Postgres on the tables someone chose. Changing it is the branch owner's.
export type TrackOptions = { created: string; updated: string; by: string; label_existing?: boolean }
export type TrackedTable = { schema: string; name: string; created: string; updated: string; by: string }
export type Tracking = { settings: { track_new: boolean; created: string; updated: string; by: string }; tables: TrackedTable[] }
export const getTracking = (branch: string) => req('GET', `${API}/api/branches/${branch}/tracking`) as Promise<Tracking>
export const trackTable = (branch: string, schema: string, table: string, o: TrackOptions) =>
  req('PUT', `${API}/api/branches/${branch}/tracking/tables/${encodeURIComponent(schema)}/${encodeURIComponent(table)}`, o) as Promise<Tracking>
export const untrackTable = (branch: string, schema: string, table: string) =>
  req('DELETE', `${API}/api/branches/${branch}/tracking/tables/${encodeURIComponent(schema)}/${encodeURIComponent(table)}`) as Promise<Tracking>
export const setTrackNew = (branch: string, on: boolean, o: Omit<TrackOptions, 'label_existing'>) =>
  req('PUT', `${API}/api/branches/${branch}/tracking/new`, { on, ...o }) as Promise<Tracking>

// Personal-data discovery (point 4.1). A finding says where and what, never a
// value: the engine keeps none.
export type PIISkip = { object: string; reason: string }
export type PIIScan = {
  id: number
  started: string
  finished: string
  actor: string
  sample: number
  tables: number
  columns: number
  newOnly?: boolean
  skipped: PIISkip[] | null
  limits: string[] | null
}
export type PIIFinding = {
  id: number
  schema: string
  table: string
  column: string
  path: string
  category: string
  rule: 'name' | 'value' | 'name+value'
  confidence: 'high' | 'medium' | 'low'
  why: string
  matched: number
  sampled: number
  state: 'suggested' | 'confirmed' | 'rejected'
  firstScan: number
  lastScan: number
  lastSeen: string
  decidedBy?: string
  decidedAt?: string | null
  note?: string
}
export type PersonalData = {
  branch: string
  scan: PIIScan | null
  findings: PIIFinding[] | null
  fullScan?: number // the latest scan that read every table
  unclassified?: number // new places since the first scan, not reviewed (4.7)
}
export const getPersonalData = (branch: string) =>
  req('GET', `${API}/api/branches/${branch}/personal-data`) as Promise<PersonalData>
export const scanPersonalData = (branch: string, sample?: number, newOnly?: boolean) =>
  req('POST', `${API}/api/branches/${branch}/personal-data/scan`, { ...(sample ? { sample } : {}), ...(newOnly ? { newOnly } : {}) }) as Promise<PersonalData>

// Review (point 4.6): a reviewer decides what each finding is, from masked
// samples read as their own role.
export type PIIDecision = { id: number; state: PIIFinding['state']; actor: string; note: string; at: string }
export type PIIFindingDetail = { finding: PIIFinding; decisions: PIIDecision[] | null }
export type PIISamples = { finding: PIIFinding; samples: { masked: string; matches: boolean }[] | null; read: number; as: string }
const findingURL = (branch: string, id: number) => `${API}/api/branches/${branch}/personal-data/findings/${id}`
export const getFinding = (branch: string, id: number) => req('GET', findingURL(branch, id)) as Promise<PIIFindingDetail>
export const markFinding = (branch: string, id: number, state: PIIFinding['state'], note: string) =>
  req('POST', `${findingURL(branch, id)}/mark`, { state, note }) as Promise<PIIFindingDetail>
export const getSamples = (branch: string, id: number, n = 5) =>
  req('GET', `${findingURL(branch, id)}/samples?n=${n}`) as Promise<PIISamples>

// Keeping it current (point 4.7): what appeared after a branch's first scan
// and no one has reviewed yet. Names only.
export type PIIColumn = {
  id: number
  schema: string
  table: string
  column: string
  path: string
  status: 'known' | 'unclassified' | 'reviewed'
  firstScan: number
  lastScan: number
  firstSeen: string
  reviewedBy: string
  reviewedAt: string | null
  note: string
  findings: number
  undecided: number
}
export const getUnclassified = (branch: string) =>
  req('GET', `${API}/api/branches/${branch}/personal-data/unclassified`) as Promise<{ branch: string; columns: PIIColumn[] | null }>
export const acceptColumn = (branch: string, id: number, note = '') =>
  req('POST', `${API}/api/branches/${branch}/personal-data/columns/${id}/accept`, note ? { note } : {}) as Promise<PIIColumn>

// The data grid's save (point 12.2): rows added, changed and deleted, applied
// together as you, or not at all.
export const saveRows = (branch: string, schema: string, table: string, changes: import('./gridquery').RowChange[]) =>
  req('POST', `${API}/api/branches/${branch}/rows`, { schema, table, changes }) as Promise<{ inserted: number; updated: number; deleted: number }>

// Saved queries (point 8.2): a statement kept under a name until you delete it.
export type SavedQuery = { id: number; name: string; sql: string; created: number; updated: number }
export const listSaved = (q = '') =>
  req('GET', `${API}/api/saved-queries${q ? `?q=${encodeURIComponent(q)}` : ''}`) as Promise<{ queries: SavedQuery[] }>
export const saveQuery = (name: string, sql: string) => req('POST', `${API}/api/saved-queries`, { name, sql }) as Promise<SavedQuery>
export const updateSaved = (id: number, p: { name?: string; sql?: string }) =>
  req('PUT', `${API}/api/saved-queries/${id}`, p) as Promise<SavedQuery>
export const deleteSaved = (id: number) => req('DELETE', `${API}/api/saved-queries/${id}`)
// exportQuery is the whole result of one statement as a file (point 1.3), not
// the 1,000 rows a run holds. The server streams it as the signed-in user, read
// only, and records it in the security log. A failure before the first row is
// a JSON error; one part way through ends the connection, which arrives here
// as a failed read, so a short file is never handed back as a whole one.
export const exportQuery = async (name: string, sql: string, format: 'csv' | 'json' | 'xlsx', safe: boolean): Promise<Blob> => {
  const r = await fetch(`${API}/api/branches/${name}/export`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sql, format, safe }),
  })
  if (!r.ok) {
    if (r.status === 401 && location.pathname !== '/login') location.assign('/login')
    let msg = `HTTP ${r.status}`
    try { msg = (await r.json()).error || msg } catch { /* not JSON */ }
    throw new ApiError(r.status, msg)
  }
  try {
    return await r.blob()
  } catch {
    throw new Error('the export stopped part way, so nothing was saved: run it again')
  }
}
// Recomputes the Blackbox hash chain (GET …/ledger/verify).
export type LedgerVerify = { legacy: number; chained: number; broken: number; firstBroken: string }
export const verifyLedger = async (name: string): Promise<LedgerVerify> => {
  const r = await req('GET', `${API}/api/branches/${name}/ledger/verify`) as QueryResult
  if (r.error) throw new Error(r.error)
  const row = r.rows?.[0] ?? []
  const at = (c: string) => row[(r.columns ?? []).indexOf(c)]
  return { legacy: Number(at('legacy') ?? 0), chained: Number(at('chained') ?? 0), broken: Number(at('broken') ?? 0), firstBroken: String(at('first_broken') ?? '') }
}

// Base backups in object storage: what a point-in-time restore can start from.
export type Backup = {
  name: string; started_at?: string; finished_at: string; size_bytes?: number; newest?: boolean
}
export const listBackups = () => req('GET', `${API}/api/backups`) as Promise<Backup[]>

// Continuous imports (logical replication into a branch).
export type Replication = {
  branch: string; replicating: boolean; tables: number; tables_ready: number
  last_message_at?: string; received_lsn?: string
}
export const listReplication = () => req('GET', `${API}/api/replication`) as Promise<Replication[]>
export const cutoverReplication = (branch: string) =>
  req('POST', `${API}/api/branches/${branch}/replication/cutover`) as Promise<{ branch: string; status: string; tables: number }>

export const getLedger = (name: string, filters: Record<string, string> = {}) => {
  const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString()
  return req('GET', `${API}/api/branches/${name}/ledger${qs ? '?' + qs : ''}`) as Promise<QueryResult>
}
// --- Blackbox integrity (Blackbox 2.0) ---
export type IntegrityReport = {
  intact: boolean; rows: number; chained_rows: number; legacy_rows: number
  checkpoints: number; anchored_rows: number; unanchored_rows: number
  first_broken_id?: number; problems: string[]; notes: string[]
}
export type Checkpoint = {
  checkpoint_id: number; from_id: number; to_id: number; entry_count: number
  merkle_root: string; prev_root: string; last_row_hash: string; created_at: string
}
export const getIntegrity = (name: string) =>
  req('GET', `${API}/api/branches/${name}/ledger/integrity`) as Promise<IntegrityReport>
export const createCheckpoint = (name: string) =>
  req('POST', `${API}/api/branches/${name}/ledger/checkpoint`) as Promise<{ checkpoint: Checkpoint | null; anchor_path?: string; status: string }>
export const exportLedgerUrl = (name: string) => `${API}/api/branches/${name}/ledger/export`
export type LedgerEntry = {
  id: number; at: string; actor: string; command_tag: string; object_identity: string; status: string; risk: string
}
export const getLedgerEntries = (name: string, limit = 50) =>
  req('GET', `${API}/api/branches/${name}/ledger/entries?limit=${limit}`) as Promise<LedgerEntry[]>
export type BranchBeforeResult = {
  branch: string; source: string; entry_id: number; command_tag: string; object_identity: string
  statement: string; target_kind: 'xid' | 'time'; target: string; base_backup: string
  last_ledger_id: number; seconds: number
}
export const branchBeforeEntry = (source: string, entryId: number, name?: string) =>
  req('POST', `${API}/api/branches/${source}/ledger/${entryId}/branch`, name ? { name } : {}) as Promise<BranchBeforeResult>

// --- Change requests: a branch's schema changes, offered for review ---
export type RequestEntry = {
  id: number; at: string; actor: string; kind: string
  command: string; object: string; sql: string; risk?: string
}
export type ChangeRequest = {
  id: number; source: string; target: string; created_by: string; created: string
  status: 'open' | 'approved' | 'rejected' | 'failed'
  fork_after_id: number; decided_by?: string; decided?: string; note?: string
  applied: number; entries: RequestEntry[]
}
export const listRequests = (status = '') =>
  req('GET', `${API}/api/requests${status ? '?status=' + status : ''}`) as Promise<ChangeRequest[]>
export const getRequest = (id: number) =>
  req('GET', `${API}/api/requests/${id}`) as Promise<ChangeRequest>
export const createRequest = (source: string, target: string) =>
  req('POST', `${API}/api/branches/${source}/request`, { target }) as Promise<ChangeRequest>
export const decideRequest = (id: number, decision: 'approve' | 'reject', note?: string) =>
  req('POST', `${API}/api/requests/${id}/${decision}`, note ? { note } : {}) as Promise<ChangeRequest>

// --- Blackbox policy gate (docs/policy-errors.md) ---
export type PolicyAction = 'warn' | 'block'
export type PolicyRule = {
  rule_id: string; command_tag: string; pattern: string | null; action: PolicyAction; reason: string
  hint: string | null; enabled: boolean; builtin: boolean; updated_at: string; updated_by: string | null
}
export type PolicyMatch = {
  v: number; rule_id: string; action: PolicyAction; command: string; matched: string | null; reason: string
  hint: string; override: string | null; evaluation_id: number | null; blackbox_id: number | null
}
export type PolicyCheckResult = { command: string; matches: PolicyMatch[] }
export type PolicyEvaluation = {
  id: number; at: string; xid: number | null; rule_id: string; action: 'warn' | 'block' | 'allowed'
  command_tag: string | null; actor: string | null; blackbox_id: number | null
}
const policies = (branch: string) => `${API}/api/branches/${branch}/policies`
export const getPolicyRules = (branch: string) => req('GET', policies(branch)) as Promise<PolicyRule[]>
export const addPolicyRule = (branch: string, rule: Pick<PolicyRule, 'rule_id' | 'command_tag' | 'pattern' | 'action' | 'reason' | 'hint'>) =>
  req('POST', policies(branch), rule)
export const updatePolicyRule = (branch: string, rule: string, change: { action?: PolicyAction; enabled?: boolean }) =>
  req('PUT', `${policies(branch)}/${encodeURIComponent(rule)}`, change)
export const removePolicyRule = (branch: string, rule: string) =>
  req('DELETE', `${policies(branch)}/${encodeURIComponent(rule)}`)
export const checkPolicy = (branch: string, sql: string) =>
  req('POST', `${policies(branch)}/check`, { sql }) as Promise<PolicyCheckResult>
export const getPolicyEvaluations = (branch: string, limit = 20) =>
  req('GET', `${policies(branch)}/evaluations?limit=${limit}`) as Promise<PolicyEvaluation[]>

// Who may override blocking rules (db_admin) on a branch. Anyone signed in may
// read it; granting and revoking need db_admin there.
export type BranchAdmins = { admins: string[]; you: string; you_are_admin: boolean }
const admins = (branch: string) => `${API}/api/branches/${branch}/admins`
export const getAdmins = (branch: string) => req('GET', admins(branch)) as Promise<BranchAdmins>
export const grantAdmin = (branch: string, email: string) => req('POST', admins(branch), { email })
export const revokeAdmin = (branch: string, email: string) =>
  req('DELETE', `${admins(branch)}/${encodeURIComponent(email)}`)

// --- migration (streamed as Server-Sent Events) ---
export type ImportResult = { status: string; target: string; tables: number }
export type ImportEvent =
  | { type: 'log'; line: string }
  | { type: 'progress'; done: number; total: number; label: string }
  | { type: 'done'; status: string; target: string; tables: number }
  | { type: 'error'; message: string }

// consumeSSE reads a text/event-stream response, dispatching each event and
// resolving with the final `done` payload (or rejecting on `error`).
async function consumeSSE(res: Response, onEvent: (e: ImportEvent) => void): Promise<ImportResult> {
  if (!res.ok) {
    if (res.status === 401 && location.pathname !== '/login') location.assign('/login')
    const data = await res.json().catch(() => ({}))
    throw new ApiError(res.status, (data as { error?: string }).error || `HTTP ${res.status}`)
  }
  const reader = res.body!.getReader()
  const dec = new TextDecoder()
  let buf = '', result: ImportResult | null = null, errMsg: string | null = null
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buf += dec.decode(value, { stream: true })
    let idx: number
    while ((idx = buf.indexOf('\n\n')) >= 0) {
      const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2)
      let event = 'message', dataStr = ''
      for (const ln of chunk.split('\n')) {
        if (ln.startsWith('event:')) event = ln.slice(6).trim()
        else if (ln.startsWith('data:')) dataStr += ln.slice(5).trim()
      }
      let data: Record<string, unknown> = {}
      try { data = JSON.parse(dataStr) } catch { /* ignore keep-alives */ }
      if (event === 'log') onEvent({ type: 'log', line: String(data.line ?? '') })
      else if (event === 'progress') onEvent({ type: 'progress', done: Number(data.done), total: Number(data.total), label: String(data.label ?? '') })
      else if (event === 'done') { result = data as unknown as ImportResult; onEvent({ type: 'done', ...(data as any) }) }
      else if (event === 'error') { errMsg = String(data.message ?? 'migration failed'); onEvent({ type: 'error', message: errMsg }) }
    }
  }
  if (errMsg) throw new Error(errMsg)
  if (!result) throw new Error('the migration ended without a result')
  return result
}

export const importDBStream = async (source: string, target: string, continuous: boolean, onEvent: (e: ImportEvent) => void) => {
  const res = await fetch(`${API}/api/import`, {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source, target, continuous }),
  })
  return consumeSSE(res, onEvent)
}

export const importFileStream = async (file: File, target: string, onEvent: (e: ImportEvent) => void) => {
  const fd = new FormData()
  fd.append('file', file)
  if (target) fd.append('target', target)
  const res = await fetch(`${API}/api/import/file`, { method: 'POST', credentials: 'include', body: fd })
  return consumeSSE(res, onEvent)
}

// --- ETL pipelines ---
export type PipelineModel = { name: string; sql: string; materialized?: string }
export type PipelineTest = { name?: string; model?: string; type: string; column?: string; values?: string[]; min?: number; sql?: string }
export type PipelineSpec = { source: string; models: PipelineModel[]; tests: PipelineTest[] }
export type Pipeline = { id: string; name: string; spec: string; created: number; updated: number }
export type TestResult = { name: string; passed: boolean; detail?: string }
export type PipelineRun = { id: string; pipeline_id: string; status: string; started: number; finished: number; tables: number; tests: string }
export type PipelineRunResult = ImportResult & { tests?: TestResult[]; failed?: boolean }

export const listPipelines = () => req('GET', `${API}/api/pipelines`) as Promise<{ pipelines: Pipeline[] }>
export const getPipeline = (id: string) => req('GET', `${API}/api/pipelines/${encodeURIComponent(id)}`) as Promise<Pipeline>
export const createPipeline = (name: string, spec: PipelineSpec) =>
  req('POST', `${API}/api/pipelines`, { name, spec }) as Promise<Pipeline>
export const updatePipeline = (id: string, name: string, spec: PipelineSpec) =>
  req('PUT', `${API}/api/pipelines/${encodeURIComponent(id)}`, { name, spec })
export const deletePipeline = (id: string) =>
  req('DELETE', `${API}/api/pipelines/${encodeURIComponent(id)}`)
export const listPipelineRuns = (id: string) =>
  req('GET', `${API}/api/pipelines/${encodeURIComponent(id)}/runs`) as Promise<{ runs: PipelineRun[] }>
export const runPipelineStream = async (id: string, onEvent: (e: ImportEvent) => void) => {
  const res = await fetch(`${API}/api/pipelines/${encodeURIComponent(id)}/run`, { method: 'POST', credentials: 'include' })
  return consumeSSE(res, onEvent) as Promise<PipelineRunResult>
}
