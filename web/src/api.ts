// Typed client for the FoxByte control-plane API (cookie/session auth).
// When the UI is served by the control-plane itself (the embedded production
// build sets VITE_API_URL=""), API is "" — i.e. same-origin, relative requests.
// The dev server (`make web-dev`, VITE_API_URL unset) falls back to :8080.
export const API = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8080'
export const AGENT_API = (import.meta.env.VITE_AGENT_API_URL as string | undefined) ?? 'http://localhost:8088'

export type User = { id: number; email: string }
export type HAState = { enabled: boolean; standby: string; streaming: boolean; primary: string }
export type StorageInfo = { used: string; avail: string }
export type Status = {
  mainReady: boolean
  branches: number
  agents: number
  ha: HAState
  storage: StorageInfo
  servers: { gateway: boolean; api: boolean }
}
export type Branch = {
  name: string; primary: boolean; agent: boolean; state: string
  used: string; refer: string; connections: number; port: string
}
export type QueryResult = { columns?: string[]; rows?: unknown[][]; command?: string; error?: string }
export type ApiKey = { id: string; name: string; prefix: string; created: number }
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
  const data = await r.json().catch(() => ({}))
  if (!r.ok) {
    // Session expired mid-use → bounce to login (except when probing /auth/me).
    if (r.status === 401 && !url.endsWith('/auth/me')) {
      if (location.pathname !== '/login') location.assign('/login')
    }
    throw new ApiError(r.status, (data && (data as any).error) || `HTTP ${r.status}`)
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
export const listKeys = () => req('GET', `${API}/api/keys`) as Promise<{ keys: ApiKey[] }>
export const createKey = (name: string) => req('POST', `${API}/api/keys`, { name }) as Promise<{ key: string; info: ApiKey }>
export const revokeKey = (id: string) => req('DELETE', `${API}/api/keys/${encodeURIComponent(id)}`)

// --- control plane ---
export const getStatus = () => req('GET', `${API}/api/status`) as Promise<Status>
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
export const runQuery = (name: string, sql: string, opts: { allowDestructive?: boolean; allowRules?: string[] } = {}) =>
  req('POST', `${API}/api/branches/${name}/query`, {
    sql,
    ...(opts.allowDestructive ? { allow_destructive: true } : {}),
    ...(opts.allowRules?.length ? { allow_rules: opts.allowRules } : {}),
  }) as Promise<QueryResult>
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
