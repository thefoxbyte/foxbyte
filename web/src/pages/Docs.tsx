import { useState } from 'react'
import { Link } from 'react-router-dom'
import { getStatus, getBranches } from '../api'

export default function Docs() {
  const [out, setOut] = useState('// responses appear here')
  const call = async (label: string, fn: () => Promise<unknown>) => {
    setOut(label + ' …')
    try {
      setOut(label + '\n' + JSON.stringify(await fn(), null, 2))
    } catch (e) {
      setOut('error: ' + (e as Error).message)
    }
  }

  return (
    <div className="fade-up">
      <h1>Reference</h1>
      <p className="lead">The <code>fox</code> CLI, the REST API, and configuration.</p>

      <div className="note" style={{ border: '1px solid var(--border)', borderLeft: '4px solid var(--accent)', borderRadius: 10, padding: '10px 14px', background: 'var(--panel)' }}>
        <strong>New to FoxByte?</strong> The <Link to="/guide">Developer Guide</Link> walks you from install
        to connecting an app and doing CRUD. This page is the lookup reference.
      </div>

      <h2>CLI reference</h2>
      <table>
        <thead><tr><th>Command</th><th>What it does</th></tr></thead>
        <tbody>
          <tr><td><code>fox setup</code></td><td>One-time (macOS / Windows): create/start the local VM (WSL2 on Windows) and bring everything up</td></tr>
          <tr><td><code>fox start</code> · <code>fox stop</code></td><td>Start / stop the whole stack in the background</td></tr>
          <tr><td><code>fox status</code></td><td>Servers, primary readiness, and branches</td></tr>
          <tr><td><code>fox logs [gateway|api]</code></td><td>Print a background server's log</td></tr>
          <tr><td><code>fox branch create|list|delete|suspend|resume &lt;name&gt;</code></td><td>Manage copy-on-write branches (<code>create … --from &lt;branch&gt;</code> copies another branch)</td></tr>
          <tr><td><code>fox vm [status|shell]</code></td><td>macOS / Windows: the engine VM's state and size, or a shell inside it</td></tr>
          <tr><td><code>fox backup create|list</code> · <code>fox restore --to &lt;ts|latest&gt;</code></td><td>Time-travel / point-in-time recovery</td></tr>
          <tr><td><code>fox ha enable|status|failover|disable|failback</code></td><td>High availability (streaming standby, failover, and failback to main)</td></tr>
          <tr><td><code>fox gateway [--addr :6432] [--idle 2m]</code></td><td>The smart SQL gateway — routes by branch, auto-suspend/resume</td></tr>
          <tr><td><code>fox serve [--addr :8088]</code></td><td>Agent Branch API — one database per AI agent</td></tr>
          <tr><td><code>fox user create &lt;email&gt;</code> · <code>fox apikey create|list|revoke &lt;email&gt;</code></td><td>Accounts &amp; API keys</td></tr>
        </tbody>
      </table>

      <h2>REST API</h2>
      <p className="muted">The control-plane API (default <code>https://localhost:8080</code>). Calls require a session
        cookie or <code>Authorization: Bearer &lt;api-key&gt;</code>. The full description is served at{' '}
        <code>GET /api/openapi.yaml</code> — point a client generator at it. Try the live ones:</p>
      <div className="row">
        <button className="ghost" onClick={() => call('GET /api/status', getStatus)}>GET /api/status</button>
        <button className="ghost" onClick={() => call('GET /api/branches', getBranches)}>GET /api/branches</button>
      </div>
      <pre><code>{out}</code></pre>

      <table>
        <thead><tr><th>Method &amp; path</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>GET /api/status</code></td><td>Primary, counts, HA, storage, servers</td></tr>
          <tr><td><code>GET /api/branches</code></td><td>List branches (state, size, connections)</td></tr>
          <tr><td><code>POST /api/branches</code></td><td>Create a branch — {'{ "name": "qa", "from": "main" }'}</td></tr>
          <tr><td><code>DELETE /api/branches/{'{name}'}</code></td><td>Delete a branch</td></tr>
          <tr><td><code>POST /api/branches/{'{name}'}/suspend|resume</code></td><td>Suspend / resume</td></tr>
          <tr><td><code>POST /api/branches/{'{name}'}/query</code></td><td>Run SQL as the signed-in user — {'{ "sql": "…", "allow_destructive": false, "allow_rules": [] }'}</td></tr>
          <tr><td><code>GET /api/branches/{'{name}'}/ledger</code></td><td>Blackbox entries (filters: <code>actor</code>, <code>table</code>, <code>risk</code>, <code>status</code>, <code>kind</code>, <code>since</code>, <code>until</code>; <code>with=session</code> adds the session)</td></tr>
          <tr><td><code>GET …/ledger/verify</code> · <code>…/integrity</code> · <code>…/export</code> · <code>…/entries</code> · <code>…/sessions</code></td><td>Verify the hash chain, check against anchors, export JSONL, list entries and agent sessions</td></tr>
          <tr><td><code>POST …/ledger/checkpoint</code> · <code>POST …/ledger/{'{id}'}/branch</code></td><td>Anchor new entries; branch <code>main</code> from just before an entry</td></tr>
          <tr><td className="muted" colSpan={2}>Every <code>…/ledger…</code> path is also served as <code>…/blackbox…</code></td></tr>
          <tr><td><code>GET /api/branches/{'{name}'}/policies</code> · <code>POST</code> · <code>PUT|DELETE …/{'{rule}'}</code></td><td>Policy gate rules (changes need <code>db_admin</code>)</td></tr>
          <tr><td><code>POST …/policies/check</code> · <code>GET …/policies/evaluations</code></td><td>Preview what a statement triggers; recent warnings and blocks</td></tr>
          <tr><td><code>GET|POST /api/branches/{'{name}'}/admins</code> · <code>DELETE …/admins/{'{email}'}</code></td><td>Who may override blocking rules; grant or revoke it (needs <code>db_admin</code>)</td></tr>
          <tr><td><code>POST /api/branches/{'{name}'}/impact</code></td><td>What a change would affect, before running it</td></tr>
          <tr><td><code>GET /api/ledger/diff</code> · <code>GET /api/blackbox/diff</code></td><td>Schema changes distinguishing two branches (<code>?a=&amp;b=</code>)</td></tr>
          <tr><td><code>POST /api/import</code> · <code>POST /api/import/file</code></td><td>Migrate from a connection string ({'{ "source", "target", "continuous" }'}) or an upload</td></tr>
          <tr><td><code>GET /api/backups</code></td><td>Base backups in object storage, newest first — the oldest is the earliest point <code>fox restore --to</code> can reach</td></tr>
          <tr><td><code>GET /api/replication</code> · <code>GET /api/branches/{'{name}'}/replication</code> · <code>POST …/replication/cutover</code></td><td>Continuous imports: how far each has copied, and the cutover that makes the branch standalone</td></tr>
          <tr><td><code>GET|POST /api/pipelines</code> · <code>GET|PUT|DELETE …/{'{id}'}</code> · <code>…/runs</code> · <code>…/run</code></td><td>ETL pipelines and their run history</td></tr>
          <tr><td><code>GET|POST /api/keys</code> · <code>DELETE /api/keys/{'{id}'}</code></td><td>API keys</td></tr>
          <tr><td><code>POST /auth/login</code> · <code>/auth/register</code> · <code>/auth/logout</code> · <code>GET /auth/me</code></td><td>Browser sessions (public)</td></tr>
          <tr><td><code>POST /agents/{'{id}'}/branch</code> · <code>DELETE …</code></td><td>Agent API (<code>https://localhost:8088</code>) — create / destroy an agent database</td></tr>
        </tbody>
      </table>

      <h2>Agents over MCP</h2>
      <p className="muted">Agent frameworks can skip HTTP: <code>fox mcp</code> speaks the Model Context Protocol on
        stdio, with 16 tools for branches, SQL, Blackbox, impact analysis and the policy gate.{' '}
        <a href="https://github.com/foxbyte/foxbyte/blob/main/docs/mcp.md" target="_blank" rel="noreferrer">Setup and tool reference</a>.</p>
      <table>
        <thead><tr><th>Client config</th><th>Notes</th></tr></thead>
        <tbody>
          <tr><td><code>{'{ "command": "fox", "args": ["mcp"], "env": { "FOX_API_KEY": "key_…" } }'}</code></td><td>Needs <code>fox start</code> running and an API key — the server acts as that account; a branch-scoped key limits it to one branch</td></tr>
        </tbody>
      </table>

      <h2>Configuration</h2>
      <p className="muted">Set these in the environment before <code>fox start</code>.</p>
      <table>
        <thead><tr><th>Variable</th><th>Purpose</th></tr></thead>
        <tbody>
          <tr><td><code>FOX_SIGNUP</code></td><td><code>open</code> (default) or <code>closed</code> — allow browser self-signup</td></tr>
          <tr><td><code>FOX_PUBLIC_URL</code></td><td>Public base URL, for OAuth callbacks and links (default <code>https://localhost:8080</code>)</td></tr>
          <tr><td><code>FOX_WEB_ORIGIN</code></td><td>Where the web console is served, for CORS and the return from an OAuth login (default: the public URL — set it only for a separately hosted UI)</td></tr>
          <tr><td><code>FOX_GITHUB_CLIENT_ID</code> · <code>_SECRET</code></td><td>Enable “Continue with GitHub” (optional)</td></tr>
          <tr><td><code>FOX_GOOGLE_CLIENT_ID</code> · <code>_SECRET</code></td><td>Enable “Continue with Google” (optional)</td></tr>
          <tr><td><code>FOX_ZPOOL_DEVICE</code> · <code>_SIZE</code></td><td>ZFS pool vdev &amp; size (auto-created on a loopback file if unset)</td></tr>
          <tr><td><code>FOX_LIMA_INSTANCE</code></td><td>macOS: which Lima VM <code>fox</code> manages</td></tr>
        </tbody>
      </table>
    </div>
  )
}
