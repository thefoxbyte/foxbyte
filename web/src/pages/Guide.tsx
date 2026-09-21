import { useState } from 'react'

function Code({ children }: { children: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <pre>
      <code>{children}</code>
      <button
        className="copy"
        onClick={() => {
          navigator.clipboard?.writeText(children)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        }}
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </pre>
  )
}

// A small theme-aware connection diagram: App -> gateway -> branches.
function ConnectDiagram() {
  const box: React.CSSProperties = {
    border: '1px solid var(--border)', borderRadius: 12, padding: '12px 14px',
    background: 'var(--panel, var(--card))', textAlign: 'center', flex: 1, minWidth: 130,
  }
  const arrow: React.CSSProperties = { color: 'var(--muted)', fontSize: 22, alignSelf: 'center' }
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'stretch', flexWrap: 'wrap', margin: '14px 0' }}>
      <div style={box}>
        <div style={{ fontWeight: 700 }}>📱 Your app</div>
        <div className="muted" style={{ fontSize: 12 }}>any Postgres driver / ORM</div>
        <div className="muted" style={{ fontSize: 12 }}>DATABASE_URL → :6432</div>
      </div>
      <div style={arrow}>→</div>
      <div style={{ ...box, borderColor: 'var(--accent)' }}>
        <div style={{ fontWeight: 700 }}>FoxByte Gateway</div>
        <div className="muted" style={{ fontSize: 12 }}>one endpoint · :6432</div>
        <div className="muted" style={{ fontSize: 12 }}>database name = branch</div>
      </div>
      <div style={arrow}>→</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flex: 1, minWidth: 150 }}>
        <div style={{ ...box, padding: '8px 12px' }}><b>⚡ /main</b> <span className="muted" style={{ fontSize: 12 }}>· primary</span></div>
        <div style={{ ...box, padding: '8px 12px' }}><b>🌿 /feature-x</b> <span className="muted" style={{ fontSize: 12 }}>· dev/test</span></div>
        <div style={{ ...box, padding: '8px 12px' }}><b>🌿 /agent-bob</b> <span className="muted" style={{ fontSize: 12 }}>· per agent</span></div>
      </div>
    </div>
  )
}

export default function Guide() {
  return (
    <div className="fade-up">
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ marginBottom: 4 }}>Developer Guide</h1>
          <p className="lead" style={{ margin: 0 }}>Build an app on FoxByte — set up locally, create a schema, connect, and do CRUD.</p>
        </div>
        <a className="ghost" href="/foxbyte-developer-guide.pdf" target="_blank" rel="noreferrer"
           style={{ whiteSpace: 'nowrap' }}>⬇ Download PDF</a>
      </div>

      <p>FoxByte is <strong>PostgreSQL</strong> with three superpowers — instant branches,
        time-travel, and per-agent databases. It speaks the native Postgres wire protocol, so your
        existing driver, ORM, and SQL work unchanged.</p>

      <div className="note" style={{ borderLeft: '4px solid var(--accent)', padding: '10px 14px', borderRadius: 10, background: 'var(--panel, var(--card))', border: '1px solid var(--border)' }}>
        <strong>The one idea to hold onto:</strong> FoxByte gives your app one stable endpoint —
        <code>localhost:6432</code> — and the <strong>database name you connect to is the branch name</strong>.
        Use <code>/main</code> for your primary data, or <code>/feature-x</code> for an instant, isolated copy.
      </div>

      <ConnectDiagram />

      <h2>1 · Run FoxByte on your machine</h2>
      <p>Install the <code>fox</code> command — it sets up the rest (the local Linux VM on macOS,
        Docker, ZFS, the storage pool, and the image).</p>
      <p><strong>macOS</strong> (needs <a href="https://lima-vm.io" target="_blank" rel="noreferrer">Lima</a>):</p>
      <Code>{`brew install lima
curl -fsSL https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.sh | sh
fox setup`}</Code>
      <p><strong>Linux</strong>:</p>
      <Code>{`curl -fsSL https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.sh | sh
sudo fox start`}</Code>
      <p><strong>Windows</strong> (needs <a href="https://learn.microsoft.com/windows/wsl/install" target="_blank" rel="noreferrer">WSL2</a> —
        enable it once with <code>wsl --install</code> in an <strong>Administrator</strong> PowerShell, then reboot).
        Run the commands below <strong>in PowerShell</strong> (not Command Prompt) — <code>irm</code>/<code>iex</code> are
        PowerShell commands:</p>
      <Code>{`irm https://raw.githubusercontent.com/thefoxbyte/foxbyte/main/deploy/install.ps1 | iex
fox setup`}</Code>
      <p className="muted">Seeing <code>irm : not recognized</code>? You're in Command Prompt — open <strong>PowerShell</strong>
        and retry. If scripts are blocked, run <code>Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass</code> first.
        After install, open a <strong>new</strong> terminal so <code>fox</code> is on your PATH.</p>
      <p className="muted">The engine runs inside a dedicated <code>fox</code> WSL2 distro (the analog of
        the macOS VM); your other WSL distros and Docker Desktop are left untouched. Full steps &amp; troubleshooting:{' '}
        <a href="https://github.com/thefoxbyte/foxbyte/blob/main/docs/windows-setup.md" target="_blank" rel="noreferrer">Windows setup guide</a>.</p>
      <p>Your app connects at <code>localhost:6432</code>; the web console &amp; dashboard are served by
        <code>fox start</code> at <code>https://localhost:8080</code> (all platforms) — the same engine,
        no separate web server to run.</p>

      <p>Nothing is started with a key of its own: create your account at <code>https://localhost:8080</code>{' '}
        (the first account on an install becomes the admin of <code>main</code>), then make a key on the{' '}
        <a href="/keys">API keys</a> page — or with <code>fox apikey create &lt;email&gt; &lt;name&gt;</code> — and use it as
        the password everywhere below.</p>

      <h2>2 · Create a branch &amp; your schema</h2>
      <p>Work on <code>main</code>, or make an instant isolated branch. Either is a normal Postgres
        database — use plain SQL or your migration tool.</p>
      <Code>{`fox branch create dev          # instant copy-on-write branch of main
fox branch list                # branches + their copy-on-write size`}</Code>
      <Code>{`psql "postgres://dbadmin:<API_KEY>@localhost:6432/dev?sslmode=require"

CREATE TABLE notes (
  id          serial PRIMARY KEY,
  title       text NOT NULL,
  body        text,
  created_at  timestamptz DEFAULT now()
);`}</Code>
      <p className="muted">Prefer migrations? Point Prisma, Alembic, golang-migrate, Flyway, etc. at the
        same <code>postgres://dbadmin:&lt;API_KEY&gt;@localhost:6432/&lt;branch&gt;?sslmode=require</code> URL.</p>

      <h2>3 · Connect from your application</h2>
      <p>Put the connection string in an env var and use your language's standard Postgres library.</p>
      <Code>{`# .env
DATABASE_URL=postgres://dbadmin:<API_KEY>@localhost:6432/dev?sslmode=require`}</Code>
      <p className="muted"><strong>Why <code>postgres://</code>?</strong> Because FoxByte <em>is</em> PostgreSQL —
        the scheme tells your driver to speak the standard protocol, so every Postgres client and ORM connects with no changes.</p>
      <p className="muted"><strong>The password is your API key.</strong> The Gateway (<code>:6432</code>) requires a valid
        key — create one on the <a href="/keys">API keys</a> page (or <code>fox apikey create &lt;email&gt;</code>) and use it as the password.</p>

      <h3>Node.js — <code>pg</code></h3>
      <Code>{`import { Pool } from 'pg'
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

const { rows } = await pool.query('SELECT now()')
console.log(rows[0])`}</Code>

      <h3>Python — <code>psycopg</code> (v3)</h3>
      <Code>{`import os, psycopg
with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT now()")
        print(cur.fetchone())`}</Code>

      <h3>Go — <code>pgx</code></h3>
      <Code>{`conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
if err != nil { log.Fatal(err) }
defer conn.Close(ctx)`}</Code>
      <p className="muted">ORMs (Prisma, Drizzle, SQLAlchemy, Django, GORM, ActiveRecord) — set their
        database URL to the same value. To FoxByte they're ordinary Postgres clients.</p>

      <h2>4 · Create · Read · Update · Delete</h2>
      <h3>SQL</h3>
      <Code>{`INSERT INTO notes (title, body) VALUES ('First', 'hello') RETURNING id;   -- Create
SELECT * FROM notes ORDER BY id;                                         -- Read
UPDATE notes SET body = 'edited' WHERE id = 1;                           -- Update
DELETE FROM notes WHERE id = 1;                                          -- Delete`}</Code>
      <h3>Node.js (<code>pg</code>) — use parameterized queries</h3>
      <Code>{`// Create
const { rows } = await pool.query(
  'INSERT INTO notes(title, body) VALUES($1, $2) RETURNING *', ['First', 'hello'])
// Read
await pool.query('SELECT * FROM notes')
// Update
await pool.query('UPDATE notes SET body=$1 WHERE id=$2', ['edited', rows[0].id])
// Delete
await pool.query('DELETE FROM notes WHERE id=$1', [rows[0].id])`}</Code>
      <p className="muted">Always use <code>$1, $2…</code> placeholders — never concatenate user input into SQL.</p>

      <h2>5 · The superpower: a branch per feature or test</h2>
      <p>A branch is an instant, isolated, full copy of your database (copy-on-write — seconds, almost
        no disk). Point your app or CI at it, do anything, throw it away. <code>main</code> is never touched.</p>
      <Code>{`fox branch create feature-x                 # seconds, near-zero disk
# in your app / CI:
DATABASE_URL=postgres://dbadmin:<API_KEY>@localhost:6432/feature-x?sslmode=require
# …run migrations, tests, a demo, anything…
fox branch delete feature-x                 # throw it away; main is untouched`}</Code>
      <ul>
        <li><strong>Every pull request</strong> — a preview database with production-like data.</li>
        <li><strong>CI / integration tests</strong> — a fresh branch per run, deleted after.</li>
        <li><strong>Risky migrations</strong> — try on a branch first; if it breaks, delete and retry.</li>
      </ul>

      <h2>6 · One database per AI agent</h2>
      <p>Give each agent its own disposable database over HTTP (these endpoints need an API key —
        create one with <code>fox apikey create &lt;email&gt;</code>):</p>
      <Code>{`curl -H "Authorization: Bearer $FOX_KEY" -X POST   https://localhost:8088/agents/alice/branch
# -> { "dsn": "postgres://…:PORT/foxbyte" }  — the agent connects to that dsn
curl -H "Authorization: Bearer $FOX_KEY" -X DELETE https://localhost:8088/agents/alice/branch`}</Code>
      <p className="muted">The agent API serves TLS with a self-signed certificate, so add <code>-k</code> to curl
        (or trust the certificate). Agent frameworks can skip HTTP entirely and speak{' '}
        <a href="https://github.com/thefoxbyte/foxbyte/blob/main/docs/mcp.md" target="_blank" rel="noreferrer">MCP</a>{' '}
        instead: <code>fox mcp</code>, which takes an API key of its own (<code>FOX_API_KEY</code>) and acts as that account.</p>

      <h2>Quick reference</h2>
      <table>
        <thead><tr><th>Task</th><th>Command / value</th></tr></thead>
        <tbody>
          <tr><td>Start / stop everything</td><td><code>fox start</code> · <code>fox stop</code></td></tr>
          <tr><td>Connection string</td><td><code>postgres://dbadmin:&lt;API_KEY&gt;@localhost:6432/&lt;branch&gt;?sslmode=require</code></td></tr>
          <tr><td>Create / list / delete a branch</td><td><code>fox branch create|list|delete &lt;name&gt;</code></td></tr>
          <tr><td>Time-travel (PITR)</td><td><code>fox backup create</code> · <code>fox restore --to latest</code></td></tr>
          <tr><td>Web console &amp; dashboard</td><td><code>fox start</code> → <code>localhost:8080</code></td></tr>
        </tbody>
      </table>

      <p className="muted" style={{ marginTop: 18 }}>
        Want the printable version with diagrams? <a href="/foxbyte-developer-guide.pdf" target="_blank" rel="noreferrer">Download the PDF guide</a>.
      </p>
    </div>
  )
}
