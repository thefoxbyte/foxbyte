import { Link } from 'react-router-dom'
import { useAuth } from '../auth-context'

const features: [string, string, string][] = [
  ['🌿', 'Instant branches', 'Copy-on-write clones of your entire database in seconds — near-zero extra space.'],
  ['⏱️', 'Time-travel', 'Restore to any point within the archived WAL window. Undo mistakes.'],
  ['🤖', 'A database per agent', 'Each AI agent gets an isolated, disposable database over a simple HTTP call.'],
  ['💤', 'Serverless', 'Idle branches suspend automatically; the gateway wakes them on the next connection.'],
  ['☁️', 'High availability', 'A streaming standby with a promotion that reroutes clients transparently.'],
  ['🔌', 'One endpoint', 'A smart gateway reads the database name and routes you to the right branch — one stable address.'],
]

export default function Landing() {
  const { user } = useAuth()
  return (
    <>
      <section className="hero fade-up">
        <div>
          <span className="eyebrow"><span className="pip" /> Serverless PostgreSQL · open source</span>
          <h1>The database that <span className="gradient-text">branches like code</span>.</h1>
          <p className="sub">
            FoxByte gives Postgres instant copy-on-write branches, time-travel, a database per AI
            agent, and high availability — at native transaction speed.
          </p>
          <div className="cta">
            <Link className="btn" to="/guide">Get started</Link>
          </div>
        </div>

        <div className="hero-visual">
          <div className="terminal">
            <div className="bar"><i className="r" /><i className="y" /><i className="g" /><span className="t">fox — zsh</span></div>
            <div className="body">
              <div><span className="prompt">$</span> <span className="cmd">fox branch create feature</span></div>
              <div className="ok">  ✓ branch “feature” ready in 1.9s · copy-on-write</div>
              <div><span className="prompt">$</span> <span className="cmd">psql …/feature -c "UPDATE …"</span></div>
              <div className="dim">  UPDATE 4200</div>
              <div><span className="prompt">$</span> <span className="cmd">fox ha failover</span></div>
              <div className="ok">  ✓ standby promoted · same endpoint</div>
              <div><span className="prompt">$</span> <span className="cursor" /></div>
            </div>
          </div>
        </div>
      </section>

      <div className="feat">
        {features.map(([ic, t, d]) => (
          <div className="tile" key={t}>
            <div className="ic">{ic}</div>
            <b>{t}</b>
            <p>{d}</p>
          </div>
        ))}
      </div>

      <div className="panel" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, alignItems: 'center', marginTop: 8 }}>
        <div>
          <div className="section-title"><h2 style={{ margin: 0 }}>Branch, don’t copy</h2></div>
          <p className="muted">
            A branch is a <b style={{ color: 'var(--text)' }}>zfs clone</b> of the primary served by its own
            Postgres — created in seconds regardless of size, storing only the blocks it changes. Perfect for a
            per-PR database, a safe migration rehearsal, or a sandbox for every agent.
          </p>
          <Link className="btn ghost" to="/guide">See how it works</Link>
        </div>
        <BranchGraph />
      </div>

      <div className="section-title"><h2 style={{ margin: 0 }}>How it works</h2></div>
      <div className="steps">
        <div className="step"><span className="n">1</span><b>Native hot path</b><p className="muted">Stock PostgreSQL on local storage — full-speed commits and reads.</p></div>
        <div className="step"><span className="n">2</span><b>Off-path durability</b><p className="muted">Async WAL archival to object storage powers time-travel &amp; recovery.</p></div>
        <div className="step"><span className="n">3</span><b>Instant branches</b><p className="muted">ZFS copy-on-write clones, one gateway endpoint, auto-suspend.</p></div>
      </div>

      <div className="builton">
        <span>PostgreSQL</span><span>ZFS</span><span>object storage (S3/MinIO)</span><span>wal-g</span><span>Go</span>
      </div>

      <div className="cta-band">
        <h2>Spin up a branch in seconds.</h2>
        <p className="muted">Run the API, open the dashboard, and start branching.</p>
        <div className="cta" style={{ justifyContent: 'center', marginTop: 16 }}>
          <Link className="btn" to="/docs">Read the docs</Link>
          {user
            ? <Link className="btn ghost" to="/console">Open the SQL console</Link>
            : <Link className="btn ghost" to="/login">Log in</Link>}
        </div>
      </div>
    </>
  )
}

function BranchGraph() {
  const label = { fill: 'var(--muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }
  return (
    <svg className="branch-svg" viewBox="0 0 420 170" width="100%" role="img" aria-label="branch graph">
      <defs>
        <linearGradient id="bvg" x1="0" y1="170" x2="420" y2="0">
          <stop offset="0" stopColor="#8b6dff" />
          <stop offset="1" stopColor="#34d6f0" />
        </linearGradient>
      </defs>
      <line className="trunk draw" x1="24" y1="128" x2="396" y2="128" stroke="url(#bvg)" />
      <path className="limb draw d2" d="M150 128 C150 92, 230 96, 236 64" stroke="url(#bvg)" />
      <path className="limb draw d3" d="M262 128 C262 80, 340 74, 348 42" stroke="url(#bvg)" />
      <g className="node"><circle cx="24" cy="128" r="6" fill="url(#bvg)" /><text x="24" y="150" textAnchor="middle" style={label}>main</text></g>
      <g className="node n2"><circle cx="236" cy="64" r="6" fill="url(#bvg)" /><text x="236" y="50" textAnchor="middle" style={label}>feature</text></g>
      <g className="node n3"><circle cx="348" cy="42" r="6" fill="url(#bvg)" /><text x="348" y="28" textAnchor="middle" style={label}>qa</text></g>
    </svg>
  )
}
