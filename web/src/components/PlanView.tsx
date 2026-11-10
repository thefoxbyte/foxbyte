// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Plan } from '../plan'

// A plan as a table (point 12.4): each step under the one that uses it, the
// estimate, what happened with ANALYZE, and a bar for each step's share of
// the whole, the most expensive one marked.

const fmt = (n: number) => (n >= 100 ? Math.round(n).toLocaleString() : n.toFixed(n < 1 ? 3 : 2))

export default function PlanView({ plan, raw }: { plan: Plan; raw: string }) {
  const top = Math.max(...plan.rows.map(r => r.share))
  return (
    <div className="plan" data-testid="plan">
      <div className="pane-h">
        <span>{plan.analyzed ? 'Plan, as it ran' : 'Plan, as estimated'}</span>
        <span className="wb-sp" />
        {plan.analyzed && (
          <span className="muted" data-testid="plan-times">
            planning {fmt(plan.planningMs ?? 0)} ms · execution {fmt(plan.executionMs ?? 0)} ms · rolled back
          </span>
        )}
      </div>
      <div className="table-wrap">
        <table aria-label="Plan" className="plan-table">
          <thead>
            <tr>
              <th>Step</th><th>Detail</th><th className="num">Est. rows</th>
              {plan.analyzed ? <><th className="num">Rows</th><th className="num">Loops</th><th className="num">ms (own)</th></> : <th className="num">Cost</th>}
              <th>Share</th>
            </tr>
          </thead>
          <tbody>
            {plan.rows.map((r, i) => (
              <tr key={i} data-testid="plan-row" className={r.share === top && top > 0.3 ? 'plan-hot' : ''}>
                <td style={{ paddingLeft: 8 + r.depth * 18 }}>
                  {r.depth > 0 && <span className="muted">↳ </span>}<b>{r.node}</b>{r.on && <span className="muted"> {r.on}</span>}
                </td>
                <td className="mono" style={{ fontSize: 12 }}>{r.detail}</td>
                <td className="num">{fmt(r.estRows)}</td>
                {plan.analyzed ? (
                  <>
                    <td className={'num' + (r.misestimate ? ' err' : '')} title={r.misestimate ? 'Ten times the estimate or more, either way: the statistics may be stale (analyse the table)' : undefined}>
                      {fmt(r.actRows ?? 0)}{r.misestimate && ' ⚠'}
                    </td>
                    <td className="num">{r.loops}</td>
                    <td className="num">{fmt(r.ms ?? 0)}</td>
                  </>
                ) : <td className="num">{fmt(r.cost)}</td>}
                <td style={{ minWidth: 90 }}>
                  <div className="cow" title={`${Math.round(r.share * 100)}% of the whole`}><span style={{ width: `${Math.max(2, Math.round(r.share * 100))}%` }} /></div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <details className="muted" style={{ marginTop: 8 }}><summary>The plan as Postgres wrote it</summary><pre className="ddl-text">{raw}</pre></details>
    </div>
  )
}
