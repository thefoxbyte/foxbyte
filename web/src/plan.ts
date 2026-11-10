// SPDX-License-Identifier: AGPL-3.0-or-later

// A plan, read from EXPLAIN (FORMAT JSON) into rows for a table (point 12.4):
// each step indented under the one that uses it, what it reads and how, the
// planner's estimate, and with ANALYZE what happened, and how much of the
// whole each step took on its own, so the expensive one stands out.

export type PlanRow = {
  depth: number
  node: string   // Seq Scan, Hash Join, …
  on: string     // the table, alias and index it reads, "" for none
  detail: string // its conditions, sort and group keys
  estRows: number
  cost: number   // total cost
  actRows?: number
  ms?: number    // its time on its own, over every loop
  loops?: number
  share: number  // of the whole, 0 to 1: time with ANALYZE, else cost
  misestimate: boolean // actual rows ten times the estimate or more, either way
}

export type Plan = { rows: PlanRow[]; analyzed: boolean; planningMs?: number; executionMs?: number }

type Node = Record<string, unknown> & { Plans?: Node[] }

const num = (v: unknown) => (typeof v === 'number' ? v : 0)
const str = (v: unknown) => (typeof v === 'string' ? v : '')

function on(n: Node): string {
  const rel = str(n['Relation Name'])
  let s = rel ? (str(n['Schema']) ? `${str(n['Schema'])}.${rel}` : rel) : str(n['CTE Name']) || str(n['Function Name'])
  const alias = str(n['Alias'])
  if (alias && alias !== rel && s) s += ` ${alias}`
  if (n['Index Name']) s += `${s ? ' ' : ''}using ${str(n['Index Name'])}`
  return s
}

function detail(n: Node): string {
  const parts: string[] = []
  for (const k of ['Index Cond', 'Recheck Cond', 'Hash Cond', 'Merge Cond', 'Join Filter', 'Filter']) {
    if (n[k]) parts.push(`${k.replace(' Cond', '').toLowerCase()}: ${str(n[k])}`)
  }
  if (Array.isArray(n['Sort Key'])) parts.push(`sort: ${(n['Sort Key'] as string[]).join(', ')}`)
  if (Array.isArray(n['Group Key'])) parts.push(`group: ${(n['Group Key'] as string[]).join(', ')}`)
  if (num(n['Rows Removed by Filter'])) parts.push(`${num(n['Rows Removed by Filter'])} removed by the filter`)
  return parts.join('; ')
}

/** parsePlan reads EXPLAIN's JSON, as Postgres returns it (an array of one). */
export function parsePlan(json: string): Plan {
  const doc = JSON.parse(json) as unknown
  const top = (Array.isArray(doc) ? doc[0] : doc) as Record<string, unknown>
  const root = top?.['Plan'] as Node | undefined
  if (!root) throw new Error('not a plan')
  const analyzed = 'Actual Total Time' in root
  const total = (n: Node) => (analyzed ? num(n['Actual Total Time']) * Math.max(1, num(n['Actual Loops'])) : num(n['Total Cost']))
  const whole = Math.max(total(root), 1e-9)
  const rows: PlanRow[] = []
  const walk = (n: Node, depth: number) => {
    const kids = n.Plans ?? []
    const self = Math.max(0, total(n) - kids.reduce((a, k) => a + total(k), 0))
    // A write is ModifyTable to Postgres, and Insert, Update, Delete or Merge to a reader.
    let node = str(n['Node Type']) === 'ModifyTable' && n['Operation'] ? str(n['Operation']) : str(n['Node Type'])
    if (n['Join Type'] && !node.includes(str(n['Join Type']))) node = `${node} (${str(n['Join Type']).toLowerCase()})`
    if (n['Parent Relationship'] === 'SubPlan' || n['Parent Relationship'] === 'InitPlan') node = `${node} · ${str(n['Subplan Name']) || 'subplan'}`
    const est = num(n['Plan Rows'])
    const act = analyzed ? num(n['Actual Rows']) : undefined
    rows.push({
      depth, node, on: on(n), detail: detail(n), estRows: est, cost: num(n['Total Cost']),
      actRows: act, loops: analyzed ? num(n['Actual Loops']) : undefined, ms: analyzed ? self : undefined,
      share: self / whole,
      misestimate: act !== undefined && Math.max(act, 1) / Math.max(est, 1) >= 10 || act !== undefined && Math.max(est, 1) / Math.max(act, 1) >= 10,
    })
    kids.forEach(k => walk(k, depth + 1))
  }
  walk(root, 0)
  return {
    rows, analyzed,
    planningMs: typeof top['Planning Time'] === 'number' ? top['Planning Time'] as number : undefined,
    executionMs: typeof top['Execution Time'] === 'number' ? top['Execution Time'] as number : undefined,
  }
}

/** explainSQL wraps one statement: with ANALYZE it runs, inside a transaction that is rolled back. */
export function explainSQL(stmt: string, analyze: boolean): { sql?: string; error?: string } {
  const s = stmt.trim().replace(/;+\s*$/, '')
  if (!s) return { error: 'Nothing to explain: write a statement, or select one.' }
  if (s.includes(';')) return { error: 'Explain one statement at a time: select it in the editor.' }
  if (/^explain\b/i.test(s)) return { error: 'It is already an EXPLAIN: run it, or take EXPLAIN off.' }
  const e = `EXPLAIN (FORMAT JSON${analyze ? ', ANALYZE, BUFFERS' : ''}) ${s}`
  return { sql: analyze ? `BEGIN;\n${e};\nROLLBACK;` : e }
}
