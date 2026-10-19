// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The data grid (point 12.2): the query that sorts, filters and pages a table's
// rows, and the changes a save sends. Pure functions, so every rule is a unit
// test (gridquery.test.ts).
//
// Reading builds SQL here, run as the signed-in user like anything typed in
// the console, with every name and value quoted. Writing never sends SQL: the
// changes go to POST /api/branches/{name}/rows, which builds the statements
// from the catalog and passes each value as a parameter.

export type Sort = { col: string; dir: 'asc' | 'desc' } | null
export type FilterOp = '=' | '<>' | '<' | '>' | '<=' | '>=' | 'contains' | 'starts' | 'null' | 'notnull'
export type Filter = { col: string; op: FilterOp; value: string }

export const FILTER_OPS: { op: FilterOp; label: string; needsValue: boolean }[] = [
  { op: '=', label: '=', needsValue: true },
  { op: '<>', label: '≠', needsValue: true },
  { op: '<', label: '<', needsValue: true },
  { op: '>', label: '>', needsValue: true },
  { op: '<=', label: '≤', needsValue: true },
  { op: '>=', label: '≥', needsValue: true },
  { op: 'contains', label: 'contains', needsValue: true },
  { op: 'starts', label: 'starts with', needsValue: true },
  { op: 'null', label: 'is NULL', needsValue: false },
  { op: 'notnull', label: 'is not NULL', needsValue: false },
]

export const qid = (s: string) => '"' + s.replace(/"/g, '""') + '"'
export const lit = (s: string) => "'" + s.replace(/'/g, "''") + "'"
// LIKE's own wildcards, and its escape, match themselves.
const likeText = (s: string) => s.replace(/[\\%_]/g, c => '\\' + c)

/** condition is one filter as SQL. A comparison leaves the value untyped, so
 *  Postgres reads it as the column's type, as typing the SQL would. */
export function condition(f: Filter): string {
  const c = qid(f.col)
  switch (f.op) {
    case 'null': return `${c} IS NULL`
    case 'notnull': return `${c} IS NOT NULL`
    case 'contains': return `${c}::text ILIKE ${lit('%' + likeText(f.value) + '%')}`
    case 'starts': return `${c}::text ILIKE ${lit(likeText(f.value) + '%')}`
    default: return `${c} ${f.op} ${lit(f.value)}`
  }
}

export function where(filters: Filter[]): string {
  return filters.length ? ' WHERE ' + filters.map(condition).join(' AND ') : ''
}

/** rowsQuery is one page of a table. Sorted on a column, ties broken by the key;
 *  otherwise in key order, so a page stays the same page while it is edited. */
export function rowsQuery(rel: string, o: { sort: Sort; filters: Filter[]; page: number; pageSize: number; key: string[] }): string {
  const order: string[] = []
  if (o.sort) order.push(`${qid(o.sort.col)} ${o.sort.dir === 'asc' ? 'ASC' : 'DESC'} NULLS LAST`)
  for (const k of o.key) if (!o.sort || k !== o.sort.col) order.push(qid(k))
  return `SELECT * FROM ${rel}${where(o.filters)}${order.length ? ' ORDER BY ' + order.join(', ') : ''} LIMIT ${o.pageSize} OFFSET ${o.page * o.pageSize}`
}

export function countQuery(rel: string, filters: Filter[]): string {
  return `SELECT count(*) FROM ${rel}${where(filters)}`
}

/** nextSort is a header click: ascending, then descending, then as it was. */
export function nextSort(cur: Sort, col: string): Sort {
  if (!cur || cur.col !== col) return { col, dir: 'asc' }
  return cur.dir === 'asc' ? { col, dir: 'desc' } : null
}

/** toText is a value as the grid edits it and the engine casts it: null stays null. */
export function toText(v: unknown): string | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

const scalar = (v: unknown) => v === null || ['string', 'number', 'boolean'].includes(typeof v)

export type RowChange =
  | { op: 'insert'; values: Record<string, string | null> }
  | { op: 'update'; key: Record<string, string>; values: Record<string, string | null>; old: Record<string, string | null> }
  | { op: 'delete'; key: Record<string, string> }

/**
 * buildChanges turns what was done on screen into a save: deletions, then
 * edits, then new rows. An edited cell set back to what it was is no change; a
 * deleted row's edits are dropped; a new row's untouched cells take their
 * defaults. An update carries the old value of each column it changes, so it
 * applies only to the row as it was loaded (not for a structured value, whose
 * text Postgres would not read back the same).
 */
export function buildChanges(cols: string[], rows: unknown[][], key: string[],
  edits: Map<number, Map<number, string | null>>, deleted: Set<number>, added: Map<number, string | null>[]): RowChange[] {
  const keyOf = (r: unknown[]) => {
    const k: Record<string, string> = {}
    for (const name of key) k[name] = toText(r[cols.indexOf(name)]) ?? ''
    return k
  }
  const out: RowChange[] = []
  for (const i of [...deleted].sort((a, b) => a - b)) out.push({ op: 'delete', key: keyOf(rows[i]) })
  for (const [i, cells] of [...edits.entries()].sort((a, b) => a[0] - b[0])) {
    if (deleted.has(i)) continue
    const values: Record<string, string | null> = {}
    const old: Record<string, string | null> = {}
    for (const [j, v] of cells) {
      const was = rows[i][j]
      if (v === toText(was)) continue
      values[cols[j]] = v
      if (scalar(was)) old[cols[j]] = toText(was)
    }
    if (Object.keys(values).length) out.push({ op: 'update', key: keyOf(rows[i]), values, old })
  }
  for (const cells of added) {
    const values: Record<string, string | null> = {}
    for (const [j, v] of cells) values[cols[j]] = v
    out.push({ op: 'insert', values })
  }
  return out
}

/** summary says what a save would do, in words. */
export function summary(changes: RowChange[]): string {
  const n = (op: RowChange['op']) => changes.filter(c => c.op === op).length
  const parts = [[n('insert'), 'added'], [n('update'), 'changed'], [n('delete'), 'deleted']]
    .filter(([c]) => c) .map(([c, w]) => `${c} ${w}`)
  return parts.length ? parts.join(', ') : 'no changes'
}
