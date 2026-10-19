// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Query suggestions in the SQL editor (point 9): what to offer as you type
// (9.1), how to apply a "did you mean" fix (9.2), and the snippets for a table
// (9.3). Pure functions over the text and the branch's schema, so every rule is
// a unit test (sqlcomplete.test.ts) rather than something to click through.
//
// This reads SQL the way a person writing it does, not the way Postgres parses
// it: enough to know whether the caret is after FROM, after an alias and a dot,
// or inside a string. It never decides what runs.

export type Col = { name: string; type: string; pk: boolean }
export type Rel = { schema: string; name: string; kind: 'table' | 'view'; cols: Col[] }

export type Item = {
  label: string
  insert: string
  kind: 'table' | 'column' | 'keyword' | 'schema'
  detail?: string
}
export type Completion = { from: number; to: number; items: Item[] }

const KEYWORDS = [
  'SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'INNER JOIN', 'RIGHT JOIN', 'FULL JOIN', 'CROSS JOIN', 'ON',
  'USING', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT', 'OFFSET', 'DISTINCT', 'AS', 'AND', 'OR', 'NOT', 'NULL',
  'IS NULL', 'IS NOT NULL', 'IN', 'LIKE', 'ILIKE', 'BETWEEN', 'EXISTS', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'ASC', 'DESC', 'UNION', 'UNION ALL', 'WITH', 'INSERT INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE FROM',
  'RETURNING', 'CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'CREATE INDEX', 'PRIMARY KEY', 'REFERENCES',
  'DEFAULT', 'TRUE', 'FALSE', 'COUNT(*)', 'SUM(', 'AVG(', 'MIN(', 'MAX(', 'COALESCE(', 'NOW()',
]
const RESERVED = new Set(['all', 'and', 'any', 'as', 'asc', 'case', 'check', 'column', 'constraint', 'create',
  'default', 'desc', 'distinct', 'do', 'else', 'end', 'false', 'for', 'foreign', 'from', 'grant', 'group',
  'having', 'in', 'limit', 'not', 'null', 'offset', 'on', 'or', 'order', 'primary', 'references', 'select',
  'table', 'then', 'to', 'true', 'union', 'unique', 'user', 'using', 'when', 'where', 'with'])
// After these, a table name is what comes next.
const TABLE_AFTER = new Set(['from', 'join', 'into', 'update', 'table'])
// Words that end a FROM item, so they are never read as an alias.
const NOT_ALIAS = new Set(['where', 'join', 'on', 'inner', 'left', 'right', 'full', 'cross', 'group', 'order',
  'limit', 'offset', 'set', 'using', 'natural', 'values', 'select', 'union', 'having', 'returning', 'as', 'lateral'])

const MAX_ITEMS = 50

/** ident writes a name as SQL needs it: bare when plain lower case, quoted otherwise. */
export function ident(s: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(s) && !RESERVED.has(s) ? s : '"' + s.replace(/"/g, '""') + '"'
}

/** rel names a table as SQL needs it, with its schema unless that is public. */
export function relName(r: { schema: string; name: string }): string {
  return (r.schema === 'public' ? '' : ident(r.schema) + '.') + ident(r.name)
}

const unquote = (s: string) => (s.startsWith('"') && s.endsWith('"') && s.length > 1 ? s.slice(1, -1).replace(/""/g, '"') : s.toLowerCase())

/** inCode reports whether pos is in SQL rather than in a string, a quoted name or a comment. */
export function inCode(text: string, pos: number): boolean {
  let i = 0
  while (i < pos) {
    const c = text[i], n = text[i + 1]
    if (c === '-' && n === '-') { const e = text.indexOf('\n', i); if (e < 0 || e >= pos) return false; i = e + 1; continue }
    if (c === '/' && n === '*') { const e = text.indexOf('*/', i + 2); if (e < 0 || e + 2 > pos) return false; i = e + 2; continue }
    if (c === "'") { let j = i + 1; while (j < text.length && !(text[j] === "'" && text[j + 1] !== "'")) j += text[j] === "'" ? 2 : 1; if (j >= pos) return false; i = j + 1; continue }
    if (c === '$') {
      const m = /^\$([A-Za-z_]*)\$/.exec(text.slice(i))
      if (m) { const e = text.indexOf(m[0], i + m[0].length); if (e < 0 || e >= pos) return false; i = e + m[0].length; continue }
    }
    i++
  }
  return true
}

/** statementAt is the statement the caret is in: between the semicolons around it. */
function statementAt(text: string, pos: number): { start: number; sql: string } {
  const start = text.lastIndexOf(';', pos - 1) + 1
  const end = text.indexOf(';', pos)
  return { start, sql: text.slice(start, end < 0 ? text.length : end) }
}

/** tablesIn finds the tables a statement reads and the aliases it gives them. */
export function tablesIn(sql: string, schema: Rel[]): Map<string, Rel> {
  const out = new Map<string, Rel>()
  const name = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`
  const re = new RegExp(String.raw`\b(?:from|join|update|into)\s+(${name}(?:\s*\.\s*${name})?)(?:\s+(?:as\s+)?(${name}))?`, 'gi')
  for (const m of sql.matchAll(re)) {
    const parts = m[1].split(/\s*\.\s*(?=(?:"|[A-Za-z_]))/)
    const [sch, nm] = parts.length > 1 ? [unquote(parts[0]), unquote(parts[1])] : [null, unquote(parts[0])]
    const r = schema.find(x => x.name.toLowerCase() === nm.toLowerCase() && (sch === null || x.schema.toLowerCase() === sch.toLowerCase()))
      ?? schema.find(x => x.name === nm && (sch === null || x.schema === sch))
    if (!r) continue
    out.set(r.name.toLowerCase(), r)
    const alias = m[2] && !NOT_ALIAS.has(m[2].toLowerCase()) ? unquote(m[2]) : null
    if (alias) out.set(alias.toLowerCase(), r)
  }
  return out
}

const matchCase = (word: string, prefix: string) => (prefix && prefix === prefix.toLowerCase() ? word.toLowerCase() : word)

/**
 * complete says what to offer at the caret: the span it would replace and the
 * items, best first. null inside a string or a comment.
 */
export function complete(text: string, caret: number, schema: Rel[]): Completion | null {
  if (!inCode(text, caret)) return null
  // The word being typed, and a qualifier before a dot: "c.na" is c and na.
  let s = caret
  while (s > 0 && /[\w$]/.test(text[s - 1])) s--
  const prefix = text.slice(s, caret)
  let qual: string | null = null
  if (text[s - 1] === '.') {
    let q = s - 1
    if (text[q - 1] === '"') { const open = text.lastIndexOf('"', q - 2); qual = text.slice(open, q) }
    else { let b = q; while (b > 0 && /[\w$]/.test(text[b - 1])) b--; qual = text.slice(b, q) }
  }
  const st = statementAt(text, caret)
  const inScope = tablesIn(st.sql, schema)
  const p = prefix.toLowerCase()
  const starts = (n: string) => n.toLowerCase().startsWith(p)
  const items: Item[] = []

  if (qual !== null) {
    const q = unquote(qual).toLowerCase()
    const r = inScope.get(q) ?? schema.find(x => x.name.toLowerCase() === q)
    if (r) {
      for (const c of r.cols) if (starts(c.name)) items.push({ label: c.name, insert: ident(c.name), kind: 'column', detail: c.type + (c.pk ? ' · key' : '') })
    } else {
      for (const x of schema) if (x.schema.toLowerCase() === q && starts(x.name)) items.push({ label: x.name, insert: ident(x.name), kind: 'table', detail: x.kind })
    }
    return { from: s, to: caret, items: items.slice(0, MAX_ITEMS) }
  }

  const before = text.slice(st.start, s).trimEnd()
  const prev = /([A-Za-z]+)$/.exec(before)?.[1]?.toLowerCase()
  const afterComma = before.endsWith(',') && /\bfrom\b[^;]*$/i.test(before) && !/\b(where|group|order|having|limit|set|on)\b[^;]*$/i.test(before.replace(/^[\s\S]*\bfrom\b/i, ''))
  if ((prev && TABLE_AFTER.has(prev)) || afterComma) {
    for (const x of schema) if (starts(x.name)) items.push({ label: relName(x), insert: relName(x), kind: 'table', detail: x.kind })
    const schemas = [...new Set(schema.map(x => x.schema))].filter(x => x !== 'public' && starts(x))
    for (const sc of schemas) items.push({ label: sc + '.', insert: ident(sc) + '.', kind: 'schema' })
    return { from: s, to: caret, items: items.slice(0, MAX_ITEMS) }
  }

  // Anywhere else: the columns of the tables in this statement, then words,
  // then tables. Nothing until something is typed, unless asked for.
  const seen = new Set<string>()
  for (const r of new Set(inScope.values())) {
    for (const c of r.cols) {
      if (!starts(c.name) || seen.has(c.name)) continue
      seen.add(c.name)
      items.push({ label: c.name, insert: ident(c.name), kind: 'column', detail: `${r.name} · ${c.type}` })
    }
  }
  if (p) {
    for (const k of KEYWORDS) if (k.toLowerCase().startsWith(p)) items.push({ label: k, insert: matchCase(k, prefix), kind: 'keyword' })
    for (const x of schema) if (starts(x.name) && !inScope.has(x.name.toLowerCase())) items.push({ label: relName(x), insert: relName(x), kind: 'table', detail: x.kind })
  }
  return { from: s, to: caret, items: items.slice(0, MAX_ITEMS) }
}

/** charIndex turns Postgres's position (characters from 1) into a JavaScript index. */
function charIndex(text: string, position: number): number {
  let i = 0, n = 1
  while (i < text.length && n < position) { i += text.codePointAt(i)! > 0xffff ? 2 : 1; n++ }
  return i
}

/**
 * applySuggestion writes a "did you mean" fix into the SQL (point 9.2): the
 * misspelt name nearest to where Postgres pointed, as a whole word, quoted or
 * not, replaced by the name as it must be written. null when it cannot be found.
 */
export function applySuggestion(sql: string, s: { wrong: string; insert: string }, position?: number): string | null {
  const w = s.wrong.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`(?<![\\w$"])(?:"${w}"|${w})(?![\\w$])`, 'gi')
  const from = position ? charIndex(sql, position) : 0
  let hit: RegExpExecArray | null = null
  for (const m of sql.matchAll(re)) {
    if (!inCode(sql, m.index!)) continue
    if (m.index! >= from) { hit = m; break }
    if (!hit) hit = m
  }
  if (!hit) return null
  return sql.slice(0, hit.index!) + s.insert + sql.slice(hit.index! + hit[0].length)
}

/** Snippets for one table (point 9.3): ready to edit, never run on their own. */
export function snippets(r: Rel): { label: string; sql: string }[] {
  const t = relName(r)
  const cols = r.cols.map(c => ident(c.name))
  const list = cols.length ? cols.join(', ') : '*'
  const out = [
    { label: 'Select rows', sql: `SELECT ${list}\nFROM ${t}\nLIMIT 100;` },
    { label: 'Count rows', sql: `SELECT count(*) FROM ${t};` },
  ]
  if (r.kind !== 'table') return out
  const keys = r.cols.filter(c => c.pk)
  const where = keys.length ? keys.map(c => `${ident(c.name)} = NULL`).join(' AND ') : '/* condition */ false'
  const rest = r.cols.filter(c => !c.pk)
  const types = r.cols.map(c => `${c.name} ${c.type}`).join(', ')
  out.push({ label: 'Insert a row', sql: `INSERT INTO ${t} (${list})\nVALUES (${r.cols.map(() => 'NULL').join(', ')});  -- ${types}` })
  if (rest.length) out.push({ label: 'Update a row', sql: `UPDATE ${t}\nSET ${rest.map(c => `${ident(c.name)} = NULL`).join(',\n    ')}\nWHERE ${where};` })
  out.push({ label: 'Delete a row', sql: `DELETE FROM ${t}\nWHERE ${where};` })
  return out
}

/** SCHEMA_SQL reads every column the caller can see, with whether it is in the primary key. */
export const SCHEMA_SQL = `SELECT n.nspname, c.relname, CASE WHEN c.relkind IN ('v','m') THEN 'view' ELSE 'table' END,
  a.attname, format_type(a.atttypid, a.atttypmod), coalesce(a.attnum = ANY (i.indkey), false)
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_index i ON i.indrelid = c.oid AND i.indisprimary
WHERE c.relkind IN ('r','p','v','m','f') AND a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
  AND has_table_privilege(c.oid, 'SELECT')
ORDER BY 1, 2, a.attnum
LIMIT 20000`

/** schemaFrom reads SCHEMA_SQL's rows. */
export function schemaFrom(rows: unknown[][]): Rel[] {
  const byKey = new Map<string, Rel>()
  for (const r of rows) {
    const [schema, name, kind, col, type, pk] = r.map(v => (typeof v === 'boolean' ? v : String(v)))
    const k = `${schema}.${name}`
    let rel = byKey.get(k)
    if (!rel) { rel = { schema: String(schema), name: String(name), kind: kind === 'view' ? 'view' : 'table', cols: [] }; byKey.set(k, rel) }
    rel.cols.push({ name: String(col), type: String(type), pk: pk === true || pk === 'true' || pk === 't' })
  }
  return [...byKey.values()]
}
