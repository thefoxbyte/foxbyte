// SPDX-License-Identifier: AGPL-3.0-or-later
import { quoteIdent } from './runcall'

// The SQL behind the create and edit dialogs (point 12.3). The dialogs show it
// as it is built and run it as the person, through the console, so it is
// governed as anything they write is: their rights, the guardrails, the
// Blackbox. Arguments, return types, conditions and bodies are the person's
// own SQL; names are always quoted.

export type RoutineSpec = {
  kind: 'function' | 'procedure'; schema: string; name: string
  arguments: string; returns?: string; language: string; body: string
  volatility?: string; strict?: boolean; definer?: boolean; leakproof?: boolean; window?: boolean
  parallel?: string; cost?: number; rows?: number; set?: string[]
  replace: boolean
}

const defaultCost = 100
const defaultRows = 1000

/** A dollar-quote tag the body does not contain. */
export function dollarTag(body: string): string {
  for (let i = 0; ; i++) {
    const tag = i === 0 ? '$body$' : `$body${i}$`
    if (!body.includes(tag)) return tag
  }
}

export function buildRoutine(r: RoutineSpec): { sql?: string; error?: string } {
  if (!r.name.trim()) return { error: 'It needs a name.' }
  if (r.kind === 'function' && !r.returns?.trim()) return { error: 'A function says what it returns.' }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(r.language)) return { error: 'The language is a single word: plpgsql, sql, …' }
  if (!r.body.trim()) return { error: 'It needs a body.' }
  const lines = [`CREATE ${r.replace ? 'OR REPLACE ' : ''}${r.kind.toUpperCase()} ${quoteIdent(r.schema)}.${quoteIdent(r.name.trim())}(${r.arguments.trim()})`]
  if (r.kind === 'function') lines.push(` RETURNS ${r.returns!.trim()}`)
  lines.push(` LANGUAGE ${r.language}`)
  if (r.kind === 'function') {
    if (r.window) lines.push(' WINDOW')
    if (r.volatility === 'immutable') lines.push(' IMMUTABLE')
    if (r.volatility === 'stable') lines.push(' STABLE')
    if (r.leakproof) lines.push(' LEAKPROOF')
    if (r.strict) lines.push(' STRICT')
  }
  if (r.definer) lines.push(' SECURITY DEFINER')
  if (r.kind === 'function') {
    if (r.parallel === 'safe') lines.push(' PARALLEL SAFE')
    if (r.parallel === 'restricted') lines.push(' PARALLEL RESTRICTED')
    if (r.cost !== undefined && r.cost !== defaultCost) lines.push(` COST ${r.cost}`)
    if (r.rows !== undefined && r.rows > 0 && r.rows !== defaultRows) lines.push(` ROWS ${r.rows}`)
  }
  for (const s of r.set ?? []) lines.push(` ${s}`)
  const tag = dollarTag(r.body)
  const body = r.body.endsWith('\n') ? r.body : r.body + '\n'
  lines.push(`AS ${tag}\n${body}${tag}`)
  return { sql: lines.join('\n') }
}

export const TRIGGER_BODY = `BEGIN
  -- NEW is the row being written: return it, or NULL to skip the row.
  RETURN NEW;
END;`

export const renameRoutine = (kind: string, schema: string, name: string, identity: string, to: string) =>
  `ALTER ${kind.toUpperCase()} ${quoteIdent(schema)}.${quoteIdent(name)}(${identity}) RENAME TO ${quoteIdent(to.trim())}`
export const dropRoutine = (kind: string, schema: string, name: string, identity: string) =>
  `DROP ${kind.toUpperCase()} ${quoteIdent(schema)}.${quoteIdent(name)}(${identity})`

export type TriggerSpec = {
  name: string; schema: string; table: string
  timing: string; events: string[]; columns: string; forEach: string
  when: string; func: string; args: string; referencing?: string
  replace: boolean
  disabled?: boolean // an edited trigger that was disabled stays so
}

export function buildTrigger(t: TriggerSpec): { sql?: string; error?: string } {
  if (!t.name.trim()) return { error: 'It needs a name.' }
  if (t.events.length === 0) return { error: 'Choose at least one event.' }
  if (!t.func) return { error: 'Choose the trigger function it runs.' }
  if (t.events.includes('TRUNCATE') && t.forEach === 'ROW') return { error: 'TRUNCATE fires once for the statement, not for each row.' }
  if (t.when.trim() && t.events.includes('TRUNCATE')) return { error: 'A TRUNCATE trigger cannot have a WHEN condition.' }
  const cols = t.columns.split(',').map(c => c.trim()).filter(Boolean)
  if (cols.length && !t.events.includes('UPDATE')) return { error: 'Columns narrow an UPDATE: choose UPDATE, or clear them.' }
  const events = t.events.map(e => (e === 'UPDATE' && cols.length ? `UPDATE OF ${cols.map(quoteIdent).join(', ')}` : e)).join(' OR ')
  const rel = `${quoteIdent(t.schema)}.${quoteIdent(t.table)}`
  const name = quoteIdent(t.name.trim())
  let sql = `CREATE ${t.replace ? 'OR REPLACE ' : ''}TRIGGER ${name} ${t.timing} ${events} ON ${rel}`
  if (t.referencing) sql += `\n REFERENCING ${t.referencing}`
  sql += `\n FOR EACH ${t.forEach}`
  if (t.when.trim()) sql += `\n WHEN (${t.when.trim()})`
  sql += `\n EXECUTE FUNCTION ${t.func}(${t.args.trim()})`
  // CREATE OR REPLACE enables what it replaces.
  if (t.replace && t.disabled) sql += `;\nALTER TABLE ${rel} DISABLE TRIGGER ${name}`
  return { sql }
}

export const renameTrigger = (schema: string, table: string, name: string, to: string) =>
  `ALTER TRIGGER ${quoteIdent(name)} ON ${quoteIdent(schema)}.${quoteIdent(table)} RENAME TO ${quoteIdent(to.trim())}`
export const dropTrigger = (schema: string, table: string, name: string) =>
  `DROP TRIGGER ${quoteIdent(name)} ON ${quoteIdent(schema)}.${quoteIdent(table)}`

// ── Tables ────────────────────────────────────────────────────────────────
// A column's type and default, and a check's condition, are the person's own
// SQL, as a function's arguments are. A multi-statement run is one transaction,
// so an edit that also renames is applied whole or not at all.

const rel = (schema: string, table: string) => `${quoteIdent(schema)}.${quoteIdent(table)}`

export type ColumnSpec = { name: string; type: string; notNull: boolean; default: string; pk?: boolean }

function columnDef(c: ColumnSpec): string {
  let d = `${quoteIdent(c.name.trim())} ${c.type.trim()}`
  if (c.notNull) d += ' NOT NULL'
  if (c.default.trim()) d += ` DEFAULT ${c.default.trim()}`
  return d
}

function columnProblem(c: ColumnSpec): string {
  if (!c.name.trim()) return 'Each column needs a name.'
  if (!c.type.trim()) return `${c.name.trim()} needs a type.`
  return ''
}

export function buildCreateTable(schema: string, name: string, columns: ColumnSpec[]): { sql?: string; error?: string } {
  if (!name.trim()) return { error: 'It needs a name.' }
  const cols = columns.filter(c => c.name.trim() || c.type.trim())
  if (cols.length === 0) return { error: 'It needs at least one column.' }
  for (const c of cols) { const p = columnProblem(c); if (p) return { error: p } }
  const names = cols.map(c => c.name.trim())
  const twice = names.find((n, i) => names.indexOf(n) !== i)
  if (twice) return { error: `${twice} is named twice.` }
  const lines = cols.map(columnDef)
  const pk = cols.filter(c => c.pk).map(c => quoteIdent(c.name.trim()))
  if (pk.length) lines.push(`PRIMARY KEY (${pk.join(', ')})`)
  return { sql: `CREATE TABLE ${rel(schema, name.trim())} (\n  ${lines.join(',\n  ')}\n)` }
}

export function buildAddColumn(schema: string, table: string, c: ColumnSpec): { sql?: string; error?: string } {
  const p = columnProblem(c)
  return p ? { error: p } : { sql: `ALTER TABLE ${rel(schema, table)} ADD COLUMN ${columnDef(c)}` }
}

/** buildAlterColumn writes what changed, and nothing when nothing did. */
export function buildAlterColumn(schema: string, table: string, before: ColumnSpec, after: ColumnSpec, using: string): { sql?: string; error?: string } {
  const p = columnProblem(after)
  if (p) return { error: p }
  const col = `ALTER COLUMN ${quoteIdent(before.name)}`
  const parts: string[] = []
  if (after.type.trim() !== before.type) parts.push(`${col} TYPE ${after.type.trim()}${using.trim() ? ` USING ${using.trim()}` : ''}`)
  if (after.notNull !== before.notNull) parts.push(`${col} ${after.notNull ? 'SET' : 'DROP'} NOT NULL`)
  if (after.default.trim() !== before.default) parts.push(after.default.trim() ? `${col} SET DEFAULT ${after.default.trim()}` : `${col} DROP DEFAULT`)
  const stmts: string[] = []
  if (parts.length) stmts.push(`ALTER TABLE ${rel(schema, table)}\n  ${parts.join(',\n  ')}`)
  if (after.name.trim() !== before.name) stmts.push(`ALTER TABLE ${rel(schema, table)} RENAME COLUMN ${quoteIdent(before.name)} TO ${quoteIdent(after.name.trim())}`)
  return stmts.length ? { sql: stmts.join(';\n') } : {}
}

export const dropColumn = (schema: string, table: string, name: string) =>
  `ALTER TABLE ${rel(schema, table)} DROP COLUMN ${quoteIdent(name)}`
export const renameTable = (schema: string, table: string, to: string) =>
  `ALTER TABLE ${rel(schema, table)} RENAME TO ${quoteIdent(to.trim())}`
export const dropTable = (schema: string, table: string) => `DROP TABLE ${rel(schema, table)}`

export type KeyType = 'primary' | 'unique' | 'foreign' | 'check'
export type KeySpec = {
  type: KeyType; columns: string[]
  refSchema?: string; refTable?: string; refColumns?: string[]
  onDelete?: string; onUpdate?: string; match?: string
  deferrable?: boolean; deferred?: boolean; notValid?: boolean; noInherit?: boolean
  check?: string
}

export function keyClause(k: KeySpec): { clause?: string; error?: string } {
  const cols = () => k.columns.map(quoteIdent).join(', ')
  let c: string
  if (k.type === 'check') {
    if (!k.check?.trim()) return { error: 'It needs a condition.' }
    c = `CHECK (${k.check.trim()})`
    if (k.noInherit) c += ' NO INHERIT'
  } else {
    if (k.columns.length === 0) return { error: 'Choose at least one column.' }
    if (k.type === 'foreign') {
      if (!k.refTable) return { error: 'Choose the table it references.' }
      if ((k.refColumns ?? []).length !== k.columns.length) return { error: 'A foreign key names as many columns on each side.' }
      c = `FOREIGN KEY (${cols()}) REFERENCES ${rel(k.refSchema ?? 'public', k.refTable)} (${k.refColumns!.map(quoteIdent).join(', ')})`
      if (k.match) c += ` MATCH ${k.match}`
      if (k.onUpdate) c += ` ON UPDATE ${k.onUpdate}`
      if (k.onDelete) c += ` ON DELETE ${k.onDelete}`
    } else {
      c = `${k.type === 'primary' ? 'PRIMARY KEY' : 'UNIQUE'} (${cols()})`
    }
    if (k.deferrable) c += ` DEFERRABLE${k.deferred ? ' INITIALLY DEFERRED' : ''}`
  }
  if (k.notValid && (k.type === 'foreign' || k.type === 'check')) c += ' NOT VALID'
  return { clause: c }
}

export function buildAddKey(schema: string, table: string, name: string, k: KeySpec): { sql?: string; error?: string } {
  const { clause, error } = keyClause(k)
  if (!clause) return { error }
  return { sql: `ALTER TABLE ${rel(schema, table)}\n  ADD ${name.trim() ? `CONSTRAINT ${quoteIdent(name.trim())} ` : ''}${clause}` }
}

/** buildEditKey replaces a key in one statement, as Postgres cannot change one in place. */
export function buildEditKey(schema: string, table: string, name: string, before: KeySpec, after: KeySpec): { sql?: string; error?: string } {
  const { clause, error } = keyClause(after)
  if (!clause) return { error }
  if (clause === keyClause(before).clause) return {}
  return { sql: `ALTER TABLE ${rel(schema, table)}\n  DROP CONSTRAINT ${quoteIdent(name)},\n  ADD CONSTRAINT ${quoteIdent(name)} ${clause}` }
}

export const renameKey = (schema: string, table: string, name: string, to: string) =>
  `ALTER TABLE ${rel(schema, table)} RENAME CONSTRAINT ${quoteIdent(name)} TO ${quoteIdent(to.trim())}`
export const dropKey = (schema: string, table: string, name: string) =>
  `ALTER TABLE ${rel(schema, table)} DROP CONSTRAINT ${quoteIdent(name)}`
