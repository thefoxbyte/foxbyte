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
