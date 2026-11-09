// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FuncParam } from './api'

// A call to a function or a procedure, written from a form (point 12.4).
//
// Every value is a literal cast to its argument's type, so overloads resolve
// as declared and nothing typed into the form becomes SQL of its own. The call
// runs as the person, through the console, like anything they write.
//
// Named notation (a => …) when every argument has a name: then any argument
// with a default may be left out. Otherwise positional, where only the last
// ones may be, as Postgres allows.

export type ArgInput = { value: string; isNull: boolean; useDefault: boolean }

export const quoteIdent = (s: string) => '"' + s.replace(/"/g, '""') + '"'
const quoteLit = (s: string) => "'" + s.replace(/'/g, "''") + "'"

/** The arguments a caller gives: inputs; for a procedure, its OUT ones too, as NULL. */
export function inputsOf(params: FuncParam[]): FuncParam[] {
  return params.filter(p => p.mode === 'in' || p.mode === 'inout' || p.mode === 'variadic')
}

export function buildCall(kind: 'function' | 'procedure', schema: string, name: string, params: FuncParam[], inputs: ArgInput[]): { sql?: string; error?: string } {
  const given = inputsOf(params)
  const named = given.length > 0 && given.every(p => !!p.name) && params.filter(p => p.mode === 'out').every(p => !!p.name)
  const value = (p: FuncParam, a: ArgInput) => {
    const v = a.isNull ? `NULL::${p.type}` : `CAST(${quoteLit(a.value)} AS ${p.type})`
    return p.mode === 'variadic' ? `VARIADIC ${named ? `${quoteIdent(p.name!)} => ` : ''}${v}` : `${named ? `${quoteIdent(p.name!)} => ` : ''}${v}`
  }
  const args: string[] = []
  let gi = 0
  let leftOut = ''
  for (const p of params) {
    if (p.mode === 'table' || (p.mode === 'out' && kind === 'function')) continue
    if (p.mode === 'out') {
      // A procedure's OUT argument is given as NULL; its value comes back.
      if (!leftOut) args.push(named ? `${quoteIdent(p.name!)} => NULL` : 'NULL')
      continue
    }
    const a = inputs[gi++] ?? { value: '', isNull: false, useDefault: false }
    if (a.useDefault && p.default) {
      if (!named) leftOut = leftOut || (p.name || `argument ${gi}`)
      continue
    }
    if (leftOut) {
      return { error: `Only the last arguments can take their defaults here, as ${leftOut} has no name: give it a value, or give values to the ones after it` }
    }
    args.push(value(p, a))
  }
  const target = `${quoteIdent(schema)}.${quoteIdent(name)}(${args.join(', ')})`
  return { sql: kind === 'procedure' ? `CALL ${target}` : `SELECT * FROM ${target}` }
}
