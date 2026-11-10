// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import type { FuncParam } from './api'
import { buildCall, inputsOf } from './runcall'

const v = (value: string, o: Partial<{ isNull: boolean; useDefault: boolean }> = {}) => ({ value, isNull: false, useDefault: false, ...o })

describe('buildCall', () => {
  const f1: FuncParam[] = [{ name: 'a', type: 'integer', mode: 'in' }, { name: 'b', type: 'text', mode: 'in', default: true },
    { name: 'c', type: 'integer[]', mode: 'variadic', default: true }]

  it('casts every value to its type, in named notation when every argument has a name', () => {
    expect(buildCall('function', 'public', 'f1', f1, [v('7'), v("it's"), v('{1,2}')]).sql)
      .toBe(`SELECT * FROM "public"."f1"("a" => CAST('7' AS integer), "b" => CAST('it''s' AS text), VARIADIC "c" => CAST('{1,2}' AS integer[]))`)
  })

  it('leaves out any argument taking its default when named, and gives NULL as NULL of the type', () => {
    expect(buildCall('function', 'public', 'f1', f1, [v('', { isNull: true }), v('', { useDefault: true }), v('{3}')]).sql)
      .toBe(`SELECT * FROM "public"."f1"("a" => NULL::integer, VARIADIC "c" => CAST('{3}' AS integer[]))`)
  })

  it('positional without names, where only the last may take defaults', () => {
    const p: FuncParam[] = [{ type: 'integer', mode: 'in' }, { type: 'text', mode: 'in', default: true }, { type: 'text', mode: 'in', default: true }]
    expect(buildCall('function', 's', 'g', p, [v('1'), v('x'), v('', { useDefault: true })]).sql)
      .toBe(`SELECT * FROM "s"."g"(CAST('1' AS integer), CAST('x' AS text))`)
    expect(buildCall('function', 's', 'g', p, [v('1'), v('', { useDefault: true }), v('y')]).error).toContain('Only the last arguments')
  })

  it("leaves a function's OUT and TABLE columns out, and gives a procedure's OUT as NULL", () => {
    const f2: FuncParam[] = [{ type: 'integer', mode: 'in' }, { name: 's', type: 'integer', mode: 'out' }]
    expect(buildCall('function', 'public', 'f2', f2, [v('3')]).sql).toBe(`SELECT * FROM "public"."f2"(CAST('3' AS integer))`)
    const p1: FuncParam[] = [{ name: 'a', type: 'integer', mode: 'in' }, { name: 'b', type: 'integer', mode: 'inout' }, { name: 'c', type: 'text', mode: 'out' }]
    expect(inputsOf(p1).map(p => p.name)).toEqual(['a', 'b'])
    expect(buildCall('procedure', 'public', 'p1', p1, [v('1'), v('2')]).sql)
      .toBe(`CALL "public"."p1"("a" => CAST('1' AS integer), "b" => CAST('2' AS integer), "c" => NULL)`)
  })

  it('quotes names whole, and nothing in a value becomes SQL', () => {
    const p: FuncParam[] = [{ name: 'x"y', type: 'text', mode: 'in' }]
    expect(buildCall('function', 'my"schema', 'f', p, [v("'); DROP TABLE t; --")]).sql)
      .toBe(`SELECT * FROM "my""schema"."f"("x""y" => CAST('''); DROP TABLE t; --' AS text))`)
  })
})
