// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { buildChanges, condition, countQuery, nextSort, rowsQuery, summary, toText } from './gridquery'

const rel = '"public"."orders"'

describe('rowsQuery', () => {
  it('pages in key order when nothing is sorted', () => {
    expect(rowsQuery(rel, { sort: null, filters: [], page: 2, pageSize: 100, key: ['id'] }))
      .toBe('SELECT * FROM "public"."orders" ORDER BY "id" LIMIT 100 OFFSET 200')
  })
  it('sorts on a column, NULLs last, ties broken by the key', () => {
    expect(rowsQuery(rel, { sort: { col: 'Total', dir: 'desc' }, filters: [], page: 0, pageSize: 50, key: ['id'] }))
      .toBe('SELECT * FROM "public"."orders" ORDER BY "Total" DESC NULLS LAST, "id" LIMIT 50 OFFSET 0')
    expect(rowsQuery(rel, { sort: { col: 'id', dir: 'asc' }, filters: [], page: 0, pageSize: 50, key: ['id'] }))
      .toBe('SELECT * FROM "public"."orders" ORDER BY "id" ASC NULLS LAST LIMIT 50 OFFSET 0')
  })
  it('without a key or a sort, it pages as the table gives the rows', () => {
    expect(rowsQuery(rel, { sort: null, filters: [], page: 0, pageSize: 100, key: [] })).toBe('SELECT * FROM "public"."orders" LIMIT 100 OFFSET 0')
  })
  it('filters, and counts with the same filters', () => {
    const f = [{ col: 'status', op: '=' as const, value: 'paid' }, { col: 'note', op: 'null' as const, value: '' }]
    expect(rowsQuery(rel, { sort: null, filters: f, page: 0, pageSize: 10, key: ['id'] }))
      .toBe(`SELECT * FROM "public"."orders" WHERE "status" = 'paid' AND "note" IS NULL ORDER BY "id" LIMIT 10 OFFSET 0`)
    expect(countQuery(rel, f)).toBe(`SELECT count(*) FROM "public"."orders" WHERE "status" = 'paid' AND "note" IS NULL`)
  })
})

describe('condition', () => {
  it('quotes names and values, so nothing typed becomes SQL', () => {
    expect(condition({ col: 'na"me', op: '=', value: "O'Brien'; DROP TABLE x; --" })).toBe(`"na""me" = 'O''Brien''; DROP TABLE x; --'`)
  })
  it('matches text with LIKE\'s wildcards as themselves', () => {
    expect(condition({ col: 'code', op: 'contains', value: '50%_off' })).toBe(`"code"::text ILIKE '%50\\%\\_off%'`)
    expect(condition({ col: 'code', op: 'starts', value: 'a\\b' })).toBe(`"code"::text ILIKE 'a\\\\b%'`)
  })
  it('has every comparison', () => {
    for (const op of ['<>', '<', '>', '<=', '>='] as const) expect(condition({ col: 'n', op, value: '3' })).toBe(`"n" ${op} '3'`)
    expect(condition({ col: 'n', op: 'notnull', value: 'ignored' })).toBe('"n" IS NOT NULL')
  })
})

describe('nextSort', () => {
  it('goes ascending, descending, then off; another column starts over', () => {
    let s = nextSort(null, 'a')
    expect(s).toEqual({ col: 'a', dir: 'asc' })
    s = nextSort(s, 'a')
    expect(s).toEqual({ col: 'a', dir: 'desc' })
    expect(nextSort(s, 'a')).toBeNull()
    expect(nextSort(s, 'b')).toEqual({ col: 'b', dir: 'asc' })
  })
})

describe('toText', () => {
  it('is what the engine casts back', () => {
    expect(toText(null)).toBeNull()
    expect(toText(3.5)).toBe('3.5')
    expect(toText(true)).toBe('true')
    expect(toText({ a: 1 })).toBe('{"a":1}')
    expect(toText('')).toBe('')
  })
})

describe('buildChanges', () => {
  const cols = ['id', 'name', 'meta', 'qty']
  const rows: unknown[][] = [[1, 'Ada', { x: 1 }, 2], [2, 'Bob', null, 5], [3, 'Cy', null, 1]]

  it('deletes, then changes, then adds; each update carrying the row as it was loaded', () => {
    const edits = new Map([[0, new Map<number, string | null>([[1, 'Ada L.'], [3, null]])], [1, new Map<number, string | null>([[1, 'Robert']])]])
    const added = [new Map<number, string | null>([[1, 'Dee']])]
    expect(buildChanges(cols, rows, ['id'], edits, new Set([2]), added)).toEqual([
      { op: 'delete', key: { id: '3' } },
      { op: 'update', key: { id: '1' }, values: { name: 'Ada L.', qty: null }, old: { name: 'Ada', qty: '2' } },
      { op: 'update', key: { id: '2' }, values: { name: 'Robert' }, old: { name: 'Bob' } },
      { op: 'insert', values: { name: 'Dee' } },
    ])
  })

  it('drops a cell set back to what it was, and the edits of a deleted row', () => {
    const edits = new Map([[0, new Map<number, string | null>([[1, 'Ada']])], [1, new Map<number, string | null>([[1, 'X']])]])
    expect(buildChanges(cols, rows, ['id'], edits, new Set([1]), [])).toEqual([{ op: 'delete', key: { id: '2' } }])
  })

  it('does not check a structured value it cannot read back the same', () => {
    const edits = new Map([[0, new Map<number, string | null>([[2, '{"x": 2}']])]])
    expect(buildChanges(cols, rows, ['id'], edits, new Set(), [])).toEqual([
      { op: 'update', key: { id: '1' }, values: { meta: '{"x": 2}' }, old: {} },
    ])
  })

  it('names a row by every column of its key', () => {
    const c = buildChanges(['a', 'b', 'v'], [['x', 2, 'old']], ['a', 'b'], new Map(), new Set([0]), [])
    expect(c).toEqual([{ op: 'delete', key: { a: 'x', b: '2' } }])
  })

  it('says what a save would do', () => {
    expect(summary([{ op: 'insert', values: {} }, { op: 'delete', key: {} }, { op: 'delete', key: {} }])).toBe('1 added, 2 deleted')
    expect(summary([])).toBe('no changes')
  })
})
