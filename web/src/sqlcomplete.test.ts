// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { applySuggestion, complete, ident, inCode, schemaFrom, snippets, tablesIn, type Rel } from './sqlcomplete'

const schema: Rel[] = [
  { schema: 'public', name: 'customers', kind: 'table', cols: [
    { name: 'id', type: 'integer', pk: true }, { name: 'name', type: 'text', pk: false }, { name: 'email', type: 'text', pk: false }] },
  { schema: 'public', name: 'orders', kind: 'table', cols: [
    { name: 'id', type: 'bigint', pk: true }, { name: 'customer_id', type: 'integer', pk: false }, { name: 'total', type: 'numeric', pk: false }] },
  { schema: 'public', name: 'Order Items', kind: 'table', cols: [{ name: 'Qty', type: 'integer', pk: false }] },
  { schema: 'sales', name: 'leads', kind: 'view', cols: [{ name: 'lead_id', type: 'integer', pk: false }] },
]

// The caret is where | is.
const at = (s: string) => { const i = s.indexOf('|'); return { text: s.slice(0, i) + s.slice(i + 1), caret: i } }
const labels = (s: string) => { const { text, caret } = at(s); return complete(text, caret, schema)?.items.map(i => i.label) ?? null }

describe('complete', () => {
  it('offers tables after FROM and JOIN, and schemas to qualify with', () => {
    expect(labels('SELECT * FROM cu|')).toEqual(['customers'])
    expect(labels('SELECT * FROM customers c JOIN o|')).toEqual(['orders', '"Order Items"'])
    expect(labels('select * from |')).toEqual(['customers', 'orders', '"Order Items"', 'sales.leads', 'sales.'])
    expect(labels('SELECT * FROM sales.|')).toEqual(['leads'])
    expect(labels('INSERT INTO or|')).toEqual(['orders', '"Order Items"'])
    expect(labels('SELECT * FROM customers, or|')).toEqual(['orders', '"Order Items"'])
  })

  it('offers a table\'s columns after its alias or name and a dot', () => {
    expect(labels('SELECT c.| FROM customers c')).toEqual(['id', 'name', 'email'])
    expect(labels('SELECT c.na| FROM customers AS c')).toEqual(['name'])
    expect(labels('SELECT orders.to| FROM orders')).toEqual(['total'])
    expect(labels('SELECT o.| FROM customers c JOIN orders o ON o.customer_id = c.id')).toEqual(['id', 'customer_id', 'total'])
    const { text, caret } = at('SELECT oi.| FROM "Order Items" oi')
    expect(complete(text, caret, schema)!.items[0]).toMatchObject({ label: 'Qty', insert: '"Qty"' })
  })

  it('offers the statement\'s columns first, then words, then other tables', () => {
    expect(labels('SELECT na| FROM customers')).toEqual(['name'])
    const l = labels('SELECT * FROM customers WHERE e|')!
    expect(l[0]).toBe('email')
    expect(l).toContain('END')
    expect(l).toContain('EXISTS')
    expect(labels('sel|')).toEqual(['SELECT'])
  })

  it('writes a keyword in the case being typed', () => {
    const { text, caret } = at('sel|')
    expect(complete(text, caret, schema)!.items[0].insert).toBe('select')
    const u = at('SEL|')
    expect(complete(u.text, u.caret, schema)!.items[0].insert).toBe('SELECT')
  })

  it('replaces only the word being typed', () => {
    const { text, caret } = at('SELECT c.na| FROM customers c')
    expect(complete(text, caret, schema)).toMatchObject({ from: 9, to: 11 })
  })

  it('reads only the statement the caret is in', () => {
    expect(labels('SELECT * FROM orders; SELECT na| FROM customers')).toEqual(['name'])
    expect(labels('SELECT na| FROM customers; SELECT * FROM orders')).toEqual(['name'])
  })

  it('offers nothing in a string or a comment', () => {
    expect(labels("SELECT 'FROM cu|'")).toBeNull()
    expect(labels('-- FROM cu|')).toBeNull()
    expect(labels('/* FROM cu|')).toBeNull()
    expect(labels("SELECT 'it''s' FROM cu|")).toEqual(['customers'])
    expect(labels('SELECT $$ x $$ FROM cu|')).toEqual(['customers'])
  })
})

describe('tablesIn', () => {
  it('finds tables and aliases, not keywords that follow a table', () => {
    const m = tablesIn('SELECT * FROM customers c JOIN sales.leads AS l ON true WHERE 1=1', schema)
    expect([...m.keys()].sort()).toEqual(['c', 'customers', 'l', 'leads'])
    expect(tablesIn('SELECT * FROM orders WHERE true', schema).has('where')).toBe(false)
    expect(tablesIn('UPDATE "Order Items" SET "Qty" = 1', schema).get('order items')?.name).toBe('Order Items')
  })
})

describe('ident', () => {
  it('quotes only when it must', () => {
    expect(ident('customers')).toBe('customers')
    expect(ident('Order Items')).toBe('"Order Items"')
    expect(ident('user')).toBe('"user"')
    expect(ident('a"b')).toBe('"a""b"')
  })
})

describe('inCode', () => {
  it('knows strings, comments and dollar quotes', () => {
    expect(inCode("SELECT 'x' ", 11)).toBe(true)
    expect(inCode("SELECT 'x", 9)).toBe(false)
    expect(inCode('SELECT 1 -- note\nFROM', 21)).toBe(true)
  })
})

describe('applySuggestion', () => {
  it('replaces the misspelt name where Postgres pointed', () => {
    expect(applySuggestion('SELECT * FROM custmers', { wrong: 'custmers', insert: 'customers' }, 15)).toBe('SELECT * FROM customers')
    // The first one is in a string; the one meant is after the position.
    const sql = "SELECT 'custmers' AS x FROM custmers c JOIN custmers d ON true"
    expect(applySuggestion(sql, { wrong: 'custmers', insert: 'customers' }, sql.indexOf('custmers c') + 1))
      .toBe("SELECT 'custmers' AS x FROM customers c JOIN custmers d ON true")
  })

  it('matches whatever case or quotes it was written in, as a whole word', () => {
    expect(applySuggestion('SELECT * FROM Custmers', { wrong: 'custmers', insert: 'customers' }, 15)).toBe('SELECT * FROM customers')
    expect(applySuggestion('SELECT * FROM "products"', { wrong: 'products', insert: '"Products"' }, 15)).toBe('SELECT * FROM "Products"')
    expect(applySuggestion('SELECT nmae, nmaex FROM t', { wrong: 'nmae', insert: 'name' })).toBe('SELECT name, nmaex FROM t')
  })

  it('counts Postgres\'s position in characters', () => {
    expect(applySuggestion("SELECT '😀' AS x FROM custmers", { wrong: 'custmers', insert: 'customers' }, 22))
      .toBe("SELECT '😀' AS x FROM customers")
  })

  it('gives up rather than guess', () => {
    expect(applySuggestion('SELECT 1', { wrong: 'custmers', insert: 'customers' }, 3)).toBeNull()
  })
})

describe('snippets', () => {
  it('writes a table\'s statements with its columns and its key', () => {
    const s = Object.fromEntries(snippets(schema[0]).map(x => [x.label, x.sql]))
    expect(Object.keys(s)).toEqual(['Select rows', 'Count rows', 'Insert a row', 'Update a row', 'Delete a row'])
    expect(s['Select rows']).toBe('SELECT id, name, email\nFROM customers\nLIMIT 100;')
    expect(s['Count rows']).toBe('SELECT count(*) FROM customers;')
    expect(s['Update a row']).toBe('UPDATE customers\nSET name = NULL,\n    email = NULL\nWHERE id = NULL;')
    expect(s['Delete a row']).toBe('DELETE FROM customers\nWHERE id = NULL;')
    expect(s['Insert a row']).toMatch(/^INSERT INTO customers \(id, name, email\)\nVALUES \(NULL, NULL, NULL\);/)
  })

  it('quotes what must be, and gives a view only reads', () => {
    expect(snippets(schema[2])[0].sql).toBe('SELECT "Qty"\nFROM "Order Items"\nLIMIT 100;')
    expect(snippets(schema[3]).map(x => x.label)).toEqual(['Select rows', 'Count rows'])
    expect(snippets(schema[3])[1].sql).toBe('SELECT count(*) FROM sales.leads;')
  })

  it('without a key, a change has no WHERE that runs until it is written', () => {
    const noKey: Rel = { schema: 'public', name: 'log', kind: 'table', cols: [{ name: 'msg', type: 'text', pk: false }] }
    const del = snippets(noKey).find(x => x.label === 'Delete a row')!.sql
    expect(del).toBe('DELETE FROM log\nWHERE /* condition */ false;')
  })
})

describe('schemaFrom', () => {
  it('reads the schema query\'s rows into tables and columns', () => {
    const rel = schemaFrom([
      ['public', 'orders', 'table', 'id', 'bigint', true],
      ['public', 'orders', 'table', 'total', 'numeric(10,2)', false],
      ['sales', 'leads', 'view', 'lead_id', 'integer', false],
    ])
    expect(rel).toEqual([
      { schema: 'public', name: 'orders', kind: 'table', cols: [{ name: 'id', type: 'bigint', pk: true }, { name: 'total', type: 'numeric(10,2)', pk: false }] },
      { schema: 'sales', name: 'leads', kind: 'view', cols: [{ name: 'lead_id', type: 'integer', pk: false }] },
    ])
  })
})
