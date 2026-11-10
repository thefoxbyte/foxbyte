// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { explainSQL, parsePlan } from './plan'

const estimated = JSON.stringify([{ Plan: {
  'Node Type': 'Hash Join', 'Join Type': 'Inner', 'Total Cost': 100, 'Plan Rows': 50, 'Hash Cond': '(o.customer_id = c.id)',
  Plans: [
    { 'Node Type': 'Seq Scan', 'Relation Name': 'orders', Schema: 'public', Alias: 'o', 'Total Cost': 70, 'Plan Rows': 1000, Filter: '(total > 10)' },
    { 'Node Type': 'Hash', 'Total Cost': 20, 'Plan Rows': 10, Plans: [
      { 'Node Type': 'Index Scan', 'Relation Name': 'customers', Alias: 'c', 'Index Name': 'customers_pkey', 'Total Cost': 20, 'Plan Rows': 10, 'Index Cond': '(id < 10)' },
    ] },
  ] } }])

describe('parsePlan', () => {
  it('reads each step under the one that uses it, what it reads, and its share of the cost', () => {
    const p = parsePlan(estimated)
    expect(p.analyzed).toBe(false)
    expect(p.rows.map(r => [r.depth, r.node, r.on])).toEqual([
      [0, 'Hash Join (inner)', ''], [1, 'Seq Scan', 'public.orders o'], [1, 'Hash', ''], [2, 'Index Scan', 'customers c using customers_pkey'],
    ])
    expect(p.rows[0].detail).toBe('hash: (o.customer_id = c.id)')
    expect(p.rows[1].share).toBeCloseTo(0.7)
    expect(p.rows[0].share).toBeCloseTo(0.1)
    expect(p.rows[2].share).toBe(0)
  })

  it('with ANALYZE: time on its own over every loop, the totals, and a misestimate flagged', () => {
    const p = parsePlan(JSON.stringify([{ 'Planning Time': 0.2, 'Execution Time': 12.5, Plan: {
      'Node Type': 'Nested Loop', 'Total Cost': 10, 'Plan Rows': 1, 'Actual Rows': 500, 'Actual Total Time': 12, 'Actual Loops': 1,
      Plans: [{ 'Node Type': 'Index Scan', 'Relation Name': 't', 'Total Cost': 5, 'Plan Rows': 1, 'Actual Rows': 1, 'Actual Total Time': 0.02, 'Actual Loops': 500, 'Rows Removed by Filter': 3 }],
    } }]))
    expect(p.analyzed).toBe(true)
    expect([p.planningMs, p.executionMs]).toEqual([0.2, 12.5])
    expect(p.rows[1].ms).toBeCloseTo(10)
    expect(p.rows[0].ms).toBeCloseTo(2)
    expect(p.rows[0].misestimate).toBe(true)
    expect(p.rows[1].misestimate).toBe(false)
    expect(p.rows[1].detail).toBe('3 removed by the filter')
  })

  it('names a write by what it does, as EXPLAIN does in text', () => {
    const p = parsePlan(JSON.stringify([{ Plan: { 'Node Type': 'ModifyTable', Operation: 'Delete', 'Relation Name': 't', 'Total Cost': 3, 'Plan Rows': 0 } }]))
    expect(p.rows[0].node).toBe('Delete')
    expect(p.rows[0].on).toBe('t')
  })

  it('refuses what is not a plan', () => {
    expect(() => parsePlan('[{}]')).toThrow('not a plan')
  })
})

describe('explainSQL', () => {
  it('explains one statement; with ANALYZE inside a transaction that is rolled back', () => {
    expect(explainSQL('SELECT 1;', false).sql).toBe('EXPLAIN (FORMAT JSON) SELECT 1')
    expect(explainSQL('DELETE FROM t', true).sql).toBe('BEGIN;\nEXPLAIN (FORMAT JSON, ANALYZE, BUFFERS) DELETE FROM t;\nROLLBACK;')
  })
  it('refuses nothing, two statements, and an EXPLAIN already', () => {
    expect(explainSQL('  ', false).error).toContain('Nothing to explain')
    expect(explainSQL('SELECT 1; SELECT 2', false).error).toContain('one statement')
    expect(explainSQL('explain select 1', false).error).toContain('already an EXPLAIN')
  })
})
