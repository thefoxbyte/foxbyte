// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { buildRoutine, buildTrigger, dollarTag, dropRoutine, dropTrigger, renameRoutine, renameTrigger, type RoutineSpec, type TriggerSpec } from './ddl'

const f: RoutineSpec = { kind: 'function', schema: 'public', name: 'add', arguments: 'a integer, b integer DEFAULT 1', returns: 'integer', language: 'sql', body: 'SELECT a + b', replace: false }

describe('buildRoutine', () => {
  it('writes a plain function, volatile and cost left to their defaults', () => {
    expect(buildRoutine({ ...f, volatility: 'volatile', cost: 100, parallel: 'unsafe' }).sql).toBe(
      `CREATE FUNCTION "public"."add"(a integer, b integer DEFAULT 1)\n RETURNS integer\n LANGUAGE sql\nAS $body$\nSELECT a + b\n$body$`)
  })

  it('keeps on an edit everything it was not asked to change', () => {
    expect(buildRoutine({ ...f, replace: true, volatility: 'stable', strict: true, definer: true, leakproof: true, parallel: 'safe', cost: 50, rows: 20,
      set: [`SET search_path TO 'public', 'pg_temp'`] }).sql).toBe(
      `CREATE OR REPLACE FUNCTION "public"."add"(a integer, b integer DEFAULT 1)\n RETURNS integer\n LANGUAGE sql\n STABLE\n LEAKPROOF\n STRICT\n SECURITY DEFINER\n PARALLEL SAFE\n COST 50\n ROWS 20\n SET search_path TO 'public', 'pg_temp'\nAS $body$\nSELECT a + b\n$body$`)
  })

  it('writes a procedure without what only a function has', () => {
    expect(buildRoutine({ kind: 'procedure', schema: 's', name: 'p', arguments: '', language: 'plpgsql', body: 'BEGIN NULL; END;', replace: false, volatility: 'stable', strict: true, cost: 7 }).sql)
      .toBe(`CREATE PROCEDURE "s"."p"()\n LANGUAGE plpgsql\nAS $body$\nBEGIN NULL; END;\n$body$`)
  })

  it('never lets the body close its own quoting', () => {
    expect(dollarTag('x')).toBe('$body$')
    expect(dollarTag('a $body$ b $body1$')).toBe('$body2$')
    expect(buildRoutine({ ...f, body: 'SELECT $body$x$body$' }).sql).toContain('AS $body1$\n')
  })

  it('says what is missing, and refuses a language that is not a word', () => {
    expect(buildRoutine({ ...f, name: ' ' }).error).toContain('name')
    expect(buildRoutine({ ...f, returns: '' }).error).toContain('returns')
    expect(buildRoutine({ ...f, body: '  ' }).error).toContain('body')
    expect(buildRoutine({ ...f, language: 'sql; DROP' }).error).toContain('language')
  })

  it('renames and drops by identity, quoting names', () => {
    expect(renameRoutine('function', 'public', 'a"b', 'x integer', 'c')).toBe(`ALTER FUNCTION "public"."a""b"(x integer) RENAME TO "c"`)
    expect(dropRoutine('procedure', 'public', 'p', '')).toBe(`DROP PROCEDURE "public"."p"()`)
  })
})

const t: TriggerSpec = { name: 'trg', schema: 'public', table: 'orders', timing: 'BEFORE', events: ['INSERT'], columns: '', forEach: 'ROW', when: '', func: 'public.fn', args: '', replace: false }

describe('buildTrigger', () => {
  it('writes the trigger', () => {
    expect(buildTrigger(t).sql).toBe(`CREATE TRIGGER "trg" BEFORE INSERT ON "public"."orders"\n FOR EACH ROW\n EXECUTE FUNCTION public.fn()`)
  })
  it('narrows an UPDATE to columns, keeps a condition, arguments and REFERENCING', () => {
    expect(buildTrigger({ ...t, replace: true, timing: 'AFTER', events: ['INSERT', 'UPDATE'], columns: 'a, b', when: 'new.a > 0', args: `'x'`, referencing: 'NEW TABLE AS n', forEach: 'STATEMENT' }).sql)
      .toBe(`CREATE OR REPLACE TRIGGER "trg" AFTER INSERT OR UPDATE OF "a", "b" ON "public"."orders"\n REFERENCING NEW TABLE AS n\n FOR EACH STATEMENT\n WHEN (new.a > 0)\n EXECUTE FUNCTION public.fn('x')`)
  })
  it('leaves an edited trigger disabled if it was', () => {
    expect(buildTrigger({ ...t, replace: true, disabled: true }).sql).toContain(`;\nALTER TABLE "public"."orders" DISABLE TRIGGER "trg"`)
  })
  it('says what cannot be', () => {
    expect(buildTrigger({ ...t, name: '' }).error).toContain('name')
    expect(buildTrigger({ ...t, events: [] }).error).toContain('event')
    expect(buildTrigger({ ...t, func: '' }).error).toContain('function')
    expect(buildTrigger({ ...t, events: ['TRUNCATE'] }).error).toContain('TRUNCATE')
    expect(buildTrigger({ ...t, columns: 'a' }).error).toContain('UPDATE')
  })
  it('renames and drops on its table', () => {
    expect(renameTrigger('public', 'orders', 'a', 'b')).toBe(`ALTER TRIGGER "a" ON "public"."orders" RENAME TO "b"`)
    expect(dropTrigger('public', 'orders', 'a')).toBe(`DROP TRIGGER "a" ON "public"."orders"`)
  })
})
