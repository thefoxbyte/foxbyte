// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest'
import { buildRoutine, buildTrigger, dollarTag, dropRoutine, dropTrigger, renameRoutine, renameTrigger, type RoutineSpec, type TriggerSpec } from './ddl'
import { buildAddColumn, buildAddKey, buildAlterColumn, buildCreateTable, buildEditKey, dropColumn, dropKey, dropTable, keyClause, renameKey, renameTable, type ColumnSpec, type KeySpec } from './ddl'

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

const col = (name: string, type: string, extra: Partial<ColumnSpec> = {}): ColumnSpec => ({ name, type, notNull: false, default: '', ...extra })

describe('buildCreateTable', () => {
  it('writes the columns and a primary key of one or several', () => {
    expect(buildCreateTable('public', 'orders', [col('id', 'bigserial', { pk: true }), col('Label', 'text', { notNull: true, default: `'x'` })]).sql).toBe(
      `CREATE TABLE "public"."orders" (\n  "id" bigserial,\n  "Label" text NOT NULL DEFAULT 'x',\n  PRIMARY KEY ("id")\n)`)
    expect(buildCreateTable('s', 't', [col('a', 'int', { pk: true }), col('b', 'int', { pk: true })]).sql).toContain('PRIMARY KEY ("a", "b")')
  })
  it('leaves out an empty row, and says what is missing', () => {
    expect(buildCreateTable('s', 't', [col('a', 'int'), col('', '')]).sql).toBe('CREATE TABLE "s"."t" (\n  "a" int\n)')
    expect(buildCreateTable('s', '', [col('a', 'int')]).error).toBe('It needs a name.')
    expect(buildCreateTable('s', 't', [col('', '')]).error).toBe('It needs at least one column.')
    expect(buildCreateTable('s', 't', [col('a', '')]).error).toBe('a needs a type.')
    expect(buildCreateTable('s', 't', [col('', 'int')]).error).toBe('Each column needs a name.')
    expect(buildCreateTable('s', 't', [col('a', 'int'), col('a', 'text')]).error).toBe('a is named twice.')
  })
  it('never lets a name close its own quoting', () => {
    expect(buildCreateTable('s', 'a"b', [col('c"d', 'int')]).sql).toBe('CREATE TABLE "s"."a""b" (\n  "c""d" int\n)')
  })
})

describe('columns', () => {
  const before = col('qty', 'integer', { default: '1' })
  it('adds one', () => {
    expect(buildAddColumn('s', 't', col('a', 'int', { notNull: true, default: '0' })).sql).toBe('ALTER TABLE "s"."t" ADD COLUMN "a" int NOT NULL DEFAULT 0')
    expect(buildAddColumn('s', 't', col('a', '')).error).toBe('a needs a type.')
  })
  it('writes nothing when nothing changed', () => {
    expect(buildAlterColumn('s', 't', before, before, '')).toEqual({})
  })
  it('writes only what changed', () => {
    expect(buildAlterColumn('s', 't', before, { ...before, notNull: true }, '').sql).toBe('ALTER TABLE "s"."t"\n  ALTER COLUMN "qty" SET NOT NULL')
    expect(buildAlterColumn('s', 't', before, { ...before, default: '' }, '').sql).toBe('ALTER TABLE "s"."t"\n  ALTER COLUMN "qty" DROP DEFAULT')
    expect(buildAlterColumn('s', 't', { ...before, notNull: true }, before, '').sql).toBe('ALTER TABLE "s"."t"\n  ALTER COLUMN "qty" DROP NOT NULL')
  })
  it('changes the type with its conversion, then renames, under the old name until the last', () => {
    expect(buildAlterColumn('s', 't', before, { name: 'amount', type: 'text', notNull: true, default: `'2'` }, 'qty::text').sql).toBe(
      `ALTER TABLE "s"."t"\n  ALTER COLUMN "qty" TYPE text USING qty::text,\n  ALTER COLUMN "qty" SET NOT NULL,\n  ALTER COLUMN "qty" SET DEFAULT '2';\nALTER TABLE "s"."t" RENAME COLUMN "qty" TO "amount"`)
  })
  it('drops and renames', () => {
    expect(dropColumn('s', 't', 'a')).toBe('ALTER TABLE "s"."t" DROP COLUMN "a"')
    expect(renameTable('s', 't', ' u ')).toBe('ALTER TABLE "s"."t" RENAME TO "u"')
    expect(dropTable('s', 't')).toBe('DROP TABLE "s"."t"')
  })
})

describe('keys', () => {
  const fk: KeySpec = { type: 'foreign', columns: ['a', 'b'], refSchema: 'r', refTable: 'p', refColumns: ['x', 'y'], onDelete: 'CASCADE', onUpdate: '' }
  it('writes each kind, its columns in the order chosen', () => {
    expect(keyClause({ type: 'primary', columns: ['b', 'a'] }).clause).toBe('PRIMARY KEY ("b", "a")')
    expect(keyClause({ type: 'unique', columns: ['a'], deferrable: true, deferred: true }).clause).toBe('UNIQUE ("a") DEFERRABLE INITIALLY DEFERRED')
    expect(keyClause(fk).clause).toBe('FOREIGN KEY ("a", "b") REFERENCES "r"."p" ("x", "y") ON DELETE CASCADE')
    expect(keyClause({ type: 'check', columns: [], check: 'a > 0' }).clause).toBe('CHECK (a > 0)')
  })
  it('keeps what the dialog has no field for', () => {
    expect(keyClause({ ...fk, match: 'FULL', onUpdate: 'RESTRICT', notValid: true }).clause).toBe('FOREIGN KEY ("a", "b") REFERENCES "r"."p" ("x", "y") MATCH FULL ON UPDATE RESTRICT ON DELETE CASCADE NOT VALID')
    expect(keyClause({ type: 'check', columns: [], check: 'a > 0', noInherit: true, notValid: true }).clause).toBe('CHECK (a > 0) NO INHERIT NOT VALID')
  })
  it('says what is missing', () => {
    expect(keyClause({ type: 'primary', columns: [] }).error).toBe('Choose at least one column.')
    expect(keyClause({ type: 'check', columns: [], check: ' ' }).error).toBe('It needs a condition.')
    expect(keyClause({ ...fk, refTable: '' }).error).toBe('Choose the table it references.')
    expect(keyClause({ ...fk, refColumns: ['x'] }).error).toBe('A foreign key names as many columns on each side.')
  })
  it('adds one, named or left to Postgres', () => {
    expect(buildAddKey('s', 't', 'k', { type: 'unique', columns: ['a'] }).sql).toBe('ALTER TABLE "s"."t"\n  ADD CONSTRAINT "k" UNIQUE ("a")')
    expect(buildAddKey('s', 't', '', { type: 'unique', columns: ['a'] }).sql).toBe('ALTER TABLE "s"."t"\n  ADD UNIQUE ("a")')
  })
  it('replaces one in a single statement, and writes nothing when nothing changed', () => {
    expect(buildEditKey('s', 't', 'k', fk, fk)).toEqual({})
    expect(buildEditKey('s', 't', 'k', fk, { ...fk, onDelete: 'SET NULL' }).sql).toBe(
      'ALTER TABLE "s"."t"\n  DROP CONSTRAINT "k",\n  ADD CONSTRAINT "k" FOREIGN KEY ("a", "b") REFERENCES "r"."p" ("x", "y") ON DELETE SET NULL')
  })
  it('renames and drops', () => {
    expect(renameKey('s', 't', 'k', 'l')).toBe('ALTER TABLE "s"."t" RENAME CONSTRAINT "k" TO "l"')
    expect(dropKey('s', 't', 'k')).toBe('ALTER TABLE "s"."t" DROP CONSTRAINT "k"')
  })
})
