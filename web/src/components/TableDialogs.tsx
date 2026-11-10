// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { getObject, type CatalogCol, type CatalogObject, type CatalogPart } from '../api'
import { buildAddColumn, buildAddKey, buildAlterColumn, buildCreateTable, buildEditKey, type ColumnSpec, type KeySpec, type KeyType } from '../ddl'
import { Field, runDDL, Shell } from './RoutineDialogs'

// The table dialogs (point 12.3): a table, its columns and its keys. As with
// the function and trigger dialogs, each shows the SQL and runs it as the person.

function useSave(branch: string, sql: string | undefined, onDone: () => void) {
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const save = async () => {
    if (!sql) return
    setBusy(true); setErr('')
    const e = await runDDL(branch, sql)
    setBusy(false)
    if (e) setErr(e); else onDone()
  }
  return { err, busy, save }
}

const TYPES = ['bigint', 'bigserial', 'boolean', 'bytea', 'date', 'double precision', 'integer', 'interval', 'json', 'jsonb', 'numeric', 'real', 'serial', 'smallint', 'text', 'time', 'timestamp', 'timestamptz', 'uuid', 'varchar(255)']
const TypeList = () => <datalist id="ddl-types">{TYPES.map(t => <option key={t} value={t} />)}</datalist>

type Row = ColumnSpec & { id: number }

/** NewTableDialog makes a table: its columns and primary key. */
export function NewTableDialog({ branch, schemas, onClose, onDone, onOpenSql }: {
  branch: string; schemas: string[]
  onClose: () => void; onDone: (schema: string, name: string) => void; onOpenSql: (sql: string) => void
}) {
  const nextId = useRef(2)
  const [schema, setSchema] = useState(schemas.includes('public') ? 'public' : schemas[0] ?? 'public')
  const [name, setName] = useState('')
  const [rows, setRows] = useState<Row[]>([{ id: 1, name: 'id', type: 'bigserial', notNull: false, default: '', pk: true }])
  const set = (id: number, patch: Partial<Row>) => setRows(rs => rs.map(r => (r.id === id ? { ...r, ...patch } : r)))
  const built = buildCreateTable(schema, name, rows)
  const { err, busy, save } = useSave(branch, built.sql, () => onDone(schema, name.trim()))
  return (
    <Shell title="New table" sql={built.sql} error={err || built.error || ''} busy={busy} save="Create" onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        <Field label="Schema">
          <select aria-label="Schema" value={schema} onChange={e => setSchema(e.target.value)}>
            {(schemas.includes(schema) ? schemas : [schema, ...schemas]).map(s => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Name"><input aria-label="Name" autoFocus value={name} onChange={e => setName(e.target.value)} /></Field>
        <div className="ddl-cols" role="group" aria-label="Columns">
          <TypeList />
          {rows.map((r, i) => (
            <div className="ddl-col" key={r.id}>
              <input type="text" aria-label={`Column ${i + 1} name`} placeholder="name" value={r.name} onChange={e => set(r.id, { name: e.target.value })} />
              <input type="text" aria-label={`Column ${i + 1} type`} placeholder="type" list="ddl-types" value={r.type} onChange={e => set(r.id, { type: e.target.value })} />
              <input type="text" aria-label={`Column ${i + 1} default`} placeholder="default" value={r.default} onChange={e => set(r.id, { default: e.target.value })} />
              <label><input type="checkbox" aria-label={`Column ${i + 1} not null`} checked={r.notNull} onChange={e => set(r.id, { notNull: e.target.checked })} /> not null</label>
              <label><input type="checkbox" aria-label={`Column ${i + 1} primary key`} checked={!!r.pk} onChange={e => set(r.id, { pk: e.target.checked })} /> key</label>
              <button type="button" className="ghost sm" aria-label={`Remove column ${i + 1}`} disabled={rows.length === 1} onClick={() => setRows(rs => rs.filter(x => x.id !== r.id))}>✕</button>
            </div>
          ))}
          <div><button type="button" className="ghost sm" onClick={() => setRows(rs => [...rs, { id: nextId.current++, name: '', type: '', notNull: false, default: '' }])}>+ Add a column</button></div>
        </div>
      </form>
    </Shell>
  )
}

/** ColumnDialog adds a column to a table, or edits one. */
export function ColumnDialog({ branch, schema, table, edit, onClose, onDone, onOpenSql }: {
  branch: string; schema: string; table: string; edit?: CatalogCol
  onClose: () => void; onDone: () => void; onOpenSql: (sql: string) => void
}) {
  const before: ColumnSpec = { name: edit?.name ?? '', type: edit?.type ?? '', notNull: !!edit?.not_null, default: edit?.default ?? '' }
  const [name, setName] = useState(before.name)
  const [type, setType] = useState(before.type)
  const [notNull, setNotNull] = useState(before.notNull)
  const [def, setDef] = useState(before.default)
  const [using, setUsing] = useState('')
  const after: ColumnSpec = { name, type, notNull, default: def }
  const built = edit ? buildAlterColumn(schema, table, before, after, using) : buildAddColumn(schema, table, after)
  const { err, busy, save } = useSave(branch, built.sql, onDone)
  // Postgres fills these two itself: an identity column is always NOT NULL,
  // and neither takes a default.
  const filled = !!edit?.identity || !!edit?.generated
  return (
    <Shell title={edit ? `Edit column ${edit.name}` : `Add a column to ${table}`} sql={built.sql} error={err || built.error || ''} busy={busy}
      save={edit ? 'Save' : 'Add'} onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        <TypeList />
        <Field label="Name"><input aria-label="Name" autoFocus value={name} onChange={e => setName(e.target.value)} /></Field>
        <Field label="Type"><input aria-label="Type" list="ddl-types" value={type} onChange={e => setType(e.target.value)} /></Field>
        {edit && type.trim() !== before.type && (
          <Field label="How existing values convert (USING)">
            <input aria-label="Using" value={using} placeholder={`${quoteHint(before.name)}::${type.trim() || 'type'}`} onChange={e => setUsing(e.target.value)} />
          </Field>
        )}
        <Field label="Default"><input aria-label="Default" value={def} disabled={filled} onChange={e => setDef(e.target.value)} /></Field>
        <label><input type="checkbox" aria-label="Not null" checked={notNull} disabled={!!edit?.identity} onChange={e => setNotNull(e.target.checked)} /> Not null</label>
        {edit?.identity && <p className="muted" style={{ fontSize: 13, margin: 0 }}>An identity column: Postgres numbers it.</p>}
        {edit?.generated && <p className="muted" style={{ fontSize: 13, margin: 0 }}>A generated column: Postgres computes it.</p>}
      </form>
    </Shell>
  )
}

const quoteHint = (n: string) => (/^[a-z_][a-z0-9_]*$/.test(n) ? n : `"${n}"`)

/** DropDialog says what a drop does and shows the SQL; a guardrail's refusal is answered in the editor. */
export function DropDialog({ title, sql, children, branch, onClose, onDone, onOpenSql }: {
  title: string; sql: string; children: ReactNode; branch: string
  onClose: () => void; onDone: () => void; onOpenSql: (sql: string) => void
}) {
  const { err, busy, save } = useSave(branch, sql, onDone)
  return (
    <Shell title={title} sql={sql} error={err} busy={busy} save="Drop it" onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        <p style={{ margin: 0 }}>{children}</p>
      </form>
    </Shell>
  )
}

/** Pick columns: the order they are picked in is the order the key has. */
function ColumnPicker({ label, options, value, onChange }: { label: string; options: string[]; value: string[]; onChange: (v: string[]) => void }) {
  const all = [...options, ...value.filter(v => !options.includes(v))]
  return (
    <div className="ddl-field">
      <span>{label}</span>
      <div className="ddl-pick" role="group" aria-label={label}>
        {all.map(c => (
          <label key={c}>
            <input type="checkbox" aria-label={`${label}: ${c}`} checked={value.includes(c)}
              onChange={e => onChange(e.target.checked ? [...value, c] : value.filter(x => x !== c))} /> {c}
            {value.length > 1 && value.includes(c) && <span className="n">{value.indexOf(c) + 1}</span>}
          </label>
        ))}
        {all.length === 0 && <span className="muted">Choose a table first.</span>}
      </div>
    </div>
  )
}

const ACTIONS = ['', 'CASCADE', 'SET NULL', 'SET DEFAULT', 'RESTRICT']
const actionLabel = (a: string) => a || 'NO ACTION'
const KEY_LABEL: Record<KeyType, string> = { primary: 'Primary key', unique: 'Unique', foreign: 'Foreign key', check: 'Check' }

const specOf = (p?: CatalogPart): KeySpec | undefined => p?.key && ({
  type: p.key.type as KeyType, columns: p.key.columns ?? [], refSchema: p.key.refSchema, refTable: p.key.refTable, refColumns: p.key.refColumns ?? [],
  onDelete: p.key.onDelete ?? '', onUpdate: p.key.onUpdate ?? '', match: p.key.match, deferrable: p.key.deferrable, deferred: p.key.deferred,
  notValid: p.key.notValid, noInherit: p.key.noInherit, check: p.key.check ?? '',
})

/** KeyDialog adds a primary, unique, foreign or check key to a table, or edits one. */
export function KeyDialog({ branch, schema, table, columns, tables, edit, hasPrimary, onClose, onDone, onOpenSql }: {
  branch: string; schema: string; table: string; columns: string[]; tables: CatalogObject[]
  edit?: CatalogPart; hasPrimary: boolean
  onClose: () => void; onDone: () => void; onOpenSql: (sql: string) => void
}) {
  const before = specOf(edit)
  const [type, setType] = useState<KeyType>(before?.type ?? (hasPrimary ? 'unique' : 'primary'))
  const [name, setName] = useState(edit?.name ?? '')
  const [cols, setCols] = useState<string[]>(before?.columns ?? [])
  const [target, setTarget] = useState(before?.refTable ? `${before.refSchema}.${before.refTable}` : '')
  const [refCols, setRefCols] = useState<string[]>(before?.refColumns ?? [])
  const [refOptions, setRefOptions] = useState<string[]>([])
  const [onDelete, setOnDelete] = useState(before?.onDelete ?? '')
  const [onUpdate, setOnUpdate] = useState(before?.onUpdate ?? '')
  const [deferrable, setDeferrable] = useState(!!before?.deferrable)
  const [deferred, setDeferred] = useState(!!before?.deferred)
  const [check, setCheck] = useState(before?.check ?? '')

  const label = (o: CatalogObject) => `${o.schema ?? 'public'}.${o.name}`
  const targetObj = tables.find(o => label(o) === target)
  const first = useRef(true)
  // A table chosen brings its columns, and its primary key as what is referenced.
  useEffect(() => {
    const keep = first.current && !!edit
    first.current = false
    if (!targetObj) { setRefOptions([]); return }
    let live = true
    getObject(branch, 'table', targetObj.oid).then(d => {
      if (!live) return
      setRefOptions((d.columns ?? []).map(c => c.name))
      if (!keep) setRefCols(d.constraints?.find(k => k.key?.type === 'primary')?.key?.columns ?? [])
    }).catch(() => { if (live) setRefOptions([]) })
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [branch, targetObj?.oid])

  const dot = target.indexOf('.')
  // A schema or table name holding a dot is told apart through the catalog.
  const refSchema = targetObj?.schema ?? (dot > 0 ? target.slice(0, dot) : undefined)
  const refTable = targetObj?.name ?? (dot > 0 ? target.slice(dot + 1) : undefined)
  const canDefer = type !== 'check'
  const after: KeySpec = {
    type, columns: type === 'check' ? [] : cols,
    ...(type === 'foreign' ? { refSchema, refTable, refColumns: refCols, onDelete, onUpdate, match: before?.match } : {}),
    deferrable: canDefer && deferrable, deferred: canDefer && deferrable && deferred,
    notValid: before?.notValid, noInherit: before?.noInherit, check,
  }
  const built = edit && before ? buildEditKey(schema, table, edit.name, before, after) : buildAddKey(schema, table, name, after)
  const { err, busy, save } = useSave(branch, built.sql, onDone)
  const tableOptions = [...tables.map(label), ...(target && !targetObj ? [target] : [])]
  return (
    <Shell title={edit ? `Edit ${edit.name}` : `Add a key to ${table}`} sql={built.sql} error={err || built.error || ''} busy={busy}
      save={edit ? 'Save' : 'Add'} onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        <Field label="Kind">
          <select aria-label="Kind" value={type} disabled={!!edit} onChange={e => setType(e.target.value as KeyType)}>
            {(Object.keys(KEY_LABEL) as KeyType[]).map(k => <option key={k} value={k} disabled={k === 'primary' && hasPrimary && !edit}>{KEY_LABEL[k]}</option>)}
          </select>
        </Field>
        <Field label="Name"><input aria-label="Name" value={name} disabled={!!edit} placeholder="Postgres names it if left empty" onChange={e => setName(e.target.value)} /></Field>
        {type === 'check'
          ? <Field label="Condition"><input aria-label="Condition" className="mono" value={check} placeholder="total > 0" onChange={e => setCheck(e.target.value)} /></Field>
          : <ColumnPicker label="Columns" options={columns} value={cols} onChange={setCols} />}
        {type === 'foreign' && (
          <>
            <Field label="References">
              <select aria-label="References" value={target} onChange={e => setTarget(e.target.value)}>
                <option value="">Choose a table…</option>
                {tableOptions.map(t => <option key={t}>{t}</option>)}
              </select>
            </Field>
            <ColumnPicker label="Its columns" options={refOptions} value={refCols} onChange={setRefCols} />
            <Field label="On delete">
              <select aria-label="On delete" value={onDelete} onChange={e => setOnDelete(e.target.value)}>{ACTIONS.map(a => <option key={a} value={a}>{actionLabel(a)}</option>)}</select>
            </Field>
            <Field label="On update">
              <select aria-label="On update" value={onUpdate} onChange={e => setOnUpdate(e.target.value)}>{ACTIONS.map(a => <option key={a} value={a}>{actionLabel(a)}</option>)}</select>
            </Field>
          </>
        )}
        {canDefer && (
          <div className="row" style={{ gap: 16 }}>
            <label><input type="checkbox" aria-label="Deferrable" checked={deferrable} onChange={e => setDeferrable(e.target.checked)} /> Deferrable</label>
            {deferrable && <label><input type="checkbox" aria-label="Initially deferred" checked={deferred} onChange={e => setDeferred(e.target.checked)} /> Checked at commit</label>}
          </div>
        )}
        {edit && <p className="muted" style={{ fontSize: 13, margin: 0 }}>Postgres cannot change a key in place: saving drops it and adds it again in one statement, checking every row.</p>}
      </form>
    </Shell>
  )
}
