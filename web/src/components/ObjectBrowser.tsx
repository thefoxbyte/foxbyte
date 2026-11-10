// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState, type ReactNode } from 'react'
import { getObject, runQuery, type CatalogCol, type CatalogKind, type CatalogObject, type CatalogPart, type FuncParam, type ObjectDetail } from '../api'
import { useConfirm } from '../confirm'
import { buildCall, inputsOf, quoteIdent, type ArgInput } from '../runcall'
import { dropColumn, dropKey, dropRoutine, dropTable, dropTrigger, renameKey, renameRoutine, renameTable, renameTrigger } from '../ddl'
import { RenameDialog, RoutineDialog, runDDL, TriggerDialog } from './RoutineDialogs'
import { ColumnDialog, DropDialog, KeyDialog } from './TableDialogs'

// The object browser (point 12.1). The schema rail already lists tables and
// views; these are the rest of what a branch holds (functions, procedures,
// sequences, types, schemas, extensions) and, for any object, what it is made
// of and its CREATE script. The engine reads the catalog as you. A function
// or a procedure can be run from a form, and a table's own triggers switched
// off and on (point 12.4), and functions, procedures and triggers made, edited,
// renamed and dropped (point 12.3): all as SQL the person runs, through the console.

const GROUPS: { kind: CatalogKind; title: string; icon: string }[] = [
  { kind: 'function', title: 'Functions', icon: 'ƒ' },
  { kind: 'procedure', title: 'Procedures', icon: '▸' },
  { kind: 'sequence', title: 'Sequences', icon: '#' },
  { kind: 'type', title: 'Types', icon: 'T' },
  { kind: 'schema', title: 'Schemas', icon: '▤' },
  { kind: 'extension', title: 'Extensions', icon: '⧉' },
]

/** objectLabel is how the rail names an object: schema-qualified outside public, with a function's arguments. */
export function objectLabel(o: CatalogObject): string {
  let n = o.schema && o.schema !== 'public' && o.kind !== 'extension' ? `${o.schema}.${o.name}` : o.name
  if (o.kind === 'function' || o.kind === 'procedure') n += `(${o.args ?? ''})`
  return n
}

const objKey = (o: CatalogObject) => `${o.kind}:${o.oid}`

/** The rail's groups beyond tables and views, folded until opened or searched. */
export function CatalogGroups({ objects, filter, showSystem, active, onOpen, onNew, onNewTable }: {
  objects: CatalogObject[]
  filter: string
  showSystem: boolean
  active: CatalogObject | null
  onOpen: (o: CatalogObject) => void
  onNew?: () => void
  onNewTable?: () => void
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const f = filter.trim().toLowerCase()
  return (
    <>
      {onNewTable && <button type="button" className="ghost sm obj-new" onClick={onNewTable}>+ New table…</button>}
      {onNew && <button type="button" className="ghost sm obj-new" onClick={onNew}>+ New function…</button>}
      {GROUPS.map(g => {
        const list = objects.filter(o => o.kind === g.kind && (showSystem || !o.system)
          && (!f || objectLabel(o).toLowerCase().includes(f) || (o.schema ?? '').toLowerCase().includes(f)))
        if (list.length === 0) return null
        const shown = open[g.kind] ?? !!f
        return (
          <div key={g.kind} className="obj-cat">
            <button className="obj-group obj-group-btn" aria-expanded={shown}
              onClick={() => setOpen(s => ({ ...s, [g.kind]: !shown }))}>
              <span className="caret" aria-hidden="true">{shown ? '▾' : '▸'}</span>{g.title} <span className="n">{list.length}</span>
            </button>
            {shown && list.map(o => (
              <button key={objKey(o)} className={'obj-item' + (active && objKey(active) === objKey(o) ? ' active' : '')}
                title={objectLabel(o) + (o.sub ? ` (${o.sub})` : '')} onClick={() => onOpen(o)}>
                <i className="ic">{g.icon}</i><span className="obj-name">{objectLabel(o)}</span>
                {o.sub && o.kind !== 'extension' && <span className="obj-sub">{o.sub}</span>}
                {o.kind === 'extension' && <span className="obj-sub">{o.sub}</span>}
              </button>
            ))}
          </div>
        )
      })}
    </>
  )
}

function useObject(branch: string, obj: CatalogObject | null) {
  const [d, setD] = useState<ObjectDetail | null>(null)
  const [err, setErr] = useState('')
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!obj) return
    let live = true
    if (tick === 0) setD(null)
    setErr('')
    getObject(branch, obj.kind, obj.oid).then(x => { if (live) setD(x) }).catch(e => { if (live) setErr((e as Error).message) })
    return () => { live = false }
  }, [branch, obj, tick])
  return { d, err, reload: () => setTick(t => t + 1) }
}

/** DDL is a CREATE script, with Copy and Open in editor. */
export function DDL({ text, onOpenSql }: { text: string; onOpenSql: (sql: string) => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="ddl">
      <div className="ddl-bar">
        <span className="pane-t">CREATE script</span>
        <span className="wb-sp" />
        {copied && <span className="ok">Copied ✓</span>}
        <button className="ghost sm" onClick={() => navigator.clipboard?.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }).catch(() => {})}>Copy</button>
        <button className="ghost sm" onClick={() => onOpenSql(text)}>Open in editor</button>
      </div>
      <pre className="ddl-text" aria-label="CREATE script"><code>{text}</code></pre>
    </div>
  )
}

function Parts({ title, parts, empty, onToggle, actions }: {
  title: string; parts?: CatalogPart[]; empty: string; onToggle?: (p: CatalogPart) => void; actions?: (p: CatalogPart) => ReactNode
}) {
  return (
    <section className="obj-parts" aria-label={title}>
      {!parts?.length ? <p className="muted">{empty}</p> : (
        <table className="obj-table">
          <thead><tr><th>Name</th><th>Definition</th>{(onToggle || actions) && <th />}</tr></thead>
          <tbody>
            {parts.map(p => (
              <tr key={p.name} data-testid={`part-${p.name}`}>
                <td className="mono">{p.name}
                  {p.kind && <span className="obj-sub">{p.kind}</span>}
                  {p.system && <span className="obj-sub" title="Installed by FoxByte on every table it records; left out of the CREATE script">FoxByte</span>}
                  {p.disabled && <span className="obj-sub">disabled</span>}
                </td>
                <td className="mono">{p.def}</td>
                {(onToggle || actions) && (
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {p.system
                      ? <span className="muted" title="FoxByte keeps its records with it: it is not switched off here">FoxByte&rsquo;s own</span>
                      : <>{onToggle && <button type="button" className="ghost sm" onClick={() => onToggle(p)}>{p.disabled ? 'Enable' : 'Disable…'}</button>}{actions?.(p)}</>}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

/** Triggers, each of the user's own switched off and on (point 12.4), as the person, through the console. */
function TriggerParts({ branch, obj, d, reload, catalog, onOpenSql }: {
  branch: string; obj: CatalogObject; d: ObjectDetail; reload: () => void; catalog: CatalogObject[]; onOpenSql: (sql: string) => void
}) {
  const confirm = useConfirm()
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [dialog, setDialog] = useState<{ type: 'new' } | { type: 'edit' | 'rename'; part: CatalogPart } | null>(null)
  const schema = obj.schema ?? 'public'
  const functions = catalog.filter(o => o.kind === 'function' && o.sub === 'trigger' && !o.system && !o.args)
    .map(o => `${quoteIdent(o.schema ?? 'public')}.${quoteIdent(o.name)}`)
  const done = (msg: string) => { setDialog(null); setErr(''); setNote(msg); reload() }
  const drop = async (p: CatalogPart) => {
    if (!await confirm({
      title: 'Drop trigger',
      message: <>This drops <code>{p.name}</code> from <code>{obj.name}</code>. The change is recorded in the Blackbox.</>,
      confirmText: 'Drop it', danger: true,
    })) return
    setNote('')
    const e = await runDDL(branch, dropTrigger(schema, obj.name, p.name))
    if (e) setErr(e); else done(`${p.name} dropped.`)
  }
  const toggle = async (p: CatalogPart) => {
    const on = p.disabled
    if (!on && !await confirm({
      title: 'Disable trigger',
      message: <>While <code>{p.name}</code> is disabled it does not fire: rows written meanwhile are not seen by it. The change is recorded in the Blackbox.</>,
      confirmText: 'Disable', danger: true,
    })) return
    setErr(''); setNote('')
    const sql = `ALTER TABLE ${quoteIdent(obj.schema ?? 'public')}.${quoteIdent(obj.name)} ${on ? 'ENABLE' : 'DISABLE'} TRIGGER ${quoteIdent(p.name)}`
    try {
      const r = await runQuery(branch, sql)
      const e = r.error ?? r.results?.find(x => x.error)?.error
      if (e) { setErr(e); return }
      setNote(`${p.name} ${on ? 'enabled' : 'disabled'}.`)
      reload()
    } catch (e) { setErr((e as Error).message) }
  }
  return (
    <>
      <div className="row" style={{ margin: '0 0 8px' }}>
        <button type="button" className="ghost sm" onClick={() => setDialog({ type: 'new' })}>+ New trigger…</button>
      </div>
      <Parts title="Triggers" parts={d.triggers} empty="No triggers." onToggle={toggle} actions={p => (
        <>
          {' '}{!p.trigger?.constraint && <button type="button" className="ghost sm" onClick={() => setDialog({ type: 'edit', part: p })}>Edit…</button>}
          {' '}<button type="button" className="ghost sm" onClick={() => setDialog({ type: 'rename', part: p })}>Rename…</button>
          {' '}<button type="button" className="ghost sm danger" onClick={() => void drop(p)}>Drop…</button>
        </>
      )} />
      {note && <div className="ok" role="status" data-testid="trigger-note">{note}</div>}
      {err && <div className="err">{err}</div>}
      {dialog?.type === 'new' && (
        <TriggerDialog branch={branch} schema={schema} table={obj.name} functions={functions} onOpenSql={onOpenSql}
          onClose={() => setDialog(null)} onDone={() => done('Trigger created.')} />
      )}
      {dialog?.type === 'edit' && (
        <TriggerDialog branch={branch} schema={schema} table={obj.name} functions={functions} edit={dialog.part} onOpenSql={onOpenSql}
          onClose={() => setDialog(null)} onDone={() => done(`${dialog.part.name} saved.`)} />
      )}
      {dialog?.type === 'rename' && (
        <RenameDialog title={`Rename ${dialog.part.name}`} current={dialog.part.name} branch={branch} onOpenSql={onOpenSql}
          build={to => renameTrigger(schema, obj.name, dialog.part.name, to)}
          onClose={() => setDialog(null)} onDone={() => done('Trigger renamed.')} />
      )}
    </>
  )
}

/** Whether the table dialogs apply: FoxByte's own are not offered, and a foreign table is altered otherwise. */
export const tableEditable = (o?: CatalogObject | null) => !!o && o.kind === 'table' && !o.system && o.sub !== 'foreign'

export type TableChange = { gone?: boolean; renamed?: string }

/** A table's columns, each edited and dropped; the table renamed and dropped (point 12.3). */
function ColumnParts({ branch, obj, d, reload, onOpenSql, onChanged }: {
  branch: string; obj: CatalogObject; d: ObjectDetail; reload: () => void; onOpenSql: (sql: string) => void; onChanged: (c: TableChange) => void
}) {
  const [note, setNote] = useState('')
  const [dialog, setDialog] = useState<{ type: 'add' | 'renameTable' | 'dropTable' } | { type: 'edit' | 'drop'; col: CatalogCol } | null>(null)
  const schema = obj.schema ?? 'public'
  const done = (msg: string) => { setDialog(null); setNote(msg); reload(); onChanged({}) }
  return (
    <>
      <div className="table-actions">
        <button type="button" className="ghost sm" onClick={() => { setNote(''); setDialog({ type: 'add' }) }}>+ Add column…</button>
        <button type="button" className="ghost sm" onClick={() => { setNote(''); setDialog({ type: 'renameTable' }) }}>Rename table…</button>
        <button type="button" className="ghost sm danger" onClick={() => { setNote(''); setDialog({ type: 'dropTable' }) }}>Drop table…</button>
      </div>
      <section className="obj-parts" aria-label="Columns">
        <table className="obj-table">
          <thead><tr><th>Name</th><th>Type</th><th>Not null</th><th>Default</th><th /></tr></thead>
          <tbody>
            {(d.columns ?? []).map(c => (
              <tr key={c.name} data-testid={`col-${c.name}`}>
                <td className="mono">{c.name}
                  {c.identity && <span className="obj-sub">identity</span>}
                  {c.generated && <span className="obj-sub">generated</span>}
                </td>
                <td className="mono">{c.type}</td>
                <td>{c.not_null ? 'not null' : ''}</td>
                <td className="mono">{c.generated || c.default}</td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <button type="button" className="ghost sm" onClick={() => { setNote(''); setDialog({ type: 'edit', col: c }) }}>Edit…</button>
                  {' '}<button type="button" className="ghost sm danger" onClick={() => { setNote(''); setDialog({ type: 'drop', col: c }) }}>Drop…</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      {note && <div className="ok" role="status" data-testid="table-note">{note}</div>}
      {dialog?.type === 'add' && (
        <ColumnDialog branch={branch} schema={schema} table={obj.name} onOpenSql={onOpenSql} onClose={() => setDialog(null)} onDone={() => done('Column added.')} />
      )}
      {dialog?.type === 'edit' && (
        <ColumnDialog branch={branch} schema={schema} table={obj.name} edit={dialog.col} onOpenSql={onOpenSql} onClose={() => setDialog(null)} onDone={() => done(`${dialog.col.name} saved.`)} />
      )}
      {dialog?.type === 'drop' && (
        <DropDialog title={`Drop column ${dialog.col.name}`} sql={dropColumn(schema, obj.name, dialog.col.name)} branch={branch} onOpenSql={onOpenSql}
          onClose={() => setDialog(null)} onDone={() => done(`${dialog.col.name} dropped.`)}>
          Every row loses this column&rsquo;s value. The change is recorded in the Blackbox.
        </DropDialog>
      )}
      {dialog?.type === 'renameTable' && (
        <RenameDialog title={`Rename ${obj.name}`} current={obj.name} branch={branch} onOpenSql={onOpenSql}
          build={to => renameTable(schema, obj.name, to)} onClose={() => setDialog(null)}
          onDone={to => { setDialog(null); onChanged({ renamed: to }) }} />
      )}
      {dialog?.type === 'dropTable' && (
        <DropDialog title={`Drop table ${obj.name}`} sql={dropTable(schema, obj.name)} branch={branch} onOpenSql={onOpenSql}
          onClose={() => setDialog(null)} onDone={() => { setDialog(null); onChanged({ gone: true }) }}>
          The table and all its rows go. A guardrail refuses this until it is allowed: if it does, put it in the editor, where the Console can ask to override.
        </DropDialog>
      )}
    </>
  )
}

/** A table's primary, unique, foreign and check keys, added, edited, renamed and dropped (point 12.3). */
function KeyParts({ branch, obj, d, reload, catalog, onOpenSql, onChanged }: {
  branch: string; obj: CatalogObject; d: ObjectDetail; reload: () => void; catalog: CatalogObject[]; onOpenSql: (sql: string) => void; onChanged: (c: TableChange) => void
}) {
  const [note, setNote] = useState('')
  const [dialog, setDialog] = useState<{ type: 'add' } | { type: 'edit' | 'rename' | 'drop'; part: CatalogPart } | null>(null)
  const schema = obj.schema ?? 'public'
  const done = (msg: string) => { setDialog(null); setNote(msg); reload(); onChanged({}) }
  const columns = (d.columns ?? []).map(c => c.name)
  const tables = catalog.filter(o => o.kind === 'table' && !o.system && o.sub !== 'foreign')
  const hasPrimary = !!d.constraints?.some(k => k.key?.type === 'primary')
  const dialogProps = { branch, schema, table: obj.name, columns, tables, hasPrimary, onOpenSql, onClose: () => setDialog(null) }
  return (
    <>
      <div className="table-actions">
        <button type="button" className="ghost sm" onClick={() => { setNote(''); setDialog({ type: 'add' }) }}>+ Add key…</button>
      </div>
      <Parts title="Constraints" parts={d.constraints} empty="No constraints." actions={p => (
        <>
          {p.key?.editable && <><button type="button" className="ghost sm" onClick={() => { setNote(''); setDialog({ type: 'edit', part: p }) }}>Edit…</button>{' '}</>}
          <button type="button" className="ghost sm" onClick={() => { setNote(''); setDialog({ type: 'rename', part: p }) }}>Rename…</button>
          {' '}<button type="button" className="ghost sm danger" onClick={() => { setNote(''); setDialog({ type: 'drop', part: p }) }}>Drop…</button>
        </>
      )} />
      {note && <div className="ok" role="status" data-testid="key-note">{note}</div>}
      {dialog?.type === 'add' && <KeyDialog {...dialogProps} onDone={() => done('Key added.')} />}
      {dialog?.type === 'edit' && <KeyDialog {...dialogProps} edit={dialog.part} onDone={() => done(`${dialog.part.name} saved.`)} />}
      {dialog?.type === 'rename' && (
        <RenameDialog title={`Rename ${dialog.part.name}`} current={dialog.part.name} branch={branch} onOpenSql={onOpenSql}
          build={to => renameKey(schema, obj.name, dialog.part.name, to)} onClose={() => setDialog(null)} onDone={() => done('Key renamed.')} />
      )}
      {dialog?.type === 'drop' && (
        <DropDialog title={`Drop ${dialog.part.name}`} sql={dropKey(schema, obj.name, dialog.part.name)} branch={branch} onOpenSql={onOpenSql}
          onClose={() => setDialog(null)} onDone={() => done(`${dialog.part.name} dropped.`)}>
          The table stops enforcing this. The change is recorded in the Blackbox.
        </DropDialog>
      )}
    </>
  )
}

/** The table tabs the catalog fills: columns, constraints, triggers and the CREATE script. */
export function TableParts({ branch, obj, tab, onOpenSql, catalog, onChanged }: {
  branch: string
  obj: CatalogObject | null
  tab: 'structure' | 'constraints' | 'triggers' | 'ddl'
  onOpenSql: (sql: string) => void
  catalog: CatalogObject[]
  onChanged?: (c: TableChange) => void
}) {
  const { d, err, reload } = useObject(branch, obj)
  if (!obj) return <p className="muted">Not in this branch's catalog for you.</p>
  if (err) return <div className="err">{err}</div>
  if (!d) return <div className="muted">Loading…</div>
  const changed = onChanged ?? (() => {})
  if (tab === 'structure') return <ColumnParts branch={branch} obj={obj} d={d} reload={reload} onOpenSql={onOpenSql} onChanged={changed} />
  if (tab === 'constraints') {
    return tableEditable(obj)
      ? <KeyParts branch={branch} obj={obj} d={d} reload={reload} catalog={catalog} onOpenSql={onOpenSql} onChanged={changed} />
      : <Parts title="Constraints" parts={d.constraints} empty="No constraints." />
  }
  if (tab === 'triggers') return <TriggerParts branch={branch} obj={obj} d={d} reload={reload} catalog={catalog} onOpenSql={onOpenSql} />
  return <DDL text={d.ddl} onOpenSql={onOpenSql} />
}

/** ObjectView is any object that is not a table or a view: what it is, and its CREATE script. */
export function ObjectView({ branch, obj, onOpenSql, onRunSql, onChanged }: {
  branch: string; obj: CatalogObject; onOpenSql: (sql: string) => void; onRunSql?: (sql: string) => void
  onChanged?: (gone: boolean) => void
}) {
  const { d, err, reload } = useObject(branch, obj)
  const confirm = useConfirm()
  const [dialog, setDialog] = useState<'edit' | 'rename' | null>(null)
  const [actErr, setActErr] = useState('')
  const [dropSql, setDropSql] = useState('')
  const routine = (obj.kind === 'function' || obj.kind === 'procedure') && !obj.system && onChanged ? d?.routine : undefined
  const schema = obj.schema ?? 'public'
  const editable = routine && !routine.atomic && (routine.language === 'plpgsql' || routine.language === 'sql')
  const drop = async () => {
    if (!routine || !await confirm({
      title: `Drop ${obj.kind}`,
      message: <>This drops <code>{objectLabel(obj)}</code>. Anything that calls it stops working. The change is recorded in the Blackbox.</>,
      confirmText: 'Drop it', danger: true,
    })) return
    const sql = dropRoutine(obj.kind, schema, obj.name, routine.identity)
    setActErr(''); setDropSql('')
    const e = await runDDL(branch, sql)
    if (e) { setActErr(e); setDropSql(sql) } else onChanged?.(true)
  }
  return (
    <section className="wb-pane wb-res obj-view" aria-label={`${obj.kind} ${objectLabel(obj)}`}>
      <div className="obj-view-head">
        <h2>{objectLabel(obj)}</h2>
        <span className="path">{obj.kind}{obj.sub ? ` · ${obj.sub}` : ''}{obj.schema && obj.kind !== 'extension' ? ` · ${obj.schema}` : ''}</span>
      </div>
      {err && <div className="err">{err}</div>}
      {!d && !err && <div className="muted">Loading…</div>}
      {d && (
        <div className="obj-body">
          {d.comment && <p className="muted">{d.comment}</p>}
          {!!d.facts?.length && (
            <table className="obj-table obj-facts"><tbody>
              {d.facts.map(([k, v], i) => <tr key={k + i}><th>{k}</th><td className="mono">{v}</td></tr>)}
            </tbody></table>
          )}
          {!!d.values?.length && <p>Values: {d.values.map(v => <code key={v} className="obj-value">{v}</code>)}</p>}
          {!!d.columns?.length && (
            <table className="obj-table"><thead><tr><th>Field</th><th>Type</th></tr></thead><tbody>
              {d.columns.map(c => <tr key={c.name}><td className="mono">{c.name}</td><td className="mono">{c.type}</td></tr>)}
            </tbody></table>
          )}
          {!!d.constraints?.length && <Parts title="Constraints" parts={d.constraints} empty="" />}
          {routine && (
            <div className="row" style={{ gap: 8 }}>
              {editable
                ? <button type="button" className="ghost sm" onClick={() => setDialog('edit')}>Edit…</button>
                : <span className="muted" style={{ fontSize: 13 }}>Written in a way the dialog cannot edit: change its CREATE script in the editor.</span>}
              <button type="button" className="ghost sm" onClick={() => setDialog('rename')}>Rename…</button>
              <button type="button" className="ghost sm danger" onClick={() => void drop()}>Drop…</button>
            </div>
          )}
          {actErr && (
            <div className="err" data-testid="routine-err">{actErr}
              {dropSql && <> <button type="button" className="ghost sm" onClick={() => onOpenSql(dropSql)}>Put it in the editor</button></>}
            </div>
          )}
          {dialog === 'edit' && routine && (
            <RoutineDialog branch={branch} schemas={[schema]} edit={{ obj, routine }} onOpenSql={onOpenSql}
              onClose={() => setDialog(null)} onDone={() => { setDialog(null); reload(); onChanged?.(false) }} />
          )}
          {dialog === 'rename' && routine && (
            <RenameDialog title={`Rename ${obj.name}`} current={obj.name} branch={branch} onOpenSql={onOpenSql}
              build={to => renameRoutine(obj.kind, schema, obj.name, routine.identity, to)}
              onClose={() => setDialog(null)} onDone={() => { setDialog(null); onChanged?.(true) }} />
          )}
          {(obj.kind === 'function' || obj.kind === 'procedure') && d.params && onRunSql && (
            <RunForm key={`${obj.kind}${obj.oid}`} kind={obj.kind} schema={obj.schema ?? 'public'} name={obj.name}
              params={d.params} onRun={onRunSql} onOpen={onOpenSql} />
          )}
          {!!d.members?.length && (
            <details className="obj-members"><summary>Installed ({d.members.length})</summary>
              <ul>{d.members.map(m => <li key={m.Kind + m.Name} className="mono">{m.Name}</li>)}</ul>
            </details>
          )}
          <DDL text={d.ddl} onOpenSql={onOpenSql} />
        </div>
      )}
    </section>
  )
}

/** RunForm calls a function or a procedure (point 12.4): one field per argument, the call shown as it is built. */
function RunForm({ kind, schema, name, params, onRun, onOpen }: {
  kind: 'function' | 'procedure'; schema: string; name: string; params: FuncParam[]
  onRun: (sql: string) => void; onOpen: (sql: string) => void
}) {
  const ins = inputsOf(params)
  const [vals, setVals] = useState<ArgInput[]>(() => ins.map(p => ({ value: '', isNull: false, useDefault: !!p.default })))
  const set = (i: number, v: Partial<ArgInput>) => setVals(vs => vs.map((x, j) => (j === i ? { ...x, ...v } : x)))
  const call = buildCall(kind, schema, name, params, vals)
  const returns = params.filter(p => p.mode === 'out' || p.mode === 'table' || (kind === 'procedure' && p.mode === 'inout'))
  return (
    <form className="run-form" aria-label={`Run ${name}`} onSubmit={e => { e.preventDefault(); if (call.sql) onRun(call.sql) }}>
      <div className="pane-t">Run {kind === 'procedure' ? 'the procedure' : 'the function'}</div>
      {ins.length === 0 && <p className="muted">It takes no arguments.</p>}
      {ins.map((p, i) => (
        <div className="row" key={i} style={{ gap: 8, alignItems: 'center', marginTop: 6 }}>
          <label className="field-inline" style={{ minWidth: 220 }}>
            <span className="mono">{p.name || `$${i + 1}`}{p.mode !== 'in' && <span className="muted"> {p.mode}</span>}</span>
            <input aria-label={`Value of ${p.name || `$${i + 1}`}`} value={vals[i].value} placeholder={p.type}
              disabled={vals[i].isNull || (vals[i].useDefault && !!p.default)} onChange={e => set(i, { value: e.target.value })} />
          </label>
          <label className="muted" style={{ fontSize: 13 }}>
            <input type="checkbox" checked={vals[i].isNull} onChange={e => set(i, { isNull: e.target.checked })} /> NULL
          </label>
          {p.default && (
            <label className="muted" style={{ fontSize: 13 }}>
              <input type="checkbox" checked={vals[i].useDefault} onChange={e => set(i, { useDefault: e.target.checked })} /> its default
            </label>
          )}
        </div>
      ))}
      {returns.length > 0 && (
        <p className="muted" style={{ fontSize: 13 }}>Returns {returns.map(p => `${p.name || '?'} ${p.type}`).join(', ')}.</p>
      )}
      {call.sql && <pre className="ddl-text" data-testid="run-sql"><code>{call.sql}</code></pre>}
      {call.error && <div className="err">{call.error}</div>}
      <div className="row" style={{ gap: 8 }}>
        <button type="submit" className="primary" disabled={!call.sql}>Run</button>
        <button type="button" className="ghost" disabled={!call.sql} onClick={() => call.sql && onOpen(call.sql)}>Put the call in the editor</button>
      </div>
      <p className="muted" style={{ fontSize: 13 }}>It runs as you, in the Console, like anything you write there.</p>
    </form>
  )
}
