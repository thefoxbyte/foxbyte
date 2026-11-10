// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { getObject, runQuery, type CatalogKind, type CatalogObject, type CatalogPart, type FuncParam, type ObjectDetail } from '../api'
import { useConfirm } from '../confirm'
import { buildCall, inputsOf, quoteIdent, type ArgInput } from '../runcall'

// The object browser (point 12.1). The schema rail already lists tables and
// views; these are the rest of what a branch holds (functions, procedures,
// sequences, types, schemas, extensions) and, for any object, what it is made
// of and its CREATE script. The engine reads the catalog as you. A function
// or a procedure can be run from a form, and a table's own triggers switched
// off and on (point 12.4): both as SQL the person runs, through the console.

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
export function CatalogGroups({ objects, filter, showSystem, active, onOpen }: {
  objects: CatalogObject[]
  filter: string
  showSystem: boolean
  active: CatalogObject | null
  onOpen: (o: CatalogObject) => void
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const f = filter.trim().toLowerCase()
  return (
    <>
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

function Parts({ title, parts, empty, onToggle }: { title: string; parts?: CatalogPart[]; empty: string; onToggle?: (p: CatalogPart) => void }) {
  return (
    <section className="obj-parts" aria-label={title}>
      {!parts?.length ? <p className="muted">{empty}</p> : (
        <table className="obj-table">
          <thead><tr><th>Name</th><th>Definition</th>{onToggle && <th />}</tr></thead>
          <tbody>
            {parts.map(p => (
              <tr key={p.name} data-testid={`part-${p.name}`}>
                <td className="mono">{p.name}
                  {p.kind && <span className="obj-sub">{p.kind}</span>}
                  {p.system && <span className="obj-sub" title="Installed by FoxByte on every table it records; left out of the CREATE script">FoxByte</span>}
                  {p.disabled && <span className="obj-sub">disabled</span>}
                </td>
                <td className="mono">{p.def}</td>
                {onToggle && (
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {p.system
                      ? <span className="muted" title="FoxByte keeps its records with it: it is not switched off here">FoxByte&rsquo;s own</span>
                      : <button type="button" className="ghost sm" onClick={() => onToggle(p)}>{p.disabled ? 'Enable' : 'Disable…'}</button>}
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
function TriggerParts({ branch, obj, d, reload }: { branch: string; obj: CatalogObject; d: ObjectDetail; reload: () => void }) {
  const confirm = useConfirm()
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
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
      <Parts title="Triggers" parts={d.triggers} empty="No triggers." onToggle={toggle} />
      {note && <div className="ok" role="status" data-testid="trigger-note">{note}</div>}
      {err && <div className="err">{err}</div>}
    </>
  )
}

/** The table tabs the catalog fills: constraints, triggers and the CREATE script. */
export function TableParts({ branch, obj, tab, onOpenSql }: {
  branch: string
  obj: CatalogObject | null
  tab: 'constraints' | 'triggers' | 'ddl'
  onOpenSql: (sql: string) => void
}) {
  const { d, err, reload } = useObject(branch, obj)
  if (!obj) return <p className="muted">Not in this branch's catalog for you.</p>
  if (err) return <div className="err">{err}</div>
  if (!d) return <div className="muted">Loading…</div>
  if (tab === 'constraints') return <Parts title="Constraints" parts={d.constraints} empty="No constraints." />
  if (tab === 'triggers') return <TriggerParts branch={branch} obj={obj} d={d} reload={reload} />
  return <DDL text={d.ddl} onOpenSql={onOpenSql} />
}

/** ObjectView is any object that is not a table or a view: what it is, and its CREATE script. */
export function ObjectView({ branch, obj, onOpenSql, onRunSql }: {
  branch: string; obj: CatalogObject; onOpenSql: (sql: string) => void; onRunSql?: (sql: string) => void
}) {
  const { d, err } = useObject(branch, obj)
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
