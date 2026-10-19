// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { getObject, type CatalogKind, type CatalogObject, type CatalogPart, type ObjectDetail } from '../api'

// The object browser (point 12.1). The schema rail already lists tables and
// views; these are the rest of what a branch holds (functions, procedures,
// sequences, types, schemas, extensions) and, for any object, what it is made
// of and its CREATE script. Read-only: the engine reads the catalog as you.

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
  useEffect(() => {
    if (!obj) return
    let live = true
    setD(null); setErr('')
    getObject(branch, obj.kind, obj.oid).then(x => { if (live) setD(x) }).catch(e => { if (live) setErr((e as Error).message) })
    return () => { live = false }
  }, [branch, obj])
  return { d, err }
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

function Parts({ title, parts, empty }: { title: string; parts?: CatalogPart[]; empty: string }) {
  return (
    <section className="obj-parts" aria-label={title}>
      {!parts?.length ? <p className="muted">{empty}</p> : (
        <table className="obj-table">
          <thead><tr><th>Name</th><th>Definition</th></tr></thead>
          <tbody>
            {parts.map(p => (
              <tr key={p.name}>
                <td className="mono">{p.name}
                  {p.kind && <span className="obj-sub">{p.kind}</span>}
                  {p.system && <span className="obj-sub" title="Installed by FoxByte on every table it records; left out of the CREATE script">FoxByte</span>}
                  {p.disabled && <span className="obj-sub">disabled</span>}
                </td>
                <td className="mono">{p.def}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

/** The table tabs the catalog fills: constraints, triggers and the CREATE script. */
export function TableParts({ branch, obj, tab, onOpenSql }: {
  branch: string
  obj: CatalogObject | null
  tab: 'constraints' | 'triggers' | 'ddl'
  onOpenSql: (sql: string) => void
}) {
  const { d, err } = useObject(branch, obj)
  if (!obj) return <p className="muted">Not in this branch's catalog for you.</p>
  if (err) return <div className="err">{err}</div>
  if (!d) return <div className="muted">Loading…</div>
  if (tab === 'constraints') return <Parts title="Constraints" parts={d.constraints} empty="No constraints." />
  if (tab === 'triggers') return <Parts title="Triggers" parts={d.triggers} empty="No triggers." />
  return <DDL text={d.ddl} onOpenSql={onOpenSql} />
}

/** ObjectView is any object that is not a table or a view: what it is, and its CREATE script. */
export function ObjectView({ branch, obj, onOpenSql }: { branch: string; obj: CatalogObject; onOpenSql: (sql: string) => void }) {
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
