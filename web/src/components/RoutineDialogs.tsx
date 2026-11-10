// SPDX-License-Identifier: AGPL-3.0-or-later
import { useId, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { runQuery, type CatalogObject, type CatalogPart, type RoutineInfo } from '../api'
import { buildRoutine, buildTrigger, TRIGGER_BODY } from '../ddl'

// The create and edit dialogs (point 12.3): each shows the SQL it will run,
// and runs it as the person, through the console. "Put it in the editor" is
// there for what a guardrail refuses, where the Console can ask to override.

/** runDDL runs a statement as the person and returns what went wrong, or "". */
export async function runDDL(branch: string, sql: string): Promise<string> {
  try {
    const r = await runQuery(branch, sql)
    return r.error ?? r.results?.find(x => x.error)?.error ?? ''
  } catch (e) { return (e as Error).message }
}

function Shell({ title, sql, error, busy, save, onClose, onOpenSql, children }: {
  title: string; sql?: string; error: string; busy: boolean; save: string
  onClose: () => void; onOpenSql: (sql: string) => void; children: ReactNode
}) {
  const id = useId()
  // At the top of the page: a pane around it could otherwise clip it.
  return createPortal(
    <div className="modal-overlay">
      <div className="modal fade-up ddl-dialog" role="dialog" aria-modal="true" aria-labelledby={id}>
        <h3 id={id}>{title}</h3>
        {children}
        {sql && <pre className="ddl-text" data-testid="ddl-sql"><code>{sql}</code></pre>}
        {error && <div className="err" data-testid="ddl-err">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          <button type="button" className="ghost" disabled={!sql} onClick={() => { if (sql) { onOpenSql(sql); onClose() } }}>Put it in the editor</button>
          <button type="submit" className="primary" form="ddl-form" disabled={!sql || busy}>{busy ? 'Saving…' : save}</button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

const Field = ({ label, children }: { label: string; children: ReactNode }) => <label className="field ddl-field">{label}{children}</label>

type Kind = 'function' | 'procedure' | 'trigger'

/** RoutineDialog makes a function, procedure or trigger function, or edits one. */
export function RoutineDialog({ branch, schemas, edit, onClose, onDone, onOpenSql }: {
  branch: string; schemas: string[]
  edit?: { obj: CatalogObject; routine: RoutineInfo }
  onClose: () => void; onDone: () => void; onOpenSql: (sql: string) => void
}) {
  const r = edit?.routine
  const [kind, setKind] = useState<Kind>(r?.trigger ? 'trigger' : edit?.obj.kind === 'procedure' ? 'procedure' : 'function')
  const [schema, setSchema] = useState(edit?.obj.schema ?? 'public')
  const [name, setName] = useState(edit?.obj.name ?? '')
  const [args, setArgs] = useState(r?.arguments ?? '')
  const [returns, setReturns] = useState(r?.returns ?? '')
  const [language, setLanguage] = useState(r?.language ?? 'plpgsql')
  const [volatility, setVolatility] = useState(r?.volatility ?? 'volatile')
  const [strict, setStrict] = useState(!!r?.strict)
  const [definer, setDefiner] = useState(!!r?.definer)
  const [body, setBody] = useState(r?.body?.replace(/^\n/, '') ?? '')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const isTrigger = kind === 'trigger'
  const text = !edit && isTrigger && !body.trim() ? TRIGGER_BODY : body
  const built = buildRoutine({
    kind: kind === 'procedure' ? 'procedure' : 'function', schema, name,
    arguments: isTrigger ? '' : args, returns: isTrigger ? 'trigger' : returns, language, body: text,
    volatility, strict, definer, replace: !!edit,
    // What the dialog has no field for is kept as it was.
    leakproof: r?.leakproof, window: r?.window, parallel: r?.parallel, cost: r?.cost, rows: r?.rows, set: r?.set,
  })
  const save = async () => {
    if (!built.sql) return
    setBusy(true); setErr('')
    const e = await runDDL(branch, built.sql)
    setBusy(false)
    if (e) setErr(e); else onDone()
  }
  const noun = kind === 'trigger' ? 'trigger function' : kind
  return (
    <Shell title={edit ? `Edit ${edit.obj.name}` : `New ${noun}`} sql={built.sql} error={err || built.error || ''} busy={busy}
      save={edit ? 'Save' : 'Create'} onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        {!edit && (
          <Field label="Kind">
            <select aria-label="Kind" value={kind} onChange={e => setKind(e.target.value as Kind)}>
              <option value="function">Function</option>
              <option value="procedure">Procedure</option>
              <option value="trigger">Trigger function</option>
            </select>
          </Field>
        )}
        <Field label="Schema">
          <select aria-label="Schema" value={schema} disabled={!!edit} onChange={e => setSchema(e.target.value)}>
            {(schemas.includes(schema) ? schemas : [schema, ...schemas]).map(s => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Name"><input aria-label="Name" value={name} disabled={!!edit} onChange={e => setName(e.target.value)} /></Field>
        {!isTrigger && (
          <Field label="Arguments">
            <input aria-label="Arguments" value={args} disabled={!!edit} placeholder="a integer, b text DEFAULT 'x'" onChange={e => setArgs(e.target.value)} />
          </Field>
        )}
        {kind === 'function' && (
          <Field label="Returns"><input aria-label="Returns" value={returns} disabled={!!edit} placeholder="integer" onChange={e => setReturns(e.target.value)} /></Field>
        )}
        <Field label="Language">
          <select aria-label="Language" value={language} onChange={e => setLanguage(e.target.value)}>
            <option>plpgsql</option>
            {!isTrigger && <option>sql</option>}
          </select>
        </Field>
        {kind === 'function' && (
          <Field label="Volatility">
            <select aria-label="Volatility" value={volatility} onChange={e => setVolatility(e.target.value)}>
              <option>volatile</option><option>stable</option><option>immutable</option>
            </select>
          </Field>
        )}
        <div className="row" style={{ gap: 16 }}>
          {kind === 'function' && <label><input type="checkbox" checked={strict} onChange={e => setStrict(e.target.checked)} /> Strict (NULL in, NULL out)</label>}
          <label title="It runs with its owner's rights. The hardening report and the audit log name such functions.">
            <input type="checkbox" checked={definer} onChange={e => setDefiner(e.target.checked)} /> Security definer
          </label>
        </div>
        {definer && <p className="muted" style={{ fontSize: 13, margin: '6px 0 0' }}>It runs with its owner&rsquo;s rights, not the caller&rsquo;s, and what it does is not in the audit log.</p>}
        <Field label="Body">
          <textarea aria-label="Body" rows={8} spellCheck={false} className="mono" value={text} onChange={e => setBody(e.target.value)} />
        </Field>
        {edit && <p className="muted" style={{ fontSize: 13, margin: 0 }}>Its name, arguments and return type stay: changing those makes another function. Rename it, or drop it and make a new one.</p>}
      </form>
    </Shell>
  )
}

const EVENTS = ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']

/** TriggerDialog makes a trigger on a table, or edits one. */
export function TriggerDialog({ branch, schema, table, functions, edit, onClose, onDone, onOpenSql }: {
  branch: string; schema: string; table: string; functions: string[]
  edit?: CatalogPart
  onClose: () => void; onDone: () => void; onOpenSql: (sql: string) => void
}) {
  const t = edit?.trigger
  const [name, setName] = useState(edit?.name ?? '')
  const [timing, setTiming] = useState(t?.timing ?? 'BEFORE')
  const [events, setEvents] = useState<string[]>(t?.events ?? ['INSERT'])
  const [columns, setColumns] = useState((t?.columns ?? []).join(', '))
  const [forEach, setForEach] = useState(t?.forEach ?? 'ROW')
  const [when, setWhen] = useState(t?.when ?? '')
  const [func, setFunc] = useState(t?.function ?? functions[0] ?? '')
  const [args, setArgs] = useState(t?.args ?? '')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const built = buildTrigger({ name, schema, table, timing, events: EVENTS.filter(e => events.includes(e)), columns, forEach, when, func, args,
    referencing: t?.referencing, replace: !!edit, disabled: edit?.disabled })
  const save = async () => {
    if (!built.sql) return
    setBusy(true); setErr('')
    const e = await runDDL(branch, built.sql)
    setBusy(false)
    if (e) setErr(e); else onDone()
  }
  const options = func && !functions.includes(func) ? [func, ...functions] : functions
  return (
    <Shell title={edit ? `Edit ${edit.name}` : `New trigger on ${table}`} sql={built.sql} error={err || built.error || ''} busy={busy}
      save={edit ? 'Save' : 'Create'} onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        <Field label="Name"><input aria-label="Name" value={name} disabled={!!edit} onChange={e => setName(e.target.value)} /></Field>
        <Field label="When it fires">
          <select aria-label="When it fires" value={timing} onChange={e => setTiming(e.target.value)}><option>BEFORE</option><option>AFTER</option></select>
        </Field>
        <div className="row" style={{ gap: 12 }} role="group" aria-label="Events">
          {EVENTS.map(ev => (
            <label key={ev}><input type="checkbox" checked={events.includes(ev)}
              onChange={e => setEvents(x => (e.target.checked ? [...x, ev] : x.filter(y => y !== ev)))} /> {ev}</label>
          ))}
        </div>
        <Field label="Only when these columns change (UPDATE)">
          <input aria-label="Columns" value={columns} placeholder="status, total" onChange={e => setColumns(e.target.value)} />
        </Field>
        <Field label="For each">
          <select aria-label="For each" value={forEach} onChange={e => setForEach(e.target.value)}><option>ROW</option><option>STATEMENT</option></select>
        </Field>
        <Field label="Condition (WHEN)"><input aria-label="Condition" value={when} placeholder="new.total > 0" onChange={e => setWhen(e.target.value)} /></Field>
        <Field label="Trigger function">
          <select aria-label="Trigger function" value={func} onChange={e => setFunc(e.target.value)}>
            {options.length === 0 && <option value="">None yet: make one under Functions</option>}
            {options.map(f => <option key={f}>{f}</option>)}
          </select>
        </Field>
        <Field label="Arguments"><input aria-label="Arguments" value={args} placeholder="'a', 'b'" onChange={e => setArgs(e.target.value)} /></Field>
      </form>
    </Shell>
  )
}

/** RenameDialog asks for a new name. */
export function RenameDialog({ title, current, build, branch, onClose, onDone, onOpenSql }: {
  title: string; current: string; build: (to: string) => string; branch: string
  onClose: () => void; onDone: () => void; onOpenSql: (sql: string) => void
}) {
  const [to, setTo] = useState(current)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const sql = to.trim() && to.trim() !== current ? build(to) : undefined
  const save = async () => {
    if (!sql) return
    setBusy(true); setErr('')
    const e = await runDDL(branch, sql)
    setBusy(false)
    if (e) setErr(e); else onDone()
  }
  return (
    <Shell title={title} sql={sql} error={err} busy={busy} save="Rename" onClose={onClose} onOpenSql={onOpenSql}>
      <form id="ddl-form" className="ddl-form" onSubmit={e => { e.preventDefault(); void save() }}>
        <Field label="New name"><input aria-label="New name" autoFocus value={to} onChange={e => setTo(e.target.value)} /></Field>
      </form>
    </Shell>
  )
}
