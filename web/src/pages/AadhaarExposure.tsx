// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import {
  aadhaarLogName, getAadhaar, getAadhaarLogPlaces, getAadhaarPlaces, getAccount, runAadhaar,
  type AadhaarColumn, type AadhaarLogFilter, type AadhaarLogPlace, type AadhaarLogs, type AadhaarPerson,
  type AadhaarPlace, type AadhaarPlaceFilter, type AadhaarReport, type Branch,
} from '../api'
import { useFeatures, why } from '../features'
import { useBranches } from '../useBranches'

// The Aadhaar exposure report (point 4.5): which person's Aadhaar is exposed
// in a branch, where, and since when. A run reads every row; the engine keeps
// each place as its row's key and the number's last four digits, so nothing
// here can show a whole number. Reading the report is free; a run is
// Enterprise.
//
// An admin can have a run read the branch's logs too (4.5b): its query
// history, the audit log's statement text and its Blackbox. A number in a
// table and in a log is then one person. Only an admin's report has that part.

const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString() : '–')
const where = (c: { schema: string; table: string; column: string; path: string }) =>
  `${c.schema}.${c.table}.${c.column}${c.path ? ' ' + c.path : ''}`

type Showing = { title: string; filter?: AadhaarPlaceFilter; logFilter?: AadhaarLogFilter }

export default function AadhaarExposure() {
  const [branch, setBranch] = useState('main')
  const [report, setReport] = useState<AadhaarReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [timeout, setTimeout_] = useState('300')
  const [err, setErr] = useState('')
  const [showing, setShowing] = useState<Showing | null>(null)
  const [admin, setAdmin] = useState(false)
  const [withLogs, setWithLogs] = useState(false)
  const { branches } = useBranches()
  const { can, edition } = useFeatures()
  const licensed = can('personal-data')

  const load = useCallback(async () => {
    setLoading(true); setErr(''); setShowing(null)
    try { setReport(await getAadhaar(branch)) }
    catch (e) { setReport(null); setErr((e as Error).message) }
    finally { setLoading(false) }
  }, [branch])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    let live = true
    getAccount().then(a => { if (live) setAdmin(!!a.admin) }).catch(() => {})
    return () => { live = false }
  }, [])

  const run = async () => {
    const n = Number(timeout)
    if (!Number.isInteger(n) || n < 1 || n > 3600) { setErr("A table's read may take 1 to 3,600 seconds."); return }
    setRunning(true); setErr(''); setShowing(null)
    try { setReport(await (admin && withLogs ? runAadhaar(branch, n, true) : runAadhaar(branch, n))) }
    catch (e) { setErr((e as Error).message) }
    finally { setRunning(false) }
  }

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const r = report?.run ?? null
  const cols = report?.columns ?? []
  const people = report?.people ?? []
  const logs = report?.logs ?? null
  // A person's rows: their table places, and their log entries when the logs
  // were read with this run.
  const personRows = (p: AadhaarPerson): Showing => ({
    title: `person ${p.person} (${p.masked})`,
    filter: { person: p.person },
    logFilter: logs?.linked && p.logs ? { person: p.person } : undefined,
  })

  return (
    <div className="fade-up">
      <h1>Aadhaar exposure</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Every Aadhaar number in a branch's tables: whose (by its last four digits), in which column and row, and since
        when. FoxByte reads every row and keeps where a number is, never the number.
      </p>

      {edition && !licensed && (
        <p className="muted" style={{ marginTop: -6, fontSize: 13 }}>
          {why(edition, 'The Aadhaar exposure report')} Reports from earlier runs can still be read.
        </p>
      )}

      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <label className="muted" style={{ fontSize: 13 }} htmlFor="aad-branch">Branch</label>
        <select id="aad-branch" value={branch} onChange={e => setBranch(e.target.value)}>
          {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
        <label className="muted" style={{ fontSize: 13 }} htmlFor="aad-timeout">Seconds per table</label>
        <input id="aad-timeout" type="number" min={1} max={3600} value={timeout} style={{ width: 90 }}
          onChange={e => setTimeout_(e.target.value)} />
        {admin && (
          <label style={{ fontSize: 13 }} title="Query history, the audit log's statement text and the Blackbox: says who typed whose number">
            <input type="checkbox" checked={withLogs} onChange={e => setWithLogs(e.target.checked)} /> Read the logs too (admins)
          </label>
        )}
        <button className="primary" onClick={run} disabled={running || !licensed}
          title={licensed ? 'Reads every row of every table: on a large branch this takes a while' : why(edition, 'The Aadhaar exposure report')}>
          {running ? 'Reading every row…' : licensed ? 'Run the report' : 'Run the report (Enterprise)'}
        </button>
      </div>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {loading && !report ? <p className="muted">Loading…</p> : !r ? (
        !err && (
          <div className="panel" style={{ marginTop: 16, padding: 22, textAlign: 'center' }}>
            <p className="muted" style={{ margin: 0 }}>
              <code>{branch}</code> has no Aadhaar exposure report yet.{licensed ? ' Run it to read every row for Aadhaar numbers.' : ''}
            </p>
          </div>
        )
      ) : (
        <>
          <p className="muted" style={{ marginTop: 16 }} data-testid="aadhaar-summary">
            Run {r.id}, {new Date(r.finished).toLocaleString()}{r.actor ? ` by ${r.actor}` : ''}: {r.tables} table(s), {r.columns} column(s) read.
            {' '}{r.numbers} number(s) found, {r.people} distinct; {r.listed} place(s) kept.
          </p>

          {cols.length === 0 ? (
            <div className="panel" style={{ padding: 22, textAlign: 'center' }}>
              <p className="muted" style={{ margin: 0 }}>No Aadhaar number was found in the tables read. The limits below still apply.</p>
            </div>
          ) : (
            <>
              <h3>By column</h3>
              <div className="table-wrap">
                <table aria-label="Aadhaar by column">
                  <thead>
                    <tr><th>Where</th><th className="num">Numbers</th><th className="num">Rows</th><th className="num">Kept</th><th>Since</th><th><span className="sr-only">Rows</span></th></tr>
                  </thead>
                  <tbody>
                    {cols.map((c: AadhaarColumn) => (
                      <tr key={where(c)}>
                        <td><code>{where(c)}</code></td>
                        <td className="num">{c.numbers}</td>
                        <td className="num">{c.rows}</td>
                        <td className="num">{c.listed}{c.capped && <div className="muted" style={{ fontSize: 12 }}>the first</div>}</td>
                        <td>{day(c.since)}</td>
                        <td>
                          <button className="ghost sm" aria-label={`Rows of ${where(c)}`}
                            onClick={() => setShowing({ title: where(c), filter: { column: where(c) } })}>Rows</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3>By person</h3>
              <p className="muted" style={{ marginTop: -6, fontSize: 13 }}>
                The most places first{(report?.peopleListed ?? 0) > people.length ? `; the first ${people.length} of ${report!.peopleListed}` : ''}.
                A person is this run's number for one Aadhaar: places with the same person hold the same number.
              </p>
              <div className="table-wrap">
                <table aria-label="Aadhaar by person">
                  <thead>
                    <tr><th className="num">Person</th><th>Number</th><th className="num">Places</th><th>Since</th><th>Where</th><th><span className="sr-only">Rows</span></th></tr>
                  </thead>
                  <tbody>
                    {people.map(p => (
                      <tr key={p.person}>
                        <td className="num">{p.person}</td>
                        <td><code>{p.masked}</code></td>
                        <td className="num">{p.places}</td>
                        <td>{day(p.since)}</td>
                        <td>{(p.where ?? []).map(w => <div key={w}><code>{w}</code></div>)}</td>
                        <td>
                          <button className="ghost sm" aria-label={`Rows of person ${p.person}`}
                            onClick={() => setShowing(personRows(p))}>Rows</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {(report?.gone ?? 0) > 0 && (
            <p style={{ marginTop: 12 }}>
              <button className="ghost sm" onClick={() => setShowing({ title: 'no longer found', filter: { gone: true } })}>
                {report!.gone} place(s) earlier runs found are no longer there
              </button>
            </p>
          )}

          {logs && <LogsPart logs={logs} onShow={setShowing} />}

          {showing && (
            <div className="panel" style={{ marginTop: 14 }} data-testid="aadhaar-places">
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <h3 style={{ margin: 0 }}>Rows: {showing.title}</h3>
                <button className="ghost sm" onClick={() => setShowing(null)}>Close</button>
              </div>
              {showing.filter && <Places branch={branch} runId={r.id} filter={showing.filter} />}
              {showing.logFilter && <LogPlaces branch={branch} runId={logs?.run.id ?? 0} filter={showing.logFilter} />}
            </div>
          )}

          {(r.skipped?.length ?? 0) > 0 && (
            <div className="panel" style={{ marginTop: 14 }}>
              <h3 style={{ marginTop: 0 }}>Not read</h3>
              <ul style={{ margin: 0 }}>
                {r.skipped!.map(k => <li key={k.object}><code>{k.object}</code>: {k.reason}</li>)}
              </ul>
            </div>
          )}

          <div className="panel" style={{ marginTop: 14 }}>
            <h3 style={{ marginTop: 0 }}>What this cannot claim</h3>
            <ul style={{ margin: 0 }}>
              {(r.limits ?? []).map(l => <li key={l}>{l}</li>)}
            </ul>
          </div>
        </>
      )}
    </div>
  )
}

// The logs part: what the logs held, by log, and their people when they were
// read with an earlier run of the tables.
function LogsPart({ logs, onShow }: { logs: AadhaarLogs; onShow: (s: Showing) => void }) {
  const lr = logs.run
  const read = lr.read ?? {}
  const sources = logs.sources ?? []
  return (
    <div className="panel" style={{ marginTop: 14 }}>
      <h3 style={{ marginTop: 0 }}>In the logs (admins only)</h3>
      <p className="muted" style={{ marginTop: -4 }} data-testid="aadhaar-logs-summary">
        Read with run {lr.branchRun}, {new Date(lr.finished).toLocaleString()}{lr.actor ? ` by ${lr.actor}` : ''}:
        {' '}{read.history ?? 0} query history entries, {read.audit ?? 0} audit statement texts, {read.blackbox ?? 0} Blackbox entries.
        {' '}{lr.numbers} number(s) found, {lr.people} distinct, {lr.linked} also in the tables; {lr.listed} place(s) kept.
      </p>
      {(lr.skipped?.length ?? 0) > 0 && (
        <ul>{lr.skipped!.map(k => <li key={k.source}>Not read: {aadhaarLogName[k.source] ?? k.source}: {k.reason}</li>)}</ul>
      )}
      {sources.length === 0 ? (
        <p className="muted">No Aadhaar number was found in the logs read.</p>
      ) : (
        <div className="table-wrap">
          <table aria-label="Aadhaar in the logs">
            <thead>
              <tr><th>Log</th><th className="num">Entries</th><th className="num">Places</th><th>Since</th><th><span className="sr-only">Entries</span></th></tr>
            </thead>
            <tbody>
              {sources.map(c => (
                <tr key={c.source}>
                  <td>{aadhaarLogName[c.source] ?? c.source}</td>
                  <td className="num">{c.entries}</td>
                  <td className="num">{c.places}</td>
                  <td>{day(c.since)}</td>
                  <td>
                    <button className="ghost sm" aria-label={`Entries of ${aadhaarLogName[c.source] ?? c.source}`}
                      onClick={() => onShow({ title: aadhaarLogName[c.source] ?? c.source, logFilter: { source: c.source } })}>Entries</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {!logs.linked && (logs.people?.length ?? 0) > 0 && (
        <>
          <p className="muted" style={{ fontSize: 13 }}>
            Read with run {lr.branchRun}, before the latest, so these people are numbered apart from the tables' above.
          </p>
          <div className="table-wrap">
            <table aria-label="Aadhaar by person in the logs">
              <thead><tr><th className="num">Person</th><th>Number</th><th className="num">Places</th><th>Since</th><th>Where</th></tr></thead>
              <tbody>
                {logs.people!.map(p => (
                  <tr key={p.person}>
                    <td className="num">{p.person}</td><td><code>{p.masked}</code></td><td className="num">{p.places}</td>
                    <td>{day(p.since)}</td><td>{(p.where ?? []).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {logs.gone > 0 && (
        <p>
          <button className="ghost sm" onClick={() => onShow({ title: 'no longer in the logs', logFilter: { gone: true } })}>
            {logs.gone} log place(s) earlier runs found are no longer there
          </button>
        </p>
      )}
      <h4>What the logs part cannot claim</h4>
      <ul style={{ margin: 0 }}>{(lr.limits ?? []).map(l => <li key={l}>{l}</li>)}</ul>
    </div>
  )
}

// The log entries behind a log, a person, or what is gone.
function LogPlaces({ branch, runId, filter }: { branch: string; runId: number; filter: AadhaarLogFilter }) {
  const [places, setPlaces] = useState<AadhaarLogPlace[] | null>(null)
  const [err, setErr] = useState('')
  const key = JSON.stringify(filter)

  useEffect(() => {
    let live = true
    setPlaces(null); setErr('')
    getAadhaarLogPlaces(branch, JSON.parse(key) as AadhaarLogFilter)
      .then(r => { if (live) setPlaces(r.places ?? []) })
      .catch(e => { if (live) setErr((e as Error).message) })
    return () => { live = false }
  }, [branch, runId, key])

  const gone = !!filter.gone
  if (err) return <div className="err">{err}</div>
  if (!places) return <p className="muted">Loading…</p>
  if (places.length === 0) return <p className="muted">No log entries.</p>
  return (
    <div className="table-wrap" style={{ marginTop: 8 }}>
      <table aria-label="Aadhaar log entries">
        <thead>
          <tr>
            {!gone && <th className="num">Person</th>}<th>Number</th><th>Log</th><th>Entry</th><th>By</th><th>At</th>{gone && <th>Last seen</th>}
          </tr>
        </thead>
        <tbody>
          {places.map(p => (
            <tr key={p.id}>
              {!gone && <td className="num">{p.person || '–'}</td>}
              <td><code>{p.masked}</code></td>
              <td>{aadhaarLogName[p.source] ?? p.source}</td>
              <td><code>{p.entry}{p.field ? ` (${p.field})` : ''}</code></td>
              <td>{p.actor || '–'}</td>
              <td>{new Date(p.at).toLocaleString()}</td>
              {gone && <td>{day(p.lastSeen)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// The rows behind a column, a person, or what is gone.
function Places({ branch, runId, filter }: {
  branch: string
  runId: number
  filter: AadhaarPlaceFilter
}) {
  const [places, setPlaces] = useState<AadhaarPlace[] | null>(null)
  const [err, setErr] = useState('')
  const key = JSON.stringify(filter)

  useEffect(() => {
    let live = true
    setPlaces(null); setErr('')
    getAadhaarPlaces(branch, JSON.parse(key) as AadhaarPlaceFilter)
      .then(r => { if (live) setPlaces(r.places ?? []) })
      .catch(e => { if (live) setErr((e as Error).message) })
    return () => { live = false }
  }, [branch, runId, key])

  const gone = !!filter.gone
  return (
    <>
      {err ? <div className="err">{err}</div> : !places ? <p className="muted">Loading…</p> : places.length === 0 ? (
        <p className="muted">Nothing here.</p>
      ) : (
        <div className="table-wrap" style={{ marginTop: 8 }}>
          <table aria-label="Aadhaar places">
            <thead>
              <tr>
                {!gone && <th className="num">Person</th>}<th>Number</th><th>Where</th><th>Row</th><th>Since</th>{gone && <th>Last seen</th>}
              </tr>
            </thead>
            <tbody>
              {places.map(p => (
                <tr key={p.id}>
                  {!gone && <td className="num">{p.person || '–'}</td>}
                  <td><code>{p.masked}</code></td>
                  <td><code>{where(p)}</code></td>
                  <td><code>{p.row}</code></td>
                  <td>{day(p.since)}{p.rowCreated && <div className="muted" style={{ fontSize: 12 }}>row created</div>}</td>
                  {gone && <td>{day(p.lastSeen)}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
