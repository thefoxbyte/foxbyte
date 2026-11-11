// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import {
  getAadhaar, getAadhaarPlaces, runAadhaar,
  type AadhaarColumn, type AadhaarPlace, type AadhaarPlaceFilter, type AadhaarReport, type Branch,
} from '../api'
import { useFeatures, why } from '../features'
import { useBranches } from '../useBranches'

// The Aadhaar exposure report (point 4.5): which person's Aadhaar is exposed
// in a branch, where, and since when. A run reads every row; the engine keeps
// each place as its row's key and the number's last four digits, so nothing
// here can show a whole number. Reading the report is free; a run is
// Enterprise.

const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString() : '–')
const where = (c: { schema: string; table: string; column: string; path: string }) =>
  `${c.schema}.${c.table}.${c.column}${c.path ? ' ' + c.path : ''}`

export default function AadhaarExposure() {
  const [branch, setBranch] = useState('main')
  const [report, setReport] = useState<AadhaarReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [timeout, setTimeout_] = useState('300')
  const [err, setErr] = useState('')
  const [showing, setShowing] = useState<{ title: string; filter: AadhaarPlaceFilter } | null>(null)
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

  const run = async () => {
    const n = Number(timeout)
    if (!Number.isInteger(n) || n < 1 || n > 3600) { setErr("A table's read may take 1 to 3,600 seconds."); return }
    setRunning(true); setErr(''); setShowing(null)
    try { setReport(await runAadhaar(branch, n)) }
    catch (e) { setErr((e as Error).message) }
    finally { setRunning(false) }
  }

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const r = report?.run ?? null
  const cols = report?.columns ?? []
  const people = report?.people ?? []

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
                            onClick={() => setShowing({ title: `person ${p.person} (${p.masked})`, filter: { person: p.person } })}>Rows</button>
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

          {showing && <Places branch={branch} runId={r.id} title={showing.title} filter={showing.filter} onClose={() => setShowing(null)} />}

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

// The rows behind a column, a person, or what is gone.
function Places({ branch, runId, title, filter, onClose }: {
  branch: string
  runId: number
  title: string
  filter: AadhaarPlaceFilter
  onClose: () => void
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
    <div className="panel" style={{ marginTop: 14 }} data-testid="aadhaar-places">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Rows: {title}</h3>
        <button className="ghost sm" onClick={onClose}>Close</button>
      </div>
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
    </div>
  )
}
