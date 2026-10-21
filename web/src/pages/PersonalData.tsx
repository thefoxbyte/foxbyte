// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react'
import { getPersonalData, scanPersonalData, type Branch, type PersonalData as Report, type PIIFinding } from '../api'
import { useFeatures, why } from '../features'
import { useBranches } from '../useBranches'

// Personal-data discovery (point 4.1): where a branch holds personal data,
// found from column names and sampled values. The engine keeps where it found
// it, never a value, so nothing on this page can show one.
//
// Reading the findings is free; scanning is Enterprise. The page stays and says
// which half is which rather than disappearing.

export const CATEGORY: Record<string, string> = {
  aadhaar: 'Aadhaar',
  pan: 'PAN',
  gstin: 'GSTIN',
  mobile: 'Mobile number',
  card: 'Card number',
  email: 'Email',
  upi: 'UPI ID',
  ifsc: 'IFSC',
  passport: 'Passport',
  voter_id: 'Voter ID',
  vehicle_registration: 'Vehicle registration',
  date_of_birth: 'Date of birth',
  ip_address: 'IP address',
  child: "A child's data",
}

const FOUND_BY: Record<PIIFinding['rule'], string> = {
  'name+value': 'name and values',
  value: 'values',
  name: 'name only',
}

const when = (iso: string) => new Date(iso).toLocaleString()

export default function PersonalData() {
  const [branch, setBranch] = useState('main')
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [sample, setSample] = useState('1000')
  const [err, setErr] = useState('')
  const { branches } = useBranches()
  const { can, edition } = useFeatures()
  const licensed = can('personal-data')

  const load = useCallback(async () => {
    setLoading(true); setErr('')
    try { setReport(await getPersonalData(branch)) }
    catch (e) { setReport(null); setErr((e as Error).message) }
    finally { setLoading(false) }
  }, [branch])
  useEffect(() => { load() }, [load])

  const scan = async () => {
    const n = Number(sample)
    if (!Number.isInteger(n) || n < 1 || n > 100000) { setErr('The sample is 1 to 100,000 rows per table.'); return }
    setScanning(true); setErr('')
    try { setReport(await scanPersonalData(branch, n)) }
    catch (e) { setErr((e as Error).message) }
    finally { setScanning(false) }
  }

  const options = branches.length ? branches : ([{ name: 'main' }] as Branch[])
  const s = report?.scan ?? null
  const findings = report?.findings ?? []

  return (
    <div className="fade-up">
      <h1>Personal data</h1>
      <p className="lead" style={{ marginTop: -2 }}>
        Where a branch holds personal data: Aadhaar, PAN, mobile numbers, cards, emails and more, found from column
        names and from a sample of each table's values. FoxByte keeps where it found them, never the values.
      </p>

      {edition && !licensed && (
        <p className="muted" style={{ marginTop: -6, fontSize: 13 }}>
          {why(edition, 'Scanning for personal data')} Findings from earlier scans can still be read.
        </p>
      )}

      <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
        <label className="muted" style={{ fontSize: 13 }} htmlFor="pii-branch">Branch</label>
        <select id="pii-branch" value={branch} onChange={e => setBranch(e.target.value)}>
          {options.map(b => <option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
        <label className="muted" style={{ fontSize: 13 }} htmlFor="pii-sample">Rows per table</label>
        <input id="pii-sample" type="number" min={1} max={100000} value={sample} style={{ width: 110 }}
          onChange={e => setSample(e.target.value)} />
        <button className="primary" onClick={scan} disabled={scanning || !licensed}
          title={licensed ? undefined : why(edition, 'Scanning for personal data')}>
          {scanning ? 'Scanning…' : licensed ? 'Scan now' : 'Scan now (Enterprise)'}
        </button>
      </div>

      {err && <div className="err" style={{ marginTop: 12 }}>{err}</div>}

      {loading && !report ? <p className="muted">Loading…</p> : !s ? (
        !err && (
          <div className="panel" style={{ marginTop: 16, padding: 22, textAlign: 'center' }}>
            <p className="muted" style={{ margin: 0 }}>
              <code>{branch}</code> has not been scanned.{licensed ? ' Scan it to see where it holds personal data.' : ''}
            </p>
          </div>
        )
      ) : (
        <>
          <p className="muted" style={{ marginTop: 16 }} data-testid="pii-summary">
            Scanned {when(s.finished)}{s.actor ? ` by ${s.actor}` : ''}: {s.tables} table(s), {s.columns} column(s) read,
            up to {s.sample} rows each{(s.skipped?.length ?? 0) > 0 ? `; ${s.skipped!.length} not read` : ''}.
          </p>

          {findings.length === 0 ? (
            <div className="panel" style={{ padding: 22, textAlign: 'center' }}>
              <p className="muted" style={{ margin: 0 }}>Nothing recognised as personal data. The limits below still apply.</p>
            </div>
          ) : (
            <div className="table-wrap">
              <table aria-label="Personal data found">
                <thead>
                  <tr><th>Where</th><th>What</th><th>Confidence</th><th className="num">Matched</th><th>Found by</th><th>State</th></tr>
                </thead>
                <tbody>
                  {findings.map(f => (
                    <tr key={f.id}>
                      <td>
                        <code>{f.schema}.{f.table}.{f.column}</code>{f.path && <>{' '}<code>{f.path}</code></>}
                        <div className="muted" style={{ fontSize: 12 }}>{f.why}</div>
                      </td>
                      <td>{CATEGORY[f.category] ?? f.category}</td>
                      <td><span className={'badge' + (f.confidence === 'high' ? ' primary' : '')}>{f.confidence}</span></td>
                      <td className="num">{f.sampled > 0 ? `${f.matched}/${f.sampled}` : '–'}</td>
                      <td>{FOUND_BY[f.rule] ?? f.rule}</td>
                      <td>
                        {f.state}
                        {f.lastScan !== s.id && <div className="muted" style={{ fontSize: 12 }}>not seen in the latest scan</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {(s.skipped?.length ?? 0) > 0 && (
            <div className="panel" style={{ marginTop: 14 }}>
              <h3 style={{ marginTop: 0 }}>Not read</h3>
              <ul style={{ margin: 0 }}>
                {s.skipped!.map(k => <li key={k.object}><code>{k.object}</code>: {k.reason}</li>)}
              </ul>
            </div>
          )}

          <div className="panel" style={{ marginTop: 14 }}>
            <h3 style={{ marginTop: 0 }}>What this cannot claim</h3>
            <ul style={{ margin: 0 }}>
              {(s.limits ?? []).map(l => <li key={l}>{l}</li>)}
            </ul>
          </div>
        </>
      )}
    </div>
  )
}
