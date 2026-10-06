import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { listPipelines, deletePipeline, type Pipeline } from '../api'
import { useFeatures, why } from '../features'

export default function Pipelines() {
  const [pipelines, setPipelines] = useState<Pipeline[]>([])
  const [err, setErr] = useState('')
  const nav = useNavigate()
  // Pipelines are gated whole, listing included: unlike the record or a policy
  // rule, there is nothing here that was not created by the paid feature
  // itself, so there is nothing a Standard install could be shown.
  const { can, edition } = useFeatures()
  const licensed = can('pipelines')

  const load = () => listPipelines().then(r => setPipelines(r.pipelines || [])).catch(e => setErr((e as Error).message))
  useEffect(() => { if (licensed) load() }, [licensed])

  const del = async (id: string) => { try { await deletePipeline(id); load() } catch (e) { setErr((e as Error).message) } }

  return (
    <div className="fade-up" style={{ maxWidth: 900 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ marginBottom: 4 }}>ETL Pipelines</h1>
          <p className="lead" style={{ marginTop: 0 }}>
            Extract from a source, transform it with SQL models, test it, and load the result — into a branch.
          </p>
        </div>
        <button className="primary" onClick={() => nav('/pipelines/new')} disabled={!licensed}
          title={licensed ? undefined : why(edition, 'ETL pipelines')}>
          {licensed ? 'New pipeline' : 'New pipeline (Enterprise)'}
        </button>
      </div>

      {/* The page stays in the sidebar and says what it is. A feature nobody can
          see sells nothing, and a nav entry that leads to an error reads as a
          broken install rather than one that has not bought this. */}
      {edition && !licensed && (
        <div className="panel" style={{ marginTop: 16 }}>
          <p style={{ margin: 0 }}>{why(edition, 'ETL pipelines')}</p>
          <p className="muted" style={{ marginBottom: 0 }}>
            <code>fox import</code> is unaffected: migrating data in is onboarding, not ETL.
          </p>
        </div>
      )}

      {err && <div className="err">{err}</div>}

      {pipelines.length === 0 ? (
        <div className="panel" style={{ padding: 26, textAlign: 'center' }}>
          <p className="muted" style={{ margin: 0 }}>
            No pipelines yet. Create one to run a real ETL — e.g. extract a MongoDB collection, flatten its
            documents into columns with SQL, aggregate, and assert data quality.
          </p>
        </div>
      ) : (
        <div className="panel" style={{ padding: 0, marginTop: 14 }}>
          {pipelines.map((p, i) => (
            <div key={p.id} className="row"
              style={{ justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderTop: i ? '1px solid var(--border)' : 'none' }}>
              <Link to={`/pipelines/${p.id}`} style={{ fontWeight: 600 }}>{p.name}</Link>
              <div className="row" style={{ gap: 12, alignItems: 'center' }}>
                <span className="muted" style={{ fontSize: 12 }}>updated {new Date(p.updated * 1000).toLocaleDateString()}</span>
                <button className="ghost" onClick={() => del(p.id)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
