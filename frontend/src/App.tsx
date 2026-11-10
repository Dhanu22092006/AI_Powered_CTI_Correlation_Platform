import { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import CytoscapeComponent from './Graph'
import { Shield, LayoutDashboard, Network, Bell, Database, FileUp, LogOut, RefreshCw, Download, Search, AlertTriangle, CheckCircle2, Activity, Users } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'
type User = { email: string; role: string }
type Alert = { dedupe_key: string; title: string; description: string; status: string; risk: { score: number; severity: string; factors: Record<string, number> }; indicators: { type: string; value: string }[]; evidence: { name: string; title: string; demo: boolean }[]; explanation: string; demo: boolean }
type Indicator = { type: string; value: string; source_names?: string[]; demo?: boolean; created_at?: string }
const client = axios.create({ baseURL: API })
function App() {
  const [token, setToken] = useState(localStorage.getItem('cti_token') || '')
  const [user, setUser] = useState<User | null>(null)
  const [email, setEmail] = useState('admin@example.com'), [password, setPassword] = useState('ChangeThisAdminPassword123!')
  const [page, setPage] = useState('Dashboard')
  const [dashboard, setDashboard] = useState<any>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [indicators, setIndicators] = useState<Indicator[]>([])
  const [graph, setGraph] = useState<any>({ nodes: [], edges: [] })
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState('')
  const [search, setSearch] = useState(''), [selected, setSelected] = useState<Alert | null>(null)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  useEffect(() => { if (token) { client.defaults.headers.common.Authorization = `Bearer ${token}`; loadAll() } }, [token])
  async function login(e: React.FormEvent) { e.preventDefault(); setError(''); try { const body = new URLSearchParams(); body.set('username', email); body.set('password', password); const r = await client.post('/api/auth/login', body, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }); localStorage.setItem('cti_token', r.data.access_token); setToken(r.data.access_token); setUser(r.data.user) } catch { setError('Login failed. Check your credentials and API availability.') } }
  function logout() { localStorage.removeItem('cti_token'); delete client.defaults.headers.common.Authorization; setToken(''); setUser(null) }
  async function loadAll() { setBusy(true); setError(''); try { const [me, d, a, i, g] = await Promise.all([client.get('/api/auth/me'), client.get('/api/dashboard'), client.get('/api/alerts'), client.get('/api/indicators'), client.get('/api/graph')]); setUser(me.data); setDashboard(d.data); setAlerts(a.data.items); setIndicators(i.data.items); setGraph(g.data) } catch (e: any) { setError(e?.response?.data?.detail || 'Could not load platform data. Check backend and database services.') } finally { setBusy(false) } }
  async function action(label: string, fn: () => Promise<any>) { setBusy(true); setMessage(''); setError(''); try { const r = await fn(); setMessage(r?.data?.message || r?.data?.label || `${label} completed`); await loadAll() } catch (e: any) { setError(e?.response?.data?.detail || `${label} failed`) } finally { setBusy(false) } }
  async function loadDemo() { await action('Demo data', () => client.post('/api/demo/load')) }
  async function syncNvd() { await action('NVD sync', () => client.post('/api/sources/nvd/sync')) }
  async function syncOtx() { await action('OTX sync', () => client.post('/api/sources/otx/sync')) }
  async function upload() { if (!uploadFile) return; const f = new FormData(); f.append('file', uploadFile); await action('Upload', () => client.post('/api/ingest/upload', f)); setUploadFile(null) }
  async function updateAlert(a: Alert, status: string) { await action('Alert update', () => client.patch(`/api/alerts/${a.dedupe_key}`, { status, note: '' })); setSelected(null) }
  const filteredIndicators = useMemo(() => indicators.filter(x => (x.value + ' ' + x.type + ' ' + (x.source_names || []).join(' ')).toLowerCase().includes(search.toLowerCase())), [indicators, search])
  const filteredAlerts = useMemo(() => alerts.filter(x => (x.title + ' ' + x.description + ' ' + x.risk.severity).toLowerCase().includes(search.toLowerCase())), [alerts, search])
  if (!token) return <div className="login-shell"><form className="login-card" onSubmit={login}><div className="brand-mark"><Shield size={26} /></div><p className="eyebrow">SECURITY OPERATIONS PLATFORM</p><h1>CTI Correlation</h1><p className="muted">Collect, normalize, correlate and investigate threat intelligence.</p><label>Email</label><input value={email} onChange={e => setEmail(e.target.value)} type="email" required /><label>Password</label><input value={password} onChange={e => setPassword(e.target.value)} type="password" required /><button className="primary full" disabled={busy}>Sign in</button>{error && <p className="error">{error}</p>}<p className="tiny">Initial demo credentials are configured in your .env file.</p></form></div>
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark"><Shield /></div><div><b>CTI CORRELATION</b><small>THREAT INTELLIGENCE</small></div></div><div className="nav-label">WORKSPACE</div>{[{ n: 'Dashboard', i: LayoutDashboard }, { n: 'Indicators', i: Database }, { n: 'Alerts', i: Bell }, { n: 'Threat Graph', i: Network }, { n: 'Ingestion', i: FileUp }].map(x => <button key={x.n} className={`nav-item ${page === x.n ? 'active' : ''}`} onClick={() => { setPage(x.n); setSelected(null) }}><x.i size={17} />{x.n}</button>)}<div className="sidebar-bottom"><div className="userbox"><div className="avatar">{(user?.email || 'A')[0].toUpperCase()}</div><div><b>{user?.email || 'Analyst'}</b><small>{user?.role || 'analyst'}</small></div></div><button className="nav-item" onClick={logout}><LogOut size={17} />Sign out</button></div></aside>
    <main className="main"><header className="topbar"><div><span className="eyebrow">THREAT INTELLIGENCE /</span><b>{page}</b></div><div className="top-actions"><span className="live"><i /> SYSTEM CONNECTED</span><button className="icon-btn" onClick={loadAll} title="Refresh"><RefreshCw size={17} /></button></div></header>
      <div className="content">{message && <div className="notice success"><CheckCircle2 size={17} />{message}</div>}{error && <div className="notice danger"><AlertTriangle size={17} />{error}</div>}
        {page === 'Dashboard' && <><div className="page-heading"><div><p className="eyebrow">OVERVIEW</p><h1>Security overview</h1><p className="muted">A unified view of collected and correlated threat intelligence.</p></div><button className="primary" onClick={loadDemo} disabled={busy}>Load demo data</button></div><div className="metric-grid">{[['Indicators', dashboard?.indicators ?? '—', Database], ['CVE records', dashboard?.cves ?? '—', Shield], ['Total alerts', dashboard?.alerts ?? '—', Bell], ['Critical open', dashboard?.critical_alerts ?? '—', AlertTriangle]].map(([n, v, I]: any) => <div className="metric card"><div className="metric-top"><span>{n}</span><I size={18} /></div><strong>{v}</strong><small>Live database count</small></div>)}</div><div className="two-col"><section className="card"><div className="section-head"><div><h2>Recent alerts</h2><p className="muted">Latest explainable correlation results</p></div><button className="text-btn" onClick={() => setPage('Alerts')}>View all →</button></div>{(dashboard?.recent_alerts || []).length === 0 ? <Empty text="No alerts yet. Load demo data or ingest a report." /> : (dashboard.recent_alerts || []).map((a: Alert) => <div className="alert-row" key={a.dedupe_key} onClick={() => { setSelected(a); setPage('Alerts') }}><span className={`severity ${a.risk?.severity}`}>{a.risk?.severity}</span><div className="grow"><b>{a.title}</b><small>{a.indicators?.length || 0} indicators · {a.status}</small></div><span className="score">{a.risk?.score}/100</span></div>)}</section><section className="card"><div className="section-head"><div><h2>Quick actions</h2><p className="muted">Run a workflow</p></div><Activity size={18} /></div><button className="action-card" onClick={syncNvd}><Shield /><span><b>Sync NVD CVEs</b><small>Retrieve recent vulnerability records</small></span></button><button className="action-card" onClick={syncOtx}><Database /><span><b>Sync OTX</b><small>Requires OTX_API_KEY in .env</small></span></button><button className="action-card" onClick={() => setPage('Ingestion')}><FileUp /><span><b>Upload intelligence</b><small>Import a CSV or JSON report</small></span></button></section></div></>}
       {page === 'Indicators' && (
  <>
    <div className="page-heading">
      <div>
        <p className="eyebrow">INTELLIGENCE</p>
        <h1>Indicators of Compromise</h1>
        <p className="muted">
          Extracted indicators and their provenance.
        </p>
      </div>

      <a
        className="secondary"
        href={`${API}/api/reports/indicators.csv`}
        onClick={(e) => {
          e.preventDefault();
          client
            .get('/api/reports/indicators.csv', {
              responseType: 'blob'
            })
            .then((r) => {
              const u = URL.createObjectURL(r.data);
              const a = document.createElement('a');
              a.href = u;
              a.download = 'indicators.csv';
              a.click();
              URL.revokeObjectURL(u);
            });
        }}
      >
        <Download size={16} />
        Export CSV
      </a>
    </div>

    <div className="card">
      <div className="searchbar">
        <Search size={17} />
        <input
          placeholder="Search indicator, type or source..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>TYPE</th>
              <th>INDICATOR</th>
              <th>SOURCE</th>
              <th>DATASET</th>
            </tr>
          </thead>

          <tbody>
            {filteredIndicators.map((x, i) => (
              <tr key={i}>
                <td>
                  <span className="type-pill">{x.type}</span>
                </td>
                <td className="mono">{x.value}</td>
                <td>{(x.source_names || []).join(', ') || '—'}</td>
                <td>
                  {x.demo ? (
                    <span className="demo-tag">DEMO</span>
                  ) : (
                    'LIVE / IMPORTED'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredIndicators.length === 0 && (
          <Empty text="No indicators match your search." />
        )}
      </div>
    </div>
  </>
)}
        {page === 'Alerts' && <><div className="page-heading"><div><p className="eyebrow">INVESTIGATION</p><h1>Alerts</h1><p className="muted">Prioritized alerts with supporting evidence.</p></div></div>{selected ? <section className="card detail-card"><button className="text-btn" onClick={() => setSelected(null)}>← Back to alerts</button><div className="detail-title"><div><span className={`severity ${selected.risk.severity}`}>{selected.risk.severity}</span><h2>{selected.title}</h2></div><strong className="big-score">{selected.risk.score}<small>/100</small></strong></div><p>{selected.description}</p><div className="callout"><b>Why this alert was generated</b><p>{selected.explanation}</p></div><h3>Evidence chain</h3>{selected.evidence?.map((e, i) => <div className="evidence" key={i}><CheckCircle2 size={17} /><span><b>{e.name}</b> · {e.title} {e.demo && <em>SIMULATED DEMO</em>}</span></div>)}<h3>Related indicators</h3><div className="chips">{selected.indicators?.map((x, i) => <span className="chip" key={i}>{x.type}: {x.value}</span>)}</div><h3>Risk score factors</h3><div className="factor-list">{Object.entries(selected.risk.factors || {}).map(([k, v]) => <div><span>{k.replaceAll('_', ' ')}</span><b>{v} points</b></div>)}</div><div className="button-row"><button className="secondary" onClick={() => updateAlert(selected, 'investigating')}>Mark investigating</button><button className="primary" onClick={() => updateAlert(selected, 'resolved')}>Resolve alert</button><button className="secondary" onClick={() => updateAlert(selected, 'false_positive')}>False positive</button></div></section> : <section className="card"><div className="searchbar"><Search size={17} /><input placeholder="Search alerts..." value={search} onChange={e => setSearch(e.target.value)} /></div>{filteredAlerts.map(a => <div className="alert-row clickable" key={a.dedupe_key} onClick={() => setSelected(a)}><span className={`severity ${a.risk.severity}`}>{a.risk.severity}</span><div className="grow"><b>{a.title}</b><small>{a.indicators?.length || 0} indicators · {a.status} {a.demo && '· DEMO'}</small></div><span className="score">{a.risk.score}/100</span></div>)}{filteredAlerts.length === 0 && <Empty text="No alerts found. Ingest a record containing two or more indicators." />}</section>}</>}
        {page === 'Threat Graph' && <><div className="page-heading"><div><p className="eyebrow">RELATIONSHIP ANALYSIS</p><h1>Threat correlation graph</h1><p className="muted">Connections are inferred from shared source records and require analyst validation.</p></div><button className="secondary" onClick={loadAll}><RefreshCw size={16} /> Refresh graph</button></div><section className="card graph-card"><CytoscapeComponent graph={graph} /><div className="legend"><span>● IOC entity</span><span>→ Co-mentioned in source (inferred)</span></div></section></>}
        {page === 'Ingestion' && <><div className="page-heading"><div><p className="eyebrow">DATA COLLECTION</p><h1>Ingestion center</h1><p className="muted">Bring threat intelligence into the platform.</p></div></div><div className="two-col"><section className="card"><h2>Import CSV / JSON</h2><p className="muted">Upload a file containing a text, description, indicator or value column.</p><div className="upload-box"><FileUp size={30} /><input type="file" accept=".csv,.json,application/json,text/csv" onChange={e => setUploadFile(e.target.files?.[0] || null)} />{uploadFile && <b>{uploadFile.name}</b>}<button className="primary" disabled={!uploadFile || busy} onClick={upload}>Upload and process</button></div></section><section className="card"><h2>Connect intelligence sources</h2><div className="source-item"><div><b>National Vulnerability Database</b><small>Public CVE API · optional API key</small></div><button className="secondary" onClick={syncNvd}>Sync NVD</button></div><div className="source-item"><div><b>AlienVault OTX</b><small>Requires OTX_API_KEY</small></div><button className="secondary" onClick={syncOtx}>Sync OTX</button></div><div className="source-item"><div><b>Demo intelligence</b><small>Clearly labelled simulated records</small></div><button className="primary" onClick={loadDemo}>Load demo</button></div></section></div></>}
      </div></main></div>
}
function Empty({ text }: { text: string }) { return <div className="empty"><Database size={25} /><p>{text}</p></div> }
export default App
