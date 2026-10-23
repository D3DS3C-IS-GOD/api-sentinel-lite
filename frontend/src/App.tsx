import { useEffect, useState, useCallback } from 'react'
import { Shield, LayoutDashboard, ScanSearch, Bug, FileText, Settings, PanelLeft, AlertTriangle, Loader2 } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

type Finding = { id: string; scan_id: string; title: string; severity: string; confidence: string; endpoint: string; evidence: string; impact: string; remediation: string; verification: string; target: string }
type Scan = { id: string; target: string; started: string; status: string; error: string; findings: number }
const SEV: Record<string, string> = { critical: '#FF2DAA', high: '#FF2DAA', medium: '#F5A524', low: '#168BFF', info: '#9299AA' }
const ST: Record<string, string> = { pass: '#2DD4A0', fail: '#FF2DAA', warning: '#F5A524', not_tested: '#9299AA' }
const api = async (u: string, o?: RequestInit) => { const r = await fetch(u, o); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || 'Request failed'); return j }
const Card = ({ children, className = '' }: any) => <div className={`rounded-lg border border-line bg-panel p-4 ${className}`}>{children}</div>
const Empty = ({ t }: { t: string }) => <p className="text-sm text-slate-500 py-8 text-center">{t}</p>
const Badge = ({ s }: { s: string }) => <span className="rounded px-2 py-0.5 text-xs font-medium uppercase" style={{ background: SEV[s] + '22', color: SEV[s] }}>{s}</span>

export default function App() {
  const [page, setPage] = useState('dashboard'), [open, setOpen] = useState(true)
  const [scans, setScans] = useState<Scan[]>([]), [fs, setFs] = useState<Finding[]>([]), [loading, setLoading] = useState(true), [err, setErr] = useState('')
  const load = useCallback(async () => { try { setScans(await api('/api/scans')); setFs(await api('/api/findings')); setErr('') } catch { setErr('Backend unreachable on :8000') } setLoading(false) }, [])
  useEffect(() => { load() }, [load])
  const nav = [['dashboard', 'Dashboard', LayoutDashboard], ['new', 'New Assessment', ScanSearch], ['findings', 'Findings', Bug], ['reports', 'Reports', FileText], ['settings', 'Settings', Settings]] as const
  return <div className="flex min-h-screen">
    <aside className={`${open ? 'w-56' : 'w-14'} shrink-0 border-r border-line bg-panel transition-all`}>
      <div className="flex items-center gap-2 p-4 text-slate-100"><Shield size={20} className="text-pink shrink-0" />{open && <b className="text-sm">API Sentinel Lite</b>}</div>
      {nav.map(([k, l, I]) => <button key={k} onClick={() => setPage(k)} className={`flex w-full items-center gap-3 px-4 py-2.5 text-sm ${page === k ? 'bg-white/5 text-white' : 'text-slate-400 hover:text-white'}`}><I size={16} className="shrink-0" />{open && l}</button>)}
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-4 py-2.5 text-xs text-slate-500"><PanelLeft size={16} />{open && 'Collapse'}</button>
    </aside>
    <main className="flex-1 min-w-0 p-4 md:p-8 space-y-4">
      {err && <Card className="border-pink/40 text-pink text-sm">{err}</Card>}
      {loading ? <Loader2 className="animate-spin text-slate-500" /> : page === 'dashboard' ? <Dash scans={scans} fs={fs} /> : page === 'new' ? <NewScan done={() => { load(); setPage('findings') }} /> : page === 'findings' ? <Findings fs={fs} /> : page === 'reports' ? <Reports scans={scans} /> : <Sett />}
    </main></div>
}
function Dash({ scans, fs }: { scans: Scan[]; fs: Finding[] }) {
  const data = ['high', 'medium', 'low', 'info'].map(s => ({ s, n: fs.filter(f => f.severity === s).length }))
  return <><h1 className="text-xl font-semibold">Dashboard</h1>
    <div className="grid gap-4 sm:grid-cols-4">{[['Scans', scans.length], ['Findings', fs.length], ['High severity', fs.filter(f => f.severity === 'high').length], ['Latest scan', scans[0]?.started.slice(0, 10) ?? '—']].map(([l, v]) => <Card key={l as string}><p className="text-xs text-slate-500">{l}</p><p className="font-mono text-2xl font-semibold">{v}</p></Card>)}</div>
    <div className="grid gap-4 lg:grid-cols-2">
      <Card><h2 className="mb-2 text-sm text-slate-400">Findings by severity</h2>{fs.length ? <ResponsiveContainer height={200}><BarChart data={data}><XAxis dataKey="s" stroke="#64748b" /><YAxis allowDecimals={false} stroke="#64748b" /><Tooltip contentStyle={{ background: '#0d1424', border: '1px solid #1c2740' }} /><Bar dataKey="n">{data.map(d => <Cell key={d.s} fill={SEV[d.s]} />)}</Bar></BarChart></ResponsiveContainer> : <Empty t="No findings yet. Run an assessment." />}</Card>
      <Card><h2 className="mb-2 text-sm text-slate-400">Recent scans</h2>{scans.length ? scans.slice(0, 6).map(s => <div key={s.id} className="flex justify-between border-b border-line py-2 text-sm"><span className="truncate">{s.target}</span><span className="text-slate-500">{s.status} · {s.findings}</span></div>) : <Empty t="No scans yet." />}</Card></div></>
}
function NewScan({ done }: { done: () => void }) {
  const [f, setF] = useState({ target: 'http://127.0.0.1:8001', base_path: '/api/public', error_path: '/api/items/abc', protected: '/api/admin/users', authorized: false })
  const [busy, setBusy] = useState(false), [msg, setMsg] = useState('')
  const go = async () => { setBusy(true); setMsg(''); try { const r = await api('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...f, protected: f.protected.split(',').map(s => s.trim()).filter(Boolean) }) }); if (r.status === 'failed') setMsg('Scan failed: ' + r.error); else done() } catch (e: any) { setMsg(e.message) } setBusy(false) }
  const inp = (k: 'target' | 'base_path' | 'error_path' | 'protected', l: string) => <label className="block text-xs text-slate-400">{l}<input value={f[k]} onChange={e => setF({ ...f, [k]: e.target.value })} className="mt-1 w-full rounded border border-line bg-bg px-3 py-2 text-sm text-slate-100" /></label>
  return <><h1 className="text-xl font-semibold">New Assessment</h1>
    <Card className="border-pink/40 flex gap-3 text-sm text-pink"><AlertTriangle size={18} className="shrink-0" /><p>Only test systems you own or are explicitly authorized to assess. Localhost targets only; read-only GET requests; no exploitation.</p></Card>
    <Card className="text-sm text-slate-400"><b className="text-slate-200">Checks:</b> security headers, CORS, HTTPS/HSTS (not assessed on plain-HTTP localhost), error disclosure, authentication on the protected paths you list. <b className="text-slate-200">Not covered:</b> injection, authorization logic, rate limiting, business logic, anything outside these five checks. Results are indicators that need human verification; this is not a penetration test.</Card>
    <Card className="max-w-xl space-y-3">{inp('target', 'Target URL (localhost only)')}{inp('base_path', 'Base path')}{inp('error_path', 'Error probe path')}{inp('protected', 'Protected endpoints (comma separated)')}
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.authorized} onChange={e => setF({ ...f, authorized: e.target.checked })} />I am authorized to test this target</label>
      {msg && <p className="text-sm text-pink">{msg}</p>}
      <button disabled={busy || !f.authorized} onClick={go} className="rounded bg-blue px-4 py-2 text-sm font-medium text-white shadow-[0_0_14px_#168BFF55] hover:brightness-110 disabled:opacity-40 disabled:shadow-none">{busy ? 'Scanning…' : 'Run assessment'}</button></Card></>
}
function Findings({ fs }: { fs: Finding[] }) {
  const [q, setQ] = useState(''), [sev, setSev] = useState('all'), [sel, setSel] = useState<Finding | null>(null)
  const list = fs.filter(f => (sev === 'all' || f.severity === sev) && (f.title + f.endpoint).toLowerCase().includes(q.toLowerCase()))
  return <><h1 className="text-xl font-semibold">Findings</h1>
    <div className="flex gap-2"><input placeholder="Search…" value={q} onChange={e => setQ(e.target.value)} className="rounded border border-line bg-panel px-3 py-2 text-sm" />
      <select value={sev} onChange={e => setSev(e.target.value)} className="rounded border border-line bg-panel px-3 text-sm">{['all', 'high', 'medium', 'low', 'info'].map(s => <option key={s}>{s}</option>)}</select></div>
    <div className="grid gap-4 lg:grid-cols-2"><Card>{list.length ? list.map(f => <button key={f.id} onClick={() => setSel(f)} className="flex w-full items-center justify-between gap-2 border-b border-line py-2 text-left text-sm hover:bg-white/5"><span>{f.title}<br /><span className="text-xs text-slate-500">{f.endpoint}</span></span><Badge s={f.severity} /></button>) : <Empty t="No matching findings." />}</Card>
      <Card>{sel ? <div className="space-y-2 text-sm"><Badge s={sel.severity} /><h2 className="text-lg font-semibold">{sel.title}</h2>{([['Endpoint', sel.endpoint], ['Confidence', sel.confidence], ['Type', (sel as any).kind ?? ''], ['Verification', sel.verification], ['Evidence', sel.evidence], ['Impact', sel.impact], ['Remediation', sel.remediation]] as const).map(([k, v]) => <p key={k}><b className="text-slate-400">{k}: </b><span className={k === 'Evidence' || k === 'Endpoint' ? 'font-mono text-blue break-all' : ''}>{v}</span></p>)}</div> : <Empty t="Select a finding to see details." />}</Card></div></>
}
function Reports({ scans }: { scans: Scan[] }) {
  const [open, setOpen] = useState<string>('')
  return <><h1 className="text-xl font-semibold">Reports</h1><Card>{scans.length ? scans.map((s: any) => <div key={s.id} className="border-b border-line py-2 text-sm">
    <div className="flex items-center justify-between gap-2"><button onClick={() => setOpen(open === s.id ? '' : s.id)} className="text-left"><span className="font-mono text-blue">{s.id}</span> {s.target} <span className="text-slate-500">{s.started.slice(0, 19)} · {s.status} · {s.findings} findings</span></button>
      <span className="flex gap-3 shrink-0"><a className="text-blue underline" href={`/api/scans/${s.id}/report.html`} target="_blank">HTML</a><a className="text-blue underline" href={`/api/scans/${s.id}/report.json?download=1`}>JSON</a></span></div>
    {s.error && <p className="text-pink">{s.error}</p>}
    {open === s.id && <div className="mt-2 space-y-1">{(s.checks || []).map((c: any) => <p key={c.id} className="text-xs"><b style={{ color: ST[c.status] }} className="font-mono uppercase">{c.status}</b> {c.name} <span className="text-slate-500">— {c.detail}</span></p>)}</div>}
  </div>) : <Empty t="No scans to export yet." />}</Card></>
}
function Sett() {
  const [s, setS] = useState<any>(null); useEffect(() => { api('/api/settings').then(setS).catch(() => { }) }, [])
  return <><h1 className="text-xl font-semibold">Settings</h1><Card>{s ? <pre className="text-xs text-slate-300 whitespace-pre-wrap">{JSON.stringify(s, null, 2)}</pre> : <Empty t="Loading…" />}</Card></>
}
