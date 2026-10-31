import { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import { DetailDrawer, EvidenceTimeline, FindingList, ScanForm } from './components.jsx'

const POLL_MS = 2500

export default function App() {
  const [scans, setScans] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [selected, setSelected] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [healthy, setHealthy] = useState(null)

  const refreshList = useCallback(async () => {
    try {
      const rows = await api.listScans()
      setScans(rows)
      if (!activeId && rows.length) setActiveId(rows[0].id)
    } catch (e) {
      setError(String(e.message || e))
    }
  }, [activeId])

  const refreshDetail = useCallback(async () => {
    if (!activeId) return
    try {
      const d = await api.getScan(activeId)
      setDetail(d)
      if (!selected && d.findings.length) setSelected(d.findings[0].id)
    } catch (e) {
      setError(String(e.message || e))
    }
  }, [activeId, selected])

  useEffect(() => {
    api.health().then((h) => setHealthy(h)).catch(() => setHealthy(null))
    refreshList()
  }, [])

  useEffect(() => {
    refreshDetail()
    if (!activeId) return
    const running = detail && !['done', 'failed'].includes(detail.status)
    if (!running && detail) return
    const t = setInterval(async () => {
      try {
        const d = await api.getScan(activeId)
        setDetail(d)
        if (['done', 'failed'].includes(d.status)) {
          clearInterval(t)
          refreshList()
        }
      } catch {
        clearInterval(t)
      }
    }, POLL_MS)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId])

  const submit = async (repo_url, branch) => {
    setBusy(true)
    setError('')
    try {
      const scan = await api.createScan(repo_url, branch)
      setActiveId(scan.id)
      setSelected(null)
      setDetail(scan)
      refreshList()
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const finding = detail?.findings.find((f) => f.id === selected)
  const fixed = detail?.findings.filter((f) => f.patches?.[0]?.verifications?.[0]?.status === 'fixed').length || 0

  return (
    <div className="min-h-screen bg-[#0b1116]">
      <header className="border-b border-slate-800 bg-[#0d141b]">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-emerald-700 flex items-center justify-center font-bold text-white text-sm">
            PP
          </div>
          <div className="flex-1">
            <h1 className="text-base font-semibold text-white leading-tight">PatchProof AI</h1>
            <p className="text-xs text-slate-400">Autonomous security engineer — detect, reproduce, patch, verify</p>
          </div>
          <span className={`text-xs font-mono px-2 py-1 rounded border ${healthy ? 'text-emerald-200 border-emerald-800 bg-emerald-950' : 'text-slate-400 border-slate-700'}`}>
            {healthy ? `api ok · mock ${healthy.llm_mock ? 'on' : 'off'}` : 'api unreachable'}
          </span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-4 space-y-4">
        <section className="bg-[#0d141b] border border-slate-800 rounded-lg p-3">
          <ScanForm onSubmit={submit} busy={busy} />
          {error && <p className="text-xs font-mono text-red-300 mt-2">{error}</p>}
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <section className="lg:col-span-3 bg-[#0d141b] border border-slate-800 rounded-lg overflow-hidden">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-400 px-3 pt-3 pb-2">Scans</h2>
            <ul className="divide-y divide-slate-800 max-h-[420px] overflow-y-auto">
              {scans.map((s) => (
                <li key={s.id}>
                  <button
                    onClick={() => { setActiveId(s.id); setSelected(null); setDetail(s) }}
                    className={`w-full text-left px-3 py-2 hover:bg-slate-800/60 ${activeId === s.id ? 'bg-slate-800' : ''}`}
                  >
                    <span className="block text-xs font-mono text-slate-300 truncate">{s.repo_url}</span>
                    <span className="text-[11px] font-mono text-slate-500">{s.id} · {s.status} · {s.findings.length} findings</span>
                  </button>
                </li>
              ))}
              {!scans.length && <li className="px-3 py-4 text-xs text-slate-500">No scans yet.</li>}
            </ul>
          </section>

          <section className="lg:col-span-4 bg-[#0d141b] border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-3 pt-3 pb-2 flex items-baseline justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Findings</h2>
              {detail && (
                <span className="text-[11px] font-mono text-slate-500">
                  {detail.status} · {fixed}/{detail.findings.length} fixed
                </span>
              )}
            </div>
            <div className="max-h-[420px] overflow-y-auto pb-2">
              <FindingList findings={detail?.findings || []} selected={selected} onSelect={setSelected} />
            </div>
          </section>

          <section className="lg:col-span-5 bg-[#0d141b] border border-slate-800 rounded-lg p-4">
            <DetailDrawer finding={finding} />
            <EvidenceTimeline evidence={detail?.evidence} />
          </section>
        </div>
      </main>
    </div>
  )
}
