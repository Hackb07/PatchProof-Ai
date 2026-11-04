import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, downloadFile, getApiKey, scanToDiff, scanToJson, scanToMarkdown, setApiKey } from './api.js'
import { ApiKeyInput, DEFAULT_FILTERS, DetailDrawer, EvidenceTimeline, FindingFilters, FindingList, ScanForm, StageStepper, StatusDot, filterFindings } from './components.jsx'
import { Coverage, Hero, LiveStrip, Pipeline, SiteFooter } from './sections.jsx'

const POLL_MS = 2500
const TERMINAL = ['done', 'failed', 'cancelled']
const PAGE_SIZE = 20
const THEME_KEY = 'patchproof_theme'

function initialDark() {
  try {
    return localStorage.getItem(THEME_KEY) === 'dark'
  } catch {
    return false
  }
}

export default function App() {
  const [scans, setScans] = useState([])
  const [page, setPage] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [activeId, setActiveId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [selected, setSelected] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [healthy, setHealthy] = useState(null)
  const [apiKey, setApiKeyInput] = useState(() => getApiKey())
  const [showKey, setShowKey] = useState(false)
  const [filters, setFilters] = useState({ ...DEFAULT_FILTERS })
  const [sort, setSort] = useState('risk')
  const [dark, setDark] = useState(initialDark)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    try {
      localStorage.setItem(THEME_KEY, dark ? 'dark' : 'light')
    } catch {
      // storage unavailable; theme applies to this page load only
    }
  }, [dark])

  const refreshList = useCallback(async (nextPage = 0, append = false) => {
    try {
      const rows = await api.listScans(PAGE_SIZE, nextPage * PAGE_SIZE)
      setHasMore(rows.length === PAGE_SIZE)
      setPage(nextPage)
      setScans((prev) => {
        const next = append ? [...prev, ...rows] : rows
        setActiveId((prevId) => {
          if (prevId && next.some((s) => s.id === prevId)) return prevId
          return next.length ? next[0].id : null
        })
        return next
      })
    } catch (e) {
      setError(e.status === 401 ? `${e.message} — set the API key (Key button above).` : String(e.message || e))
    }
  }, [])

  const refreshDetail = useCallback(async () => {
    if (!activeId) return
    try {
      const d = await api.getScan(activeId)
      setDetail(d)
      setSelected((prev) => {
        if (prev && d.findings.some((f) => f.id === prev)) return prev
        return d.findings.length ? d.findings[0].id : null
      })
    } catch (e) {
      if (e.status === 404 || String(e.message).includes('404')) {
        setDetail(null)
        setSelected(null)
        refreshList(0)
      } else {
        setError(e.status === 401 ? `${e.message} — set the API key (Key button above).` : String(e.message || e))
      }
    }
  }, [activeId, refreshList])

  useEffect(() => {
    api.health().then((h) => setHealthy(h)).catch(() => setHealthy(null))
    refreshList(0)
  }, [refreshList])

  // Fetch full detail whenever the active scan changes.
  useEffect(() => {
    if (!activeId) {
      setDetail(null)
      return
    }
    refreshDetail()
  }, [activeId, refreshDetail])

  // Poll while the active scan is still running.
  const status = detail?.status
  useEffect(() => {
    if (!activeId || !status || TERMINAL.includes(status)) return
    const t = setInterval(async () => {
      try {
        const d = await api.getScan(activeId)
        setDetail(d)
        if (TERMINAL.includes(d.status)) {
          clearInterval(t)
          refreshList(0)
        }
      } catch (e) {
        clearInterval(t)
        setError(String(e.message || e))
      }
    }, POLL_MS)
    return () => clearInterval(t)
  }, [activeId, status, refreshList])

  const submit = async (repo_url, branch) => {
    setBusy(true)
    setError('')
    try {
      const scan = await api.createScan(repo_url, branch)
      setFilters({ ...DEFAULT_FILTERS })
      await refreshList(0)
      setActiveId(scan.id)
      setSelected(null)
      setDetail(scan)
    } catch (e) {
      setError(e.status === 401 ? `${e.message} — set the API key (Key button above).` : String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const rerun = async () => {
    if (!activeId || busy) return
    setBusy(true)
    setError('')
    try {
      const scan = await api.rerun(activeId)
      setSelected(null)
      setDetail(scan)
      refreshList(0)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const cancel = async () => {
    if (!activeId || busy) return
    setBusy(true)
    setError('')
    try {
      const scan = await api.cancel(activeId)
      setDetail(scan)
      refreshList(0)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id) => {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await api.remove(id)
      const next = scans.filter((s) => s.id !== id)
      setScans(next)
      if (activeId === id) {
        setActiveId(next.length ? next[0].id : null)
        setSelected(null)
        setDetail(null)
      }
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const saveKey = () => {
    setApiKey(apiKey.trim())
    setShowKey(false)
    setError('')
    refreshList(0)
    if (activeId) refreshDetail()
  }

  const clearKey = () => {
    setApiKeyInput('')
    setApiKey('')
    setShowKey(false)
    refreshList(0)
  }

  const findings = detail?.findings || []
  const rules = useMemo(() => [...new Set(findings.map((f) => f.rule_id))].sort(), [findings])
  const visible = useMemo(() => filterFindings(findings, filters, sort), [findings, filters, sort])
  const finding = findings.find((f) => f.id === selected)
  const position = finding ? visible.findIndex((f) => f.id === finding.id) + 1 : 0
  const fixed = findings.filter((f) => f.patches?.[0]?.verifications?.[0]?.status === 'fixed').length || 0
  const findingCount = (s) => s.finding_count ?? s.findings?.length ?? 0
  const running = detail && !TERMINAL.includes(detail.status)
  const keySet = getApiKey() !== ''

  const stepFinding = useCallback((dir) => {
    setSelected((prev) => {
      const idx = visible.findIndex((f) => f.id === prev)
      const next = idx < 0 ? visible[0] : visible[idx + dir]
      return (next || visible[idx] || {}).id ?? prev
    })
  }, [visible])

  // J/K moves between findings; ignored while typing.
  useEffect(() => {
    const onKey = (e) => {
      const tag = (e.target?.tagName || '').toLowerCase()
      if (tag === 'input' || tag === 'select' || tag === 'textarea' || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key === 'j') stepFinding(1)
      else if (e.key === 'k') stepFinding(-1)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stepFinding])

  const exportJson = () => {
    if (!detail) return
    downloadFile(`patchproof-${detail.id}.json`, scanToJson(detail))
  }

  const exportDiff = () => {
    if (!detail) return
    downloadFile(`patchproof-${detail.id}.patch`, scanToDiff(detail), 'text/x-patch')
  }

  const exportReport = () => {
    if (!detail) return
    downloadFile(`patchproof-${detail.id}-report.md`, scanToMarkdown(detail), 'text/markdown')
  }

  return (
    <div className="min-h-screen bg-background text-foreground font-sans">
      <header className="border-b border-border bg-card">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3 flex-wrap">
          <div
            className="w-8 h-8 rounded-sm flex items-center justify-center font-display font-bold text-[#0A0A0B] text-sm shrink-0"
            style={{ background: 'var(--gradient-brand_wash)' }}
          >
            PP
          </div>
          <div className="flex-1 min-w-[200px]">
            <h1 className="font-display text-[20px] leading-6 font-bold text-foreground">PatchProof AI</h1>
            <p className="text-body text-muted-foreground">Scan a repo, review each finding, ship the fix</p>
          </div>
          <nav className="flex items-center gap-3 text-xs font-semibold" aria-label="Sections">
            <a href="#console" className="text-muted-foreground hover:text-foreground no-underline whitespace-nowrap">Console</a>
            <a href="#coverage" className="text-muted-foreground hover:text-foreground no-underline whitespace-nowrap">Coverage</a>
            <a href="#pipeline" className="text-muted-foreground hover:text-foreground no-underline whitespace-nowrap">Pipeline</a>
          </nav>
          {showKey ? (
            <ApiKeyInput value={apiKey} onChange={setApiKeyInput} onSave={saveKey} onClear={clearKey} />
          ) : (
            <button
              onClick={() => setShowKey(true)}
              title="Set the API key for /api/scans and /api/github"
              className="btn btn-secondary btn-sm"
            >
              <span className={`dot ${keySet ? 'dot-done' : 'dot-cancelled'}`} />
              Key
            </button>
          )}
          <button
            onClick={() => setDark((d) => !d)}
            title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
            className="btn btn-secondary btn-sm"
          >
            {dark ? '☀ Light' : '☾ Dark'}
          </button>
          <span className={`text-xs font-mono px-2 py-1 rounded-sm border border-border whitespace-nowrap ${healthy ? 'bg-accent text-accent-foreground' : 'text-muted-foreground'}`}>
            {healthy ? `api ok · mock ${healthy.llm_mock ? 'on' : 'off'}` : 'api unreachable'}
          </span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-4 space-y-4">
        <Hero />
        <section id="console" className="card p-3 scroll-mt-4">
          <ScanForm onSubmit={submit} busy={busy} />
          {error && <p className="text-xs font-mono text-danger mt-2">{error}</p>}
        </section>
        <LiveStrip detail={detail} fixed={fixed} />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <section className="lg:col-span-3 card overflow-hidden">
            <h2 className="text-overline text-muted-foreground px-3 pt-3 pb-2">Scans</h2>
            <ul className="divide-y divide-border max-h-[420px] overflow-y-auto">
              {scans.map((s) => (
                <li key={s.id}>
                  <div className={`group flex items-center gap-2 px-3 py-2 hover:bg-muted ${activeId === s.id ? 'bg-accent' : ''}`}>
                    <StatusDot status={s.status} />
                    <button
                      onClick={() => { setActiveId(s.id); setSelected(null); setDetail(null) }}
                      className="flex-1 text-left min-w-0"
                    >
                      <span className="block text-xs font-mono text-foreground truncate">{s.repo_url}</span>
                      <span className="text-[11px] font-mono text-muted-foreground">{s.status} · {findingCount(s)} findings</span>
                    </button>
                    <button
                      onClick={() => remove(s.id)}
                      disabled={busy}
                      title={`Delete scan ${s.id}`}
                      className="text-[11px] font-mono text-muted-foreground hover:text-danger px-1 py-0.5 disabled:opacity-50 opacity-0 group-hover:opacity-100 focus:opacity-100"
                    >
                      ✕
                    </button>
                  </div>
                </li>
              ))}
              {!scans.length && <li className="px-3 py-4 text-xs text-muted-foreground">No scans yet — paste a repo above to start.</li>}
            </ul>
            {hasMore && (
              <div className="p-2 border-t border-border">
                <button
                  onClick={() => refreshList(page + 1, true)}
                  className="btn btn-secondary btn-sm w-full !h-8"
                >
                  Load more
                </button>
              </div>
            )}
          </section>

          <section className="lg:col-span-3 card overflow-hidden">
            <div className="px-3 pt-3 pb-2 flex items-baseline justify-between gap-2 flex-wrap">
              <h2 className="text-overline text-muted-foreground">
                Findings {detail ? <span className="normal-case font-sans font-semibold">· {fixed}/{findings.length} fixed</span> : null}
              </h2>
              <div className="flex gap-1.5">
                {detail && (
                  <>
                    <button
                      onClick={exportJson}
                      title="Download full scan report as JSON"
                      className="btn btn-secondary btn-sm"
                    >
                      JSON
                    </button>
                    <button
                      onClick={exportDiff}
                      title="Download combined unified diff of all patches"
                      className="btn btn-secondary btn-sm"
                    >
                      Fix patch
                    </button>
                    <button
                      onClick={exportReport}
                      title="Download a human-readable security report with findings and remediation evidence"
                      className="btn btn-secondary btn-sm"
                    >
                      Report
                    </button>
                  </>
                )}
                {running && (
                  <button
                    onClick={cancel}
                    disabled={busy}
                    title="Cancel this running scan"
                    className="btn btn-warn btn-sm"
                  >
                    {busy ? 'Working…' : 'Cancel'}
                  </button>
                )}
                {detail && TERMINAL.includes(detail.status) && (
                  <button
                    onClick={rerun}
                    disabled={busy}
                    title="Re-run this scan from scratch"
                    className="btn btn-primary btn-sm"
                  >
                    {busy ? 'Working…' : 'Rerun'}
                  </button>
                )}
              </div>
            </div>
            <FindingFilters rules={rules} filters={filters} onChange={setFilters} sort={sort} onSort={setSort} />
            <div className="max-h-[380px] overflow-y-auto pb-2">
              <FindingList
                findings={visible}
                selected={selected}
                onSelect={setSelected}
                emptyText={findings.length ? 'No findings match these filters.' : undefined}
              />
            </div>
            {visible.length > 0 && (
              <p className="px-3 py-1.5 border-t border-border text-[11px] font-mono text-muted-foreground">
                {visible.length} shown · J/K to move
              </p>
            )}
          </section>

          <section className="lg:col-span-6 card p-4">
            {detail ? (
              <div className="mb-3 pb-3 border-b border-border space-y-1">
                <p className="text-xs font-mono text-muted-foreground truncate" title={detail.repo_url}>{detail.repo_url}</p>
                <StageStepper status={detail.status} />
              </div>
            ) : null}
            <DetailDrawer
              key={finding?.id || 'none'}
              finding={finding}
              scanId={detail?.id}
              position={position}
              total={visible.length}
              onPrev={() => stepFinding(-1)}
              onNext={() => stepFinding(1)}
            />
            <EvidenceTimeline evidence={detail?.evidence} defaultOpen={!!running} />
          </section>
        </div>

        <Coverage />
        <Pipeline />
        <SiteFooter healthy={healthy} />
      </main>
    </div>
  )
}
