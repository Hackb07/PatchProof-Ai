import { useState } from 'react'
import { api } from './api.js'

const SEV = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
}

const STATUS = {
  fixed: 'badge-fixed',
  unfixed: 'badge-unfixed',
  inconclusive: 'badge-inconclusive',
}

export function SevBadge({ level }) {
  return (
    <span className={`badge ${SEV[level] || SEV.low}`}>
      {level}
    </span>
  )
}

export function VerifyBadge({ status }) {
  if (!status) return <span className="text-xs text-muted-foreground">not verified</span>
  return (
    <span className={`badge ${STATUS[status] || STATUS.inconclusive}`}>
      {status}
    </span>
  )
}

export function StatusDot({ status }) {
  return (
    <span
      title={status}
      className={`dot dot-${status || 'queued'}`}
    />
  )
}

const STAGES = ['queued', 'scanning', 'triaging', 'patching', 'verifying', 'done']

export function StageStepper({ status }) {
  if (!status) return null
  if (status === 'failed' || status === 'cancelled') {
    return <p className={`text-xs font-mono ${status === 'failed' ? 'text-danger' : 'text-muted-foreground'}`}>{status}</p>
  }
  const current = STAGES.indexOf(status)
  return (
    <ol className="flex flex-wrap items-center gap-x-1 gap-y-0.5 text-[11px] font-mono" aria-label={`Scan stage: ${status}`}>
      {STAGES.map((stage, i) => (
        <li key={stage} className="flex items-center gap-1 whitespace-nowrap">
          {i > 0 && <span className="text-muted-foreground">›</span>}
          <span className={i < current ? 'text-muted-foreground' : i === current ? 'text-success font-semibold' : 'text-muted-foreground opacity-60'}>
            {stage}
          </span>
        </li>
      ))}
    </ol>
  )
}

export function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  if (!text) return null
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
        } catch {
          const ta = document.createElement('textarea')
          ta.value = text
          document.body.appendChild(ta)
          ta.select()
          document.execCommand('copy')
          ta.remove()
        }
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }}
      className="btn btn-secondary btn-sm"
    >
      {copied ? 'Copied' : label}
    </button>
  )
}

export function ScanForm({ onSubmit, busy }) {
  const [repo, setRepo] = useState('')
  const [branch, setBranch] = useState('')
  return (
    <form
      className="flex flex-col sm:flex-row gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        if (repo.trim()) onSubmit(repo.trim(), branch.trim())
      }}
    >
      <input
        className="input input-md font-mono flex-1"
        placeholder="GitHub URL or local path — e.g. https://github.com/org/repo"
        value={repo}
        onChange={(e) => setRepo(e.target.value)}
      />
      <input
        className="input input-md font-mono w-full sm:w-32"
        placeholder="branch"
        value={branch}
        onChange={(e) => setBranch(e.target.value)}
      />
      <button
        disabled={busy}
        className="btn btn-primary btn-md"
      >
        {busy ? 'Scanning…' : 'Scan repo'}
      </button>
    </form>
  )
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 }

export function filterFindings(findings, { severity, rule, query }, sort) {
  const q = (query || '').trim().toLowerCase()
  let rows = (findings || []).filter((f) => {
    if (severity && severity !== 'all' && f.severity !== severity) return false
    if (rule && rule !== 'all' && f.rule_id !== rule) return false
    if (q) {
      const hay = `${f.title} ${f.file_path} ${f.rule_id} ${f.cwe}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
  const by = sort || 'risk'
  rows = [...rows].sort((a, b) => {
    if (by === 'severity') {
      return (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || (b.risk_score ?? 0) - (a.risk_score ?? 0)
    }
    if (by === 'file') {
      return a.file_path.localeCompare(b.file_path) || a.line_no - b.line_no
    }
    if (by === 'rule') {
      return a.rule_id.localeCompare(b.rule_id) || (b.risk_score ?? 0) - (a.risk_score ?? 0)
    }
    return (b.risk_score ?? 0) - (a.risk_score ?? 0)
  })
  return rows
}

export const DEFAULT_FILTERS = { severity: 'all', rule: 'all', query: '' }

export function FindingFilters({ rules, filters, onChange, sort, onSort }) {
  const active = filters.severity !== 'all' || filters.rule !== 'all' || filters.query.trim() !== ''
  return (
    <div className="flex flex-wrap items-center gap-2 px-3 pb-2">
      <select
        aria-label="Filter by severity"
        className="input input-sm"
        value={filters.severity}
        onChange={(e) => onChange({ ...filters, severity: e.target.value })}
      >
        <option value="all">all severities</option>
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="medium">medium</option>
        <option value="low">low</option>
      </select>
      <select
        aria-label="Filter by rule"
        className="input input-sm"
        value={filters.rule}
        onChange={(e) => onChange({ ...filters, rule: e.target.value })}
      >
        <option value="all">all rules</option>
        {rules.map((r) => (
          <option key={r} value={r}>{r}</option>
        ))}
      </select>
      <select
        aria-label="Sort findings"
        className="input input-sm"
        value={sort}
        onChange={(e) => onSort(e.target.value)}
      >
        <option value="risk">sort: risk</option>
        <option value="severity">sort: severity</option>
        <option value="file">sort: file</option>
        <option value="rule">sort: rule</option>
      </select>
      <input
        aria-label="Search findings"
        className="input input-sm flex-1 min-w-[120px]"
        placeholder="search title, file, rule…"
        value={filters.query}
        onChange={(e) => onChange({ ...filters, query: e.target.value })}
      />
      {active && (
        <button
          onClick={() => onChange({ ...DEFAULT_FILTERS })}
          className="link-btn"
        >
          Clear
        </button>
      )}
    </div>
  )
}

export function ApiKeyInput({ value, onChange, onSave, onClear }) {
  return (
    <form
      className="flex items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        onSave()
      }}
    >
      <input
        type="password"
        autoComplete="off"
        spellCheck={false}
        className="input input-sm font-mono w-36"
        placeholder="API key"
        title="Runtime API key for /api/scans and /api/github (stored in this browser only)"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        type="submit"
        className="btn btn-secondary btn-sm"
      >
        Save
      </button>
      {value && (
        <button
          type="button"
          onClick={onClear}
          className="link-btn"
        >
          Clear
        </button>
      )}
    </form>
  )
}

export function FindingList({ findings, selected, onSelect, emptyText }) {
  if (!findings.length)
    return <p className="text-sm text-muted-foreground px-3 py-6">{emptyText || 'No findings yet. Submit a repo scan above.'}</p>
  return (
    <ul className="divide-y divide-border">
      {findings.map((f, i) => (
        <li key={f.id}>
          <button
            onClick={() => onSelect(f.id)}
            className={`w-full text-left px-3 py-2.5 flex items-center gap-2.5 hover:bg-muted ${
              selected === f.id ? 'bg-accent' : ''
            }`}
          >
            <span className="text-[11px] font-mono text-muted-foreground w-5 shrink-0 text-right">{i + 1}</span>
            <SevBadge level={f.severity} />
            <span className="flex-1 min-w-0">
              <span className="block text-sm font-medium text-foreground truncate">{f.title}</span>
              <span className="block text-xs text-muted-foreground font-mono truncate">
                {f.file_path}:{f.line_no} · {f.rule_id} · risk {(f.risk_score ?? 0).toFixed(1)}
              </span>
            </span>
            {f.reproduced && (
              <span className="badge badge-repro">
                repro
              </span>
            )}
          </button>
        </li>
      ))}
    </ul>
  )
}

function CodeBlock({ text, tone = '', copyLabel = 'Copy' }) {
  return (
    <div className="relative">
      <pre className={`codeblock ${tone}`}>
        {text || '(empty)'}
      </pre>
      {text && (
        <div className="absolute top-2 right-2">
          <CopyButton text={text} label={copyLabel} />
        </div>
      )}
    </div>
  )
}

function FullFile({ scanId, path }) {
  const [content, setContent] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  if (content !== null) return <CodeBlock text={content} />
  return (
    <div>
      <button
        disabled={loading || !scanId}
        onClick={async () => {
          setLoading(true)
          setError('')
          try {
            const res = await api.file(scanId, path)
            setContent(res.content)
          } catch (e) {
            setError(String(e.message || e))
          } finally {
            setLoading(false)
          }
        }}
        className="btn btn-secondary btn-sm"
      >
        {loading ? 'Loading…' : 'Load full file'}
      </button>
      {error && <p className="text-xs font-mono text-danger mt-2">{error}</p>}
    </div>
  )
}

export function DetailDrawer({ finding, scanId, position, total, onPrev, onNext }) {
  const [tab, setTab] = useState('code')
  if (!finding)
    return <p className="text-sm text-muted-foreground px-1 py-6">Select a finding to inspect evidence.</p>
  const patches = finding.patches || []
  const verifications = patches.flatMap((p) => (p.verifications || []).map((v) => ({ ...v, patchId: p.id })))
  const latest = verifications[verifications.length - 1]
  const tabs = [
    ['code', 'Code'],
    ['patch', `Patch${patches.length ? ` (${patches.length})` : ' (none)'}`],
    ['verify', 'Verification'],
  ]
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <SevBadge level={finding.severity} />
        <span className="text-xs font-mono text-muted-foreground">{finding.cwe}</span>
        <span className="text-xs font-mono text-muted-foreground">{finding.rule_id}</span>
        <VerifyBadge status={latest?.status} />
        {finding.validated && <span className="text-xs text-success">validated</span>}
        {finding.false_positive && <span className="text-xs text-muted-foreground">false positive</span>}
        {total > 1 && (
          <span className="ml-auto flex items-center gap-1">
            <button
              onClick={onPrev}
              disabled={position <= 1}
              title="Previous finding (K)"
              className="btn btn-secondary w-6 h-6 text-xs font-mono !px-0"
            >
              ‹
            </button>
            <span className="text-[11px] font-mono text-muted-foreground min-w-[3rem] text-center">{position} of {total}</span>
            <button
              onClick={onNext}
              disabled={position >= total}
              title="Next finding (J)"
              className="btn btn-secondary w-6 h-6 text-xs font-mono !px-0"
            >
              ›
            </button>
          </span>
        )}
      </div>
      <h2 className="text-heading text-foreground">{finding.title}</h2>
      <p className="text-sm text-foreground mt-1">{finding.explanation}</p>
      <p className="text-xs font-mono text-muted-foreground mt-1">
        {finding.file_path}:{finding.line_no} · confidence {finding.confidence} · risk {(finding.risk_score ?? 0).toFixed(1)}
      </p>
      {finding.risk_rationale && (
        <p className="text-xs text-muted-foreground mt-2 leading-5">{finding.risk_rationale}</p>
      )}

      <div className="flex gap-1 mt-4 mb-3 border-b border-border">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`text-sm font-medium px-3 py-1.5 -mb-px border-b-2 whitespace-nowrap ${
              tab === key ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'code' && (
        <div className="space-y-3">
          <CodeBlock text={finding.snippet} />
          <FullFile scanId={scanId} path={finding.file_path} />
          <h3 className="text-label text-foreground">
            Reproduction {finding.reproduced ? '(reproduced)' : '(not reproduced)'}
          </h3>
          <CodeBlock text={finding.repro_log} tone="codeblock-amber" />
        </div>
      )}
      {tab === 'patch' && (
        <div className="space-y-4">
          {patches.length ? (
            patches.map((patch) => (
              <div key={patch.id} className="space-y-2">
                <p className="text-sm text-foreground">{patch.summary}</p>
                <p className="text-xs text-muted-foreground">
                  {patch.applied ? 'Applied to the scanned checkout.' : 'Generated, not applied.'}
                </p>
                <CodeBlock text={patch.diff} tone="codeblock-green" copyLabel="Copy diff" />
              </div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">No patch generated for this finding.</p>
          )}
        </div>
      )}
      {tab === 'verify' && (
        <div className="space-y-4">
          {verifications.length ? (
            verifications.map((verification) => (
              <div key={verification.id} className="space-y-2">
                <div className="flex items-center gap-2">
                  <VerifyBadge status={verification.status} />
                  <span className="text-xs text-muted-foreground">
                    rescan {verification.rescan_clean ? 'clean' : 'still flags'} ·
                    tests {verification.tests_passed === null ? 'n/a' : verification.tests_passed ? 'passed' : 'failed'}
                  </span>
                </div>
                <p className="text-sm text-foreground">{verification.notes}</p>
                <CodeBlock text={verification.test_log} />
              </div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">No verification run recorded.</p>
          )}
        </div>
      )}
    </div>
  )
}

export function EvidenceTimeline({ evidence, defaultOpen = true }) {
  if (!evidence?.length) return null
  return (
    <details open={defaultOpen} className="mt-4 border-t border-border pt-3">
      <summary className="text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground list-none flex items-center gap-1.5">
        <span aria-hidden="true">▸</span>
        Evidence timeline ({evidence.length})
      </summary>
      <ol className="mt-2 space-y-1.5">
        {evidence.map((e) => (
          <li key={e.id} className="text-xs font-mono text-muted-foreground break-words">
            <span>[{e.stage}]</span>{' '}
            <span className="text-foreground">{e.actor}</span> — {e.message}
          </li>
        ))}
      </ol>
    </details>
  )
}
