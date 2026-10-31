import { useState } from 'react'

const SEV = {
  critical: 'bg-red-600 text-white',
  high: 'bg-red-900 text-red-100 border border-red-700',
  medium: 'bg-amber-900 text-amber-100 border border-amber-700',
  low: 'bg-slate-700 text-slate-200',
}

const STATUS = {
  fixed: 'bg-emerald-900 text-emerald-100 border border-emerald-700',
  unfixed: 'bg-red-900 text-red-100 border border-red-700',
  inconclusive: 'bg-slate-700 text-slate-200 border border-slate-600',
}

export function SevBadge({ level }) {
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded ${SEV[level] || SEV.low}`}>
      {level}
    </span>
  )
}

export function VerifyBadge({ status }) {
  if (!status) return <span className="text-xs text-slate-400">not verified</span>
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded ${STATUS[status] || STATUS.inconclusive}`}>
      {status}
    </span>
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
        className="flex-1 bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-sm font-mono placeholder:text-slate-500 focus:outline-none focus:border-emerald-600"
        placeholder="GitHub URL or local path — e.g. https://github.com/org/repo"
        value={repo}
        onChange={(e) => setRepo(e.target.value)}
      />
      <input
        className="w-32 bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-sm font-mono placeholder:text-slate-500 focus:outline-none focus:border-emerald-600"
        placeholder="branch"
        value={branch}
        onChange={(e) => setBranch(e.target.value)}
      />
      <button
        disabled={busy}
        className="bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-md"
      >
        {busy ? 'Scanning…' : 'Scan repo'}
      </button>
    </form>
  )
}

export function FindingList({ findings, selected, onSelect }) {
  if (!findings.length)
    return <p className="text-sm text-slate-400 px-1 py-6">No findings yet. Submit a repo scan above.</p>
  return (
    <ul className="divide-y divide-slate-800">
      {findings.map((f) => (
        <li key={f.id}>
          <button
            onClick={() => onSelect(f.id)}
            className={`w-full text-left px-3 py-2.5 flex items-center gap-3 hover:bg-slate-800/60 ${
              selected === f.id ? 'bg-slate-800' : ''
            }`}
          >
            <SevBadge level={f.severity} />
            <span className="flex-1 min-w-0">
              <span className="block text-sm font-medium truncate">{f.title}</span>
              <span className="block text-xs text-slate-400 font-mono truncate">
                {f.file_path}:{f.line_no} · {f.rule_id} · risk {f.risk_score.toFixed(1)}
              </span>
            </span>
            {f.reproduced && (
              <span className="text-[11px] font-semibold text-amber-200 bg-amber-950 border border-amber-800 px-1.5 py-0.5 rounded">
                repro
              </span>
            )}
          </button>
        </li>
      ))}
    </ul>
  )
}

function CodeBlock({ text, highlight = 'text-slate-200' }) {
  return (
    <pre className={`text-xs font-mono leading-5 whitespace-pre-wrap bg-slate-950 border border-slate-800 rounded-lg p-3 overflow-x-auto ${highlight}`}>
      {text || '(empty)'}
    </pre>
  )
}

export function DetailDrawer({ finding }) {
  const [tab, setTab] = useState('code')
  if (!finding)
    return <p className="text-sm text-slate-400 px-1 py-6">Select a finding to inspect evidence.</p>
  const patch = finding.patches?.[0]
  const verification = patch?.verifications?.[0]
  const tabs = [
    ['code', 'Code'],
    ['patch', `Patch${patch ? '' : ' (none)'}`],
    ['verify', 'Verification'],
  ]
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <SevBadge level={finding.severity} />
        <span className="text-xs font-mono text-slate-400">{finding.cwe}</span>
        <span className="text-xs font-mono text-slate-400">{finding.rule_id}</span>
        <VerifyBadge status={verification?.status} />
        {finding.validated && <span className="text-xs text-emerald-300">validated</span>}
        {finding.false_positive && <span className="text-xs text-slate-400">false positive</span>}
      </div>
      <h2 className="text-lg font-semibold">{finding.title}</h2>
      <p className="text-sm text-slate-300 mt-1">{finding.explanation}</p>
      <p className="text-xs font-mono text-slate-400 mt-1">
        {finding.file_path}:{finding.line_no} · confidence {finding.confidence} · risk {finding.risk_score.toFixed(1)}
      </p>
      {finding.risk_rationale && (
        <p className="text-xs text-slate-400 mt-2 leading-5">{finding.risk_rationale}</p>
      )}

      <div className="flex gap-1 mt-4 mb-3 border-b border-slate-800">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`text-sm font-medium px-3 py-1.5 -mb-px border-b-2 ${
              tab === key ? 'border-emerald-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'code' && (
        <div className="space-y-3">
          <CodeBlock text={finding.snippet} />
          <h3 className="text-sm font-semibold text-slate-200">
            Reproduction {finding.reproduced ? '(reproduced)' : '(not reproduced)'}
          </h3>
          <CodeBlock text={finding.repro_log} highlight="text-amber-100" />
        </div>
      )}
      {tab === 'patch' && (
        <div className="space-y-3">
          {patch ? (
            <>
              <p className="text-sm text-slate-300">{patch.summary}</p>
              <p className="text-xs text-slate-400">
                {patch.applied ? 'Applied to the scanned checkout.' : 'Generated, not applied.'}
              </p>
              <CodeBlock text={patch.diff} highlight="text-emerald-100" />
            </>
          ) : (
            <p className="text-sm text-slate-400">No patch generated for this finding.</p>
          )}
        </div>
      )}
      {tab === 'verify' && (
        <div className="space-y-3">
          {verification ? (
            <>
              <div className="flex items-center gap-2">
                <VerifyBadge status={verification.status} />
                <span className="text-xs text-slate-400">
                  rescan {verification.rescan_clean ? 'clean' : 'still flags'} ·
                  tests {verification.tests_passed === null ? 'n/a' : verification.tests_passed ? 'passed' : 'failed'}
                </span>
              </div>
              <p className="text-sm text-slate-300">{verification.notes}</p>
              <CodeBlock text={verification.test_log} />
            </>
          ) : (
            <p className="text-sm text-slate-400">No verification run recorded.</p>
          )}
        </div>
      )}
    </div>
  )
}

export function EvidenceTimeline({ evidence }) {
  if (!evidence?.length) return null
  return (
    <ol className="mt-4 border-t border-slate-800 pt-3 space-y-1.5">
      {evidence.map((e) => (
        <li key={e.id} className="text-xs font-mono text-slate-400">
          <span className="text-slate-500">[{e.stage}]</span>{' '}
          <span className="text-slate-300">{e.actor}</span> — {e.message}
        </li>
      ))}
    </ol>
  )
}
