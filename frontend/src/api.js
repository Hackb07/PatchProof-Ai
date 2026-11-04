// API base is relative by default (dev proxy); production builds can point
// it at the API directly since `vite preview` does not proxy /api.
const BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')
const ENV_KEY = import.meta.env.VITE_API_KEY || ''
const LS_KEY = 'patchproof_api_key'
const TIMEOUT_MS = 30000

export function getApiKey() {
  try {
    return localStorage.getItem(LS_KEY) || ENV_KEY || ''
  } catch {
    return ENV_KEY || ''
  }
}

export function setApiKey(key) {
  try {
    if (key) localStorage.setItem(LS_KEY, key)
    else localStorage.removeItem(LS_KEY)
  } catch {
    // storage unavailable; key applies to this page load only
  }
}

async function req(path, opts = {}) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const key = getApiKey()
    const res = await fetch(`${BASE}${path}`, {
      ...opts,
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(key ? { 'X-API-Key': key } : {}),
        ...(opts.headers || {}),
      },
    })
    if (!res.ok) {
      let detail = ''
      try {
        const body = await res.json()
        detail = body.detail || JSON.stringify(body)
      } catch {
        // non-JSON error body; fall through with the status only
      }
      const err = new Error(`${opts.method || 'GET'} ${path}: ${res.status}${detail ? ` — ${detail}` : ''}`)
      err.status = res.status
      throw err
    }
    return res.json()
  } catch (e) {
    if (e.name === 'AbortError') {
      throw new Error(`${opts.method || 'GET'} ${path}: timed out after ${TIMEOUT_MS / 1000}s`)
    }
    throw e
  } finally {
    clearTimeout(t)
  }
}

export function downloadFile(filename, text, mime = 'application/json') {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function scanToJson(detail) {
  return JSON.stringify(detail, null, 2)
}

export function scanToDiff(detail) {
  const lines = [
    `# PatchProof AI — combined diff for scan ${detail.id}`,
    `# repo: ${detail.repo_url} (${detail.branch}) status: ${detail.status}`,
    '',
  ]
  for (const f of detail.findings || []) {
    lines.push(`# --- ${f.rule_id} ${f.file_path}:${f.line_no} ${f.title} ---`)
    const patches = f.patches || []
    if (!patches.length) {
      lines.push('# (no patch)')
    } else {
      for (const p of patches) {
        lines.push(`# ${p.summary}`)
        lines.push(p.diff || '# (empty diff)')
      }
    }
    lines.push('')
  }
  return lines.join('\n')
}

export function scanToMarkdown(detail) {
  const findings = detail.findings || []
  const fixed = findings.filter((f) => f.patches?.[0]?.verifications?.[0]?.status === 'fixed').length
  const redact = (value) => String(value ?? '')
    .replace(/(https?:\/\/)[^/@\s]+@/gi, '$1[REDACTED]@')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g, '[REDACTED]')
    .replace(/(api[_-]?key|secret|password|token|authorization)(\s*[:=]\s*)(["']?)[^\s"'`,;]+/gi, '$1$2[REDACTED]')
  const lines = [
    `# PatchProof security report`, '',
    `- **Repository:** ${redact(detail.repo_url)}`, `- **Branch:** ${redact(detail.branch || 'HEAD')}`,
    `- **Scan:** ${detail.id}`, `- **Status:** ${detail.status}`,
    `- **Generated:** ${new Date().toISOString()}`, `- **Findings:** ${findings.length} (${fixed} verified fixed)`, '',
    '## Summary', '',
    findings.length ? `PatchProof identified ${findings.length} finding(s). Review each result and its verification evidence before merging remediation.` : 'No findings were recorded for this scan.', '',
    '## Findings', '',
  ]
  if (!findings.length) lines.push('No findings.')
  for (const f of findings) {
    const verification = f.patches?.[0]?.verifications?.[0]
    lines.push(`### ${redact(f.severity?.toUpperCase() || 'UNKNOWN')}: ${redact(f.title)}`, '',
      `- **Rule / CWE:** ${redact(f.rule_id || 'n/a')} / ${redact(f.cwe || 'n/a')}`,
      `- **Location:** \`${redact(f.file_path)}:${f.line_no}\``,
      `- **Risk score:** ${f.risk_score ?? 'n/a'} / 10`,
      `- **Reproduced:** ${f.reproduced ? 'yes' : 'no'}`,
      `- **Fix verification:** ${verification?.status || 'not verified'}`, '',
      redact(f.explanation || 'No explanation provided.'), '',
      '**Evidence:** review the reported source location and reproduction logs in the full JSON export.', '')
    if (f.patches?.length) {
      lines.push('**Suggested remediation**', '', redact(f.patches[0].summary || 'Patch available.'), 'Download the Diff export to review the generated patch.', '')
    }
    if (verification?.notes) lines.push(`**Verification notes:** ${redact(verification.notes)}`, '')
  }
  lines.push('## Evidence timeline', '')
  for (const e of detail.evidence || []) lines.push(`- [${redact(e.stage)}] **${redact(e.actor)}**: ${redact(e.message)}`)
  return lines.join('\n') + '\n'
}

export const api = {
  health: () => req('/api/health'),
  listScans: (limit, offset) => {
    const q = new URLSearchParams()
    if (limit != null) q.set('limit', String(limit))
    if (offset) q.set('offset', String(offset))
    const qs = q.toString() ? `?${q.toString()}` : ''
    return req(`/api/scans${qs}`)
  },
  getScan: (id) => req(`/api/scans/${id}`),
  createScan: (repo_url, branch) =>
    req('/api/scans', { method: 'POST', body: JSON.stringify({ repo_url, branch: branch || 'HEAD' }) }),
  rerun: (id) => req(`/api/scans/${id}/rerun`, { method: 'POST' }),
  cancel: (id) => req(`/api/scans/${id}/cancel`, { method: 'POST' }),
  remove: (id) => req(`/api/scans/${id}`, { method: 'DELETE' }),
  file: (scan_id, path) =>
    req(`/api/github/file?scan_id=${encodeURIComponent(scan_id)}&path=${encodeURIComponent(path)}`),
}
