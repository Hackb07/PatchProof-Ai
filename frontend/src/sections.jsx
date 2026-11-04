import { SevBadge, StatusDot } from './components.jsx'

const RULES = [
  {
    id: 'PY-SQLI-001',
    title: 'Possible SQL injection',
    cwe: 'CWE-89',
    severity: 'high',
    sink: 'cursor.execute(f"SELECT ... {name}")',
    fix: "Use a parameterized query: cursor.execute('... WHERE name = ?', (name,)) — never interpolate.",
  },
  {
    id: 'PY-CMDI-001',
    title: 'Possible command injection',
    cwe: 'CWE-78',
    severity: 'high',
    sink: 'subprocess.run(cmd, shell=True)',
    fix: 'Use subprocess.run([...], shell=False) with an argv list; never shell=True with input.',
  },
  {
    id: 'PY-XSS-001',
    title: 'Possible cross-site scripting / unsafe template render',
    cwe: 'CWE-79',
    severity: 'medium',
    sink: 'render_template_string("<h1>" + name + "</h1>")',
    fix: 'Escape output with html.escape() or use autoescaped templates; avoid render_template_string with input.',
  },
  {
    id: 'PY-PATHTRAV-001',
    title: 'Possible path traversal',
    cwe: 'CWE-22',
    severity: 'medium',
    sink: 'open(f"{base}/{name}")',
    fix: 'Resolve against a base dir and reject paths escaping it via _confined_path().',
  },
  {
    id: 'PY-DESER-001',
    title: 'Insecure deserialization',
    cwe: 'CWE-502',
    severity: 'high',
    sink: 'pickle.loads(data)',
    fix: 'Replace pickle/yaml.load with json.loads, or yaml.safe_load with an explicit Loader.',
  },
  {
    id: 'PY-SECRET-001',
    title: 'Hardcoded secret',
    cwe: 'CWE-798',
    severity: 'medium',
    sink: 'api_key = "sk-live-..."',
    fix: "Load from environment: os.environ['SECRET'] — remove the literal and rotate it.",
  },
  {
    id: 'PY-SSRF-001',
    title: 'Possible SSRF (unvalidated request URL)',
    cwe: 'CWE-918',
    severity: 'medium',
    sink: 'requests.get(url)',
    fix: 'Validate the URL host against an allowlist via _checked_url() before requesting.',
  },
]

const STAGES = [
  {
    n: '01',
    name: 'Clone & plan',
    actor: 'planner',
    text: 'Copies a local path or clones the repo URL, owns the stage machine, and logs every transition as evidence.',
  },
  {
    n: '02',
    name: 'Scan & triage',
    actor: 'detector',
    text: 'Static sweep with 7 rules over every *.py file, then an LLM KEEP/DROP pass that dedupes and drops noise.',
  },
  {
    n: '03',
    name: 'Risk scoring',
    actor: 'risk-assessor',
    text: 'Scores each finding 0–10 with a rationale; low-confidence findings are penalized so real risk sorts first.',
  },
  {
    n: '04',
    name: 'Repro & validate',
    actor: 'sandbox + validator',
    text: 'A per-rule PoC runs isolated (Docker --network none, subprocess fallback) proving sink reachability with markers — never real exploitation.',
  },
  {
    n: '05',
    name: 'Patch',
    actor: 'patcher',
    text: 'Deterministic per-rule transforms emit one minimal unified diff per finding, gated on a Python syntax check.',
  },
  {
    n: '06',
    name: 'Verify',
    actor: 'verifier',
    text: 'Applies the diff, re-scans the sink region, runs the target pytest suite when present, and records fixed / unfixed / inconclusive.',
  },
]

const STATS = [
  ['7', 'detection rules'],
  ['6', 'pipeline stages'],
  ['2', 'sandbox backends'],
  ['Python', 'scan target'],
]

export function Hero() {
  return (
    <section className="card overflow-hidden">
      <div className="grid grid-cols-1 lg:grid-cols-2">
        <div className="p-4 sm:p-6 flex flex-col justify-center gap-3">
          <p className="text-overline text-success">Autonomous AI security engineer</p>
          <h2 className="text-title text-foreground">From vulnerable repo to verified fix.</h2>
          <p className="text-sm text-foreground leading-6">
            PatchProof AI scans a Python repo, investigates each finding with specialized agents,
            reproduces it in a sandbox, generates a minimal patch, verifies the fix, and presents
            the whole chain as evidence.
          </p>
          <div className="flex flex-wrap gap-2 mt-1">
            <a href="#console" className="btn btn-primary btn-md no-underline">Start a scan</a>
            <a href="#coverage" className="btn btn-secondary btn-md no-underline">Browse rule coverage</a>
          </div>
        </div>
        <div className="border-t lg:border-t-0 lg:border-l border-border">
          <img
            src="/images/hero-pipeline.png"
            alt="Six-stage PatchProof pipeline rendered as connected hexagons"
            className="w-full h-full object-cover block"
          />
        </div>
      </div>
      <dl className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border border-t border-border">
        {STATS.map(([value, label]) => (
          <div key={label} className="bg-card px-4 py-3">
            <dt className="text-overline text-muted-foreground order-2">{label}</dt>
            <dd className="font-display text-[24px] leading-7 font-bold text-foreground">{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

export function LiveStrip({ detail, fixed }) {
  if (!detail) return null
  const count = detail.findings?.length ?? 0
  return (
    <div className="card px-3 py-2 flex items-center gap-2 flex-wrap">
      <StatusDot status={detail.status} />
      <span className="text-xs font-mono text-foreground truncate min-w-0 max-w-full sm:max-w-[280px]" title={detail.repo_url}>
        {detail.repo_url}
      </span>
      <span className="text-[11px] font-mono text-muted-foreground">
        {detail.status} · {count} findings · {fixed} fixed
      </span>
    </div>
  )
}

export function Coverage() {
  return (
    <section id="coverage" className="space-y-3 scroll-mt-4">
      <div>
        <p className="text-overline text-success">Coverage</p>
        <h2 className="text-heading text-foreground mt-1">Seven rules, each with a known fix.</h2>
        <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
          Every detector ships with its remediation: the patcher applies the deterministic transform
          for the rule that fired, so each finding below maps to exactly one minimal diff.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {RULES.map((r) => (
          <article key={r.id} className="card p-4 space-y-2">
            <p className="text-[11px] font-mono text-muted-foreground">{r.id}</p>
            <h3 className="text-label text-foreground">{r.title}</h3>
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[11px] font-mono text-foreground border border-border rounded-sm px-1.5 py-0.5">
                {r.cwe}
              </span>
              <SevBadge level={r.severity} />
            </div>
            <p className="text-xs font-mono text-foreground bg-background border border-border rounded-sm px-2 py-1.5 overflow-x-auto whitespace-nowrap">
              {r.sink}
            </p>
            <p className="text-xs text-muted-foreground leading-5">
              <span className="font-semibold text-foreground">Fix: </span>
              {r.fix}
            </p>
          </article>
        ))}
      </div>
    </section>
  )
}

export function Pipeline() {
  return (
    <section id="pipeline" className="space-y-3 scroll-mt-4">
      <div>
        <p className="text-overline text-success">Pipeline</p>
        <h2 className="text-heading text-foreground mt-1">Six agents, one evidence trail.</h2>
        <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
          A scan flows through six stages — every handoff appends to an append-only evidence
          timeline, so each claim in the report is backed by a snippet, a repro log, a diff, or a
          test log.
        </p>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card overflow-hidden">
          <img
            src="/images/verify-shield.png"
            alt="Verification console showing a shield check with review statuses"
            className="w-full h-full object-cover block min-h-[220px]"
          />
        </div>
        <ol className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {STAGES.map((s) => (
            <li key={s.n} className="card p-4 space-y-1.5">
              <div className="flex items-baseline gap-2">
                <span className="font-display text-[20px] leading-6 font-bold text-success">{s.n}</span>
                <h3 className="text-label text-foreground">{s.name}</h3>
              </div>
              <p className="text-[11px] font-mono text-muted-foreground">{s.actor}</p>
              <p className="text-xs text-muted-foreground leading-5">{s.text}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}

export function SiteFooter({ healthy }) {
  return (
    <footer className="card p-4 space-y-3">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="space-y-1.5">
          <p className="text-overline text-muted-foreground">PatchProof AI</p>
          <p className="text-xs text-muted-foreground leading-5">
            MVP scope: Python repos only, 7 vulnerability classes. Runs fully offline with the
            deterministic mock LLM; point it at a Meta OpenAI-compatible endpoint for live triage.
          </p>
        </div>
        <div className="space-y-1.5">
          <p className="text-overline text-muted-foreground">Stack</p>
          <ul className="text-xs font-mono text-muted-foreground space-y-1">
            <li>Rust Axum API + pipeline crates</li>
            <li>React + Tailwind evidence console</li>
            <li>SQLite store (bundled, single file)</li>
            <li>Docker sandbox, subprocess fallback</li>
          </ul>
        </div>
        <div className="space-y-1.5">
          <p className="text-overline text-muted-foreground">Navigate</p>
          <ul className="text-xs font-semibold space-y-1.5">
            <li><a href="#console" className="text-foreground no-underline hover:underline">Scan console</a></li>
            <li><a href="#coverage" className="text-foreground no-underline hover:underline">Rule coverage</a></li>
            <li><a href="#pipeline" className="text-foreground no-underline hover:underline">Pipeline</a></li>
          </ul>
        </div>
      </div>
      <p className="text-[11px] font-mono text-muted-foreground border-t border-border pt-3">
        PatchProof AI — Security Evidence Console{healthy ? ` · api ok, mock ${healthy.llm_mock ? 'on' : 'off'}` : ''}
      </p>
    </footer>
  )
}
