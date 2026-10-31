# Architecture

```
 GitHub URL / local path
        |
        v
 +--------------+    +----------------+    +------------------+
 | planner agent| -> | detector agent | -> | risk-assessor    |
 | clone/copy   |    | AST+regex scan |    | 0-10 score + why |
 | evidence log |    | triage/dedupe  |    |                  |
 +--------------+    +----------------+    +------------------+
        |                    |                       |
        v                    v                       v
 +--------------+    +----------------+    +------------------+
 | sandbox      | -> | validator agent| -> | patcher          |
 | PoC repro    |    | true/false pos |    | minimal unified  |
 | docker|local |    | using repro log|    | diff per finding |
 +--------------+    +----------------+    +------------------+
                                                 |
                                                 v
                                        +------------------+
                                        | verifier         |
                                        | rescan + pytest  |
                                        | fixed|unfixed|?  |
                                        +------------------+
                                                 |
                                                 v
                                        SQLite evidence store
                                                 |
                                                 v
                                        React evidence console
```

## Agent roles

- **Planner** (`agents/planner.py`): owns the pipeline state machine, repo
  acquisition (GitHub clone or local copy), stage transitions, and failure
  capture. Every transition appends an `Evidence` row.
- **Detector** (`agents/detector.py` + `scanner/`): static scan produces raw
  findings; the LLM triage pass dedupes and drops obvious noise.
- **Risk assessor** (`agents/risk_assessor.py`): scores 0–10 with a rationale;
  low-confidence findings are penalized so the dashboard sorts by real risk.
- **Sandbox** (`sandbox/runner.py`): synthesizes a per-rule PoC and executes it
  isolated (Docker `--network none` preferred, subprocess fallback). PoCs prove
  sink reachability with markers — never real exploitation.
- **Validator** (`agents/validator.py`): combines code context with the repro
  log to label true vs false positives before patching.
- **Patcher** (`patcher/`): LLM proposes the minimal fix; a deterministic
  fixer guarantees a safe, reviewable diff offline (parameterize hint,
  `shell=False`, `safe_load`, env secrets, path confinement, escaping).
- **Verifier** (`verifier/`): applies the diff, re-scans the sink region,
  runs the target repo's pytest suite if present, and records
  `fixed | unfixed | inconclusive` with logs.

## Evidence model

`Scan 1—n Finding 1—n Patch 1—n Verification`, plus an append-only
`Evidence(scan_id, stage, actor, message)` timeline. The dashboard renders one
tab per stage (Code / Patch / Verification) and the full timeline, so every
claim is backed by an artifact: snippet, repro log, diff, rescan result, test log.
