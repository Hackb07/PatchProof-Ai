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

- **Planner** (`backend/app/agents/planner.py`, Rust: `crates/core/src/pipeline.rs`): owns the pipeline state machine, repo
  acquisition (GitHub clone or local copy), stage transitions, and failure
  capture. Every transition appends an `Evidence` row.
- **Detector** (`backend/app/agents/detector.py` + `scanner/`, Rust: `crates/core/src/agents/detector.rs` + `scanner/`): static scan produces raw
  findings; the LLM triage pass dedupes and drops obvious noise.
- **Risk assessor** (`backend/app/agents/risk_assessor.py`, Rust: `crates/core/src/agents/risk.rs`): scores 0–10 with a rationale;
  low-confidence findings are penalized so the dashboard sorts by real risk.
- **Sandbox** (`backend/app/sandbox/runner.py`, Rust: `crates/core/src/sandbox/`): synthesizes a per-rule PoC and executes it
  isolated (Docker `--network none` preferred, subprocess fallback). PoCs prove
  sink reachability with markers — never real exploitation.
- **Validator** (`backend/app/agents/validator.py`, Rust: `crates/core/src/agents/validator.rs`): combines code context with the repro
  log to label true vs false positives before patching.
- **Patcher** (`backend/app/patcher/`, Rust: `crates/core/src/patcher/`): deterministic per-rule transforms produce the minimal fix; a syntax
  gate guarantees a safe, reviewable diff offline (parameterize,
  `shell=False`, `safe_load`, env secrets, path confinement, escaping).
- **Verifier** (`backend/app/verifier/`, Rust: `crates/core/src/verifier/`): applies the diff, re-scans the sink region,
  runs the target repo's pytest suite if present, and records
  `fixed | unfixed | inconclusive` with logs.

## Evidence model

`Scan 1—n Finding 1—n Patch 1—n Verification`, plus an append-only
`Evidence(scan_id, stage, actor, message)` timeline. The dashboard renders one
tab per stage (Code / Patch / Verification) and the full timeline, so every
claim is backed by an artifact: snippet, repro log, diff, rescan result, test log.
