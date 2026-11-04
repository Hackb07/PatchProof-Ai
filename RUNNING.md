# Running PatchProof AI (Rust backend)

PatchProof AI scans a Python repo for 7 vulnerability classes, reproduces each
finding in a sandbox, generates a minimal patch, verifies it, and serves the
results over a small HTTP API with a React UI.

This document covers the **Rust backend** (`crates/`). The original Python
backend (`backend/`) is kept untouched for reference; the React frontend
(`frontend/`) works unchanged against either backend on port 8000.

## Layout

- `crates/core` — `patchproof-core` library: config, SQLite store, static
  scanner (7 rules), agents (LLM/triage/risk/validator), sandbox PoC runner,
  patch generator + diff applier, verifier, pipeline orchestrator.
- `crates/api` — `patchproof-api`: Axum HTTP API (library + binary).
- `fixtures/vuln-app` — intentionally vulnerable Flask app used for demos
  and end-to-end tests (one sink per rule plus a `/safe` control).
- `Dockerfile` — multi-stage image for the Rust API.

## Prerequisites

- Rust stable via [rustup](https://rustup.rs) (works with both the MSVC and
  GNU toolchains on Windows; on Linux/macOS any default toolchain works),
  plus a C compiler for some dependencies: MSVC Build Tools with the C++
  workload on Windows, `build-essential` on Debian/Ubuntu, the Xcode
  command line tools on macOS, `gcc` on Fedora.
- Node 18+ (frontend only).
- Optional: Python 3.11+ with `pytest` (enables PoC execution, the `ast.parse`
  syntax gate, and target-repo tests; without it the pipeline still runs and
  marks those steps accordingly).
- Optional: Docker (sandbox runs PoCs in `python:3.12-slim --network none`
  when a daemon is available, else falls back to a timeout-bounded
  subprocess).

## Quick start

```sh
# 1. Build everything
cargo build --workspace

# 2. Run the full test suite (mock LLM, no network needed)
cargo test --workspace

# 3. Start the API on :8000
cargo run -p patchproof-api

# 4. In another terminal, start the web UI on :5173 (proxies /api to :8000)
npm --prefix frontend install
npm --prefix frontend run dev
```

Then open http://localhost:5173, or drive the API directly (see below).

## Configuration

All settings are environment variables (a `.env` file in the repo root is
loaded automatically). Defaults run fully offline with the mock LLM.

| Variable            | Default                                | Meaning                                              |
| ------------------- | -------------------------------------- | ---------------------------------------------------- |
| `DATABASE_URL`      | `sqlite:///./patchproof.db`            | SQLite file (path after the `sqlite://` prefix)      |
| `REPO_ROOT`         | `<os-temp>/patchproof/repos`           | Where scanned repos are copied/cloned (`%TEMP%` on Windows, `$TMPDIR` or `/tmp` elsewhere) |
| `LLM_MOCK`          | `1`                                    | `1` = deterministic mock; `0` + key = live model     |
| `META_API_KEY`      | _(empty)_                              | Bearer [REDACTED] the Meta OpenAI-compatible API        |
| `META_API_BASE`     | `https://api.llama.meta.com/v1`        | Chat-completions base URL                            |
| `META_MODEL`        | `llama-4-scout`                        | Model name for live calls                            |
| `SANDBOX_BACKEND`   | `auto`                                 | `auto` \| `docker` \| `subprocess`                   |
| `SANDBOX_TIMEOUT_S` | `20`                                   | Per-PoC timeout (docker gets +30s)                   |
| `SANDBOX_IMAGE`     | `python:3.12-slim`                     | Docker image for PoCs and untrusted tests            |
| `PATCHPROOF_API_KEY`| _(empty)_                              | Shared secret for `/api/scans` + `/api/github`       |
| `HOST` / `PORT`     | `127.0.0.1` / `8000`                   | API bind address/port                                |
| `CORS_ORIGINS`      | `http://localhost:5173,...`            | Allowed UI origins (comma-separated)                 |
| `PYTHON`            | _(auto-detect)_                        | Explicit interpreter for PoCs/syntax/tests           |

Example run with a live model and Docker sandbox:

```sh
LLM_MOCK=0 META_API_KEY=... SANDBOX_BACKEND=docker cargo run -p patchproof-api
```

## API reference

Base URL `http://localhost:8000`. Errors are `{"detail": "..."}`.

| Method | Path                      | Body / query                              | Result                                   |
| ------ | ------------------------- | ----------------------------------------- | ---------------------------------------- |
| GET    | `/api/health`             | —                                         | `{status, app, llm_mock}`                |
| POST   | `/api/scans`              | `{repo_url, branch?}`                     | Scan report; pipeline runs in background |
| GET    | `/api/scans`              | `?limit=50&offset=0`                      | Paginated scan summaries (newest first)  |
| GET    | `/api/scans/{id}`         | —                                         | Full report; poll until terminal         |
| DELETE | `/api/scans/{id}`         | —                                         | Deletes scan, results, and checkout      |
| POST   | `/api/scans/{id}/rerun`   | —                                         | Re-queues the scan, pipeline restarts    |
| POST   | `/api/scans/{id}/cancel`  | —                                         | Cancels a running scan (409 if terminal) |
| POST   | `/api/github/import`      | `{repo_url, branch?}`                     | Queues pipeline in background, returns id|
| GET    | `/api/github/file`        | `?scan_id=…&path=…`                       | File content (traversal-guarded, 100k)   |

`repo_url` accepts a git URL, a local directory, or a `file://` path
handy for the fixture: `POST /api/scans {"repo_url": "fixtures/vuln-app"}`
(or an absolute path). Scan ids are 12 hex chars; status flows through
`queued → scanning → triaging → patching → verifying → done`
(`failed`/`cancelled` are terminal; `failed` carries a truncated message
in `error`). The dashboard filters/sorts findings client-side and exports
the report as JSON or a combined `.patch` download.

Minimal smoke test (needs `curl` and `jq`; on Windows use
`.\scripts\demo.ps1` instead):

```sh
curl -s localhost:8000/api/health | jq .
ID=$(curl -s -X POST localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"repo_url": "fixtures/vuln-app"}' | jq -r .id)
for i in $(seq 1 60); do
  S=$(curl -s localhost:8000/api/scans/$ID | jq -r .status)
  echo "status=$S"; [ "$S" = done ] || [ "$S" = failed ] && break; sleep 2
done
curl -s localhost:8000/api/scans/$ID | jq '{status, rules: [.findings[].rule_id] | unique}'
```

## What the pipeline does

1. **Scan** — walks `*.py` (skipping `.git`, venvs, `node_modules`, …) with
   7 rules: SQLI (CWE-89), CMDI (78), XSS (79), PATHTRAV (22), DESER (502),
   SECRET (798), SSRF (918); dedupes on `(rule, line)`.
2. **Triage** — dedupes `(rule, file, line)` and asks the LLM KEEP/DROP
   (mock always keeps).
3. **Risk** — scores 0–10 from severity priors ± confidence (mock) or a
   parsed `RISK_SCORE` (live).
4. **Patching** — runs a per-rule PoC (expects a `REPRODUCED` marker),
   validates TRUE/FALSE_POSITIVE, then emits one unified diff per finding
   from deterministic per-rule fixes (syntax-gated, advisory fallback).
5. **Verify** — applies each diff (content-matched, so multi-patch files
   stay aligned), re-scans the sink region anchored on the fix comment,
   runs the target's pytest suite if present, and records
   `fixed` / `unfixed` / `inconclusive`. For remote (cloned) scans the
   test suite only runs inside Docker — without a daemon those runs are
   skipped rather than executing untrusted code on the host.

Every stage appends to an Evidence timeline (`clone/scan/triage/risk/
repro/patch/verify/done`) returned with the report.

## Tests

```sh
cargo test --workspace            # everything (mock LLM, fixture scan)
cargo test -p patchproof-core     # rule vectors + patcher round-trip
cargo test -p patchproof-api      # health, fixture e2e, 404/422 paths
```

## Docker

```sh
docker build -t patchproof-api .
docker run --rm -p 8000:8000 -e LLM_MOCK=1 patchproof-api
```

(`docker compose up --build` starts the Rust API + dashboard. For fully
sandboxed test runs, build the sandbox image once with
`docker build -t patchproof-sandbox sandbox/` and set
`SANDBOX_IMAGE=patchproof-sandbox`.)

## Troubleshooting

- **No Python found** — PoCs record `[error] no working python interpreter
  found`, syntax gates are skipped (patches still generated), repo tests
  report `tests_passed: null`. Candidates are probed, so broken entries
  (e.g. the Windows Store redirect stub) and versions below 3.11 are
  skipped automatically. Install Python 3.11+ or set `PYTHON=` to its path.
- **No Docker daemon** — sandbox falls back to subprocess automatically;
  set `SANDBOX_BACKEND=subprocess` to skip the probe.
- **Live LLM errors** — any failure falls back to the mock reply and tags
  it `[llm-fallback: …]`; check `META_API_KEY`/`META_API_BASE`.
- **Windows paths** — `DATABASE_URL=sqlite:///./patchproof.db` and relative
  `repo_url` values work; absolute paths (`C:/…` or `/C:/…`) are accepted.
