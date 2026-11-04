# PatchProof AI — An Autonomous AI Security Engineer

PatchProof AI scans a Python repo, investigates each finding with specialized
agents, reproduces it in a sandbox, generates a minimal patch, verifies the fix,
and presents the whole chain as evidence.

## Tech stack

| Layer | Technology |
|---|---|
| API backend | Rust (Axum 0.7, Tokio, Tower-HTTP CORS) |
| Core pipeline | Rust workspace crates: scanner, agents, sandbox, patcher, verifier |
| Storage | SQLite (rusqlite, bundled — no separate database) |
| LLM | Meta models via OpenAI-compatible chat API, or deterministic offline mock |
| Sandbox | Docker (`python:3.12-slim`, `--network none`) with subprocess fallback |
| Dashboard | React 18 + Vite 5 + Tailwind CSS 3 (Node 18+) |
| Scan target | Python repositories |
| Reference backend | Python (FastAPI + SQLAlchemy) in `backend/` — kept for reference; the Rust backend is the default |

## Prerequisites

Works on Windows, Linux, and macOS.

- Rust stable via [rustup](https://rustup.rs), plus a C compiler for some
  dependencies: Windows needs the MSVC Build Tools with the C++ workload,
  Debian/Ubuntu needs `build-essential`, macOS needs the Xcode command line
  tools, Fedora needs `gcc`.
- Node 18+ (dashboard only)
- Optional: Python 3.11+ (enables PoC execution, the `ast.parse` syntax gate, and target-repo tests; the pipeline still runs without it)
- Optional: Docker (sandboxed PoC runs) and `git` (only needed to scan GitHub URLs; local paths need no git)

## Quickstart (local dev)

For a one-shot setup, run `./scripts/install.sh` (Linux/macOS) or
`.\scripts\install.ps1` (Windows) instead of the manual steps below.

```bash
cp .env.example .env        # LLM_MOCK=1 works fully offline

# terminal 1: API on http://localhost:8000
cargo build --workspace
cargo run -p patchproof-api

# terminal 2: dashboard on http://localhost:5173
npm --prefix frontend install
npm --prefix frontend run dev
```

Open http://localhost:5173 in a browser, paste a GitHub URL (or a local path
like `fixtures/vuln-app`), and watch the evidence timeline fill in.

## Terminal UI

The `patchproof-tui` npm package scans a repository, polls progress, prints
findings, saves a Markdown report, and exports generated fixes as a reviewable
`.patch` bundle. Start the API first. Node.js 18+ is required.

```powershell
# Install globally after the package is published to npm
npm install --global patchproof-tui
patchproof-tui
```

The API defaults to `http://127.0.0.1:8000`; set `PATCHPROOF_API` to override
it and `PATCHPROOF_API_KEY` when API authentication is enabled. The TUI's
**Export fix patch** option writes the generated diffs for review and manual
application. The pipeline also applies and verifies patches in its scan
checkout. A suggested patch is not confirmed fixed until verification reports
`fixed`. The npm package source is in `packages/patchproof-tui/`.

## Coding-agent security skill

Claude Code can use the bundled `.claude/skills/patchproof-security/SKILL.md`
skill from this repository. Ask Claude to use the `patchproof-security` skill
to scan an authorized Python repository, produce a report, or review fixes.
For other coding agents, keep `AGENTS.md` and `SECURITY_REVIEW.md` in the
workspace context; the latter documents the API workflow and safe remediation
guidance. The current scanner targets seven Python vulnerability classes.
Reports include locations, severity, CWE, reproduction results, patch
suggestions, verification, and evidence. Do not present an unverified patch as
a resolved vulnerability.

The web console adapts its scan form, panels, navigation, and finding controls
to narrow screens. Select **Report** in the Findings panel to download a
human-readable Markdown report; **JSON** preserves full structured evidence
and **Diff** downloads the combined generated patch.

With a live model and Docker sandbox:

```bash
LLM_MOCK=0 META_API_KEY=... SANDBOX_BACKEND=docker cargo run -p patchproof-api
```

## Configuration

Environment variables (a `.env` file in the repo root is loaded automatically).
Defaults run fully offline with the mock LLM.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./patchproof.db` | SQLite file |
| `REPO_ROOT` | `<os-temp>/patchproof/repos` | Where scanned repos are copied/cloned |
| `LLM_MOCK` | `1` | `1` = deterministic mock; `0` + key = live model |
| `META_API_KEY` | _(empty)_ | Bearer [REDACTED] the Meta OpenAI-compatible API |
| `META_API_BASE` | `https://api.llama.meta.com/v1` | Chat-completions base URL |
| `META_MODEL` | `llama-4-scout` | Model name for live calls |
| `SANDBOX_BACKEND` | `auto` | `auto` \| `docker` \| `subprocess` |
| `SANDBOX_TIMEOUT_S` | `20` | Per-PoC timeout (docker gets +30s) |
| `SANDBOX_IMAGE` | `python:3.12-slim` | Docker image for PoCs and untrusted tests (build `sandbox/` for one with pytest) |
| `PATCHPROOF_API_KEY` | _(empty)_ | Shared secret for `/api/scans` + `/api/github` (empty = open) |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | API bind address/port |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Allowed UI origins (comma-separated) |
| `PYTHON` | _(auto-detect)_ | Explicit interpreter for PoCs/syntax/tests |

## Demo script

Requires the API running on `:8000`:

```bash
# Linux/macOS (needs curl and python3)
./scripts/demo.sh              # scans fixtures/vuln-app, prints the report
./scripts/demo.sh /path/to/repo
```

```powershell
# Windows (no extra dependencies)
.\scripts\demo.ps1
.\scripts\demo.ps1 C:\path\to\repo
```

## API overview

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness + mock-mode flag |
| POST | `/api/scans` | `{"repo_url": "...", "branch": "HEAD"}` — copy/clone, run pipeline in background |
| GET | `/api/scans?limit=50&offset=0` | Recent scan summaries (paginated, newest first) |
| GET | `/api/scans/{id}` | Full report: findings, patches, verifications, evidence |
| DELETE | `/api/scans/{id}` | Delete a scan, its results, and its checkout |
| POST | `/api/scans/{id}/rerun` | Re-run the pipeline |
| POST | `/api/scans/{id}/cancel` | Cancel a running scan (`409` when already terminal) |
| POST | `/api/github/import` | `{"repo_url": "..."}` — queue pipeline in background, returns scan id |
| GET | `/api/github/file?scan_id=…&path=…` | Read a file from the scanned checkout |

`repo_url` accepts a git URL, a local directory, or a `file://` path.
Scan ids are 12 hex chars; status flows through
`queued → scanning → triaging → patching → verifying → done`
(`failed`/`cancelled` are terminal).

## Tests and gates

```bash
cargo test --workspace            # everything (mock LLM, no network needed)
cargo test -p patchproof-core     # rule vectors + patcher round-trip
cargo test -p patchproof-api      # health, fixture e2e, 404/422 paths
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
npm --prefix frontend run build   # production UI build
```

## Docker

```bash
# Rust API image
docker build -t patchproof-api .
docker run --rm -p 8000:8000 -e LLM_MOCK=1 patchproof-api
```

`docker compose up --build` starts the Rust API + dashboard.

## MVP scope

- **Languages:** Python only.
- **Vulnerability classes (7):** SQL injection, command injection, XSS/unsafe
  template render, path traversal, insecure deserialization (pickle/yaml),
  hardcoded secrets, SSRF.
- **LLM:** Meta models via an OpenAI-compatible chat endpoint (`META_API_KEY`,
  `META_API_BASE`, `META_MODEL`). With no key — or `LLM_MOCK=1` — a
  deterministic mock keeps every stage runnable offline.
- **Sandbox:** Docker (`python:3.12-slim`, `--network none`) when available,
  otherwise a timeout-bounded local subprocess. PoCs are safe by construction
  (fixed markers only, never real exploitation).

## Hackathon demo script (3 minutes)

1. Open the dashboard, submit `fixtures/vuln-app`.
2. Show the findings table: 7+ findings with severity, CWE, risk score.
3. Click SQL injection: snippet → repro log (`REPRODUCED`) → diff → verification
   (`fixed`, rescan clean, tests passed).
4. Scroll the evidence timeline: clone → scan → triage → risk → repro → patch → verify.
5. Flip to the terminal: `./scripts/demo.sh` (`.\scripts\demo.ps1` on Windows) prints the same report as JSON-derived text.

## Project layout

```
crates/core/            Rust pipeline: config, SQLite store, scanner (7 rules),
                        agents, sandbox PoC runner, patch generator, verifier
crates/api/             Rust Axum HTTP API (lib + binary) on :8000
backend/app/            Original Python backend (FastAPI) — reference only
frontend/src/           React + Tailwind evidence console
fixtures/vuln-app/      intentionally vulnerable demo target
sandbox/                PoC runner image
```

Further reading: [ARCHITECTURE.md](ARCHITECTURE.md) (pipeline + agent roles),
[RUNNING.md](RUNNING.md) (full Rust backend guide), [RUST_PORT.md](RUST_PORT.md)
(port notes and verification status).
