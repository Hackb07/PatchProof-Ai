# PatchProof AI — An Autonomous AI Security Engineer

PatchProof AI scans a Python repo, investigates each finding with specialized
agents, reproduces it in a sandbox, generates a minimal patch, verifies the fix,
and presents the whole chain as evidence.

## Quickstart (local dev)

Requires [uv](https://docs.astral.sh/uv/) (`curl -LsSf astral.sh/uv/install.sh | sh`).
For a one-shot setup, run `./scripts/install.sh` instead of the manual steps below.

```bash
cp .env.example .env        # LLM_MOCK=1 works fully offline
uv sync                     # creates .venv and installs locked deps

# terminal 1: API on http://localhost:8000
uv run uvicorn app.main:app --app-dir backend --reload --port 8000

# terminal 2: dashboard on http://localhost:5173
npm --prefix frontend install
npm --prefix frontend run dev
```

Python dependencies live in `pyproject.toml` with a committed `uv.lock`;
`uv run pytest backend/tests -q` runs the suite.

Open http://localhost:5173 in a browser, paste a GitHub URL (or a local path
like `fixtures/vuln-app`), and watch the evidence timeline fill in.

## Quickstart (Docker)

```bash
docker compose up --build
```

API: http://localhost:8000 · Dashboard: http://localhost:5173

## Demo script

```bash
./scripts/demo.sh              # scans fixtures/vuln-app, prints the report
./scripts/demo.sh /path/to/repo
```

## API overview

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness + mock-mode flag |
| POST | `/api/scans` | `{"repo_url": "...", "branch": "HEAD"}` — clone/copy, run pipeline in background |
| GET | `/api/scans` | Recent scans (summary) |
| GET | `/api/scans/{id}` | Full report: findings, patches, verifications, evidence |
| POST | `/api/scans/{id}/rerun` | Re-run the pipeline |
| GET | `/api/github/file?scan_id=…&path=…` | Read a file from the scanned checkout |

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
  (markers/echo only, never real exploitation).

## Hackathon demo script (3 minutes)

1. Open the dashboard, submit `fixtures/vuln-app`.
2. Show the findings table: 7+ findings with severity, CWE, risk score.
3. Click SQL injection: snippet → repro log (`REPRODUCED`) → diff → verification
   (`fixed`, rescan clean, tests passed).
4. Scroll the evidence timeline: clone → scan → triage → risk → repro → patch → verify.
5. Flip to the terminal: `./scripts/demo.sh` prints the same report as JSON-derived text.

## Project layout

```
backend/app/
  main.py routers/        FastAPI API
  scanner/                AST + regex detectors (7 rules)
  agents/                 detector, risk-assessor, validator, planner
  sandbox/                PoC reproduction (docker or subprocess)
  patcher/                minimal-diff generation + applier
  verifier/               rescan + pytest + PoC re-check
  models.py store.py      SQLite evidence store
frontend/src/             React + Tailwind evidence console
fixtures/vuln-app/        intentionally vulnerable demo target
sandbox/                  PoC runner image
```
# PatchProof-Ai
