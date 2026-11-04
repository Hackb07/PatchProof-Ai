# PatchProof AI — Go backend (`backend-go/`)

A port of the Rust backend (`crates/api` + `crates/core`) to Go, with full
API, database, and environment compatibility. The frontend (`frontend/`)
talks to it unchanged.

- Module: `github.com/patchproof/patchproof-go`
- HTTP: stdlib `net/http` + `http.ServeMux` (Go 1.22+ method patterns) —
  no router dependency.
- SQLite: `modernc.org/sqlite` (pure Go, no cgo, Windows-friendly).
- No other runtime dependencies: ids (`crypto/rand`), subprocesses
  (`os/exec`), LLM calls (`net/http`), and a minimal `.env` loader are all
  hand-rolled from the standard library.

Why `modernc.org/sqlite` over `mattn/go-sqlite3`: it needs no C toolchain,
so `go build` works on Windows/macOS/Linux with zero setup. (Fallback note:
if cgo is ever acceptable, swapping the driver import plus the DSN builder
in `internal/store/store.go` is the only change needed.)

## Layout

| Path | Ports |
|---|---|
| `cmd/api/main.go` | `crates/api/src/main.rs` (boot, init_db, stale-scan recovery, serve) |
| `internal/config/config.go` | `crates/core/src/config.rs` |
| `internal/model/model.go` | `crates/core/src/model.rs` |
| `internal/store/store.go` | `crates/core/src/store.rs` |
| `internal/scanner/rules.go`, `scanner.go` | `crates/core/src/scanner/{rules,scan}.rs` |
| `internal/agents/{llm,detector,risk,validator}.go` | `crates/core/src/agents/*.rs` |
| `internal/sandbox/sandbox.go` | `crates/core/src/sandbox/mod.rs` |
| `internal/patcher/{generator,applier}.go` | `crates/core/src/patcher/*.rs` |
| `internal/verifier/verifier.go` | `crates/core/src/verifier/mod.rs` |
| `internal/pipeline/pipeline.go` | `crates/core/src/pipeline.rs` |
| `internal/api/{server,errors,dto,auth,cors,health,scans,github}.go` | `crates/api/src/{lib,schemas,routes/*}.rs` |
| `internal/util/util.go` | ids, timestamps, `truncate_chars` |

## Prerequisites

- Go 1.26+ (`go version`).
- Network access to the Go module proxy for the first build
  (`GOPROXY=https://proxy.golang.org`); after that the module cache is
  enough. Dependencies are **not** vendored (the SQLite driver tree is
  ~130 MB).
- Optional: Python 3.11+ on `PATH` (or `PYTHON=` override) for PoC
  reproduction, the `ast.parse` syntax gate, and target-repo pytest runs;
  `git` for cloning remote repos; `docker` for containerized sandboxes.
  Everything degrades gracefully when they are absent.

## Run

From this directory (`backend-go/`):

```sh
go run ./cmd/api
```

With explicit env (same names as the Rust backend):

```sh
LLM_MOCK=1 DATABASE_URL='sqlite://E:/data/patchproof.db' PORT=8000 go run ./cmd/api
```

Then scan the vulnerable fixture (spot-check parity with
`make demo-scan` against the Rust API):

```sh
curl -X POST localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"repo_url": "../fixtures/vuln-app"}'
```

Poll `GET /api/scans/<id>` until `status` is `done`, then inspect
`findings[].patches[].verifications[]`.

## Test

```sh
go build ./...
go vet ./...
go test ./...
```

Test files mirror the Rust suites:

| Go test | Mirrors |
|---|---|
| `internal/scanner/rules_test.go` | `core/tests/test_rules.rs` (all 15 cases) |
| `internal/patcher/patcher_test.go` | `core/tests/test_patcher.rs` (7 round-trip tests) |
| `internal/api/api_test.go` | `api/tests/test_api.rs` (health, e2e, 404/422, list, rerun, import, auth) + file-viewer and CORS tests |
| `internal/config/config_test.go`, `internal/sandbox/sandbox_test.go` | `core/tests/test_portability.rs` + config unit tests |
| `internal/store/store_test.go` | store lifecycle (no Rust counterpart; guards the new driver) |

The patcher/API tests read the shared workspace fixture
`../../fixtures/vuln-app` (same as the Rust tests via `CARGO_MANIFEST_DIR`).

## Environment

Same variables as `config.rs` (`APP_NAME`, `DATABASE_URL`, `REPO_ROOT`,
`LLM_MOCK`, `META_API_KEY`, `META_API_BASE`, `META_MODEL`,
`SANDBOX_BACKEND`, `SANDBOX_TIMEOUT_S`, `SANDBOX_IMAGE`, `CORS_ORIGINS`,
`PATCHPROOF_API_KEY`, `HOST`, `PORT`, `PYTHON`). A `.env` file in the
working directory is loaded without overriding real env vars (dotenvy
parity). Defaults: app `PatchProof AI`, db `sqlite:///./patchproof.db`
(resolves to the current drive root on Windows, exactly like the Rust
build — prefer an absolute `sqlite://` URL), repo root under the OS temp
dir, `LLM_MOCK=true`, sandbox `auto`/20s/`python:3.12-slim`, CORS
`http://localhost:5173,http://127.0.0.1:5173`, bind `127.0.0.1:8000`.

## Compatibility table

| Area | Status | Notes |
|---|---|---|
| Routes | ✅ identical | `GET /api/health`, `POST/GET /api/scans`, `GET /api/scans/{id}`, `POST /api/scans/{id}/rerun`, `POST /api/github/import`, `GET /api/github/file` |
| JSON shapes | ✅ identical | Same field names, nesting, `{"detail": msg}` errors, `finished_at`/`tests_passed` nullability; empty lists serialize as `[]` |
| `risk_score` rendering | ⚠️ cosmetic | Whole scores render `5` (Go) vs `5.0` (Rust); both parse to the same float |
| Status/validation | ✅ identical | 404/422/500/401 mapping, `repo_url`/`branch` limits, `HEAD` default, invalid-JSON 422 |
| Auth | ✅ identical | Open when key unset; else exact `X-Api-Key` or `Authorization: Bearer` match, 401 otherwise |
| CORS | ✅ identical | `*` wildcard (no creds), empty deny, explicit list + credentials + `Content-Type,Authorization` |
| SQLite schema | ✅ identical | Same tables/columns/defaults/indexes; WAL + 5s busy timeout; DB files interchangeable |
| Scanner (7 rules) | ✅ identical | Same regexes, taint helpers, confidences, dedupe, skip dirs, evidence |
| Triage/risk/validator | ✅ identical | Same prompts, token caps (800), verdict parsing (unlabeled keeps/confirms), mock strings, score math (1dp) |
| LLM client | ✅ identical | Mock when `llm_mock \|\| key empty`; live `POST {base}/chat/completions`, temp 0.1, 30s, `[llm-fallback]` |
| Sandbox | ✅ identical | Same PoC templates/markers, backend pick, docker flags, timeouts, log shapes, truncation (4000) |
| Patcher | ✅ identical | Same per-rule transforms, helpers, syntax gate + bracket fallback, structured diffs, bottom-up apply (radius 80) |
| Verifier | ✅ identical | Same decide/rescan/legacy logic, pytest handling, docker tests, truncation (3000) |
| Pipeline | ✅ identical | Same stage machine, background tasks, evidence timeline, stale-scan recovery, clone/copy behavior |
| Behavior without Python | ✅ identical | Repro attempts record `[error] no working python ...`, patches fall back to the bracket gate |

Known minor divergences: `GET /api/github/file` with a missing `scan_id`
query param returns 404 (Rust's extractor returns 400 there); absolute
`path` params are rejected as 404 in both (matched explicitly).
