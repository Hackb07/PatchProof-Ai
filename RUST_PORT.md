# PatchProof AI — Rust port

Idiomatic Rust rewrite of the Python backend (`backend/`). The original
Python sources, the React frontend (`frontend/`), and the fixture app
(`fixtures/vuln-app/`) are untouched; the Rust workspace lives alongside
them and serves the same API on port 8000.

## Layout

- `Cargo.toml` — virtual workspace (`crates/core`, `crates/api`)
- `crates/core` — `patchproof-core` library:
  `config`, `model`, `store` (SQLite), `scanner` (rules + repo walk),
  `agents` (llm/detector/risk/validator), `sandbox` (PoC runner),
  `patcher` (generator + diff applier), `verifier`, `pipeline`
- `crates/api` — `patchproof-api`: axum HTTP API (lib + binary),
  routes `health` / `scans` / `github`, serde schemas, shared state
- `Dockerfile` — multi-stage Rust API image, used by `docker-compose.yml`

## Build / run / test

```sh
cargo build --workspace
cargo test --workspace

# Run the API (same port/env as the Python backend):
DATABASE_URL=sqlite:///./patchproof.db LLM_MOCK=1 \
  cargo run -p patchproof-api
# Web UI unchanged:
npm --prefix frontend run dev   # :5173, proxies /api to :8000
```

Useful gates: `cargo fmt --all --check`,
`cargo clippy --all-targets -- -D warnings`.

## Behavior contracts preserved

- Routes: `GET /api/health`, `POST/GET /api/scans` (list returns
  lightweight summaries), `GET /api/scans/{id}`,
  `POST /api/scans/{id}/rerun` (clears prior results first),
  `POST /api/github/import` (queues in background),
  `GET /api/github/file`
- Scan lifecycle `queued|scanning|triaging|patching|verifying|done|failed`,
  12-hex ids, findings sorted by `(-risk, file, line)`, evidence by time
- Truncations: file view 100k chars, repro log 4000, test log 3000,
  error 2000; `404 'scan not found'`, `422` empty import, traversal guard
- Same 7 rules + severities/CWEs, same PoC templates/markers, same
  deterministic fixes and helper names (`_confined_path`, `_checked_url`),
  content-matched diff application, marker-anchored rescan, same evidence
  stages/messages (plus per-patch/per-verification rows linked via `ref_id`).
  Target-repo pytest runs on the host only for local-path scans; remote
  scans require Docker, otherwise tests are reported as skipped.

## Deliberate implementation substitutions

- `rusqlite` (bundled) instead of `sqlx`: same SQLite schema with
  short-lived connections; no async runtime/TLS feature coupling
- `git` CLI via `tokio::process` instead of `gix`: same
  `--depth 1` + branch semantics without native bindings
- Line-oriented regex detectors instead of `tree-sitter`: identical
  results on all single-line sinks and hardened shapes in the test
  vectors; multi-line calls are attributed to the tell-tale token line
- Hand-rolled single-hunk unified diff instead of the `similar` crate
- Direct env parsing (+`dotenvy`) instead of the `config` crate
- `crates/api/src/lib.rs` added so integration tests can build the app
  (binary-only crates cannot be imported by `tests/`)

## Verification status

`cargo test --workspace` passes (rule vectors plus edge-case, patcher
round-trip and sequential-apply, API health / fixture e2e / rerun /
summaries / 404-422 paths), as do `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets -- -D warnings`.
Fixes applied since the initial port: 3 compile errors (a string
literal in `generator.rs`, a double dereference in `rules.rs`), axum
0.7 route syntax (`:id`), a valid CORS layer, comment-aware scanning,
and 3 clippy lints.
