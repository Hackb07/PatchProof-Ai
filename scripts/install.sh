#!/usr/bin/env bash
# One-shot setup for PatchProof AI: toolchain + env file + backend build +
# frontend deps.
# Usage: ./scripts/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/4 toolchain =="
if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: Rust stable is required: https://rustup.rs (then restart this shell)" >&2
  exit 1
fi
echo "cargo: $(cargo --version)"

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js 18+ is required for the dashboard: https://nodejs.org" >&2
  exit 1
fi
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "ERROR: Node 18+ required, found $(node --version)" >&2
  exit 1
fi
echo "node: $(node --version)"

if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
  echo "NOTE: no C compiler found; install one if the build fails (Debian/Ubuntu: build-essential, macOS: Xcode CLT, Fedora: gcc)."
fi

echo "== 2/4 environment file =="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example (offline mock mode by default)"
else
  echo ".env already exists, leaving it alone"
fi

echo "== 3/4 backend build (cargo build) =="
cargo build --workspace

echo "== 4/4 frontend dependencies (npm install) =="
npm --prefix frontend install --no-audit --no-fund

echo ""
echo "Install complete. Start the app with:"
echo "  terminal 1: cargo run -p patchproof-api"
echo "  terminal 2: npm --prefix frontend run dev"
echo "then open http://localhost:5173 and scan fixtures/vuln-app"
