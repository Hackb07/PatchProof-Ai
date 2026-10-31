#!/usr/bin/env bash
# One-shot setup for PatchProof AI: toolchain + Python env + frontend deps.
# Usage: ./scripts/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"

echo "== 1/4 toolchain =="
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
echo "uv: $(uv --version)"

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

echo "== 2/4 environment file =="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example (offline mock mode by default)"
else
  echo ".env already exists, leaving it alone"
fi

echo "== 3/4 Python dependencies (uv sync) =="
uv sync

echo "== 4/4 frontend dependencies (npm install) =="
npm --prefix frontend install --no-audit --no-fund

echo ""
echo "Install complete. Start the app with:"
echo "  terminal 1: uv run uvicorn app.main:app --app-dir backend --port 8000"
echo "  terminal 2: npm --prefix frontend run dev"
echo "then open http://localhost:5173 and scan fixtures/vuln-app"
