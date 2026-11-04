# One-shot setup for PatchProof AI on Windows: toolchain + env file +
# backend build + frontend deps.
# Usage: .\scripts\install.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host '== 1/4 toolchain =='
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Write-Host 'ERROR: Rust stable is required: https://rustup.rs (then restart this shell)' -ForegroundColor Red
    exit 1
}
Write-Host "cargo: $(cargo --version)"
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Write-Host 'ERROR: Node.js 18+ is required for the dashboard: https://nodejs.org' -ForegroundColor Red
    exit 1
}
Write-Host "node: $(node --version)"
$nodeMajor = [int](node -p 'process.versions.node.split(".")[0]')
if ($nodeMajor -lt 18) {
    Write-Host "ERROR: Node 18+ required, found $(node --version)" -ForegroundColor Red
    exit 1
}
if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    Write-Host 'NOTE: no MSVC linker found; install VS Build Tools with the C++ workload if the build fails:' -ForegroundColor Yellow
    Write-Host '  winget install Microsoft.VisualStudio.2022.BuildTools --add Microsoft.VisualStudio.Workload.VCTools --silent'
}

Write-Host '== 2/4 environment file =='
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Write-Host 'Created .env from .env.example (offline mock mode by default)'
} else {
    Write-Host '.env already exists, leaving it alone'
}

Write-Host '== 3/4 backend build (cargo build) =='
cargo build --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '== 4/4 frontend dependencies (npm install) =='
npm --prefix frontend install --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ''
Write-Host 'Install complete. Start the app with:'
Write-Host '  terminal 1: cargo run -p patchproof-api'
Write-Host '  terminal 2: npm --prefix frontend run dev'
Write-Host 'then open http://localhost:5173 and scan fixtures/vuln-app'
