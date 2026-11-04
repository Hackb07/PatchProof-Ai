# Demo: scan the bundled vulnerable fixture and print the evidence report.
# Usage: .\scripts\demo.ps1 [C:\path\to\repo] [-Api http://localhost:8000]
param(
    [string]$Repo = '',
    [string]$Api = 'http://localhost:8000'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = Join-Path $root 'fixtures\vuln-app' }

Write-Host '== PatchProof AI demo =='
Write-Host "API: $Api"
Invoke-RestMethod "$Api/api/health" | ConvertTo-Json

Write-Host "-- submitting scan for $Repo"
$scan = Invoke-RestMethod "$Api/api/scans" -Method Post -ContentType 'application/json' `
    -Body (@{ repo_url = $Repo } | ConvertTo-Json)
Write-Host "scan id: $($scan.id)"

$detail = $null
for ($i = 0; $i -lt 40; $i++) {
    $detail = Invoke-RestMethod "$Api/api/scans/$($scan.id)"
    Write-Host "status: $($detail.status)"
    if ($detail.status -eq 'done' -or $detail.status -eq 'failed') { break }
    Start-Sleep -Seconds 2
}

Write-Host "== Report: $($detail.repo_url) [$($detail.status)] =="
foreach ($f in $detail.findings) {
    $v = '?'
    if ($f.patches -and $f.patches[0].verifications) { $v = $f.patches[0].verifications[0].status }
    Write-Host "- [$($f.severity)] $($f.rule_id) $($f.file_path):$($f.line_no) risk=$($f.risk_score) repro=$($f.reproduced) verify=$v"
    Write-Host "    $($f.title)"
}
Write-Host '== Evidence =='
foreach ($e in $detail.evidence) {
    Write-Host "  [$($e.stage)] $($e.actor): $($e.message)"
}
