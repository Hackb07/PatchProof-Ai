#!/usr/bin/env bash
# Demo: scan the bundled vulnerable fixture and print the evidence report.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${API:-http://localhost:8000}"
FIXTURE="${1:-$PWD/fixtures/vuln-app}"

echo "== PatchProof AI demo =="
echo "API: $API"
curl -sf "$API/api/health" | python3 -m json.tool

echo "-- submitting scan for $FIXTURE"
PAYLOAD=$(FIXTURE="$FIXTURE" python3 -c 'import json,os; print(json.dumps({"repo_url": os.environ["FIXTURE"]}))')
SCAN_ID=$(curl -sf -X POST "$API/api/scans" -H 'Content-Type: application/json' \
  -d "$PAYLOAD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "scan id: $SCAN_ID"

for _ in $(seq 1 40); do
  STATUS=$(curl -sf "$API/api/scans/$SCAN_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
  echo "status: $STATUS"
  if [[ "$STATUS" == "done" || "$STATUS" == "failed" ]]; then break; fi
  sleep 2
done

curl -sf "$API/api/scans/$SCAN_ID" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(f"== Report: {d[\"repo_url\"]} [{d[\"status\"]}] ==")
for f in d["findings"]:
    v = (f["patches"][0]["verifications"][0]["status"] if f["patches"] and f["patches"][0]["verifications"] else "?")
    print(f"- [{f[\"severity\"]}] {f[\"rule_id\"]} {f[\"file_path\"]}:{f[\"line_no\"]} risk={f[\"risk_score\"]} repro={f[\"reproduced\"]} verify={v}")
    print(f"    {f[\"title\"]}")
print("== Evidence ==")
for e in d["evidence"]:
    print(f"  [{e[\"stage\"]}] {e[\"actor\"]}: {e[\"message\"]}")
'
