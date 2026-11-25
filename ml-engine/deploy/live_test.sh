#!/usr/bin/env bash
set -euo pipefail

echo "=== 1) HEALTH ==="
curl -s http://127.0.0.1:8088/health | python3 -m json.tool

echo "=== 2) CIC SCHEMA ==="
curl -s http://127.0.0.1:8088/cic/schema | python3 -c 'import sys,json; d=json.load(sys.stdin); print("robuste", len(d["variants"]["robuste"]), "complet", len(d["variants"]["complet"]), "ready", d["status"].get("ready"))'

echo "=== 3) SCORE CIC (zero vector) ==="
python3 <<'PY'
import json, urllib.request
sch = json.load(urllib.request.urlopen("http://127.0.0.1:8088/cic/schema"))
feats = {c: 0.0 for c in sch["variants"]["robuste"]}
body = json.dumps({"request_id":"live-cic-1","variant":"robuste","features":feats}).encode()
req = urllib.request.Request(
    "http://127.0.0.1:8088/score/cic",
    data=body,
    headers={"Content-Type":"application/json"},
)
print(json.dumps(json.load(urllib.request.urlopen(req)), indent=2))
PY

echo "=== 4) SCORE LAB (nmap alert) ==="
curl -s -X POST http://127.0.0.1:8088/score \
  -H "Content-Type: application/json" \
  -d '{"request_id":"live-lab-1","source":"manual","event":{"rule":{"id":"100101","level":10,"description":"SOC-LAB: Nmap TCP SYN scan detected via Suricata","groups":["soc_lab","nmap"]},"data":{"srcip":"192.168.221.30","dstip":"192.168.221.136","srcport":"45000","dstport":"22","proto":"TCP"},"agent":{"name":"suricata-ids"},"timestamp":"2026-11-03T20:00:00.000+0000"}}' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print({k:d.get(k) for k in ["prediction","risk_score","top_class","model_version"]})'

echo "=== 5) RESULTS / BRIDGE ==="
systemctl is-active soc-ml-bridge
curl -s "http://127.0.0.1:8088/results?limit=5" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("count", d.get("count"), "preds", d.get("predictions"), "avg_risk", d.get("avg_risk"))'

echo "=== 6) EXTERNAL ==="
curl -s http://192.168.221.138:8088/health \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("external ok", d.get("status"), "cic", (d.get("cic") or {}).get("ready"))'

echo "ALL TESTS PASSED"
