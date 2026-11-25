#!/usr/bin/env bash
# Sync friend's CIC research artifacts onto the SOC VM ML engine.
# Run from a machine that can SSH to 192.168.221.138.
set -euo pipefail

SOC_HOST="${SOC_HOST:-root@192.168.221.138}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/lab_ed25519}"
REMOTE_ROOT="${REMOTE_ROOT:-/opt/ml-engine}"
LOCAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ssh_opts=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new)

echo "[*] Ensure remote dirs"
ssh "${ssh_opts[@]}" "$SOC_HOST" "mkdir -p $REMOTE_ROOT/artifacts/cic $REMOTE_ROOT/src $REMOTE_ROOT/notebooks/cic"

echo "[*] Sync CIC models + config"
rsync -avz -e "ssh ${ssh_opts[*]}" \
  "$LOCAL_ROOT/artifacts/cic/" \
  "$SOC_HOST:$REMOTE_ROOT/artifacts/cic/"

echo "[*] Sync scoring modules"
rsync -avz -e "ssh ${ssh_opts[*]}" \
  "$LOCAL_ROOT/src/cic_scoring.py" \
  "$LOCAL_ROOT/src/scoring.py" \
  "$LOCAL_ROOT/src/score_cic_cli.py" \
  "$LOCAL_ROOT/src/api.py" \
  "$LOCAL_ROOT/src/schema.py" \
  "$SOC_HOST:$REMOTE_ROOT/src/"

echo "[*] Sync notebooks (optional)"
rsync -avz -e "ssh ${ssh_opts[*]}" \
  "$LOCAL_ROOT/notebooks/cic/" \
  "$SOC_HOST:$REMOTE_ROOT/notebooks/cic/"

echo "[*] Install xgboost/pyarrow in remote venv"
ssh "${ssh_opts[@]}" "$SOC_HOST" "bash -lc 'cd $REMOTE_ROOT && . .venv/bin/activate && pip install -q \"xgboost>=2.0.0,<4.0.0\" \"pyarrow>=14.0.0\"'"

echo "[*] Restart API"
ssh "${ssh_opts[@]}" "$SOC_HOST" "systemctl restart soc-ml-api && sleep 2 && curl -s http://127.0.0.1:8088/health"

echo "[+] Done"
