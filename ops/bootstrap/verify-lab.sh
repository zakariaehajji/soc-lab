#!/usr/bin/env bash
# End-to-end health check against a running lab (from workstation or SOC).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.sh"
load_inventory

SOC="${SOC_IP}"
IDS="${IDS_IP}"
KEY="${SSH_KEY:-$HOME/.ssh/lab_ed25519}"
USER="${SSH_USER:-root}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=8)
[[ -f "$KEY" ]] && SSH_OPTS+=(-i "$KEY")

fail=0
check() {
  local name="$1"; shift
  if "$@"; then ok "$name"; else warn "FAIL: $name"; fail=1; fi
}

echo "=== SOC lab verify (${SOC} / ${IDS}) ==="

check "SOC SSH" ssh "${SSH_OPTS[@]}" "${USER}@${SOC}" 'true'
check "SOC ML health" curl -sf "http://${SOC}:${SOC_ML_PORT:-8088}/health" >/dev/null
check "SOC ML CIC ready" bash -c "curl -sf http://${SOC}:${SOC_ML_PORT:-8088}/health | grep -q '\"ready\": true\|\"ready\":true'"
check "SOC dashboard TCP/443" bash -c "timeout 3 bash -c '</dev/tcp/${SOC}/443' 2>/dev/null || curl -skf https://${SOC}/ >/dev/null"

if ssh "${SSH_OPTS[@]}" "${USER}@${IDS}" 'true' 2>/dev/null; then
  check "IDS Suricata active" ssh "${SSH_OPTS[@]}" "${USER}@${IDS}" 'systemctl is-active --quiet suricata'
  check "IDS Wazuh agent active" ssh "${SSH_OPTS[@]}" "${USER}@${IDS}" 'systemctl is-active --quiet wazuh-agent'
else
  warn "IDS SSH unreachable — skip Suricata/agent checks"
fi

check "Lab score ATTACK" bash -c "curl -sf -X POST http://${SOC}:${SOC_ML_PORT:-8088}/score -H 'Content-Type: application/json' -d '{\"request_id\":\"verify-1\",\"source\":\"manual\",\"event\":{\"rule\":{\"id\":\"100101\",\"level\":10,\"description\":\"SOC-LAB: Nmap TCP SYN scan detected via Suricata\",\"groups\":[\"soc_lab\",\"nmap\"]},\"data\":{\"srcip\":\"192.168.221.30\",\"dstip\":\"192.168.221.136\",\"srcport\":\"45000\",\"dstport\":\"22\",\"proto\":\"TCP\"},\"agent\":{\"name\":\"suricata-ids\"},\"timestamp\":\"2026-11-03T20:00:00.000+0000\"}}' | grep -q ATTACK"

if [[ "$fail" -eq 0 ]]; then
  ok "ALL CHECKS PASSED"
  exit 0
fi
warn "Some checks failed"
exit 1
