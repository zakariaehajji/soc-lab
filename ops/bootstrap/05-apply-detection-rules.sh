#!/usr/bin/env bash
# Push Suricata local.rules to IDS and Wazuh local_rules.xml into the manager container.
# Run from operator workstation (has SSH to IDS + SOC) OR on SOC with SSH to IDS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.sh"
load_inventory

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
KEY="${SSH_KEY:-$HOME/.ssh/lab_ed25519}"
USER="${SSH_USER:-root}"
IDS="${IDS_IP}"
SOC="${SOC_IP}"
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

SURICATA_RULES="$REPO_ROOT/detection/suricata/local.rules"
WAZUH_RULES="$REPO_ROOT/detection/wazuh/local_rules.xml"

[[ -f "$SURICATA_RULES" ]] || { echo "missing $SURICATA_RULES"; exit 1; }
[[ -f "$WAZUH_RULES" ]] || { echo "missing $WAZUH_RULES"; exit 1; }

log "Deploy Suricata rules → ${IDS}"
scp "${SSH_OPTS[@]}" "$SURICATA_RULES" "${USER}@${IDS}:/var/lib/suricata/rules/local.rules"
ssh "${SSH_OPTS[@]}" "${USER}@${IDS}" 'suricata -T -c /etc/suricata/suricata.yaml && kill -USR2 $(pidof suricata) || systemctl restart suricata'
ok "Suricata rules reloaded"

log "Deploy Wazuh local_rules.xml → ${SOC} manager container"
scp "${SSH_OPTS[@]}" "$WAZUH_RULES" "${USER}@${SOC}:/tmp/local_rules.xml"
ssh "${SSH_OPTS[@]}" "${USER}@${SOC}" bash -s <<'REMOTE'
set -euo pipefail
CTR=$(docker ps --format '{{.Names}}' | grep -E 'wazuh.manager|wazuh-manager' | head -1)
[[ -n "$CTR" ]] || { echo "wazuh manager container not found"; exit 1; }
docker cp /tmp/local_rules.xml "$CTR:/var/ossec/etc/rules/local_rules.xml"
docker exec "$CTR" /var/ossec/bin/wazuh-control reload || docker restart "$CTR"
echo "Wazuh rules reloaded in $CTR"
REMOTE
ok "Detection rules applied"
