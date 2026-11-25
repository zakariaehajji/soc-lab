#!/usr/bin/env bash
# Bootstrap Ubuntu IDS VM: Suricata + Wazuh agent skeleton.
# Run ON the IDS VM as root after VMnet1 IP is set to 192.168.221.136.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.sh"
load_inventory
need_root

LAB_IFACE="${LAB_IFACE_IDS:-ens37}"
SOC="${SOC_IP}"
REPO_DIR="${REPO_DIR:-/opt/soc-lab}"

log "IDS bootstrap — Suricata ${SURICATA_VERSION} + Wazuh agent → ${SOC}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget gnupg lsb-release ca-certificates software-properties-common jq

# --- Suricata ---
if ! command -v suricata >/dev/null 2>&1; then
  add-apt-repository -y ppa:oisf/suricata-stable || true
  apt-get update -y
  apt-get install -y suricata
fi
ok "Suricata: $(suricata -V 2>&1 | head -1)"

mkdir -p /var/lib/suricata/rules /var/log/suricata
if [[ -f "$REPO_DIR/detection/suricata/local.rules" ]]; then
  cp "$REPO_DIR/detection/suricata/local.rules" /var/lib/suricata/rules/local.rules
elif [[ -f "$SCRIPT_DIR/../../detection/suricata/local.rules" ]]; then
  cp "$SCRIPT_DIR/../../detection/suricata/local.rules" /var/lib/suricata/rules/local.rules
else
  warn "local.rules not found next to script — copy detection/suricata/local.rules manually"
fi

YAML=/etc/suricata/suricata.yaml
if [[ -f "$YAML" ]]; then
  cp -a "$YAML" "/root/suricata.yaml.bak-$(date +%Y%m%d%H%M%S)"
  # Ensure local.rules is listed
  if ! grep -q 'local.rules' "$YAML"; then
    sed -i '/rule-files:/a\  - local.rules' "$YAML" || true
  fi
  # HTTP ports include 8080 (gobuster lab target)
  sed -i 's/HTTP_PORTS: "80"/HTTP_PORTS: "[80,8080]"/' "$YAML" || true
  # Point AF_PACKET at lab iface when present as placeholder
  if grep -q 'interface: eth0' "$YAML"; then
    sed -i "s/interface: eth0/interface: ${LAB_IFACE}/" "$YAML" || true
  fi
fi

# Permissions so Wazuh agent can read eve.json
id suricata >/dev/null 2>&1 || true
usermod -aG suricata wazuh 2>/dev/null || true
touch /var/log/suricata/eve.json
chown suricata:suricata /var/log/suricata/eve.json || true
chmod 644 /var/log/suricata/eve.json || true

suricata -T -c "$YAML" || warn "suricata -T reported issues — review YAML"
systemctl enable suricata
systemctl restart suricata
ok "Suricata listening intent on ${LAB_IFACE}"

# --- Wazuh agent ---
if [[ ! -d /var/ossec ]]; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -y
  WAZUH_MANAGER="$SOC" apt-get install -y wazuh-agent
fi

# Point agent at SOC + ship Suricata EVE
OSSEC=/var/ossec/etc/ossec.conf
if [[ -f "$OSSEC" ]]; then
  cp -a "$OSSEC" "/root/ossec.conf.bak-$(date +%Y%m%d%H%M%S)"
  # Ensure manager address
  sed -i "s|<address>.*</address>|<address>${SOC}</address>|" "$OSSEC" || true
  if ! grep -q 'eve.json' "$OSSEC"; then
    cat >> "$OSSEC" <<'EOF'

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
EOF
  fi
fi

# Set agent name if tool exists
if [[ -x /var/ossec/bin/agent-auth ]]; then
  warn "Enroll with: /var/ossec/bin/agent-auth -m ${SOC} -A ${WAZUH_AGENT_NAME:-suricata-ids}"
fi

systemctl enable wazuh-agent
systemctl restart wazuh-agent || true
ok "IDS bootstrap complete. Enroll agent if not yet connected, then run 05-apply-detection-rules.sh from SOC."
