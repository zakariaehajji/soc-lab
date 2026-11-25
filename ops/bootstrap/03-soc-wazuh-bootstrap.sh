#!/usr/bin/env bash
# Bootstrap Ubuntu SOC VM: Docker + Wazuh 4.14.9 single-node stack.
# Run ON the SOC VM as root after VMnet1 IP is set to 192.168.221.138.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.sh"
load_inventory
need_root

COMPOSE_DIR="${WAZUH_COMPOSE_DIR:-/opt/wazuh-docker/single-node}"
WAZUH_TAG="${WAZUH_VERSION:-4.14.9}"

log "SOC bootstrap — Wazuh Docker ${WAZUH_TAG}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget git jq ca-certificates gnupg lsb-release

if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi
ok "Docker: $(docker --version)"

if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y docker-compose-plugin || true
fi

mkdir -p "$(dirname "$COMPOSE_DIR")"
if [[ ! -d "$COMPOSE_DIR" ]]; then
  tmp=$(mktemp -d)
  git clone --depth 1 --branch "v${WAZUH_TAG}" https://github.com/wazuh/wazuh-docker.git "$tmp/wazuh-docker" \
    || git clone --depth 1 https://github.com/wazuh/wazuh-docker.git "$tmp/wazuh-docker"
  if [[ -d "$tmp/wazuh-docker/single-node" ]]; then
    mkdir -p /opt/wazuh-docker
    cp -a "$tmp/wazuh-docker/single-node" /opt/wazuh-docker/
  else
    warn "Could not locate single-node folder — place official compose under ${COMPOSE_DIR}"
  fi
  rm -rf "$tmp"
fi

cd "$COMPOSE_DIR"
# Generate certs if the official script exists
if [[ -x ./generate-indexer-certs.sh ]]; then
  log "Generating indexer certs"
  ./generate-indexer-certs.sh || true
fi

log "Pulling and starting Wazuh stack (first run can take several minutes)"
docker compose up -d

sleep 15
docker compose ps
ok "Wazuh stack requested. Dashboard: https://${SOC_IP}/"
ok "Next: enroll IDS agent, apply detection/wazuh/local_rules.xml, then 04-soc-ml-engine-bootstrap.sh"

cat <<EOF

Manual post-steps (official Wazuh docs):
  1) Open https://${SOC_IP}/ and set/change default passwords.
  2) From IDS: /var/ossec/bin/agent-auth -m ${SOC_IP} -A suricata-ids
  3) Copy repo detection/wazuh/local_rules.xml into the manager container
     (see 05-apply-detection-rules.sh).

EOF
