#!/usr/bin/env bash
# Install / refresh ML engine on SOC VM to match current lab state.
# Run ON the SOC VM as root. Prefers cloning this repo; can also sync from /tmp/soc-lab.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/common.sh"
load_inventory
need_root

ROOT="${ML_ENGINE_ROOT:-/opt/ml-engine}"
REPO_URL="${REPO_URL:-https://github.com/zakariaehajji/soc-lab.git}"
SRC_ML=""

# Prefer repo already on disk (when script runs from a clone)
if [[ -d "$REPO_ROOT/ml-engine/src" ]]; then
  SRC_ML="$REPO_ROOT/ml-engine"
elif [[ -d /tmp/soc-lab/ml-engine/src ]]; then
  SRC_ML=/tmp/soc-lab/ml-engine
else
  tmp=$(mktemp -d)
  git clone --depth 1 "$REPO_URL" "$tmp/soc-lab"
  SRC_ML="$tmp/soc-lab/ml-engine"
fi

log "Deploying ML engine from $SRC_ML → $ROOT"
mkdir -p "$ROOT"/{artifacts/cic,logs,src,notebooks/cic,deploy}
rsync -a --delete \
  --exclude '.venv' --exclude 'logs' --exclude '__pycache__' \
  --exclude 'data/cic/raw' --exclude 'data/cic/processed' \
  --exclude 'models' \
  "$SRC_ML/" "$ROOT/"

cd "$ROOT"
if [[ ! -d .venv ]]; then
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

# Secrets via EnvironmentFile (never hardcode passwords in unit files)
ENV_FILE="$ROOT/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<EOF
WAZUH_INDEXER_URL=${WAZUH_INDEXER_URL:-https://127.0.0.1:9200}
WAZUH_INDEXER_USER=${WAZUH_INDEXER_USER:-admin}
WAZUH_INDEXER_PASSWORD=${WAZUH_INDEXER_PASSWORD:-CHANGE_ME}
SOC_ML_API=${SOC_ML_API:-http://127.0.0.1:8088}
SOC_ML_MODEL=$ROOT/artifacts/model.joblib
SOC_ML_MODEL_MULTI=$ROOT/artifacts/model_multiclass.joblib
SOC_ML_ENRICHMENT=$ROOT/logs/enrichment.jsonl
SOC_ML_BLOCK_AUDIT=$ROOT/logs/block_audit.jsonl
SOC_ML_CIC_DIR=$ROOT/artifacts/cic
PYTHONPATH=$ROOT
EOF
  chmod 600 "$ENV_FILE"
  warn "Edit $ENV_FILE and set WAZUH_INDEXER_PASSWORD before enabling the bridge"
fi

install -m 644 "$ROOT/deploy/soc-ml-api.service" /etc/systemd/system/soc-ml-api.service
install -m 644 "$ROOT/deploy/soc-ml-bridge.service" /etc/systemd/system/soc-ml-bridge.service
systemctl daemon-reload
systemctl enable soc-ml-api
systemctl restart soc-ml-api
sleep 3
curl -sf "http://127.0.0.1:${SOC_ML_PORT:-8088}/health" | python3 -m json.tool || warn "API health failed"

if grep -q 'CHANGE_ME' "$ENV_FILE"; then
  warn "Bridge not started — set indexer password in $ENV_FILE then: systemctl enable --now soc-ml-bridge"
else
  systemctl enable --now soc-ml-bridge
  systemctl restart soc-ml-bridge
fi

ok "ML engine ready at http://${SOC_IP}:${SOC_ML_PORT:-8088}/ui"
ok "CIC research: POST /score/cic  |  Live lab: POST /score"
