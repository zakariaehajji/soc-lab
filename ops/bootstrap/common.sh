#!/usr/bin/env bash
# Shared helpers for SOC lab bootstrap scripts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

load_inventory() {
  local f="${LAB_INVENTORY:-$REPO_ROOT/ops/lab-inventory.env}"
  if [[ -f "$f" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$f"
    set +a
  elif [[ -f "$REPO_ROOT/ops/lab-inventory.env.example" ]]; then
    echo "[!] Using example inventory. Copy ops/lab-inventory.env.example -> ops/lab-inventory.env"
    set -a
    # shellcheck disable=SC1091
    . "$REPO_ROOT/ops/lab-inventory.env.example"
    set +a
  fi
  : "${SOC_IP:=192.168.221.138}"
  : "${IDS_IP:=192.168.221.136}"
  : "${KALI_IP:=192.168.221.30}"
  : "${ML_ENGINE_ROOT:=/opt/ml-engine}"
  : "${WAZUH_VERSION:=4.14.9}"
  : "${SURICATA_VERSION:=8.0.7}"
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[!] Run as root on the target VM"
    exit 1
  fi
}

log() { printf '[*] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
