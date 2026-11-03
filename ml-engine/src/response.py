"""Lab response actions: iptables DROP for attacker IPs (SOC host)."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

# Never block these (lab safety)
PROTECTED_NETWORKS = [
    "127.0.0.0/8",
    "192.168.221.136/32",  # IDS
    "192.168.221.138/32",  # SOC
    "::1/128",
]

CHAIN = os.getenv("SOC_ML_BLOCK_CHAIN", "SOC_ML_BLOCK")
AUDIT = Path(os.getenv("SOC_ML_BLOCK_AUDIT", "logs/block_audit.jsonl"))


def _protected() -> List[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(n, strict=False) for n in PROTECTED_NETWORKS]


def is_protected(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in _protected())


def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def ensure_chain() -> None:
    """Create dedicated iptables chain and jump from INPUT/FORWARD if missing."""
    if _run(["iptables", "-L", CHAIN, "-n"]).returncode != 0:
        _run(["iptables", "-N", CHAIN])
    # Jump once from INPUT / FORWARD
    for hook in ("INPUT", "FORWARD"):
        check = _run(["iptables", "-C", hook, "-j", CHAIN])
        if check.returncode != 0:
            _run(["iptables", "-I", hook, "1", "-j", CHAIN])


def list_blocked() -> List[str]:
    ensure_chain()
    out = _run(["iptables", "-S", CHAIN])
    ips: List[str] = []
    for line in (out.stdout or "").splitlines():
        # -A SOC_ML_BLOCK -s 192.168.221.30/32 -j DROP
        parts = line.split()
        if "-s" in parts:
            i = parts.index("-s")
            if i + 1 < len(parts):
                ips.append(parts[i + 1].split("/")[0])
    return sorted(set(ips))


def _audit(event: str, ip: str, detail: Dict[str, Any]) -> None:
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "ip": ip, **detail}
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def block_ip(ip: str, reason: str = "", actor: str = "ui") -> Dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"invalid IP: {ip}") from e
    if is_protected(ip):
        raise PermissionError(f"refusing to block protected lab IP: {ip}")

    ensure_chain()
    existing: Set[str] = set(list_blocked())
    if ip in existing:
        return {"ip": ip, "status": "already_blocked", "blocked": sorted(existing)}

    rc = _run(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
    if rc.returncode != 0:
        raise RuntimeError((rc.stderr or rc.stdout or "iptables failed").strip())

    _audit("block", ip, {"reason": reason, "actor": actor, "returncode": rc.returncode})
    return {"ip": ip, "status": "blocked", "reason": reason, "blocked": list_blocked()}


def unblock_ip(ip: str, actor: str = "ui") -> Dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"invalid IP: {ip}") from e

    ensure_chain()
    # Delete all matching source DROP rules
    while True:
        rc = _run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
        if rc.returncode != 0:
            break
    _audit("unblock", ip, {"actor": actor})
    return {"ip": ip, "status": "unblocked", "blocked": list_blocked()}
