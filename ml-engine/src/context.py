"""Extract network / host context from Wazuh or Suricata events."""

from __future__ import annotations

from typing import Any, Dict, Optional

# Known lab inventory (VMnet1)
LAB_HOSTS: Dict[str, Dict[str, str]] = {
    "192.168.221.30": {
        "name": "kali",
        "role": "attacker",
        "os": "Kali Linux",
        "notes": "Offensive lab host",
    },
    "192.168.221.135": {
        "name": "windows-notes",
        "role": "endpoint",
        "os": "Windows",
        "notes": "Windows notes / victim candidate",
    },
    "192.168.221.136": {
        "name": "suricata-ids",
        "role": "sensor",
        "os": "Linux",
        "notes": "Suricata 8 + wazuh-agent",
    },
    "192.168.221.138": {
        "name": "soc",
        "role": "siem",
        "os": "Linux",
        "notes": "Wazuh manager/indexer/dashboard + ML API",
    },
}


def lookup_host(ip: Optional[str]) -> Optional[Dict[str, str]]:
    if not ip:
        return None
    h = LAB_HOSTS.get(ip)
    if not h:
        return {"name": "unknown", "role": "unknown", "os": "unknown", "notes": "Not in lab inventory"}
    return dict(h)


def _data(event: Dict[str, Any]) -> Dict[str, Any]:
    d = event.get("data")
    return d if isinstance(d, dict) else {}


def extract_context(event: Dict[str, Any]) -> Dict[str, Any]:
    """Pull src/dst, ports, agent/machine, MITRE from a Wazuh alert."""
    data = _data(event)
    flow = data.get("flow") if isinstance(data.get("flow"), dict) else {}
    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    agent = event.get("agent") if isinstance(event.get("agent"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

    src_ip = (
        data.get("src_ip")
        or data.get("srcip")
        or flow.get("src_ip")
        or event.get("src_ip")
        or event.get("srcip")
    )
    dst_ip = (
        data.get("dest_ip")
        or data.get("dst_ip")
        or data.get("dstip")
        or flow.get("dest_ip")
        or event.get("dest_ip")
        or event.get("dstip")
    )
    src_port = data.get("src_port") or data.get("srcport") or flow.get("src_port")
    dst_port = data.get("dest_port") or data.get("dst_port") or data.get("dstport") or flow.get("dest_port")
    proto = data.get("proto") or data.get("protocol") or event.get("proto")

    src_host = lookup_host(str(src_ip) if src_ip else None)
    dst_host = lookup_host(str(dst_ip) if dst_ip else None)
    agent_ip = agent.get("ip")
    agent_host = lookup_host(str(agent_ip) if agent_ip else None)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": str(src_port) if src_port is not None else None,
        "dst_port": str(dst_port) if dst_port is not None else None,
        "proto": proto,
        "iface": data.get("in_iface"),
        "direction": data.get("direction"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "suricata_action": alert.get("action"),
        "category": alert.get("category"),
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent_ip,
            "host": agent_host,
        },
        "src_host": src_host,
        "dst_host": dst_host,
        "rule_level": rule.get("level"),
        "rule_groups": rule.get("groups") or [],
        "mitre": {
            "tactic": mitre.get("tactic") or [],
            "technique": mitre.get("technique") or [],
            "id": mitre.get("id") or [],
        },
        "recommended_action": _recommend(src_ip, src_host, rule),
    }


def _recommend(src_ip: Optional[str], src_host: Optional[Dict[str, str]], rule: Dict[str, Any]) -> Dict[str, Any]:
    role = (src_host or {}).get("role")
    level = int(rule.get("level") or 0)
    can_block = bool(src_ip) and role not in {"siem", "sensor"}
    if role == "attacker" or level >= 6:
        action = "block_src_ip"
        reason = "Source matches attacker inventory or elevated alert level"
    elif can_block:
        action = "review_then_block"
        reason = "Unknown/external source — review then block if confirmed"
    else:
        action = "monitor"
        reason = "Protected lab infrastructure — do not auto-block"
    return {
        "action": action,
        "can_block": can_block,
        "target_ip": src_ip if can_block else None,
        "reason": reason,
    }
