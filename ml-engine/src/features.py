"""Feature extraction from Suricata EVE / Wazuh alert JSON (lab-native)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .schema import FEATURE_NAMES

KALI = "192.168.221.30"
IDS = "192.168.221.136"
SOC = "192.168.221.138"


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def _parse_hour(ts: Optional[str]) -> float:
    if not ts:
        return 0.0
    try:
        t = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(t[:26].replace("Z", "") if "Z" in ts else t.split("+")[0][:26])
        return float(dt.hour)
    except Exception:
        try:
            return float(ts[11:13])
        except Exception:
            return 0.0


def _proto_flags(proto: Optional[str]) -> Dict[str, float]:
    p = (proto or "").upper()
    return {
        "proto_tcp": 1.0 if p == "TCP" else 0.0,
        "proto_udp": 1.0 if p == "UDP" else 0.0,
        "proto_icmp": 1.0 if p in {"ICMP", "IPV4-ICMP", "ICMPV4"} else 0.0,
        "proto_other": 1.0 if p and p not in {"TCP", "UDP", "ICMP", "IPV4-ICMP", "ICMPV4"} else 0.0,
    }


def _sid_family(sid: Optional[int]) -> Dict[str, float]:
    sid = int(sid or 0)
    return {
        "sid_nmap_family": 1.0 if 1000001 <= sid <= 1000007 else 0.0,
        "sid_web_family": 1.0 if 1000010 <= sid <= 1000019 else 0.0,
        "sid_icmp_family": 1.0 if 1000020 <= sid <= 1000029 else 0.0,
        "sid_et_or_other": 1.0 if sid and not (1000001 <= sid <= 1000029) else 0.0,
    }


def _rule_meta(event: Dict[str, Any]) -> Dict[str, Any]:
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    return {
        "id": str(rule.get("id") or ""),
        "level": _to_float(rule.get("level"), 0.0),
        "description": str(rule.get("description") or ""),
        "groups": [str(g) for g in (rule.get("groups") or [])],
    }


def unwrap_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Wazuh-alert-wrapped Suricata JSON into a flat-ish event."""
    if not event:
        return {}
    rule = _rule_meta(event)
    agent = (event.get("agent") or {}).get("name") if isinstance(event.get("agent"), dict) else None
    ts = event.get("timestamp") or event.get("@timestamp")

    if "data" in event and isinstance(event.get("data"), dict):
        data = event["data"]
        if "suricata" in data and isinstance(data["suricata"], dict):
            eve = data["suricata"].get("eve") or data["suricata"]
            if isinstance(eve, dict):
                merged = dict(eve)
                merged["_wazuh_rule_id"] = rule["id"]
                merged["_wazuh_rule_desc"] = rule["description"]
                merged["_wazuh_rule_level"] = rule["level"]
                merged["_wazuh_groups"] = rule["groups"]
                merged["_agent"] = agent
                merged.setdefault("timestamp", ts)
                return merged
        if any(k in data for k in ("alert", "event_type", "srcip", "dstip", "src_ip", "dest_ip", "proto")):
            merged = dict(data)
            merged["_wazuh_rule_id"] = rule["id"]
            merged["_wazuh_rule_desc"] = rule["description"]
            merged["_wazuh_rule_level"] = rule["level"]
            merged["_wazuh_groups"] = rule["groups"]
            merged["_agent"] = agent
            merged.setdefault("timestamp", ts)
            return merged

    merged = dict(event)
    merged["_wazuh_rule_id"] = rule["id"]
    merged["_wazuh_rule_desc"] = rule["description"]
    merged["_wazuh_rule_level"] = rule["level"]
    merged["_wazuh_groups"] = rule["groups"]
    merged["_agent"] = agent
    merged.setdefault("timestamp", ts)
    return merged


def _family_from_text(rule_id: str, desc: str, groups: List[str]) -> Dict[str, float]:
    blob = f"{rule_id} {desc} {' '.join(groups)}".lower()
    nmap = any(
        x in blob
        for x in ("nmap", "syn scan", "port sweep", "xmas", "null scan", "connect-style", "10010")
    )
    web = any(x in blob for x in ("web", "gobuster", "http", ".git", "/admin", "10011"))
    icmp = any(x in blob for x in ("icmp", "ping", "10012"))
    return {
        "sid_nmap_family": 1.0 if nmap else 0.0,
        "sid_web_family": 1.0 if web else 0.0,
        "sid_icmp_family": 1.0 if icmp else 0.0,
        "sid_et_or_other": 1.0 if (rule_id or desc) and not (nmap or web or icmp) else 0.0,
    }


def extract_features(
    event: Optional[Dict[str, Any]] = None, features: Optional[Dict[str, float]] = None
) -> Dict[str, float]:
    if features:
        return {k: _to_float(features.get(k, 0.0)) for k in FEATURE_NAMES}

    ev = unwrap_event(event or {})
    alert = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    flow = ev.get("flow") if isinstance(ev.get("flow"), dict) else {}

    proto = ev.get("proto") or ev.get("protocol")
    src = ev.get("src_ip") or ev.get("srcip")
    dst = ev.get("dest_ip") or ev.get("dst_ip") or ev.get("dstip")
    sport = _to_float(ev.get("src_port") or ev.get("srcport"), 0.0)
    dport = _to_float(ev.get("dest_port") or ev.get("dst_port") or ev.get("dstport"), 0.0)
    sid = alert.get("signature_id") or ev.get("signature_id")
    try:
        sid_i = int(sid) if sid is not None else 0
    except Exception:
        sid_i = 0
    sig = alert.get("signature") or ev.get("signature") or ev.get("_wazuh_rule_desc") or ""
    prio = _to_float(alert.get("severity") or alert.get("priority") or ev.get("_wazuh_rule_level") or 0.0)

    family = _sid_family(sid_i)
    if sid_i == 0:
        family = _family_from_text(
            str(ev.get("_wazuh_rule_id") or ""),
            str(sig),
            list(ev.get("_wazuh_groups") or []),
        )

    feats = {
        "hour_utc": _parse_hour(ev.get("timestamp") or ev.get("@timestamp")),
        **_proto_flags(str(proto) if proto else None),
        "src_is_kali": 1.0 if src == KALI else 0.0,
        "dst_is_ids": 1.0 if dst == IDS else 0.0,
        "dst_is_soc": 1.0 if dst == SOC else 0.0,
        "src_port": sport,
        "dst_port": dport,
        "dst_port_httpish": 1.0 if dport in {80, 8080, 443, 8000, 8443} else 0.0,
        "alert_priority": prio,
        **family,
        "sig_len": float(len(str(sig))),
        "has_flow": 1.0 if flow else 0.0,
        "flow_pkts_toserver": _to_float(flow.get("pkts_toserver")),
        "flow_pkts_toclient": _to_float(flow.get("pkts_toclient")),
        "flow_bytes_toserver": _to_float(flow.get("bytes_toserver")),
        "flow_bytes_toclient": _to_float(flow.get("bytes_toclient")),
    }
    return {k: _to_float(feats.get(k, 0.0)) for k in FEATURE_NAMES}


def label_from_event(event: Dict[str, Any]) -> str:
    """Map lab events to coarse training labels."""
    ev = unwrap_event(event)
    alert = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    sid = alert.get("signature_id") or ev.get("signature_id")
    try:
        sid_i = int(sid) if sid is not None else 0
    except Exception:
        sid_i = 0
    sig = str(alert.get("signature") or ev.get("signature") or ev.get("_wazuh_rule_desc") or "")
    rule = str(ev.get("_wazuh_rule_id") or "")

    if 1000001 <= sid_i <= 1000007 or "LOCAL SCAN" in sig or "Nmap" in sig or rule.startswith("10010"):
        return "NMAP"
    if 1000010 <= sid_i <= 1000019 or "LOCAL WEB" in sig or "Gobuster" in sig or rule.startswith("10011"):
        return "WEB"
    if 1000020 <= sid_i <= 1000029 or "LOCAL ICMP" in sig or "ICMP" in sig or rule.startswith("10012"):
        return "ICMP"
    if sid_i or "Suricata" in sig or rule.startswith("86601"):
        return "OTHER_ALERT"
    return "BENIGN"
