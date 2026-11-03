"""I/O contracts for FastAPI integration with the live SOC."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class ScoreContext(BaseModel):
    agent_name: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    suricata_sid: Optional[int] = None
    wazuh_rule_id: Optional[str] = None
    signature: Optional[str] = None


class ScoreRequest(BaseModel):
    request_id: str = Field(..., description="Caller correlation id")
    source: Literal["wazuh", "suricata", "manual", "bridge"] = "bridge"
    timestamp: Optional[str] = None
    # Either raw event OR precomputed features
    event: Optional[Dict[str, Any]] = None
    features: Optional[Dict[str, float]] = None
    context: Optional[ScoreContext] = None


class Explanation(BaseModel):
    feature: str
    contribution: float


class ScoreResponse(BaseModel):
    request_id: str
    model_version: str
    prediction: Literal["BENIGN", "ATTACK"]
    risk_score: float
    label_proba: Dict[str, float]
    top_class: Optional[str] = None
    explanations: List[Explanation] = []
    notes: Optional[str] = None
    features_used: Optional[Dict[str, float]] = None


# Feature vector keys expected by the lab-native model (Suricata/Wazuh derived)
FEATURE_NAMES: List[str] = [
    "hour_utc",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
    "src_is_kali",
    "dst_is_ids",
    "dst_is_soc",
    "src_port",
    "dst_port",
    "dst_port_httpish",
    "alert_priority",
    "sid_nmap_family",
    "sid_web_family",
    "sid_icmp_family",
    "sid_et_or_other",
    "sig_len",
    "has_flow",
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
]