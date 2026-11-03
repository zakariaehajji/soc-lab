"""
Bridge: poll Wazuh Indexer for new Suricata/SOC-LAB alerts, score via FastAPI, write enrichment JSONL.

Does not modify Wazuh/Suricata configuration. Additive only.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

from .context import extract_context

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def search_new(indexer: str, user: str, password: str, since: str, size: int = 100):
    q = {
        "bool": {
            "must": [
                {"range": {"timestamp": {"gte": since}}},
                {
                    "bool": {
                        "should": [
                            {"prefix": {"rule.description": "SOC-LAB"}},
                            {"prefix": {"rule.description": "Suricata: Alert - LOCAL"}},
                            {"match_phrase": {"rule.groups": "soc_lab"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }
    r = requests.post(
        f"{indexer.rstrip('/')}/wazuh-alerts*/_search",
        auth=(user, password),
        json={"size": size, "sort": [{"timestamp": {"order": "desc"}}], "query": q},
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return [h.get("_source", {}) for h in r.json().get("hits", {}).get("hits", [])]


def build_record(alert: dict, scored: dict) -> dict:
    ctx = extract_context(alert)
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "wazuh_timestamp": alert.get("timestamp"),
        "agent": (alert.get("agent") or {}).get("name"),
        "rule_id": (alert.get("rule") or {}).get("id"),
        "rule_desc": (alert.get("rule") or {}).get("description"),
        "src_ip": ctx.get("src_ip"),
        "dst_ip": ctx.get("dst_ip"),
        "src_port": ctx.get("src_port"),
        "dst_port": ctx.get("dst_port"),
        "proto": ctx.get("proto"),
        "src_host": ctx.get("src_host"),
        "dst_host": ctx.get("dst_host"),
        "agent_info": ctx.get("agent"),
        "mitre": ctx.get("mitre"),
        "recommended_action": ctx.get("recommended_action"),
        "context": ctx,
        "ml": {
            "prediction": scored.get("prediction"),
            "risk_score": scored.get("risk_score"),
            "top_class": scored.get("top_class"),
            "model_version": scored.get("model_version"),
            "label_proba": scored.get("label_proba"),
            "explanations": scored.get("explanations"),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indexer", default=os.getenv("WAZUH_INDEXER_URL", "https://192.168.221.138:9200"))
    ap.add_argument("--user", default=os.getenv("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.getenv("WAZUH_INDEXER_PASSWORD", ""))
    ap.add_argument("--api", default=os.getenv("SOC_ML_API", "http://127.0.0.1:8088"))
    ap.add_argument("--out", default="logs/enrichment.jsonl")
    ap.add_argument("--interval", type=int, default=20)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--since-days", type=float, default=0, help="If >0, look back N days (useful for --once backfill)")
    args = ap.parse_args()
    if not args.password:
        raise SystemExit("Set WAZUH_INDEXER_PASSWORD")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    if args.since_days and args.since_days > 0:
        from datetime import timedelta

        since = (datetime.now(timezone.utc) - timedelta(days=args.since_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    else:
        since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    while True:
        try:
            alerts = search_new(args.indexer, args.user, args.password, since=since, size=50)
            for a in alerts:
                key = f"{a.get('id')}|{a.get('timestamp')}|{(a.get('rule') or {}).get('id')}"
                if key in seen:
                    continue
                seen.add(key)
                payload = {
                    "request_id": str(uuid.uuid4()),
                    "source": "bridge",
                    "timestamp": a.get("timestamp"),
                    "event": a,
                }
                resp = requests.post(f"{args.api.rstrip('/')}/score", json=payload, timeout=20)
                resp.raise_for_status()
                scored = resp.json()
                rec = build_record(a, scored)
                with out.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                print(
                    "SCORED",
                    scored.get("prediction"),
                    round(scored.get("risk_score", 0), 3),
                    rec.get("src_ip"),
                    "->",
                    rec.get("dst_ip"),
                    (a.get("rule") or {}).get("description"),
                )
        except Exception as e:
            print("bridge_error", e)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
