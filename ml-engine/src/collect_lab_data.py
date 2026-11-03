"""Collect labeled training rows from Wazuh Indexer + optional Suricata EVE export."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import requests
import urllib3

from .features import extract_features, label_from_event
from .schema import FEATURE_NAMES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def search_indexer(base: str, user: str, password: str, query: Dict[str, Any], size: int = 5000) -> List[Dict[str, Any]]:
    url = f"{base.rstrip('/')}/wazuh-alerts*/_search"
    body = {"size": size, "sort": [{"timestamp": {"order": "desc"}}], "query": query}
    r = requests.post(url, auth=(user, password), json=body, verify=False, timeout=60)
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]


def rows_from_alerts(alerts: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for a in alerts:
        feats = extract_features(event=a)
        lab = label_from_event(a)
        binary = 0 if lab == "BENIGN" else 1
        row = dict(feats)
        row["label"] = lab
        row["is_attack"] = binary
        rows.append(row)
    return pd.DataFrame(rows)


def rows_from_eve(path: Path, max_lines: int = 200000) -> pd.DataFrame:
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = o.get("event_type")
            if et not in {"alert", "flow"}:
                continue
            # Use only a subset of flows as benign candidates (no alert)
            if et == "flow":
                # skip short noise
                if not o.get("src_ip"):
                    continue
            feats = extract_features(event=o)
            lab = label_from_event(o) if et == "alert" else "BENIGN"
            row = dict(feats)
            row["label"] = lab
            row["is_attack"] = 0 if lab == "BENIGN" else 1
            rows.append(row)
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indexer", default=os.getenv("WAZUH_INDEXER_URL", "https://192.168.221.138:9200"))
    ap.add_argument("--user", default=os.getenv("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.getenv("WAZUH_INDEXER_PASSWORD", ""))
    ap.add_argument("--eve", default="", help="Optional path to Suricata eve.json")
    ap.add_argument("--out", default="data/processed/lab_training.parquet")
    ap.add_argument("--size", type=int, default=8000)
    args = ap.parse_args()

    frames = []
    if args.password:
        # Suricata / SOC-LAB related alerts
        q_attack = {
            "bool": {
                "should": [
                    {"prefix": {"rule.description": "SOC-LAB"}},
                    {"prefix": {"rule.description": "Suricata: Alert - LOCAL"}},
                    {"wildcard": {"rule.description": "*Suricata*"}},
                ],
                "minimum_should_match": 1,
            }
        }
        alerts = search_indexer(args.indexer, args.user, args.password, q_attack, size=args.size)
        print(f"indexer alerts: {len(alerts)}")
        if alerts:
            frames.append(rows_from_alerts(alerts))

        # Some host/journal noise as weak benign (still useful diversity)
        q_benign = {
            "bool": {
                "must": [{"term": {"agent.name": "suricata-ids"}}],
                "must_not": [
                    {"prefix": {"rule.description": "SOC-LAB"}},
                    {"prefix": {"rule.description": "Suricata"}},
                ],
            }
        }
        benign = search_indexer(args.indexer, args.user, args.password, q_benign, size=min(2000, args.size))
        print(f"indexer non-suricata agent events: {len(benign)}")
        if benign:
            dfb = rows_from_alerts(benign)
            dfb["label"] = "BENIGN"
            dfb["is_attack"] = 0
            frames.append(dfb)
    else:
        print("WARNING: no indexer password — skipping indexer pull")

    if args.eve:
        p = Path(args.eve)
        if p.exists():
            dfe = rows_from_eve(p)
            print(f"eve rows: {len(dfe)}")
            frames.append(dfe)
        else:
            print("eve path missing:", p)

    if not frames:
        raise SystemExit("No training data collected")

    df = pd.concat(frames, ignore_index=True)
    # Keep feature columns + labels
    cols = FEATURE_NAMES + ["label", "is_attack"]
    df = df[cols].drop_duplicates()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix == ".csv":
        df.to_csv(out, index=False)
    else:
        df.to_parquet(out, index=False)
    print("wrote", out, df.shape)
    print(df["label"].value_counts())
    print(df["is_attack"].value_counts())


if __name__ == "__main__":
    main()