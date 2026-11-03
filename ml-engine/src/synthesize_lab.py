"""Bootstrap synthetic labeled events matching lab SID families when live volume is low."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .features import extract_features, label_from_event
from .schema import FEATURE_NAMES


def make_alert(sid: int, sig: str, proto: str, sport: int, dport: int, src: str, dst: str) -> dict:
    return {
        "timestamp": "2026-11-03T20:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": dst,
        "src_port": sport,
        "dest_port": dport,
        "proto": proto,
        "alert": {"signature_id": sid, "signature": sig, "severity": 2},
        "flow": {
            "pkts_toserver": int(np.random.randint(1, 40)),
            "pkts_toclient": int(np.random.randint(0, 20)),
            "bytes_toserver": int(np.random.randint(40, 5000)),
            "bytes_toclient": int(np.random.randint(0, 3000)),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--out", default="data/processed/lab_synth.csv")
    args = ap.parse_args()

    rng = np.random.default_rng(42)
    rows = []
    kali, ids, soc = "192.168.221.30", "192.168.221.136", "192.168.221.138"

    families = [
        (1000001, "LOCAL SCAN Possible TCP SYN Scan from Kali", "TCP", 40000, 80),
        (1000003, "LOCAL SCAN Possible TCP NULL Scan from Kali", "TCP", 40000, 22),
        (1000005, "LOCAL SCAN Possible TCP Xmas Scan from Kali", "TCP", 40000, 443),
        (1000010, "LOCAL WEB Possible Directory Enumeration (Gobuster-like) from Kali", "TCP", 45000, 8080),
        (1000012, "LOCAL WEB Suspicious Common Path Probe (.git) from Kali", "TCP", 45000, 8080),
        (1000021, "LOCAL ICMP Echo Burst / Ping Sweep from Kali", "ICMP", 0, 0),
    ]

    # attacks from kali
    for _ in range(args.n // 2):
        sid, sig, proto, sport, dport = families[int(rng.integers(0, len(families)))]
        sport = int(rng.integers(1024, 65535)) if proto == "TCP" else 0
        ev = make_alert(sid, sig, proto, sport, dport if dport else int(rng.integers(1, 1024)), kali, ids)
        feats = extract_features(event=ev)
        lab = label_from_event(ev)
        rows.append({**feats, "label": lab, "is_attack": 1})

    # benign-ish: random internal traffic without lab SIDs
    for _ in range(args.n // 2):
        src = [ids, soc, "192.168.221.135", kali][int(rng.integers(0, 4))]
        dst = [ids, soc, "192.168.221.1"][int(rng.integers(0, 3))]
        ev = {
            "timestamp": "2026-11-03T12:00:00.000000+0000",
            "event_type": "flow",
            "src_ip": src,
            "dest_ip": dst,
            "src_port": int(rng.integers(1024, 65535)),
            "dest_port": int(rng.choice([22, 53, 1514, 443, 9200])),
            "proto": "TCP",
            "flow": {
                "pkts_toserver": int(rng.integers(1, 10)),
                "pkts_toclient": int(rng.integers(1, 10)),
                "bytes_toserver": int(rng.integers(60, 800)),
                "bytes_toclient": int(rng.integers(60, 800)),
            },
        }
        feats = extract_features(event=ev)
        rows.append({**feats, "label": "BENIGN", "is_attack": 0})

    df = pd.DataFrame(rows)[FEATURE_NAMES + ["label", "is_attack"]]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print("wrote", out, df.shape)
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()