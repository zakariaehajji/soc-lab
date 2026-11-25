"""CLI smoke-test for the integrated CIC (pfe-soc-ml) research models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .cic_scoring import cic_ready, load_model, score_flows


def main() -> None:
    ap = argparse.ArgumentParser(description="Score CIC flows with friend's XGBoost models")
    ap.add_argument("--variant", choices=["robuste", "complet"], default="robuste")
    ap.add_argument(
        "--parquet",
        default="data/cic/processed/val.parquet",
        help="Parquet with CIC features + Label",
    )
    ap.add_argument("--n", type=int, default=500, help="Number of rows to score")
    ap.add_argument("--json", action="store_true", help="Print JSON summary")
    args = ap.parse_args()

    status = cic_ready()
    if not status.get("ready"):
        raise SystemExit(f"CIC stack not ready: {status}")

    path = Path(args.parquet)
    if not path.exists():
        raise SystemExit(f"Missing parquet: {path.resolve()}")

    df = pd.read_parquet(path).head(args.n)
    y = (df["Label"] != "BENIGN").astype(int) if "Label" in df.columns else None
    out = score_flows(df, model=load_model(args.variant), variant=args.variant)

    summary = {
        "variant": args.variant,
        "n": len(out),
        "niveau_counts": out["niveau"].value_counts().to_dict(),
        "prediction_counts": out["prediction"].value_counts().to_dict(),
        "mean_score": float(out["score"].mean()),
    }
    if y is not None:
        pred = (out["prediction"] == "ATTACK").astype(int)
        summary["accuracy_vs_label"] = float((pred.values == y.values).mean())

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(out.head(10).to_string(index=False))
        print("---")
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
