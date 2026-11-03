"""Train lab-native attack detector and persist artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

from .schema import FEATURE_NAMES

MODEL_VERSION = "lab_suricata_rf_v0.1.0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/lab_training.parquet")
    ap.add_argument("--outdir", default="artifacts")
    args = ap.parse_args()

    path = Path(args.data)
    if not path.exists():
        raise SystemExit(f"Missing training data: {path}")

    if path.suffix == ".csv":
        df = pd.read_csv(path)
    else:
        df = pd.read_parquet(path)

    X = df[FEATURE_NAMES].fillna(0.0)
    y = df["is_attack"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y if y.nunique() > 1 else None
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    proba = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else None
    pred = clf.predict(X_test)
    report = classification_report(y_test, pred, output_dict=True, zero_division=0)
    metrics = {
        "model_version": MODEL_VERSION,
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "report": report,
    }
    if proba is not None and y_test.nunique() > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_test, proba))

    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "features": FEATURE_NAMES, "version": MODEL_VERSION}, out / "model.joblib")
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # multiclass label model (optional coarse family)
    if "label" in df.columns and df["label"].nunique() > 2:
        y2 = df["label"].astype(str)
        Xtr, Xte, ytr, yte = train_test_split(X, y2, test_size=0.25, random_state=42, stratify=y2)
        clf2 = RandomForestClassifier(
            n_estimators=200, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1
        )
        clf2.fit(Xtr, ytr)
        joblib.dump({"model": clf2, "features": FEATURE_NAMES, "version": MODEL_VERSION + "+family"}, out / "model_multiclass.joblib")
        print("multiclass labels:", sorted(y2.unique()))

    print(json.dumps(metrics, indent=2))
    print("wrote", out / "model.joblib")


if __name__ == "__main__":
    main()