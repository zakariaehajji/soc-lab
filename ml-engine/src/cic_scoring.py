"""CIC-IDS2017 research scoring (friend deliverable: pfe-soc-ml).

Offline / research path. Live Suricata/Wazuh alerts use lab-native features
via ``src.features`` + ``artifacts/model.joblib``. This module scores CIC flow
feature vectors with the friend's XGBoost models (robuste / complet).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Sequence, Union

import numpy as np
import pandas as pd

Variant = Literal["robuste", "complet"]

_ROOT = Path(__file__).resolve().parent.parent
CIC_DIR = Path(os.getenv("SOC_ML_CIC_DIR", str(_ROOT / "artifacts" / "cic")))


def _load_config() -> Dict[str, Any]:
    cfg_path = CIC_DIR / "config.json"
    if not cfg_path.exists():
        raise FileNotFoundError(f"CIC config missing: {cfg_path}")
    return json.loads(cfg_path.read_text(encoding="utf-8"))


CFG: Dict[str, Any] = {}
_MODELS: Dict[str, Any] = {}


def ensure_config() -> Dict[str, Any]:
    global CFG
    if not CFG:
        CFG = _load_config()
    return CFG


def risk_level(score: float) -> str:
    """Map a 0–100 score to Faible / Moyen / Élevé / Critique."""
    cfg = ensure_config()
    bornes = cfg["bornes_niveaux"]
    niveaux = cfg["niveaux"]
    return niveaux[int(np.searchsorted(bornes, score, side="right"))]


def load_model(variant: Variant = "robuste"):
    """Load friend's XGBoost JSON model (``xgb_robuste.json`` / ``xgb_complet.json``)."""
    if variant in _MODELS:
        return _MODELS[variant]

    ensure_config()
    path = CIC_DIR / f"xgb_{variant}.json"
    if not path.exists():
        raise FileNotFoundError(f"CIC model missing: {path}")

    from xgboost import XGBClassifier

    model = XGBClassifier()
    model.load_model(path)
    _MODELS[variant] = model
    return model


def feature_names(variant: Variant = "robuste") -> List[str]:
    cfg = ensure_config()
    key = f"features_{variant}"
    if key not in cfg:
        raise KeyError(f"Unknown CIC feature set: {variant}")
    return list(cfg[key])


def _as_dataframe(
    rows: Union[pd.DataFrame, Dict[str, Any], Sequence[Dict[str, Any]]],
    columns: Sequence[str],
) -> pd.DataFrame:
    if isinstance(rows, pd.DataFrame):
        df = rows.copy()
    elif isinstance(rows, dict):
        df = pd.DataFrame([rows])
    else:
        df = pd.DataFrame(list(rows))

    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes : {missing}")
    # Coerce + replace non-finite values the same way the notebooks cleaned data
    out = df[list(columns)].apply(pd.to_numeric, errors="coerce")
    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return out


def score_flows(
    df: Union[pd.DataFrame, Dict[str, Any], Sequence[Dict[str, Any]]],
    model=None,
    variant: Variant = "robuste",
) -> pd.DataFrame:
    """Return per-flow score (0–100) and risk niveau for CIC feature rows."""
    cols = feature_names(variant)
    X = _as_dataframe(df, cols)
    if model is None:
        model = load_model(variant)

    proba = model.predict_proba(X)[:, 1]
    score = (proba * 100).round(1)
    pred = (proba >= float(ensure_config().get("seuil_decision", 0.5))).astype(int)
    return pd.DataFrame(
        {
            "score": score,
            "niveau": [risk_level(float(s)) for s in score],
            "prediction": ["ATTACK" if int(p) == 1 else "BENIGN" for p in pred],
            "proba_attack": np.round(proba, 6),
        }
    )


def score_one(
    features: Dict[str, Any],
    variant: Variant = "robuste",
) -> Dict[str, Any]:
    """Score a single CIC flow feature dict; returns API-friendly payload."""
    out = score_flows(features, variant=variant).iloc[0]
    return {
        "model_version": f"cic_xgb_{variant}_v1",
        "variant": variant,
        "prediction": str(out["prediction"]),
        "risk_score": float(out["proba_attack"]),
        "risk_score_0_100": float(out["score"]),
        "risk_level": str(out["niveau"]),
        "label_proba": {
            "BENIGN": float(1.0 - out["proba_attack"]),
            "ATTACK": float(out["proba_attack"]),
        },
        "feature_count": len(feature_names(variant)),
        "notes": "CIC-IDS2017 research model (pfe-soc-ml); not used for live Suricata alerts",
    }


def cic_ready() -> Dict[str, Any]:
    """Health snapshot for the CIC research stack."""
    ensure_config()
    status = {
        "cic_dir": str(CIC_DIR),
        "config": (CIC_DIR / "config.json").exists(),
        "xgb_robuste": (CIC_DIR / "xgb_robuste.json").exists(),
        "xgb_complet": (CIC_DIR / "xgb_complet.json").exists(),
        "features_robuste": len(feature_names("robuste")),
        "features_complet": len(feature_names("complet")),
        "niveaux": ensure_config().get("niveaux"),
        "seuil_decision": ensure_config().get("seuil_decision"),
    }
    status["ready"] = bool(status["config"] and status["xgb_robuste"] and status["xgb_complet"])
    return status
