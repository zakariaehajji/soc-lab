"""Compatibility alias for pfe-soc-ml notebooks (`from src.scoring import ...`)."""

from .cic_scoring import (  # noqa: F401
    CFG,
    CIC_DIR,
    cic_ready,
    feature_names,
    load_model,
    risk_level,
    score_flows,
    score_one,
)

__all__ = [
    "CFG",
    "CIC_DIR",
    "cic_ready",
    "feature_names",
    "load_model",
    "risk_level",
    "score_flows",
    "score_one",
]
