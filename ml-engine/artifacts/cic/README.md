# CIC research models (from pfe-soc-ml)

Integrated from Zakaria's final deliverable (`pfe-soc-ml`).

| File | Role |
|------|------|
| `config.json` | Feature lists (`robuste` / `complet`), risk thresholds |
| `xgb_robuste.json` | Primary XGBoost (no destination-port leakage features) |
| `xgb_complet.json` | Full-feature XGBoost |
| `XGBoost.joblib` / `RandomForest.joblib` / `baseline_tree.joblib` | Notebook baselines |

Risk levels (score 0–100): **Faible** &lt;10 · **Moyen** &lt;30 · **Élevé** &lt;90 · **Critique** ≥90
