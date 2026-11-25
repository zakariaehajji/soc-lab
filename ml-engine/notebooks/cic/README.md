# Friend notebooks (pfe-soc-ml)

Open these from `ml-engine/` as the project root (or set cwd to `ml-engine`).

Models resolve via junction `ml-engine/models` → `artifacts/cic`.

For parquet data, either:

```python
root = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
# preferred after integration:
val = pd.read_parquet(root / "data" / "cic" / "processed" / "val.parquet")
# or, if you keep the original Downloads tree:
# val = pd.read_parquet(r"C:\Users\Pc\Downloads\pfe-soc-ml\pfe-soc-ml\data\processed\val.parquet")
```

Scoring API used by `03_scoring_validation.ipynb`:

```python
from src.scoring import load_model, score_flows
```
