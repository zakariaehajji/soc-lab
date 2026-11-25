# CIC-IDS2017 data (pfe-soc-ml)

Research dataset used by the friend's final ML deliverable.

## Layout

| Path | Content |
|------|---------|
| `raw/` | Original CIC `*_ISCX.csv` day files |
| `processed/` | `all_raw.parquet`, `clean.parquet`, `train/val/test.parquet` |

On this Windows workstation, `raw/` and `processed/` are **directory junctions** to:

`C:\Users\Pc\Downloads\pfe-soc-ml\pfe-soc-ml\data\...`

so the SOC project does not duplicate ~1.6 GB.

## Live SOC path

Live alert scoring does **not** read these files. It uses Suricata/Wazuh lab-native features + `artifacts/model.joblib`.

CIC models live in `artifacts/cic/` and are exposed as `POST /score/cic`.
