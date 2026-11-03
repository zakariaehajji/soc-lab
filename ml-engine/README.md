# ML Engine — AI-Powered SOC (lab-native)

Modular scoring service for the Wazuh 4.14.9 + Suricata 8.0.7 lab.  
**Does not modify** live SIEM/IDS configs. Enrichment is additive (API + JSONL).

## Lab endpoints

| Role | Host |
|------|------|
| SOC / API | `192.168.221.138:8088` |
| Indexer | `https://192.168.221.138:9200` |
| IDS | `192.168.221.136` |
| Kali | `192.168.221.30` |

## Deployed services (SOC VM)

| Unit | Purpose |
|------|---------|
| `soc-ml-api.service` | FastAPI scoring on `0.0.0.0:8088` |
| `soc-ml-bridge.service` | Polls indexer SOC-LAB/Suricata alerts → `/score` → `/opt/ml-engine/logs/enrichment.jsonl` |

```bash
systemctl status soc-ml-api soc-ml-bridge
curl -s http://127.0.0.1:8088/health
tail -f /opt/ml-engine/logs/enrichment.jsonl
```

## API contract

- `GET /health` — model loaded + version  
- `GET /schema` — feature names + request/response JSON schema  
- `POST /score` — score one event  
- `POST /score/batch` — score list  

### Request (`ScoreRequest`)

```json
{
  "request_id": "uuid",
  "source": "bridge",
  "timestamp": "optional ISO",
  "event": { "... wazuh alert or suricata eve ..." },
  "features": null
}
```

`source` ∈ `wazuh` | `suricata` | `manual` | `bridge`.  
Pass either raw `event` **or** precomputed `features` (22 lab-native floats).

### Response (`ScoreResponse`)

```json
{
  "request_id": "...",
  "model_version": "lab_suricata_rf_v0.1.0",
  "prediction": "ATTACK",
  "risk_score": 0.99,
  "label_proba": {"BENIGN": 0.01, "ATTACK": 0.99},
  "top_class": "NMAP",
  "explanations": [{"feature": "sid_nmap_family", "contribution": 0.4}],
  "notes": "Lab-native Suricata/Wazuh feature model; not CIC-IDS columns",
  "features_used": { }
}
```

### Feature vector (22)

`hour_utc`, proto one-hots, `src_is_kali`, `dst_is_ids`/`dst_is_soc`, ports, `alert_priority`, SID/family flags (`nmap`/`web`/`icmp`/`other`), `sig_len`, flow packet/byte counters.

**CIC-IDS columns are research-only** (notebooks). Live path uses Suricata/Wazuh-derived features only.

## Local (Windows) retrain / smoke

```powershell
cd C:\Users\Pc\Desktop\work\SOC-PROJECT\ml-engine
.\.venv\Scripts\activate
$env:PYTHONPATH = (Get-Location).Path
$env:WAZUH_INDEXER_URL = "https://192.168.221.138:9200"
$env:WAZUH_INDEXER_USER = "admin"
$env:WAZUH_INDEXER_PASSWORD = "<from rotated creds file>"

python -m src.synthesize_lab --n 3000 --out data/processed/lab_synth.csv
python -m src.collect_lab_data --out data/processed/lab_live.csv --size 5000
python -m src.train --data data/processed/lab_training.csv --outdir artifacts
```

## Retrain on SOC

```bash
cd /opt/ml-engine
. .venv/bin/activate
export PYTHONPATH=/opt/ml-engine
python -m src.train --data lab_training.csv --outdir artifacts
systemctl restart soc-ml-api
```

## Notebooks (offline research)

- `notebooks/01_eda_completed.ipynb` — CIC EDA (optional)
- Live SOC scoring does **not** depend on CIC CSVs

## Layout

```
ml-engine/
  src/           # features, train, api, bridge, collect, synthesize, schema
  artifacts/     # model.joblib, model_multiclass.joblib, metrics.json
  data/processed/
  logs/          # enrichment.jsonl (on SOC: /opt/ml-engine/logs/)
```

## Safety

- No changes to Wazuh `ossec.conf` / custom rules from this module  
- No Suricata rule edits from this module  
- Bridge is read-only against the indexer; writes only local JSONL enrichment  
- Keep indexer password in systemd unit / env — never commit it  
