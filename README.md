# SOC Lab Project — Wazuh 4.14.9 + Suricata 8.0.7

Isolated VMware host-only SOC lab demonstrating detection engineering, SIEM correlation, dashboarding, ML scoring, and resilience testing.

**GitHub:** https://github.com/zakariaehajji/soc-lab

## Lab network (VMnet1 — `192.168.221.0/24`)

| Host | IP | Role |
|------|-----|------|
| Kali Linux | 192.168.221.30 | Authorized attacker / tester |
| Ubuntu IDS | 192.168.221.136 | Suricata IDS + Wazuh agent `suricata-ids` (001) |
| Ubuntu SOC | 192.168.221.138 | Wazuh manager / indexer / dashboard (Docker) |
| Windows 11 | 192.168.221.135 | Endpoint testing (optional) |

## Confirmed working pipeline

`Suricata (ens37) → /var/log/suricata/eve.json → Wazuh Agent → Manager :1514 → Indexer → Dashboard :443`

## Quick links

- Dashboard: `https://192.168.221.138/app/dashboards#/view/soc-lab-monitoring`
- Wazuh UI: `https://192.168.221.138`
- ML UI: `http://192.168.221.138:8088/ui`
- Technical report: [docs/SOC-Technical-Report.md](docs/SOC-Technical-Report.md)
- Test results: [docs/Test-Results.md](docs/Test-Results.md)
- ML runbook: [docs/ML-Integration-Runbook.md](docs/ML-Integration-Runbook.md)
- **Reproduce lab:** [ops/bootstrap/README.md](ops/bootstrap/README.md)

## Reproduce this lab (same état)

```bash
git clone https://github.com/zakariaehajji/soc-lab.git
cd soc-lab
cp ops/lab-inventory.env.example ops/lab-inventory.env   # edit IPs/passwords
# Then follow ops/bootstrap/README.md in order:
# 01 VMware → 02 IDS → 03 SOC Wazuh → 05 rules → 04 ML → verify-lab.sh
```

Windows operator sync to an already-running SOC:

```powershell
.\ops\bootstrap\windows-sync.ps1
.\ops\bootstrap\windows-sync.ps1 -IdsRules   # also push Suricata rules
```

## Project layout

```text
SOC-PROJECT/
├── README.md
├── docs/                      # Architecture, reports, runbooks
├── detection/
│   ├── suricata/              # local.rules + notes
│   └── wazuh/                 # local_rules.xml + notes
├── ml-engine/                 # FastAPI ML scoring + bridge + CIC research
├── tests/                     # Attack / recovery procedures
├── evidence/                  # Alert samples & dashboard export
├── diagrams/                  # Architecture diagrams
└── ops/
    ├── bootstrap/             # Scripts to recreate the lab VMs/stack
    ├── lab-inventory.env.example
    └── session-notes/
```

## ML engine (live on SOC)

- UI: `http://192.168.221.138:8088/ui`
- Docs: `http://192.168.221.138:8088/docs`
- Live path: Suricata/Wazuh-native scoring, enrichment JSONL, lab IP block/unblock
- Research path: friend's CIC-IDS2017 XGBoost (`pfe-soc-ml`) via `POST /score/cic` — see [ml-engine/README.md](ml-engine/README.md)

## Status (2026-11-25)

| Area | Status |
|------|--------|
| Nmap detection (SYN/Connect/NULL/FIN/Xmas/version/ports) | Verified |
| Gobuster / HTTP enum | Verified |
| ICMP detection | Verified |
| Custom Wazuh rules `100101–100130` | Deployed + live-tested |
| SOC Lab dashboard | Created (`soc-lab-monitoring`) |
| Agent/Suricata recovery | Verified |
| API / indexer credential rotation | Completed (secrets off-repo) |
| ML scoring + bridge + IP block UI | Deployed on SOC `:8088` |
| CIC research models (pfe-soc-ml) integrated | Local verified (`/score/cic`, CLI smoke 100% on val sample) |

Secrets are **not** stored in this repository.
