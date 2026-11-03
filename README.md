# SOC Lab Project — Wazuh 4.14.9 + Suricata 8.0.7

Isolated VMware host-only SOC lab demonstrating detection engineering, SIEM correlation, dashboarding, and resilience testing.

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
- API: `https://192.168.221.138:55000`
- Technical report: [documentation/SOC-Technical-Report.md](documentation/SOC-Technical-Report.md)
- Test results: [documentation/Test-Results.md](documentation/Test-Results.md)

## Project layout

```text
SOC-PROJECT/
├── README.md
├── documentation/
├── suricata/
├── wazuh/
├── tests/
├── diagrams/
├── evidence/
└── ml-engine/          # AI scoring API + bridge + block actions
```

## ML engine (live on SOC)

- UI: `http://192.168.221.138:8088/ui`
- Docs: `http://192.168.221.138:8088/docs`
- Features: Suricata/Wazuh-native scoring, enrichment JSONL, lab IP block/unblock
- Runbook: [documentation/ML-Integration-Runbook.md](documentation/ML-Integration-Runbook.md)

## Status (2026-11-03)

| Area | Status |
|------|--------|
| Nmap detection (SYN/Connect/NULL/FIN/Xmas/version/ports) | Verified in Suricata + Wazuh custom rules |
| Gobuster / HTTP enum | Verified (lab web on `:8080`) |
| ICMP detection | Verified |
| Custom Wazuh rules `100101–100130` | Deployed + live-tested |
| SOC Lab dashboard | Created (`soc-lab-monitoring`) |
| Agent/Suricata recovery | Verified |
| API / indexer credential rotation | Completed (secrets kept off-repo) |
| ML scoring + bridge + IP block UI | Deployed on SOC `:8088` |

Secrets are **not** stored in this repository. Keep rotated credentials only on the private lab host file.
