# Consolidated test results (evidence-backed)

Date: **2026-11-03** (UTC timestamps)

## End-to-end threat hunting checklist

For each scenario: EVE → Agent → Manager → Indexer → searchable alert.

| Scenario | Suricata SID | Wazuh rule | Agent | Src | Dst | Severity | Sample timestamp |
|----------|--------------|------------|-------|-----|-----|----------|------------------|
| SYN scan | 1000001 | 100101 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 6 | 2026-11-03T19:40:55.697Z |
| Connect-style | 1000002 | 100102 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 6 | 2026-11-03T19:40:55.698Z |
| NULL scan | 1000003 | 100103 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 7 | 2026-11-03T19:40:57.700Z |
| FIN scan | 1000004 | 100104 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 7 | 2026-11-03T19:37:44.111Z (EVE) |
| Xmas scan | 1000005 | 100105 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 7 | 2026-11-03T19:40:59.698Z |
| Version/probe burst | 1000006 | 100106 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 6 | 2026-11-03T19:40:55.699Z |
| Port sweep | 1000007 | 100107 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 6 | 2026-11-03T19:40:55.701Z |
| Gobuster enum | 1000010 | 100110 | suricata-ids | 192.168.221.30 | 192.168.221.136:8080 | 8 | 2026-11-03T19:41:03.705Z |
| `/admin` probe | 1000011 | 100111 | suricata-ids | 192.168.221.30 | 192.168.221.136:8080 | 7 | 2026-11-03T19:41:01.723Z |
| `.git` probe | 1000012 | 100112 | suricata-ids | 192.168.221.30 | 192.168.221.136:8080 | 8 | 2026-11-03T19:41:01.732Z |
| HTTP burst | 1000013 | 100113 | suricata-ids | 192.168.221.30 | 192.168.221.136:8080 | 7 | 2026-11-03T19:41:01.811Z |
| ICMP echo | 1000020 | 100120 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 4 | 2026-11-03T19:40:59.701Z |
| ICMP burst | 1000021 | 100121 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 6 | 2026-11-03T19:41:01.705Z |
| ICMP repeated | 1000022 | 100122 | suricata-ids | 192.168.221.30 | 192.168.221.136 | 5 | 2026-11-03T19:36:13.573Z |

## Raw evidence files

- `evidence/screenshots-and-alert-examples/kali-nmap-gobuster-icmp-tests.txt`
- `evidence/screenshots-and-alert-examples/custom-rules-retest.txt`
- `evidence/screenshots-and-alert-examples/recovery-tests.txt`

## Dashboard

- ID: `soc-lab-monitoring`
- Verified retrievable via saved-objects API (`dash_http=200`)
- URL: `https://192.168.221.138/app/dashboards#/view/soc-lab-monitoring`

Screenshots should be captured from the live UI during demos; this package includes the importable NDJSON and alert text evidence (no fabricated images).
