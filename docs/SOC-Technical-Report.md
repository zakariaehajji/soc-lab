# SOC Lab Technical Report

**Wazuh 4.14.9 + Suricata 8.0.7 — Detection Engineering Completion**  
**Date:** 2026-11-03  
**Classification:** Internal lab documentation (no production secrets)

---

## 1. Project introduction

This project completes an existing isolated SOC laboratory built on VMware Workstation. The lab already had a working Suricata sensor and Wazuh agent pipeline. The work extended detection coverage (Nmap, Gobuster, ICMP), added custom SIEM classification rules, created a demonstration dashboard, validated recovery behavior, began credential hardening, and produced professional documentation.

## 2. Project objectives

1. Preserve the working Suricata → Wazuh pipeline.
2. Expand and prove detections for common recon techniques in-lab only.
3. Enrich Wazuh alerting beyond generic Suricata rule 86601.
4. Provide a demo-ready dashboard using real events.
5. Validate agent/service resilience.
6. Improve credential hygiene after prior exposure.
7. Deliver a reusable project tree with evidence.

## 3. SOC architecture

See [Architecture.md](Architecture.md) and [`../diagrams/SOC-Architecture.mmd`](../diagrams/SOC-Architecture.mmd).

High level: Suricata on the IDS VM observes host-only traffic, emits EVE JSON, the Wazuh agent forwards events to the Dockerized manager on the SOC VM, analysisd applies rules, the indexer stores alerts, and the dashboard presents Threat Hunting + custom visualizations.

## 4. VMware network topology

See [Network-Topology.md](Network-Topology.md).

- VMnet1 host-only: `192.168.221.0/24`
- Kali `.30`, IDS `.136`, SOC `.138`, Windows `.135`

## 5. Infrastructure specifications

| Component | Detail |
|-----------|--------|
| Suricata | 8.0.7 on Ubuntu IDS, AF_PACKET `ens37` |
| Wazuh agent | 4.14.9-1, name `suricata-ids`, id `001` |
| Wazuh stack | 4.14.9 Docker on SOC `.138` |
| Dashboard | OpenSearch Dashboards 2.19.x behind `:443` |
| Tester | Kali with nmap 7.99 and gobuster |

## 6. Suricata installation and configuration

Pre-existing installation retained. Notes:

- Config `/etc/suricata/suricata.yaml` (not fully rewritten)
- Rules directory `/var/lib/suricata/rules/`
- Minimal change: `HTTP_PORTS` includes `8080` (backup taken)
- EVE output active at `/var/log/suricata/eve.json`

Details: [`../detection/suricata/configuration-notes.md`](../detection/suricata/configuration-notes.md)

## 7. Custom Suricata rules

File: [`../detection/suricata/local.rules`](../detection/suricata/local.rules)

Coverage:

- Nmap SYN / connect-style / NULL / FIN / Xmas / version burst / port sweep
- Gobuster-like HTTP enumeration and sensitive path probes
- ICMP echo, burst, and repeated lab echoes

All custom SIDs are in `1000001+` and source-scoped primarily to Kali.

## 8. Wazuh installation and configuration

Pre-existing Docker deployment retained. Manager communication TCP/1514 confirmed from IDS and Windows host.

## 9. Agent integration

Agent `ossec.conf` collects Suricata EVE as JSON. Historical repair (2026-10-28): removed XML prolog that caused error 1226; added wazuh user to suricata group for EVE readability. Live status 2026-11-03: **active** and connected.

## 10. Detection engineering

Approach:

1. Write narrow Suricata signatures with thresholds.
2. Validate with `suricata -T` / reload.
3. Execute authorized lab traffic from Kali.
4. Confirm EVE alerts.
5. Add Wazuh child rules (`if_sid` 86601) for classification and severity.
6. Hot-reload analysisd; confirm with logtest + live indexer hits.

## 11–13. Nmap / Gobuster / ICMP results

See [Test-Results.md](Test-Results.md) and:

- [`../tests/nmap-tests.md`](../tests/nmap-tests.md)
- [`../tests/gobuster-tests.md`](../tests/gobuster-tests.md)
- [`../tests/icmp-tests.md`](../tests/icmp-tests.md)

**Summary:** All primary scenarios produced Suricata alerts and corresponding custom Wazuh alerts searchable in the indexer (except where explicitly noted as initial-only for FIN during the later retest window).

## 14. Wazuh custom rules

File: [`../detection/wazuh/local_rules.xml`](../detection/wazuh/local_rules.xml)

| Rule ID | Level | Purpose |
|---------|-------|---------|
| 100101–100107 | 6–7 | Nmap family |
| 100110–100113 | 7–8 | Gobuster / web |
| 100120–100122 | 4–6 | ICMP |
| 100130 | 10 | High-volume Nmap correlation |

Logtest evidence: sample Suricata JSON decoded to rule **100101** level **6** (`SOC-LAB: Nmap TCP SYN scan detected via Suricata`).

## 15. Dashboard

- Name: **SOC Lab Monitoring - Suricata/Wazuh**
- ID: `soc-lab-monitoring`
- URL: `https://192.168.221.138/app/dashboards#/view/soc-lab-monitoring`
- Panels: totals, severity, timeline, top signatures, top src/dst, Nmap/Gobuster/ICMP counts, groups
- Export: `evidence/screenshots-and-alert-examples/soc-lab-dashboard.ndjson`

UI screenshots should be captured live for presentations; this report does not fabricate images.

## 16. Agent recovery tests

See [`../tests/recovery-tests.md`](../tests/recovery-tests.md).

Verified: agent restart reconnect, Suricata restart with continued EVE→SIEM flow, manager disconnect/reconnect after restart, TCP/1514 health. Keys preserved.

## 17. Security hardening

Performed:

- Confirmed agent XML hardening still in place.
- Confirmed EVE permissions allow agent read without world-writable secrets.
- Rotated **Wazuh API user `wazuh-wui`** password (old default rejected afterward).
- Documented that previously exposed credentials are compromised.

Pending (blocked without SOC guest/Docker shell):

- Official indexer `admin` password rotation via Wazuh Docker passwords tool
- Updating Compose/env secrets consistently
- Rotating host `labadmin`/VM passwords if still matching any shared notes

Private rotated secret material is stored only on the lab host credentials file, not in this project tree.

## 18. Problems encountered and solutions

| Problem | Solution |
|---------|----------|
| Historical agent XML 1226 | Strip XML prolog + trailing newline (retained) |
| HTTP rules on :8080 not decoded | Minimal `HTTP_PORTS` update |
| NULL/FIN/Xmas needed root | Re-run with sudo on Kali |
| SOC VMware Tools/SSH auth unavailable | Used Wazuh/Indexer APIs from Kali for rules/dashboard/creds |
| Dashboard API denied for `admin` write | Wrote saved objects via `.kibana_1` / `kibanaserver` path |
| API password JSON special chars | Generate JSON-safe secret + PUT with proper JSON body |
| Desktop notes listed SOC `.137` | Live verification → use `.138` |

## 19. Limitations

1. Temporary Python `http.server` is for lab demos only (not hardened).
2. Connect vs SYN classification overlaps at packet level.
3. Indexer admin credential still needs Docker-side rotation.
4. SOC guest shell access from automation remains unavailable (password mismatch vs notes).
5. Dashboard panels depend on field mappings (`data.src_ip` / `data.dest_ip`); if some Suricata fields land under nested paths, top-IP panels may show Missing until field aliases are adjusted.
6. Windows endpoint agent was not in scope for this completion pass.
7. Controlled iptables 1514 drop did not always surface a fresh “Lost connection” within short windows; manager-restart disconnect evidence was used and is real.

## 20. Conclusion and future improvements

The lab is now a demonstrable SOC with proven multi-technique detections, custom SIEM enrichment, a dedicated dashboard, recovery validation, and documentation. Future work:

1. Complete indexer/dashboard credential rotation from SOC console.
2. Add Windows agent + Sysmon use cases.
3. Replace temp web server with Nginx + intentional vulnerable paths.
4. Add active response playbooks for high-severity SOC-LAB rules.
5. Capture official dashboard screenshots for the report appendix.
6. Tune SID 1000002 to reduce SYN overlap or pivot to flow-based analytics.

---

**Bottom line:** Suricata + Wazuh integration was already working; this engagement completed detection engineering, verification, dashboarding, partial hardening, and professional deliverables without rebuilding the stack.
