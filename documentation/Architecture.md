# SOC architecture

## Logical architecture

1. **Sensor (IDS VM):** Suricata inspects VMnet1 traffic on `ens37`, writes alerts to EVE JSON.
2. **Collector (Wazuh agent):** Ships EVE JSON and host logs to the manager over TCP/1514 with AES.
3. **Analyzer (Wazuh manager):** Decodes Suricata JSON (base rule 86601) and applies custom SOC-LAB rules (`100101+`).
4. **Storage (Indexer):** Stores alerts in `wazuh-alerts-*`.
5. **Presentation (Dashboard):** Threat Hunting + dedicated `SOC Lab Monitoring` dashboard.

## Trust boundaries

- All offensive tests confined to `192.168.221.0/24`.
- IDS also has NAT `ens33` (`192.168.188.137`) for package updates; Suricata capture remains on lab iface.
- Dashboard/API/Indexer exposed on the lab SOC IP only (host-only network).

## Diagram

See [`../diagrams/SOC-Architecture.mmd`](../diagrams/SOC-Architecture.mmd).
