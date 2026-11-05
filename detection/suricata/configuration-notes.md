# Suricata configuration notes

## Runtime

- Version: 8.0.7 RELEASE
- Capture: AF_PACKET on `ens37` (lab IP `192.168.221.136`)
- Config: `/etc/suricata/suricata.yaml`
- Rules path: `/var/lib/suricata/rules/`
- Custom rules: `/var/lib/suricata/rules/local.rules` (included via `rule-files`)
- EVE JSON: `/var/log/suricata/eve.json`

## Minimal YAML change performed

- Backup: `/root/suricata.yaml.bak-20261103-193754`
- Change: `HTTP_PORTS: "80"` → `HTTP_PORTS: "[80,8080]"` so Gobuster tests against the lab web server on TCP/8080 are HTTP-decoded.
- Validated with `suricata -T` before restart.
- Full YAML was **not** overwritten.

## Custom SID plan

| SID | Purpose |
|-----|---------|
| 1000001 | TCP SYN scan burst from Kali |
| 1000002 | TCP connect-style SYN probe burst |
| 1000003 | TCP NULL scan |
| 1000004 | TCP FIN scan |
| 1000005 | TCP Xmas scan |
| 1000006 | Service/version probe burst |
| 1000007 | Common port sweep |
| 1000010–1000013 | Gobuster / HTTP enumeration |
| 1000020–1000022 | ICMP echo / burst / lab repeated echo |

## Permissions relevant to Wazuh

- `eve.json` owned by `suricata:suricata`, mode `644`
- Wazuh user is a member of group `suricata` (required to read EVE)

## Reload / restart

- Rule-only updates: `kill -USR2 $(pidof suricata)` after `suricata -T`
- HTTP_PORTS change required service restart: `systemctl restart suricata`
