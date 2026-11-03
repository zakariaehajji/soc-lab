# Network topology

## VMware

- Network: VMnet1 host-only
- Subnet: `192.168.221.0/24`

## Addressing (live-verified 2026-11-03)

| Host | Interface | IP | Notes |
|------|-----------|-----|-------|
| Kali | eth1 | 192.168.221.30 | Also NAT eth0 192.168.188.128 |
| IDS | ens37 | 192.168.221.136 | Suricata AF_PACKET |
| IDS | ens33 | 192.168.188.137 | NAT |
| SOC | (lab) | 192.168.221.138 | Authoritative SIEM IP |
| Windows 11 | | 192.168.221.135 | From lab notes |

## Service ports on SOC

| Port | Service |
|------|---------|
| 1514/tcp | Wazuh agent communication |
| 1515/tcp | Agent enrollment |
| 55000/tcp | Wazuh API |
| 9200/tcp | Indexer |
| 443/tcp | Wazuh Dashboard |
| 5601/tcp | Closed in this deployment |

## Correction vs older notes

Desktop `lab networks.txt` listed SOC as `.137`. Live agent config and connectivity confirm **`.138`**.
