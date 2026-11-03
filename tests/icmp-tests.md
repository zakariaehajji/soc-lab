# ICMP detection tests

## Commands

```bash
ping -c 3 192.168.221.136
ping -c 12 -i 0.2 192.168.221.136
```

Source: `192.168.221.30` → Destination: `192.168.221.136`

## Results

| Test | Suricata SID | Wazuh rule | Evidence |
|------|--------------|------------|----------|
| Echo request (rate-limited alert) | 1000020 | 100120 (lvl 4) | EVE 19:36:04Z; Wazuh 19:36:05Z / 19:40:59Z |
| Echo burst | 1000021 | 100121 (lvl 6) | EVE 19:36:11Z; Wazuh 19:36:11Z / 19:41:01Z |
| Repeated lab ICMP | 1000022 | 100122 (lvl 5) | EVE 19:36:11Z; Wazuh 19:36:13Z |

## Tuning

- `1000020` uses `threshold:type limit` (1 / 30s) to avoid flooding on routine pings.
- Burst rules require multiple echoes in a short window.
