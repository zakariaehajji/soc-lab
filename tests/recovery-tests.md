# Agent / service recovery tests

## R1 — Wazuh agent restart

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
```

**Result:** `active` after restart. Log shows reconnect and EVE collection:

- `2026-11-03T19:41:47Z` Connected to `192.168.221.138:1514/tcp`
- `2026-11-03T19:41:49Z` Analyzing `/var/log/suricata/eve.json`

## R2 — Suricata restart

```bash
sudo systemctl restart suricata
```

**Result:** `active`. Post-restart nmap produced indexed SOC-LAB alerts at `19:42:35Z` (rules 100101/100102/100106/100107).

## R3 — Manager unavailability / reconnect

Evidence from controlled manager restart earlier the same session:

- `19:39:43Z` Lost connection with manager
- `19:40:03Z` Connected to server again

Agent registration keys were **not** deleted.

## R4 — TCP/1514 connectivity

```bash
timeout 3 bash -c 'echo >/dev/tcp/192.168.221.138/1514'
```

**Result:** open/`mgr_1514_ok` after recovery.

## Post-recovery detection proof

Indexer query after recovery returned live SOC-LAB alerts from agent `suricata-ids` (see `evidence/.../custom-rules-retest.txt` and post-recovery hits at `19:42:35Z`).
