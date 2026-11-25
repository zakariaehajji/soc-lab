# Reproduce this SOC lab (same state)

These scripts recreate the **verified** lab:

| Host | IP | Stack |
|------|-----|--------|
| Kali | `192.168.221.30` | nmap / gobuster tester |
| Ubuntu IDS | `192.168.221.136` | Suricata 8.0.7 + Wazuh agent `suricata-ids` |
| Ubuntu SOC | `192.168.221.138` | Wazuh Docker 4.14.9 + ML engine `:8088` |

## Order

1. **Network** — [01-vmware-network.md](01-vmware-network.md)
2. Copy inventory — `cp ops/lab-inventory.env.example ops/lab-inventory.env` and edit
3. Clone repo on each Ubuntu VM (or scp this tree):
   ```bash
   git clone https://github.com/zakariaehajji/soc-lab.git /opt/soc-lab
   cd /opt/soc-lab
   ```
4. **IDS** — `sudo bash ops/bootstrap/02-ids-bootstrap.sh`
5. **SOC Wazuh** — `sudo bash ops/bootstrap/03-soc-wazuh-bootstrap.sh`
6. Enroll agent from IDS:
   ```bash
   /var/ossec/bin/agent-auth -m 192.168.221.138 -A suricata-ids
   systemctl restart wazuh-agent
   ```
7. **Rules** — from a machine with SSH to both:
   ```bash
   bash ops/bootstrap/05-apply-detection-rules.sh
   ```
8. **ML engine** — on SOC:
   ```bash
   # set indexer password in env first
   export WAZUH_INDEXER_PASSWORD='your-admin-password'
   sudo -E bash ops/bootstrap/04-soc-ml-engine-bootstrap.sh
   ```
9. **Kali** — [06-kali-notes.md](06-kali-notes.md)
10. **Verify** — `bash ops/bootstrap/verify-lab.sh`

## Windows operator helper

```powershell
cd C:\path\to\soc-lab
.\ops\bootstrap\windows-sync.ps1   # push repo + restart ML on SOC
```

## What “same état” means

- Same IPs / VMnet1 subnet
- Same custom Suricata SIDs + Wazuh rules `100101+`
- Same ML API contract (`/score` lab-native + `/score/cic` research)
- Systemd units `soc-ml-api` + `soc-ml-bridge`
- Secrets only in `/opt/ml-engine/.env` (not in git)

## Safety

- Lab traffic only on `192.168.221.0/24`
- Do not commit `ops/lab-inventory.env` with real passwords
