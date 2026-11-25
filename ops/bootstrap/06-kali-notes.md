# 06 — Kali attacker VM (match lab)

## Network

- Lab NIC: `192.168.221.30` on VMnet1
- Keep NAT for package updates if needed

## Tools used in verified tests

```bash
sudo apt update
sudo apt install -y nmap gobuster
```

## Smoke commands (authorized lab only)

```bash
# Nmap SYN against IDS
nmap -sS -p 1-100 192.168.221.136

# Gobuster (needs HTTP target on IDS/SOC lab port 80 or 8080)
gobuster dir -u http://192.168.221.136:8080/ -w /usr/share/wordlists/dirb/common.txt

# ICMP
ping -c 20 192.168.221.136
```

Then confirm alerts in:

- Wazuh Dashboard → Threat Hunting / SOC Lab Monitoring
- ML UI → `http://192.168.221.138:8088/ui`
