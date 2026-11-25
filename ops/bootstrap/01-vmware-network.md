# 01 — VMware network (match verified lab)

Recreate the **exact** addressing used by this project.

## Create host-only network

1. VMware → **Edit → Virtual Network Editor**
2. Add **VMnet1** (Host-only)
3. Subnet: `192.168.221.0` / mask `255.255.255.0`
4. Disable DHCP if you prefer static IPs (recommended)

## Create 3 Ubuntu + 1 Kali VMs

| VM | Role | Lab NIC (VMnet1) | Optional NAT |
|----|------|------------------|--------------|
| Kali | Attacker / tester | `192.168.221.30` | yes |
| Ubuntu IDS | Suricata + Wazuh agent | `192.168.221.136` (`ens37`) | yes (`ens33`) |
| Ubuntu SOC | Wazuh Docker + ML | `192.168.221.138` | optional |
| Windows 11 | Endpoint (optional) | `192.168.221.135` | — |

## IDS interface note

Suricata must listen on the **lab** NIC (`ens37` / `192.168.221.136`), not the NAT NIC.

```bash
ip -br a
# ens37 should own 192.168.221.136
```

## SSH from Windows host

```powershell
ssh -i $env:USERPROFILE\.ssh\lab_ed25519 root@192.168.221.138
ssh -i $env:USERPROFILE\.ssh\lab_ed25519 root@192.168.221.136
```

Generate a lab key if needed:

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\lab_ed25519 -N '""'
```

Then continue with `02-ids-bootstrap.sh` and `03-soc-wazuh-bootstrap.sh`.
