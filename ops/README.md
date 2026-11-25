# Ops

Lab session notes and **bootstrap scripts** to recreate the verified SOC état.

## Reproduce the lab

See **[bootstrap/README.md](bootstrap/README.md)** for the full ordered guide:

1. VMware VMnet1 `192.168.221.0/24`
2. IDS Suricata + agent
3. SOC Wazuh 4.14.9 Docker
4. Detection rules push
5. ML engine (`/score` + `/score/cic`)
6. `verify-lab.sh`

## Inventory

Copy and edit (do not commit secrets):

```bash
cp ops/lab-inventory.env.example ops/lab-inventory.env
```

## Session notes

Historical bring-up logs live under `session-notes/`.
