# SOC ML Runbook

## Status check
ssh -i ~/.ssh/lab_ed25519 root@192.168.221.138
systemctl status soc-ml-api soc-ml-bridge --no-pager
curl -s http://127.0.0.1:8088/health
tail -n 20 /opt/ml-engine/logs/enrichment.jsonl

## Score a Wazuh alert manually
curl -s -X POST http://127.0.0.1:8088/score \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{"request_id":"manual-1","source":"manual","event":{"rule":{"id":"100101","level":10,"description":"SOC-LAB: Nmap TCP SYN scan detected via Suricata","groups":["soc_lab","nmap"]},"data":{"srcip":"192.168.221.30","dstip":"192.168.221.136","srcport":"45000","dstport":"22","proto":"TCP"},"agent":{"name":"suricata-ids"},"timestamp":"2026-11-03T20:00:00.000+0000"}}
EOF

## Restart
systemctl restart soc-ml-api soc-ml-bridge

## Logs
journalctl -u soc-ml-api -f
journalctl -u soc-ml-bridge -f

## Paths
- Code/models: /opt/ml-engine
- Enrichment: /opt/ml-engine/logs/enrichment.jsonl
- Units: /etc/systemd/system/soc-ml-*.service

## Notes
- Additive only: SIEM/IDS configs unchanged
- Features are Suricata/Wazuh-derived (not CIC)
- Bridge polls indexer every 20s for SOC-LAB / LOCAL Suricata alerts