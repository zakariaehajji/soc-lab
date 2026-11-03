# Nmap detection tests

**Scope:** Kali `192.168.221.30` → IDS `192.168.221.136` only (VMnet1).  
**Window:** 2026-11-03 ~19:35–19:41 UTC

## Commands

| Test | Command |
|------|---------|
| TCP SYN | `nmap -sS -Pn -T4 --top-ports 20 192.168.221.136` |
| TCP Connect | `nmap -sT -Pn -T4 --top-ports 20 192.168.221.136` |
| TCP NULL | `sudo nmap -sN -Pn -T4 --top-ports 30 192.168.221.136` |
| TCP FIN | `sudo nmap -sF -Pn -T4 --top-ports 30 192.168.221.136` |
| TCP Xmas | `sudo nmap -sX -Pn -T4 --top-ports 30 192.168.221.136` |
| Version | `nmap -sV -Pn -T4 --top-ports 15 192.168.221.136` |
| Common ports | `nmap -sS -Pn -T4 --top-ports 100 192.168.221.136` |

## Results

| Test | Suricata SID | Suricata evidence | Wazuh rule | Indexed |
|------|--------------|-------------------|------------|---------|
| SYN | 1000001 | EVE alert 19:35:34Z+ | 100101 (lvl 6) | Yes |
| Connect-style | 1000002 | EVE alert | 100102 (lvl 6) | Yes |
| NULL | 1000003 | EVE 19:37:40Z / retest 19:40:57Z | 100103 (lvl 7) | Yes |
| FIN | 1000004 | EVE 19:37:44Z | 100104 (lvl 7) | Yes (initial); retest omitted FIN |
| Xmas | 1000005 | EVE 19:37:48Z / retest 19:40:59Z | 100105 (lvl 7) | Yes |
| Version burst | 1000006 | EVE during -sV / sweeps | 100106 (lvl 6) | Yes |
| Common ports | 1000007 | EVE during top-ports 100 | 100107 (lvl 6) | Yes |

## Notes / FP-FN

- Connect scans and SYN scans both emit SYNs; SIDs 1000001/1000002 may co-fire. Acceptable for lab classification; correlation rule `100130` covers multi-signature bursts.
- NULL/FIN/Xmas require root on Kali (`sudo`). First attempt without passwordless sudo failed; re-run with credentials succeeded.
- Stock Emerging Threats also fired (e.g. Nmap User-Agent on `:8080`) — not used as primary success criteria.
