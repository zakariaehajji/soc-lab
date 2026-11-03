# Gobuster / web enumeration tests

## Lab web target

Temporary authorized server on IDS:

```bash
python3 -m http.server 8080 --bind 192.168.221.136 --directory /opt/soc-lab-web
```

Content includes `/`, `/admin/`, `/images/`, `/.git/HEAD`.

Suricata `HTTP_PORTS` updated to `[80,8080]` (backed up YAML first).

## Commands

```bash
gobuster dir -u http://192.168.221.136:8080 -w /tmp/wl.txt -q -t 20 --no-error
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.221.136:8080/admin/
curl -s -o /dev/null -w '%{http_code}\n' http://192.168.221.136:8080/.git/HEAD
```

## Results

| Behavior | Suricata SID | Wazuh rule | Evidence time (UTC) |
|----------|--------------|------------|---------------------|
| Directory enum burst | 1000010 | 100110 (lvl 8) | 2026-11-03T19:36:16Z / 19:41:03Z |
| `/admin` probe | 1000011 | 100111 (lvl 7) | 19:36:15Z / 19:41:01Z |
| `.git` probe | 1000012 | 100112 (lvl 8) | 19:36:15Z / 19:41:01Z |
| High-frequency HTTP | 1000013 | 100113 (lvl 7) | 19:36:16Z / 19:41:01Z |

Gobuster found: `admin`, `images`, `.git` (HTTP 301).

## Design notes

- Thresholds avoid single-page browsing noise.
- Source restricted to Kali `192.168.221.30`.
- No external websites scanned.
