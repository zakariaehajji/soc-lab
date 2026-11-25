# Sync this repo's ML + detection bits to the live SOC (and optionally IDS).
# Run from Windows operator host with lab SSH key.
param(
  [string]$SocHost = "192.168.221.138",
  [string]$IdsHost = "192.168.221.136",
  [string]$Key = "$env:USERPROFILE\.ssh\lab_ed25519",
  [switch]$IdsRules,
  [switch]$SkipRestart
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$SshBase = @("-i", $Key, "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10")

function Invoke-Ssh([string]$Target, [string]$RemoteCmd) {
  & ssh @SshBase $Target $RemoteCmd
}
function Invoke-Scp([string[]]$Sources, [string]$Dest) {
  & scp @SshBase @Sources $Dest
}

Write-Host "[*] Repo: $RepoRoot"
Write-Host "[*] SOC:  $SocHost"

Invoke-Ssh "root@$SocHost" "mkdir -p /tmp/soc-sync/ml-engine /tmp/soc-sync/detection /tmp/soc-sync/ops /opt/ml-engine /opt/soc-lab"

Invoke-Scp @("$RepoRoot\detection") "root@${SocHost}:/tmp/soc-sync/"
Invoke-Scp @("$RepoRoot\ops") "root@${SocHost}:/tmp/soc-sync/"
Invoke-Scp @(
  "$RepoRoot\ml-engine\src",
  "$RepoRoot\ml-engine\artifacts",
  "$RepoRoot\ml-engine\deploy",
  "$RepoRoot\ml-engine\requirements.txt",
  "$RepoRoot\ml-engine\README.md"
) "root@${SocHost}:/tmp/soc-sync/ml-engine/"

Invoke-Ssh "root@$SocHost" @'
set -e
rsync -a /tmp/soc-sync/detection /opt/soc-lab/
rsync -a /tmp/soc-sync/ops /opt/soc-lab/
rsync -a /tmp/soc-sync/ml-engine/src/ /opt/ml-engine/src/
rsync -a /tmp/soc-sync/ml-engine/artifacts/ /opt/ml-engine/artifacts/
rsync -a /tmp/soc-sync/ml-engine/deploy/ /opt/ml-engine/deploy/
cp /tmp/soc-sync/ml-engine/requirements.txt /opt/ml-engine/requirements.txt
cp /tmp/soc-sync/ml-engine/README.md /opt/ml-engine/README.md
cd /opt/ml-engine
. .venv/bin/activate
pip install -q -r requirements.txt
'@

if (-not $SkipRestart) {
  Invoke-Ssh "root@$SocHost" "systemctl daemon-reload; systemctl restart soc-ml-api; sleep 2; curl -s http://127.0.0.1:8088/health; echo"
}

if ($IdsRules) {
  Write-Host "[*] Push Suricata rules to IDS $IdsHost"
  Invoke-Scp @("$RepoRoot\detection\suricata\local.rules") "root@${IdsHost}:/var/lib/suricata/rules/local.rules"
  Invoke-Ssh "root@$IdsHost" 'suricata -T -c /etc/suricata/suricata.yaml && (kill -USR2 $(pidof suricata) || systemctl restart suricata)'
}

Write-Host "[+] Sync complete"
