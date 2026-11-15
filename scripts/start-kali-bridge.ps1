param([switch]$Once)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$key=Join-Path $root 'work\kali-ssh'
$known=Join-Path $root 'work\kali-known-hosts'
if(-not (Get-Command ssh -ErrorAction SilentlyContinue)){throw 'Windows OpenSSH client is required.'}
if(-not (Test-Path -LiteralPath $key) -or -not (Test-Path -LiteralPath $known)){throw 'Existing Kali SSH key and verified known-hosts file are required in work/. Do not disable host-key checking.'}
$pythonExe=Join-Path $root '.venv\Scripts\python.exe'
Push-Location -LiteralPath $root
try {
 $connectionJson = & $pythonExe -m cbb.kali
 if($LASTEXITCODE -ne 0){throw 'Invalid Kali connection configuration.'}
 $connection = $connectionJson | ConvertFrom-Json
} finally { Pop-Location }
$destination = $connection.username + '@' + $connection.host
Write-Host 'Kali log connection: guest localhost:18765 -> Windows localhost:8765.'
Write-Host 'Start Cloud Box and the Kali VM first. Keep this terminal open. Ctrl+C stops the connection.'
do {
 & ssh -N -i $key -p $connection.port -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known" -o ExitOnForwardFailure=yes -o ConnectTimeout=8 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -R 127.0.0.1:18765:127.0.0.1:8765 $destination
 $result=$LASTEXITCODE
 if($Once){exit $result}
 Write-Host "Connection ended (code $result). Retrying in 10 seconds; check Kali and avoid running duplicate bridge windows."
 Start-Sleep -Seconds 10
} while($true)
