# Read-only health checks: Windows -> Kali, Docker -> Kali, Windows -> Cloud Box.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$envFile = Join-Path $root 'lab\.env'
if (-not (Test-Path $envFile)) { throw 'Missing lab/.env. Run Start-Attack-Lab.ps1 first.' }
$line = Get-Content $envFile | Where-Object { $_ -match '^KALI_IP=' } | Select-Object -First 1
if (-not $line) { throw 'Missing KALI_IP in lab/.env.' }
$ip = ($line -split '=', 2)[1]
Write-Host "[Windows -> Kali] ${ip}:8088" -ForegroundColor Cyan
Test-NetConnection -ComputerName $ip -Port 8088 | Select-Object ComputerName,TcpTestSucceeded
try { Invoke-RestMethod "http://${ip}:8088/health" -TimeoutSec 5 | Format-List } catch { Write-Warning "Kali decoy failed: $_" }
Write-Host '[Windows -> Cloud Box] localhost:8765' -ForegroundColor Cyan
try { Invoke-RestMethod 'http://127.0.0.1:8765/health/ready' -TimeoutSec 5 | Format-List } catch { Write-Warning "Cloud Box failed: $_" }
Write-Host '[Docker -> Kali] using attacker-dashboard container' -ForegroundColor Cyan
$probe = "import os,urllib.request;print(urllib.request.urlopen(os.environ['KALI_TARGET_URL']+'/health',timeout=5).read().decode())"
& docker compose --env-file lab/.env -f compose.lab.yml exec -T attacker-dashboard python -c $probe
if ($LASTEXITCODE -ne 0) { Write-Warning 'Docker cannot reach Kali. Check the Docker Desktop/VMware private network route.' }
