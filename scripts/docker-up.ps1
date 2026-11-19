param([switch]$Reset, [switch]$NoBuild)
# Creates .env with random secrets (first run only), then builds and starts
# the four-container stack and prints the first-time setup token.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker Desktop is not installed.' }
docker info --format '{{.OSType}}' *> $null
if ($LASTEXITCODE -ne 0) { throw 'Start Docker Desktop (Linux containers) and run this again.' }

function New-Secret { $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant() }

if ($Reset) {
    Write-Host 'Removing containers AND all evidence volumes...' -ForegroundColor Yellow
    docker compose down -v
    if ($LASTEXITCODE -ne 0) { throw 'Reset failed; existing credentials were preserved.' }
    Remove-Item -LiteralPath '.env' -ErrorAction SilentlyContinue
}
if (-not (Test-Path -LiteralPath '.env')) {
    @(
        "POSTGRES_PASSWORD=$(New-Secret)",
        "CBB_SIGNER_TOKEN=$(New-Secret)",
        "CBB_LAB_SENDER_TOKEN=$(New-Secret)",
        "CBB_PORT=8765"
    ) | Set-Content -LiteralPath '.env' -Encoding ascii
    Write-Host 'Created .env with new random secrets.'
}

if (-not $NoBuild) {
    docker compose build app
    if ($LASTEXITCODE -ne 0) { throw 'Image build failed.' }
}
docker compose up -d
if ($LASTEXITCODE -ne 0) { throw 'docker compose up failed.' }

$port = ((Get-Content '.env' | Where-Object { $_ -like 'CBB_PORT=*' }) -replace 'CBB_PORT=', '')
if (-not $port) { $port = '8765' }
Write-Host 'Waiting for the console to become ready...'
$ready = $false
for ($i = 0; $i -lt 90; $i++) {
    try { Invoke-RestMethod "http://localhost:$port/health/ready" -TimeoutSec 3 | Out-Null; $ready = $true; break } catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) { throw 'Console readiness timed out. Check docker compose logs app trust db before retrying.' }
docker compose ps
$token = docker compose exec -T app sh -c 'cat /data/keys/bootstrap.token 2>/dev/null'
Write-Host ''
Write-Host "Cyber Black Box console: http://localhost:$port" -ForegroundColor Cyan
if ($token) {
    Write-Host 'First-time setup token (paste into the setup screen):' -ForegroundColor Cyan
    Write-Host $token
} else {
    Write-Host 'Setup already completed. Sign in with your administrator account.'
}
Start-Process "http://localhost:$port"
