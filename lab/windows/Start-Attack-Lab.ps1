param([string]$KaliIP = "")
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$envFile = Join-Path $root 'lab\.env'
if (-not (Test-Path -LiteralPath $envFile)) {
    if (-not $KaliIP) { $KaliIP = Read-Host 'Kali VM private IPv4 address (example: 192.168.56.101)' }
    if ($KaliIP -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
        throw 'Kali must have a private RFC1918 IPv4 address. Do not use a public target.'
    }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $buffer = New-Object byte[] 36; $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    $password = [Convert]::ToBase64String($buffer)
    @("KALI_IP=$KaliIP", "LAB_OPERATOR_PASSWORD=$password") | Set-Content -Encoding ASCII -LiteralPath $envFile
    Write-Host 'Saved dashboard-only credentials into lab/.env (Git ignored).' -ForegroundColor Green
    Write-Host "Dashboard operator password: $password" -ForegroundColor Cyan
    Write-Host 'Save it securely. It is not the Kali shared key or Cloud Box password.'
} else {
    Write-Host 'Using existing lab/.env. No credentials were changed.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker CLI not found. Install and start Docker Desktop.' }
& docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not running.' }
& docker compose --env-file 'lab/.env' -f compose.lab.yml up -d --build
if ($LASTEXITCODE -ne 0) { throw 'Docker compose failed. Check the output above.' }
Write-Host 'Attack Lab is available at http://127.0.0.1:8844' -ForegroundColor Green
Write-Host 'Verify that Kali target.py is running and that its IP matches lab/.env.'
Start-Process 'http://127.0.0.1:8844'
