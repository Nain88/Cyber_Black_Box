param([Parameter(Mandatory=$true)][string]$KaliIP)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Create the project Python virtual environment first.' }
$env:KALI_TARGET_URL = "http://${KaliIP}:8088"
$env:LAB_BIND = '127.0.0.1'
$envFile = Join-Path $root 'lab\.env'
if (Test-Path -LiteralPath $envFile) {
    $line = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^LAB_OPERATOR_PASSWORD=' } | Select-Object -First 1
    if ($line) { $env:LAB_OPERATOR_PASSWORD = $line.Substring('LAB_OPERATOR_PASSWORD='.Length) }
}
if (-not $env:LAB_OPERATOR_PASSWORD) {
    $buffer = New-Object byte[] 36
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    $env:LAB_OPERATOR_PASSWORD = [Convert]::ToBase64String($buffer)
    @("KALI_IP=$KaliIP", "LAB_OPERATOR_PASSWORD=$env:LAB_OPERATOR_PASSWORD") | Set-Content -LiteralPath $envFile -Encoding ASCII
}
Write-Host 'Controller: http://127.0.0.1:8844. Operator password is saved in lab/.env.'
Write-Host 'Keep this terminal open; Ctrl+C ends the controller.'
& $python (Join-Path $root 'lab\controller\controller.py')
exit $LASTEXITCODE
