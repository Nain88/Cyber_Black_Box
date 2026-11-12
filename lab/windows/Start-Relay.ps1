param([string]$KaliIP = "", [switch]$Once)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$pythonExe = Join-Path $root '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $pythonExe) {
    $python = $pythonExe; $args0 = @()
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $python = 'py'; $args0 = @('-3.12')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $python = 'python'; $args0 = @()
} else {
    throw 'Python 3.12 or later is required on the Windows host.'
}
$script = Join-Path $root 'lab\relay\relay.py'
$stateDir = Join-Path $root 'lab\.lab-state'
$state = Join-Path $stateDir 'relay.json'
if (-not (Test-Path $state)) {
    if (-not $KaliIP) { $KaliIP = Read-Host 'Kali VM private IPv4 address' }
    Write-Host 'First-time relay enrollment. Create a one-time collector token in Cloud Box > Collectors > Enroll.' -ForegroundColor Yellow
    & $python @args0 $script init --kali "http://${KaliIP}:8088"
    if ($LASTEXITCODE -ne 0) { throw 'Relay enrollment failed.' }
    # Restrict the local secret directory. Keep it OUT of Git.
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $stateDir /inheritance:r /grant:r "${user}:(OI)(CI)F" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Could not tighten ACLs automatically. Protect lab/.lab-state manually.' }
}
Write-Host 'The relay runs on Windows because Cloud Box listens only on 127.0.0.1.' -ForegroundColor Cyan
Write-Host 'Keep this console running while triggering tests in the Docker dashboard.'
if ($Once) { & $python @args0 $script run --once }
else { & $python @args0 $script run --interval 3 }
if ($LASTEXITCODE -ne 0) { throw "Relay ended with exit code $LASTEXITCODE" }
