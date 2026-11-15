param([string]$Data = 'data')
$ErrorActionPreference = 'Stop'
$keys = Join-Path ([IO.Path]::GetFullPath($Data)) 'keys'
[void][IO.Directory]::CreateDirectory($keys)
$operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')

function Set-KeyAccess([string]$Path, [bool]$Directory) {
    $existing = Get-Acl -LiteralPath $Path
    $rules = @($existing.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $expectedSids = @($operatorSid.Value, $systemSid.Value)
    $expectedInheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else { [Security.AccessControl.InheritanceFlags]::None }
    $matching = @($rules | Where-Object {
        $_.IdentityReference.Value -in $expectedSids -and
        $_.AccessControlType -eq 'Allow' -and
        $_.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl -and
        $_.InheritanceFlags -eq $expectedInheritance -and
        $_.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None -and
        -not $_.IsInherited
    })
    if ($existing.AreAccessRulesProtected -and $rules.Count -eq 2 -and $matching.Count -eq 2 -and
        @($matching.IdentityReference.Value | Select-Object -Unique).Count -eq 2) {
        return # Already restricted to this operator and SYSTEM; no write needed.
    }
    # Construct only the access-control section. Reapplying Get-Acl's complete
    # descriptor can attempt to write audit information and require
    # SeSecurityPrivilege even when the operator owns the directory.
    $acl = if ($Directory) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
    foreach ($sid in @($operatorSid, $systemSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', $inheritance, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Set-KeyAccess $keys $true
foreach ($name in @('signing.pem', 'bootstrap.token')) {
    $path = Join-Path $keys $name
    if (Test-Path -LiteralPath $path -PathType Leaf) { Set-KeyAccess $path $false }
}
