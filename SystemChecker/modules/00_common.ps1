#Requires -Version 5.1
<#
.SYNOPSIS
    Shared helpers for SystemChecker. Dot-source this file. Do not run it alone.

.DESCRIPTION
    Read-only output, registry, ACL, and native-command helpers for Windows
    PowerShell 5.1. Other modules and Run-SystemChecker.ps1 dot-source this
    script. It does not collect secrets and it does not change the host.

    Adding a module:
      1. Create modules/NN_name.ps1 that dot-sources this file.
      2. Register an alias in Run-SystemChecker.ps1.
      3. Print a banner with Write-SCHeader and group checks with Start-SCSection.
      4. Use Write-SCInfo / Write-SCReview / Write-SCWeak / Write-SCWarn.
      5. Finish with the nested-runner tail shown at the bottom of 01_system.ps1.
         Call operator (&) from the runner. Do not dot-source a module, because
         a top-level return would unwind the runner.

    PowerShell 5.1 notes:
      - No ternary operator, no null-coalescing operator, no && / || chains.
      - Join-Path accepts only two parts.
      - ANSI uses [char]27. The `e escape is PowerShell 7 only.
      - $script:SCPlain and $script:SCLogPath are the in-script switches.
        The runner also mirrors them to $global:SCPlain / $global:SCLogPath
        and to SYSTEMCHECKER_PLAIN / SYSTEMCHECKER_LOG so a child script sees
        them after it dot-sources this file.
#>

# Dot-sourcing applies these assignments to the caller (runner or module).
if (-not (Test-Path -Path 'variable:global:SCPlain')) {
    $global:SCPlain = $false
}
if (-not (Test-Path -Path 'variable:global:SCLogPath')) {
    $global:SCLogPath = $null
}

if ($env:SYSTEMCHECKER_PLAIN -eq '1') {
    $script:SCPlain = $true
} else {
    $script:SCPlain = [bool]$global:SCPlain
}

if ($env:SYSTEMCHECKER_LOG) {
    $script:SCLogPath = [string]$env:SYSTEMCHECKER_LOG
} elseif ($global:SCLogPath) {
    $script:SCLogPath = [string]$global:SCLogPath
} else {
    $script:SCLogPath = $null
}

$script:SCLogFailed = $false
$script:SCSectionOpen = $false
$script:SCSectionCount = 0
$script:SCContextCache = $null

function Test-SCPlainMode {
    # True when the operator asked for text without ANSI color.
    if ($script:SCPlain) { return $true }
    if ((Test-Path -Path 'variable:global:SCPlain') -and $global:SCPlain) { return $true }
    if ($env:SYSTEMCHECKER_PLAIN -eq '1') { return $true }
    return $false
}

function Get-SCAnsi {
    param([Parameter(Mandatory = $true)][string]$Name)
    $esc = [string]([char]27)
    switch ($Name) {
        'Header'  { return ($esc + '[1;36m') }
        'Section' { return ($esc + '[1;37m') }
        'Info'    { return ($esc + '[36m') }
        'Review'  { return ($esc + '[33m') }
        'Weak'    { return ($esc + '[1;35m') }
        'Warn'    { return ($esc + '[1;31m') }
        'Dim'     { return ($esc + '[90m') }
        'Reset'   { return ($esc + '[0m') }
        default   { return '' }
    }
}

function Write-SCLog {
    param([AllowEmptyString()][string]$Text)
    if ($script:SCLogFailed) { return }
    if (-not $script:SCLogPath) { return }
    try {
        $utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
        $line = $Text + [Environment]::NewLine
        [System.IO.File]::AppendAllText($script:SCLogPath, $line, $utf8)
    } catch {
        # One warning, then stop touching the disk. Never throw into a check.
        $script:SCLogFailed = $true
        Write-Host ("[WARN] Log write failed: {0}" -f $_.Exception.Message)
    }
}

function Set-SCOutputRendering {
    # Windows PowerShell 5.1 prints ANSI bytes from Write-Host as-is.
    # PowerShell 7 can force PlainText and strip them. Keep the codes on a
    # console when color is on, and force plain text when -Plain is set.
    # $PSStyle does not exist in Windows PowerShell 5.1.
    if (-not (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue)) { return }
    try {
        if (Test-SCPlainMode) {
            $PSStyle.OutputRendering = 'PlainText'
            return
        }
        $redirected = $false
        try { $redirected = [Console]::IsOutputRedirected } catch { $redirected = $false }
        if ($redirected) { return }
        $PSStyle.OutputRendering = 'ANSI'
    } catch {
        # Color is optional. A host that rejects the setting still prints text.
    }
}

function Write-SCLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,
        [string]$Style = 'None'
    )
    if ((-not (Test-SCPlainMode)) -and $Style -and $Style -ne 'None') {
        $painted = (Get-SCAnsi -Name $Style) + $Text + (Get-SCAnsi -Name 'Reset')
        Write-Host $painted
    } else {
        Write-Host $Text
    }
    Write-SCLog -Text $Text
}

function Write-SCHeader {
    param([Parameter(Mandatory = $true)][string]$Title)
    $ctx = Get-SCContext
    $adminText = 'No'
    if ($ctx.IsAdmin) { $adminText = 'Yes' }
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $lines = @(
        '============================================================'
        (" SystemChecker :: {0}" -f $Title)
        (" Computer : {0}" -f $ctx.ComputerName)
        (" User     : {0}" -f $ctx.UserName)
        (" Time     : {0}" -f $stamp)
        (" Admin    : {0}" -f $adminText)
        '============================================================'
    )
    foreach ($line in $lines) {
        Write-SCLine -Text $line -Style Header
    }
}

function Start-SCSection {
    param([Parameter(Mandatory = $true)][string]$Title)
    if ($script:SCSectionOpen -and $script:SCSectionCount -eq 0) {
        Write-SCLine -Text 'Nothing notable' -Style Dim
    }
    Write-SCLine -Text ''
    Write-SCLine -Text ("---- {0} ----" -f $Title) -Style Section
    $script:SCSectionOpen = $true
    $script:SCSectionCount = 0
}

function Complete-SCSection {
    # Close the open section. Safe to call when nothing is open.
    if (-not $script:SCSectionOpen) { return }
    if ($script:SCSectionCount -eq 0) {
        Write-SCLine -Text 'Nothing notable' -Style Dim
    }
    $script:SCSectionOpen = $false
    $script:SCSectionCount = 0
}

function Write-SCFinding {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$Style
    )
    $script:SCSectionCount = [int]$script:SCSectionCount + 1
    Write-SCLine -Text ("[{0}] {1}" -f $Label, $Message) -Style $Style
}

function Write-SCInfo {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-SCFinding -Label 'INFO' -Message $Message -Style Info
}

function Write-SCReview {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-SCFinding -Label 'REVIEW' -Message $Message -Style Review
}

function Write-SCWeak {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-SCFinding -Label 'WEAK' -Message $Message -Style Weak
}

function Write-SCWarn {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-SCFinding -Label 'WARN' -Message $Message -Style Warn
}

function Write-SCNeedsAdmin {
    param([string]$Detail)
    if ($Detail) {
        Write-SCWarn -Message ("NEEDS ADMIN: {0}" -f $Detail)
    } else {
        Write-SCWarn -Message 'NEEDS ADMIN'
    }
}

function Test-SCAccessDenied {
    param([string]$Message)
    if ([string]::IsNullOrEmpty($Message)) { return $false }
    return ($Message -match 'access is denied|Access denied|0x80070005|privilege not held|UnauthorizedAccess|not authorized')
}

function Test-SCAdmin {
    # Process token, not the account's potential to elevate.
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-SCContext {
    # Cached for the current script. A module invoked with & has its own cache.
    if ($script:SCContextCache) { return $script:SCContextCache }

    $computer = $env:COMPUTERNAME
    if (-not $computer) { $computer = [System.Environment]::MachineName }
    $account = $env:USERNAME
    if (-not $account) { $account = [System.Environment]::UserName }
    if ($env:USERDOMAIN -and $account) {
        $user = '{0}\{1}' -f $env:USERDOMAIN, $account
    } elseif ($account) {
        $user = $account
    } else {
        $user = 'unknown'
    }

    $ctx = [ordered]@{
        ComputerName = $computer
        UserName     = $user
        IsAdmin      = (Test-SCAdmin)
        OsCaption    = $null
        OsVersion    = $null
        OsBuild      = $null
        Architecture = $env:PROCESSOR_ARCHITECTURE
        InstallDate  = $null
        LastBoot     = $null
        Uptime       = $null
        PartOfDomain = $null
        Domain       = $null
        Workgroup    = $null
        DomainRole   = $null
    }

    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            if ($os.Caption) { $ctx.OsCaption = [string]$os.Caption }
            if ($os.Version) { $ctx.OsVersion = [string]$os.Version }
            if ($os.BuildNumber) { $ctx.OsBuild = [string]$os.BuildNumber }
            if ($os.OSArchitecture) { $ctx.Architecture = [string]$os.OSArchitecture }
            if ($os.InstallDate) { $ctx.InstallDate = [datetime]$os.InstallDate }
            if ($os.LastBootUpTime) {
                $ctx.LastBoot = [datetime]$os.LastBootUpTime
                $ctx.Uptime = (Get-Date) - $ctx.LastBoot
            }
            if ($os.CSName) { $ctx.ComputerName = [string]$os.CSName }
        } catch {
            # Leave OS fields empty. The caller prints a warning.
        }
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($cs.Name) { $ctx.ComputerName = [string]$cs.Name }
            $ctx.PartOfDomain = [bool]$cs.PartOfDomain
            if ($cs.Domain) { $ctx.Domain = [string]$cs.Domain }
            if ($cs.Workgroup) { $ctx.Workgroup = [string]$cs.Workgroup }
            if ($null -ne $cs.DomainRole) { $ctx.DomainRole = [int]$cs.DomainRole }
        } catch {
            # Domain fields stay null.
        }
    }

    # [pscustomobject] keeps every field, including nulls, on Windows PowerShell 5.1.
    $script:SCContextCache = [pscustomobject]$ctx
    return $script:SCContextCache
}

function Format-SCDate {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return 'unknown' }
    try {
        return ([datetime]$Value).ToString('yyyy-MM-dd')
    } catch {
        return [string]$Value
    }
}

function Get-SCRegistryValue {
    <#
        .SYNOPSIS
            Read one registry value. Missing path or value is not an error.
        .OUTPUTS
            Object with Found (bool), Value, and Error (string or null).
            Error is set for access denied and unexpected failures.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $result = New-Object psobject -Property @{
        Found = $false
        Value = $null
        Error = $null
    }
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            return $result
        }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        $result.Found = $true
        $result.Value = $item.$Name
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) {
            $result.Error = $message
        } elseif ($message -notmatch 'does not exist|Cannot find path|ItemNotFound') {
            $result.Error = $message
        }
    }
    return $result
}

function Test-SCPrivilegedIdentity {
    param([string]$Sid, [string]$Name)
    if ($Sid) {
        $exact = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-544')
        if ($exact -contains $Sid) { return $true }
        if ($Sid -like 'S-1-5-80-*') { return $true }
        # Domain Admins 512, Schema Admins 518, Enterprise Admins 519, Administrators 544.
        if ($Sid -match '-(512|518|519|544)$') { return $true }
    }
    if ($Name) {
        $leaf = $Name
        if ($Name -match '\\') {
            $pieces = $Name.Split('\')
            $leaf = $pieces[$pieces.Length - 1]
        }
        $adminNames = @(
            'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'Administrators',
            'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'TrustedInstaller'
        )
        if ($adminNames -contains $leaf) { return $true }
    }
    return $false
}

function Test-SCBroadIdentity {
    # Principals that cover more than one interactive user.
    param([string]$Sid, [string]$Name)
    $broadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-7', 'S-1-5-4')
    if ($Sid -and ($broadSids -contains $Sid)) { return $true }
    if ($Name) {
        $leaf = $Name
        if ($Name -match '\\') {
            $pieces = $Name.Split('\')
            $leaf = $pieces[$pieces.Length - 1]
        }
        $broadNames = @(
            'Everyone', 'Authenticated Users', 'Users', 'Guests',
            'ANONYMOUS LOGON', 'INTERACTIVE'
        )
        if ($broadNames -contains $leaf) { return $true }
    }
    return $false
}

function Test-SCFileWriteMask {
    param($Rights)
    # Write-oriented file bits. This is an ACL flag test, not effective access.
    $value = 0
    try { $value = [int]$Rights } catch { return $false }
    $mask = 0x0002 -bor 0x0004 -bor 0x0010 -bor 0x0100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    return (($value -band $mask) -ne 0)
}

function Format-SCServiceRights {
    param([int]$Mask)
    $names = New-Object System.Collections.Generic.List[string]
    if (($Mask -band 0xF01FF) -eq 0xF01FF) {
        $names.Add('FullControl')
    } else {
        if ($Mask -band 0x0001) { $names.Add('QueryConfig') }
        if ($Mask -band 0x0002) { $names.Add('ChangeConfig') }
        if ($Mask -band 0x0004) { $names.Add('QueryStatus') }
        if ($Mask -band 0x0008) { $names.Add('EnumerateDependents') }
        if ($Mask -band 0x0010) { $names.Add('Start') }
        if ($Mask -band 0x0020) { $names.Add('Stop') }
        if ($Mask -band 0x0040) { $names.Add('Pause') }
        if ($Mask -band 0x0080) { $names.Add('Interrogate') }
        if ($Mask -band 0x0100) { $names.Add('UserDefined') }
        if ($Mask -band 0x10000) { $names.Add('Delete') }
        if ($Mask -band 0x20000) { $names.Add('ReadControl') }
        if ($Mask -band 0x40000) { $names.Add('WriteDac') }
        if ($Mask -band 0x80000) { $names.Add('WriteOwner') }
    }
    if ($names.Count -eq 0) { return ('0x{0:X}' -f $Mask) }
    return ('{0} (0x{1:X})' -f ($names -join ', '), $Mask)
}

function New-SCAclResult {
    param([string]$Target, [string]$Kind)
    return New-Object psobject -Property @{
        Target                   = $Target
        Kind                     = $Kind
        Owner                    = $null
        Entries                  = @()
        Truncated                = $false
        NonAdminWritePrincipals  = @()
        BroadWritePrincipals     = @()
        Error                    = $null
    }
}

function Add-SCWritePrincipal {
    param($Bag, [string]$Identity, [bool]$Broad)
    if (-not $Identity) { return }
    if ($Bag.NonAdmin -notcontains $Identity) { [void]$Bag.NonAdmin.Add($Identity) }
    if ($Broad -and ($Bag.Broad -notcontains $Identity)) { [void]$Bag.Broad.Add($Identity) }
}

function Get-SCFileAclSummary {
    param([Parameter(Mandatory = $true)][string]$Path)
    $result = New-SCAclResult -Target $Path -Kind 'File'
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $result.Error = 'Path not found.'
        return $result
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $result.Owner = [string]$acl.Owner
        $display = New-Object System.Collections.Generic.List[object]
        $writers = @{
            NonAdmin = New-Object System.Collections.Generic.List[string]
            Broad    = New-Object System.Collections.Generic.List[string]
        }
        foreach ($ace in @($acl.Access)) {
            if (-not $ace) { continue }
            $identity = [string]$ace.IdentityReference
            $sid = $null
            if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                $sid = $ace.IdentityReference.Value
            } else {
                try {
                    $translated = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    $sid = $translated.Value
                } catch {
                    $sid = $null
                }
            }
            $isWrite = Test-SCFileWriteMask -Rights $ace.FileSystemRights
            $isAllow = ($ace.AccessControlType.ToString() -eq 'Allow')
            $isPrivileged = Test-SCPrivilegedIdentity -Sid $sid -Name $identity
            $isBroad = Test-SCBroadIdentity -Sid $sid -Name $identity
            if ($isAllow -and $isWrite -and -not $isPrivileged) {
                Add-SCWritePrincipal -Bag $writers -Identity $identity -Broad $isBroad
            }
            if ($display.Count -ge 40) {
                $result.Truncated = $true
                continue
            }
            $display.Add((New-Object psobject -Property @{
                Identity     = $identity
                Rights       = $ace.FileSystemRights.ToString()
                Type         = $ace.AccessControlType.ToString()
                IsWrite      = [bool]$isWrite
                IsPrivileged = [bool]$isPrivileged
                IsBroad      = [bool]$isBroad
            }))
        }
        $result.Entries = $display.ToArray()
        $result.NonAdminWritePrincipals = $writers.NonAdmin.ToArray()
        $result.BroadWritePrincipals = $writers.Broad.ToArray()
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-SCServiceAclSummary {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $result = New-SCAclResult -Target $ServiceName -Kind 'Service'
    if ($ServiceName -notmatch '^[A-Za-z0-9_.:-]{1,256}$') {
        $result.Error = 'Invalid service name.'
        return $result
    }
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        $result.Error = 'CIM is not available.'
        return $result
    }
    try {
        $filter = "Name='{0}'" -f $ServiceName.Replace("'", "''")
        $service = Get-CimInstance -ClassName Win32_Service -Filter $filter -ErrorAction Stop
        if (-not $service) {
            $result.Error = 'Service not found.'
            return $result
        }
        $method = Invoke-CimMethod -InputObject $service -MethodName GetSecurityDescriptor -ErrorAction Stop
        if ($null -eq $method -or $method.ReturnValue -ne 0) {
            $code = $null
            if ($method) { $code = $method.ReturnValue }
            if ($code -eq 2) {
                $result.Error = 'NEEDS ADMIN'
            } else {
                $result.Error = ("GetSecurityDescriptor returned {0}." -f $code)
            }
            return $result
        }
        $descriptor = $method.Descriptor
        if (-not $descriptor) {
            $result.Error = 'Security descriptor was empty.'
            return $result
        }
        $display = New-Object System.Collections.Generic.List[object]
        $writers = @{
            NonAdmin = New-Object System.Collections.Generic.List[string]
            Broad    = New-Object System.Collections.Generic.List[string]
        }
        foreach ($ace in @($descriptor.DACL)) {
            if (-not $ace) { continue }
            $trustee = $ace.Trustee
            $name = $null
            $domain = $null
            $sid = $null
            if ($trustee) {
                if ($trustee.PSObject.Properties['Name']) { $name = [string]$trustee.Name }
                if ($trustee.PSObject.Properties['Domain']) { $domain = [string]$trustee.Domain }
                if ($trustee.PSObject.Properties['SIDString']) { $sid = [string]$trustee.SIDString }
            }
            $identity = 'unknown'
            if ($domain -and $name) { $identity = '{0}\{1}' -f $domain, $name }
            elseif ($name) { $identity = $name }
            elseif ($sid) { $identity = $sid }

            $mask = 0
            if ($ace.PSObject.Properties['AccessMask']) {
                try { $mask = [int]$ace.AccessMask } catch { $mask = 0 }
            }
            $aceType = 'Other'
            if ($ace.PSObject.Properties['AceType']) {
                if ([int]$ace.AceType -eq 0) { $aceType = 'Allow' }
                elseif ([int]$ace.AceType -eq 1) { $aceType = 'Deny' }
            }
            $rights = Format-SCServiceRights -Mask $mask
            # ChangeConfig, Delete, WriteDac, WriteOwner, or full control.
            $isWrite = (($mask -band 0x0002) -ne 0 -or ($mask -band 0x10000) -ne 0 -or ($mask -band 0x40000) -ne 0 -or ($mask -band 0x80000) -ne 0 -or ($mask -band 0xF01FF) -eq 0xF01FF)
            $isPrivileged = Test-SCPrivilegedIdentity -Sid $sid -Name $identity
            $isBroad = Test-SCBroadIdentity -Sid $sid -Name $identity
            if ($aceType -eq 'Allow' -and $isWrite -and -not $isPrivileged) {
                Add-SCWritePrincipal -Bag $writers -Identity $identity -Broad $isBroad
            }
            if ($display.Count -ge 40) {
                $result.Truncated = $true
                continue
            }
            $display.Add((New-Object psobject -Property @{
                Identity     = $identity
                Rights       = $rights
                Type         = $aceType
                IsWrite      = [bool]$isWrite
                IsPrivileged = [bool]$isPrivileged
                IsBroad      = [bool]$isBroad
            }))
        }
        $result.Entries = $display.ToArray()
        $result.NonAdminWritePrincipals = $writers.NonAdmin.ToArray()
        $result.BroadWritePrincipals = $writers.Broad.ToArray()
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            $result.Error = 'NEEDS ADMIN'
        } else {
            $result.Error = $_.Exception.Message
        }
    }
    return $result
}

function Get-SCAclSummary {
    <#
        .SYNOPSIS
            Summarize a file, folder, or service DACL.
        .DESCRIPTION
            Pass Path or ServiceName, not both. The result is a summary for
            review. It is not a full effective-access evaluation. Deny ACEs
            are listed and are not expanded into an access-check engine.
            Service reads use the Win32_Service GetSecurityDescriptor method.
    #>
    param(
        [string]$Path,
        [string]$ServiceName
    )
    $hasPath = -not [string]::IsNullOrWhiteSpace($Path)
    $hasService = -not [string]::IsNullOrWhiteSpace($ServiceName)
    if ($hasPath -and $hasService) {
        $both = New-SCAclResult -Target $Path -Kind 'Invalid'
        $both.Error = 'Pass Path or ServiceName, not both.'
        return $both
    }
    if ($hasService) { return (Get-SCServiceAclSummary -ServiceName $ServiceName.Trim()) }
    if ($hasPath) { return (Get-SCFileAclSummary -Path $Path) }
    $missing = New-SCAclResult -Target '' -Kind 'Invalid'
    $missing.Error = 'Path or ServiceName is required.'
    return $missing
}

function Test-SCWritableByNonAdmin {
    <#
        .SYNOPSIS
            Report whether a file or folder ACL grants write to a non-admin.
        .OUTPUTS
            Writable, BroadWritable, Principals, BroadPrincipals, Error.
            BroadWritable is Everyone, Users, Authenticated Users, and similar.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $summary = Get-SCAclSummary -Path $Path
    $principals = @()
    $broad = @()
    if ($summary.NonAdminWritePrincipals) { $principals = @($summary.NonAdminWritePrincipals) }
    if ($summary.BroadWritePrincipals) { $broad = @($summary.BroadWritePrincipals) }
    return New-Object psobject -Property @{
        Writable        = ($principals.Count -gt 0)
        BroadWritable   = ($broad.Count -gt 0)
        Principals      = $principals
        BroadPrincipals = $broad
        Error           = $summary.Error
    }
}

function Test-SCUnquotedPath {
    <#
        .SYNOPSIS
            Return true when an executable path contains a space and is not quoted.
        .DESCRIPTION
            Configuration test for service ImagePath values. A true result means
            the path is unquoted. It is not instructions for using that fact.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $text = $Path.Trim()
    if ($text.StartsWith('"')) { return $false }
    $exe = $text
    $match = [regex]::Match($text, '(?i)\.(exe|cmd|bat|com)(?=\s|$)')
    if ($match.Success) {
        $exe = $text.Substring(0, $match.Index + $match.Length)
    }
    return ($exe -match '\s')
}

function Invoke-SCNative {
    <#
        .SYNOPSIS
            Run one approved built-in command. Failures return an object.
        .DESCRIPTION
            Allowlist: whoami, net, schtasks, systeminfo. The leaf name is
            used so a path discovered on disk cannot be executed. Non-zero
            exits and missing commands do not throw.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [string[]]$ArgumentList = @()
    )
    $leaf = [System.IO.Path]::GetFileName($FileName)
    if ($leaf.EndsWith('.exe')) { $leaf = $leaf.Substring(0, $leaf.Length - 4) }
    $allowed = @('whoami', 'net', 'schtasks', 'systeminfo')
    if ($allowed -notcontains $leaf.ToLower()) {
        return New-Object psobject -Property @{
            Ok       = $false
            ExitCode = $null
            Output   = @()
            Error    = 'Unsupported command. Allowed: whoami, net, schtasks, systeminfo.'
        }
    }
    try {
        $captured = @(& $leaf @ArgumentList 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
        return New-Object psobject -Property @{
            Ok       = ($code -eq 0)
            ExitCode = $code
            Output   = $captured
            Error    = $null
        }
    } catch {
        return New-Object psobject -Property @{
            Ok       = $false
            ExitCode = $null
            Output   = @()
            Error    = $_.Exception.Message
        }
    }
}

function Initialize-SCRuntime {
    <#
        .SYNOPSIS
            Apply -Plain and -Log for this process and for modules it calls.
        .DESCRIPTION
            Creates the log file only when LogPath is set and the parent
            directory already exists. A bad log path prints a warning and
            the assessment continues without a file.
    #>
    param(
        [switch]$Plain,
        [string]$LogPath
    )
    if ($Plain) {
        $script:SCPlain = $true
        $global:SCPlain = $true
        $env:SYSTEMCHECKER_PLAIN = '1'
    } else {
        $script:SCPlain = $false
        $global:SCPlain = $false
        if (Test-Path -Path 'Env:SYSTEMCHECKER_PLAIN') {
            Remove-Item -Path 'Env:SYSTEMCHECKER_PLAIN' -ErrorAction SilentlyContinue
        }
    }
    # Do this before any return. -Plain must win even when no log path is set.
    Set-SCOutputRendering

    $script:SCLogPath = $null
    $global:SCLogPath = $null
    $script:SCLogFailed = $false
    if (Test-Path -Path 'Env:SYSTEMCHECKER_LOG') {
        Remove-Item -Path 'Env:SYSTEMCHECKER_LOG' -ErrorAction SilentlyContinue
    }

    if ([string]::IsNullOrWhiteSpace($LogPath)) { return }

    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
    $parent = Split-Path -Parent $resolved
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        Write-SCWarn -Message ("Log directory does not exist. Continuing without a log: {0}" -f $parent)
        return
    }
    if ((Test-Path -LiteralPath $resolved) -and (Get-Item -LiteralPath $resolved).PSIsContainer) {
        Write-SCWarn -Message ("Log path is a directory. Continuing without a log: {0}" -f $resolved)
        return
    }
    try {
        $script:SCLogPath = $resolved
        $global:SCLogPath = $resolved
        $env:SYSTEMCHECKER_LOG = $resolved
        Write-SCLog -Text ("===== SystemChecker {0} =====" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    } catch {
        $script:SCLogPath = $null
        $global:SCLogPath = $null
        Write-SCWarn -Message ("Log file could not be opened. Continuing without a log: {0}" -f $_.Exception.Message)
    }
}

# Apply rendering after -Plain / the environment flag has been copied above.
Set-SCOutputRendering
