#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only service, scheduled-task, and startup configuration checks.

.DESCRIPTION
    Reports service configuration, path quoting, and permission facts.
    Scheduled tasks, Run keys, and startup folders are included the same way.
    This module does not start, stop, or change a service or task, and it
    does not execute binaries named in those settings.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\04_services.ps1
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$commonPath = Join-Path $PSScriptRoot '00_common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host ("Missing helper library: {0}" -f $commonPath)
    if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
    exit 1
}
. $commonPath

function Test-SCStringInList {
    # Local copy so -File .\modules\04_services.ps1 still works when 00_common.ps1
    # is older than this module. -contains on List[string] throws in Windows
    # PowerShell 5.1 ("Argument types do not match"), so compare items directly.
    param($List, [string]$Value)
    if ($null -eq $List) { return $false }
    foreach ($item in $List) {
        if ($null -eq $item) { continue }
        if ([string]::Equals([string]$item, $Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function ConvertTo-SCArray {
    # @($value) throws "Argument types do not match" for List[object] under
    # Set-StrictMode 2.0. Copy items instead. A string stays one element.
    param($Value)
    $copy = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return ,$copy.ToArray() }
    $asString = $Value -is [string]
    $enumerable = (-not $asString) -and ($Value -is [System.Collections.IEnumerable])
    if ($enumerable) {
        foreach ($item in $Value) { [void]$copy.Add($item) }
    } else {
        [void]$copy.Add($Value)
    }
    return ,$copy.ToArray()
}

function Get-SCProp {
    param($Object, [string]$Name)
    if (-not $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if (-not $prop) { return $null }
    return $prop.Value
}

function New-SCFinding {
    param([string]$Level, [string]$Text)
    return New-Object psobject -Property @{
        Level = $Level
        Text  = $Text
    }
}

function Write-SCLevel {
    param([string]$Level, [string]$Message)
    switch ($Level) {
        'WEAK'   { Write-SCWeak -Message $Message }
        'REVIEW' { Write-SCReview -Message $Message }
        'WARN'   { Write-SCWarn -Message $Message }
        default  { Write-SCInfo -Message $Message }
    }
}

function Format-SCShortText {
    param([string]$Text, [int]$Max = 100)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ([string]$Text -replace '[\r\n]+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max)
}

function Test-SCNativeDenied {
    param($Result)
    if (-not $Result) { return $false }
    $text = ''
    if ($Result.Output) { $text = [string]($Result.Output -join "`n") }
    if ($Result.Error) { $text = $text + ' ' + [string]$Result.Error }
    if (Test-SCAccessDenied -Message $text) { return $true }
    if ($text -match 'System error 5') { return $true }
    if ($Result.ExitCode -eq 5) { return $true }
    return $false
}

function Test-SCCommandMissingText {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return ($Message -match 'not recognized|No such file|cannot find the file|CommandNotFound|not found')
}

function Format-SCNameList {
    param($Names, [int]$Max = 5)
    $arr = New-Object System.Collections.Generic.List[string]
    foreach ($name in (ConvertTo-SCArray $Names)) {
        if ($name) { [void]$arr.Add([string]$name) }
    }
    if ($arr.Count -eq 0) { return '' }
    if ($arr.Count -le $Max) { return ($arr.ToArray() -join ', ') }
    $shown = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Max; $i++) { [void]$shown.Add($arr[$i]) }
    $extra = $arr.Count - $Max
    return ('{0} (+{1})' -f ($shown.ToArray() -join ', '), $extra)
}

function Get-SCWindowsDir {
    if ($env:WINDIR) { return $env:WINDIR }
    if ($env:SystemRoot) { return $env:SystemRoot }
    return $null
}

function Join-SCWindowsPath {
    # Text join. Join-Path asks the provider to resolve the drive, which throws
    # when a Windows path is expanded on a host that has no such drive.
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return $Child }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Expand-SCSystemPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $text = $Path.Trim()
    if ($text.StartsWith('\??\')) {
        $text = $text.Substring(4)
    }
    if ($text.Length -ge 11 -and [string]::Equals($text.Substring(0, 11), '\SystemRoot', [System.StringComparison]::OrdinalIgnoreCase)) {
        $rest = ''
        if ($text.Length -gt 11) { $rest = $text.Substring(11) }
        $root = $env:SystemRoot
        if (-not $root) { $root = $env:WINDIR }
        if (-not $root) { $root = 'C:\Windows' }
        $text = Join-SCWindowsPath -Root $root -Child $rest
    }
    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($text)
        if ($expanded) { $text = $expanded }
    } catch {
        # Keep the original text when the host cannot expand variables.
    }
    $hasDrive = $text -match '^[A-Za-z]:'
    $isUnc = $text.StartsWith('\\')
    if ((-not $hasDrive) -and (-not $isUnc) -and ($text -match '^(?i)(system32|syswow64)\\')) {
        $root = Get-SCWindowsDir
        if ($root) { $text = Join-SCWindowsPath -Root $root -Child $text }
    }
    return $text
}

function Get-SCCommandExecutable {
    # Executable path only. Argument text is dropped and must not be printed.
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $text = $Command.Trim()
    if ($text.StartsWith('"')) {
        $end = $text.IndexOf('"', 1)
        $inner = $text.Trim('"')
        if ($end -gt 1) { $inner = $text.Substring(1, $end - 1) }
        $quotedExe = [regex]::Match($inner, '(?i)^(.*?\.(?:exe|cmd|bat|com))')
        if ($quotedExe.Success) { return $quotedExe.Groups[1].Value.Trim() }
        $innerSpace = $inner.IndexOf(' ')
        if ($innerSpace -gt 0) { return $inner.Substring(0, $innerSpace) }
        return $inner.Trim()
    }
    $rooted = [regex]::Match($text, '(?i)^((?:[a-z]:|\\SystemRoot|%[A-Za-z0-9_]+%)\\.*?\.exe)')
    if ($rooted.Success) { return $rooted.Groups[1].Value }
    $unc = [regex]::Match($text, '(?i)^(\\\\[^\\]+\\[^\\]+\\.*?\.exe)')
    if ($unc.Success) { return $unc.Groups[1].Value }
    $anyExe = [regex]::Match($text, '(?i)^(.*?\.exe)(?=\s|$)')
    if ($anyExe.Success) { return $anyExe.Groups[1].Value.Trim() }
    $space = $text.IndexOf(' ')
    if ($space -lt 0) { return $text }
    return $text.Substring(0, $space)
}

function Test-SCUncPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path.StartsWith('\\?\')) { return $false }
    return $Path.StartsWith('\\')
}

function Test-SCMicrosoftBinary {
    param([string]$Path, [string]$Company, [string]$WindowsDir)
    if ($Company -and ($Company -match '(?i)microsoft')) { return $true }
    if ($Company -and $Company.Trim()) { return $false }
    if ($Path -and $WindowsDir) {
        $root = $WindowsDir.Trim().TrimEnd('\')
        $full = $Path.Trim()
        if ($full.Length -ge $root.Length) {
            $head = $full.Substring(0, $root.Length)
            if ([string]::Equals($head, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($full.Length -eq $root.Length) { return $true }
                if ($full[$root.Length] -eq '\') { return $true }
            }
        }
    }
    return $false
}

function Get-SCFileCompany {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (Test-SCUncPath -Path $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return $null }
    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($info -and $info.CompanyName) { return [string]$info.CompanyName }
    } catch {
        return $null
    }
    return $null
}

function Get-SCCachedCompany {
    param($Cache, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $key = $Path.ToLowerInvariant()
    if ($Cache.ContainsKey($key)) { return [string]$Cache[$key] }
    $company = Get-SCFileCompany -Path $Path
    if (-not $company) { $company = '' }
    $Cache[$key] = $company
    return $company
}

function Format-SCStartMode {
    param($Value)
    if ($null -eq $Value) { return 'unknown' }
    $text = ([string]$Value).Trim()
    if (-not $text) { return 'unknown' }
    switch -Regex ($text) {
        '^(?i)boot$' { return 'Boot' }
        '^(?i)system$' { return 'System' }
        '^(?i)auto(matic)?$' { return 'Auto' }
        '^(?i)manual$' { return 'Manual' }
        '^(?i)disabled$' { return 'Disabled' }
        '^0$' { return 'Boot' }
        '^1$' { return 'System' }
        '^2$' { return 'Auto' }
        '^3$' { return 'Manual' }
        '^4$' { return 'Disabled' }
        default { return $text }
    }
}

function Test-SCServiceAccountBuiltin {
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return $true }
    $text = $Account.Trim()
    if ($text -match '(?i)^(LocalSystem|NT AUTHORITY\\SYSTEM|NT AUTHORITY\\LOCAL SERVICE|NT AUTHORITY\\NETWORK SERVICE|LOCAL SERVICE|NETWORK SERVICE)$') {
        return $true
    }
    if ($text -match '(?i)^NT SERVICE\\') { return $true }
    return $false
}

function Test-SCMicrosoftTaskName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $text = $Name.Trim()
    if (-not $text.StartsWith('\')) { $text = '\' + $text }
    return ($text -match '(?i)^\\Microsoft\\')
}

function Test-SCEveryoneName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $leaf = $Name
    if ($Name.Contains('\')) {
        $parts = $Name.Split('\')
        $leaf = $parts[$parts.Length - 1]
    }
    if ([string]::Equals($leaf, 'Everyone', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ([string]::Equals($Name, 'S-1-1-0', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

function Test-SCCurrentUserPrincipal {
    param([string]$Principal)
    if ([string]::IsNullOrWhiteSpace($Principal)) { return $false }
    $leaf = $Principal
    if ($Principal.Contains('\')) {
        $parts = $Principal.Split('\')
        $leaf = $parts[$parts.Length - 1]
    }
    $user = $env:USERNAME
    if ($user -and [string]::Equals($leaf, [string]$user, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($env:USERDOMAIN -and $user) {
        $full = '{0}\{1}' -f $env:USERDOMAIN, $user
        if ([string]::Equals($Principal, $full, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-SCPathLeaf {
    # Last segment of a Windows path. IO.Path uses the host separator, so a
    # backslash path is not split when this file is parsed on another OS.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $text = $Path.Trim().TrimEnd('\').TrimEnd('/')
    $slash = [Math]::Max($text.LastIndexOf('\'), $text.LastIndexOf('/'))
    if ($slash -lt 0) { return $text }
    if ($slash -ge ($text.Length - 1)) { return '' }
    return $text.Substring($slash + 1)
}

function Get-SCParentPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (Test-SCUncPath -Path $Path) { return $null }
    $text = $Path.Trim().TrimEnd('\').TrimEnd('/')
    $slash = [Math]::Max($text.LastIndexOf('\'), $text.LastIndexOf('/'))
    if ($slash -le 0) { return $null }
    $parent = $text.Substring(0, $slash)
    if ($parent.EndsWith(':')) { return ($parent + '\') }
    return $parent
}

function Test-SCRegistryWriteMask {
    param($Rights)
    $value = 0
    try { $value = [int]$Rights } catch { return $false }
    $mask = 2 -bor 4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    return (($value -band $mask) -ne 0)
}

function Get-SCRegistryWriteInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    $result = New-Object psobject -Property @{
        Writable        = $false
        BroadWritable   = $false
        Principals      = @()
        BroadPrincipals = @()
        Error           = $null
    }
    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Error = 'NEEDS ADMIN' }
        else { $result.Error = $message }
        return $result
    }
    if (-not $exists) {
        $result.Error = 'Path not found.'
        return $result
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $nonAdmin = New-Object System.Collections.Generic.List[string]
        $broad = New-Object System.Collections.Generic.List[string]
        foreach ($ace in (ConvertTo-SCArray $acl.Access)) {
            if (-not $ace) { continue }
            $typeName = ''
            try { $typeName = $ace.AccessControlType.ToString() } catch { $typeName = '' }
            if ($typeName -ne 'Allow') { continue }
            $rightsProp = $ace.PSObject.Properties['RegistryRights']
            if (-not $rightsProp) { continue }
            if (-not (Test-SCRegistryWriteMask -Rights $rightsProp.Value)) { continue }
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
            if (Test-SCPrivilegedIdentity -Sid $sid -Name $identity) { continue }
            $isBroad = Test-SCBroadIdentity -Sid $sid -Name $identity
            if (-not (Test-SCStringInList -List $nonAdmin -Value $identity)) { [void]$nonAdmin.Add($identity) }
            if ($isBroad -and -not (Test-SCStringInList -List $broad -Value $identity)) { [void]$broad.Add($identity) }
        }
        $result.Principals = $nonAdmin.ToArray()
        $result.BroadPrincipals = $broad.ToArray()
        $result.Writable = ($nonAdmin.Count -gt 0)
        $result.BroadWritable = ($broad.Count -gt 0)
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Error = 'NEEDS ADMIN' }
        else { $result.Error = $message }
    }
    return $result
}

function Get-SCNonAdminWriteLevel {
    param(
        $Info,
        [switch]$IgnoreCurrentUser,
        [switch]$BroadIsReview
    )
    $result = New-Object psobject -Property @{
        Level           = 'NONE'
        Principals      = @()
        BroadPrincipals = @()
        Error           = $null
    }
    if (-not $Info) { return $result }
    $err = [string](Get-SCProp $Info 'Error')
    if ($err) {
        $result.Error = $err
        return $result
    }
    $principals = New-Object System.Collections.Generic.List[string]
    $broad = New-Object System.Collections.Generic.List[string]
    foreach ($name in (ConvertTo-SCArray (Get-SCProp $Info 'Principals'))) {
        if (-not $name) { continue }
        if ($IgnoreCurrentUser -and (Test-SCCurrentUserPrincipal -Principal $name)) { continue }
        [void]$principals.Add([string]$name)
    }
    foreach ($name in (ConvertTo-SCArray (Get-SCProp $Info 'BroadPrincipals'))) {
        if (-not $name) { continue }
        if ($IgnoreCurrentUser -and (Test-SCCurrentUserPrincipal -Principal $name)) { continue }
        [void]$broad.Add([string]$name)
    }
    $result.Principals = $principals.ToArray()
    $result.BroadPrincipals = $broad.ToArray()
    if ($broad.Count -gt 0) {
        $everyone = $false
        foreach ($name in $broad) {
            if (Test-SCEveryoneName -Name $name) { $everyone = $true }
        }
        if ($BroadIsReview -and -not $everyone) { $result.Level = 'REVIEW' }
        else { $result.Level = 'WEAK' }
    } elseif ($principals.Count -gt 0) {
        $result.Level = 'REVIEW'
    }
    return $result
}

function Get-SCCachedWrite {
    param($Cache, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($Cache.ContainsKey($key)) { return $Cache[$key] }
    $info = Test-SCWritableByNonAdmin -Path $Path
    $Cache[$key] = $info
    return $info
}

function Add-SCGroupedWrite {
    param(
        $Map,
        [string]$Kind,
        [string]$Level,
        [string]$Path,
        $Principals,
        $BroadPrincipals,
        [string]$OwnerName
    )
    if (-not $Path) { return }
    if ($Level -ne 'WEAK' -and $Level -ne 'REVIEW') { return }
    $key = ($Kind + '|' + $Path).ToLowerInvariant()
    if (-not $Map.ContainsKey($key)) {
        $Map[$key] = New-Object psobject -Property @{
            Kind            = $Kind
            Level           = $Level
            Path            = $Path
            Principals      = (ConvertTo-SCArray $Principals)
            BroadPrincipals = (ConvertTo-SCArray $BroadPrincipals)
            Names           = (New-Object System.Collections.Generic.List[string])
        }
    }
    $entry = $Map[$key]
    if ($Level -eq 'WEAK') {
        $entry.Level = 'WEAK'
        $broadCopy = ConvertTo-SCArray $BroadPrincipals
        if ($broadCopy.Count -gt 0) { $entry.BroadPrincipals = $broadCopy }
    }
    if ($OwnerName -and -not (Test-SCStringInList -List $entry.Names -Value $OwnerName)) {
        [void]$entry.Names.Add($OwnerName)
    }
}

function Format-SCGroupedFinding {
    param($Entry)
    $who = 'a non-admin principal'
    $names = ConvertTo-SCArray (Get-SCProp $Entry 'Principals')
    if ($Entry.Level -eq 'WEAK') {
        $who = 'a broad principal'
        $broadNames = ConvertTo-SCArray (Get-SCProp $Entry 'BroadPrincipals')
        if ($broadNames.Count -gt 0) { $names = $broadNames }
    }
    $principalText = Format-SCNameList -Names $names -Max 4
    if (-not $principalText) { $principalText = 'non-admin' }
    $noun = 'Path is writable'
    $subject = 'Items'
    switch ($Entry.Kind) {
        'binary'         { $noun = 'Service binary is writable'; $subject = 'Services' }
        'binary-dir'     { $noun = 'Service binary directory is writable'; $subject = 'Services' }
        'dll'            { $noun = 'ServiceDll is writable'; $subject = 'Services' }
        'dll-dir'        { $noun = 'ServiceDll directory is writable'; $subject = 'Services' }
        'registry'       { $noun = 'Service registry key allows ImagePath changes'; $subject = 'Services' }
        'task'           { $noun = 'Scheduled task action is writable'; $subject = 'Tasks' }
        'task-dir'       { $noun = 'Scheduled task action directory is writable'; $subject = 'Tasks' }
        'run'            { $noun = 'Run value binary is writable'; $subject = 'Entries' }
        'run-dir'        { $noun = 'Run value directory is writable'; $subject = 'Entries' }
        'run-key'        { $noun = 'Run key is writable'; $subject = 'Keys' }
        'startup-file'   { $noun = 'Startup file is writable'; $subject = 'Files' }
        'startup-dir'    { $noun = 'Startup folder is writable'; $subject = 'Folders' }
        'startup-target' { $noun = 'Startup shortcut target is writable'; $subject = 'Shortcuts' }
    }
    $ownerText = Format-SCNameList -Names (ConvertTo-SCArray (Get-SCProp $Entry 'Names')) -Max 5
    $pathText = Format-SCShortText -Text ([string]$Entry.Path) -Max 140
    if ($ownerText) {
        return ('{0} by {1}: {2} ({3}). {4}: {5}' -f $noun, $who, $pathText, $principalText, $subject, $ownerText)
    }
    return ('{0} by {1}: {2} ({3})' -f $noun, $who, $pathText, $principalText)
}

function Get-SCGroupedFindings {
    param($Map)
    $weak = New-Object System.Collections.Generic.List[object]
    $review = New-Object System.Collections.Generic.List[object]
    foreach ($key in $Map.Keys) {
        $entry = $Map[$key]
        $text = Format-SCGroupedFinding -Entry $entry
        $item = New-SCFinding -Level ([string]$entry.Level) -Text $text
        if ($entry.Level -eq 'WEAK') { [void]$weak.Add($item) }
        else { [void]$review.Add($item) }
    }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($item in $weak) { [void]$all.Add($item) }
    foreach ($item in $review) { [void]$all.Add($item) }
    return New-Object psobject -Property @{
        Items = $all.ToArray()
    }
}

function Write-SCSortedFindings {
    param($Items, [int]$Cap = 30)
    $weak = New-Object System.Collections.Generic.List[object]
    $review = New-Object System.Collections.Generic.List[object]
    foreach ($item in (ConvertTo-SCArray $Items)) {
        if (-not $item) { continue }
        if ($item.Level -eq 'WEAK') { [void]$weak.Add($item) }
        else { [void]$review.Add($item) }
    }
    $shown = 0
    $hidden = 0
    foreach ($bucket in @($weak, $review)) {
        foreach ($item in $bucket) {
            if (-not $item) { continue }
            if ($shown -ge $Cap) {
                $hidden++
                continue
            }
            Write-SCLevel -Level ([string]$item.Level) -Message ([string]$item.Text)
            $shown++
        }
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional findings were omitted." -f $hidden)
    }
}

function Write-SCPathProblemSummary {
    param($Cache)
    $denied = 0
    $other = 0
    foreach ($key in $Cache.Keys) {
        $info = $Cache[$key]
        $err = [string](Get-SCProp $info 'Error')
        if (-not $err) { continue }
        if ($err -eq 'Path not found.') { continue }
        if ($err -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $err)) { $denied++ }
        else { $other++ }
    }
    if ($denied -gt 0) {
        Write-SCNeedsAdmin -Detail ("File or folder ACLs could not be read for {0} paths." -f $denied)
    }
    if ($other -gt 0) {
        Write-SCWarn -Message ("{0} file or folder ACLs could not be read." -f $other)
    }
}

function Add-SCPathWriteFindings {
    param(
        $Map,
        $Cache,
        [string]$Kind,
        [string]$DirKind,
        [string]$Path,
        [string]$OwnerName,
        [switch]$IgnoreCurrentUser,
        [switch]$BroadIsReview,
        [switch]$SkipParent
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (Test-SCUncPath -Path $Path) { return $false }
    $hit = $false
    $info = Get-SCCachedWrite -Cache $Cache -Path $Path
    $level = Get-SCNonAdminWriteLevel -Info $info -IgnoreCurrentUser:$IgnoreCurrentUser -BroadIsReview:$BroadIsReview
    if ($level.Level -eq 'WEAK' -or $level.Level -eq 'REVIEW') {
        Add-SCGroupedWrite -Map $Map -Kind $Kind -Level $level.Level -Path $Path -Principals $level.Principals -BroadPrincipals $level.BroadPrincipals -OwnerName $OwnerName
        $hit = $true
    }
    if ($SkipParent) { return $hit }
    $parent = Get-SCParentPath -Path $Path
    if (-not $parent) { return $hit }
    $parentInfo = Get-SCCachedWrite -Cache $Cache -Path $parent
    $parentLevel = Get-SCNonAdminWriteLevel -Info $parentInfo -IgnoreCurrentUser:$IgnoreCurrentUser -BroadIsReview:$BroadIsReview
    if ($parentLevel.Level -eq 'WEAK' -or $parentLevel.Level -eq 'REVIEW') {
        Add-SCGroupedWrite -Map $Map -Kind $DirKind -Level $parentLevel.Level -Path $parent -Principals $parentLevel.Principals -BroadPrincipals $parentLevel.BroadPrincipals -OwnerName $OwnerName
        $hit = $true
    }
    return $hit
}

function Get-SCServiceDllPath {
    param([string]$ServiceName, [string]$ImagePath)
    if ([string]::IsNullOrWhiteSpace($ServiceName) -or [string]::IsNullOrWhiteSpace($ImagePath)) { return $null }
    if ($ServiceName -match '[\\/]') { return $null }
    $exe = Get-SCCommandExecutable -Command $ImagePath
    if (-not $exe) { return $null }
    $leaf = Get-SCPathLeaf -Path $exe
    if ($leaf -notmatch '(?i)^svchost\.exe$') { return $null }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}\Parameters' -f $ServiceName
    $val = Get-SCRegistryValue -Path $key -Name 'ServiceDll'
    $dllPath = $null
    if ((-not $val.Error) -and $val.Found -and $val.Value) { $dllPath = [string]$val.Value }
    return New-Object psobject -Property @{
        Path  = $dllPath
        Error = $val.Error
    }
}

function Test-SCRegistryServiceType {
    param($Type)
    if ($null -eq $Type -or [string]$Type -eq '') { return $true }
    $t = 0
    try { $t = [int]$Type } catch { return $true }
    if (($t -band 16) -ne 0) { return $true }
    if (($t -band 32) -ne 0) { return $true }
    return $false
}

function New-SCConfigRecord {
    param(
        [string]$Name,
        [string]$State,
        [string]$StartMode,
        [string]$Account,
        [string]$ImagePath
    )
    return New-Object psobject -Property @{
        Name      = $Name
        State     = $State
        StartMode = $StartMode
        Account   = $Account
        ImagePath = $ImagePath
    }
}

function Get-SCServiceRecords {
    $items = New-Object System.Collections.Generic.List[object]
    $cimError = $null
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $rows = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
            foreach ($row in $rows) {
                if (-not $row) { continue }
                $name = [string](Get-SCProp $row 'Name')
                if (-not $name) { continue }
                [void]$items.Add((New-SCConfigRecord -Name $name -State ([string](Get-SCProp $row 'State')) -StartMode ([string](Get-SCProp $row 'StartMode')) -Account ([string](Get-SCProp $row 'StartName')) -ImagePath ([string](Get-SCProp $row 'PathName'))))
            }
            return New-Object psobject -Property @{
                Items  = $items.ToArray()
                Source = 'cim'
                Error  = $null
            }
        } catch {
            $cimError = $_.Exception.Message
        }
    } else {
        $cimError = 'CIM is not available.'
    }

    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $regError = $null
    $hive = $false
    try {
        $hive = Test-Path -LiteralPath $base -ErrorAction Stop
    } catch {
        $regError = $_.Exception.Message
        $hive = $false
    }
    if ($hive) {
        try {
            $statusMap = @{}
            if (Get-Command -Name Get-Service -ErrorAction SilentlyContinue) {
                try {
                    foreach ($svc in @(Get-Service -ErrorAction Stop)) {
                        if (-not $svc) { continue }
                        $statusMap[$svc.Name.ToLowerInvariant()] = [string]$svc.Status
                    }
                } catch {
                    # State stays unknown when the service controller cannot be queried.
                }
            }
            foreach ($key in @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
                if (-not $key) { continue }
                $props = $null
                try { $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { continue }
                if (-not (Test-SCRegistryServiceType -Type (Get-SCProp $props 'Type'))) { continue }
                $image = [string](Get-SCProp $props 'ImagePath')
                if ([string]::IsNullOrWhiteSpace($image)) { continue }
                $name = [string]$key.PSChildName
                $state = 'unknown'
                $nameKey = $name.ToLowerInvariant()
                if ($statusMap.ContainsKey($nameKey)) { $state = [string]$statusMap[$nameKey] }
                [void]$items.Add((New-SCConfigRecord -Name $name -State $state -StartMode (Format-SCStartMode -Value (Get-SCProp $props 'Start')) -Account ([string](Get-SCProp $props 'ObjectName')) -ImagePath $image))
            }
            return New-Object psobject -Property @{
                Items  = $items.ToArray()
                Source = 'registry'
                Error  = $cimError
            }
        } catch {
            $regError = $_.Exception.Message
        }
    } elseif (-not $regError) {
        $regError = 'Service registry key was not found.'
    }

    $combined = $cimError
    if ($regError) {
        if ($combined) { $combined = $combined + ' ' + $regError }
        else { $combined = $regError }
    }
    return New-Object psobject -Property @{
        Items  = @()
        Source = 'none'
        Error  = $combined
    }
}

function Invoke-SCCheckServices {
    Start-SCSection -Title 'Services'
    $bag = Get-SCServiceRecords
    $records = ConvertTo-SCArray $bag.Items
    if ($bag.Source -eq 'none') {
        $message = [string]$bag.Error
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'Service list could not be read.'
        } else {
            Write-SCWarn -Message ("Service list could not be read: {0}" -f (Format-SCShortText -Text $message -Max 160))
        }
        return
    }
    if ($bag.Source -eq 'registry') {
        $cimMessage = [string]$bag.Error
        if (Test-SCAccessDenied -Message $cimMessage) {
            Write-SCNeedsAdmin -Detail 'CIM service query was denied. The list was read from the registry.'
        } else {
            Write-SCInfo -Message 'Service list was read from the registry.'
        }
    }

    $windowsDir = Get-SCWindowsDir
    $pathCache = @{}
    $companyCache = @{}
    $grouped = @{}
    $extra = New-Object System.Collections.Generic.List[object]
    $infoRows = New-Object System.Collections.Generic.List[object]
    $total = 0
    $quietMicrosoft = 0
    $nonMicrosoft = 0
    $nonMicrosoftAuto = 0
    $missingBinary = 0
    $emptyImage = 0
    $networkPaths = 0
    $regDenied = 0
    $regOther = 0
    $dllDenied = 0
    $itemErrors = 0
    $firstItemError = $null

    foreach ($svc in $records) {
        if (-not $svc -or -not $svc.Name) { continue }
        $total++
        try {
            $image = [string]$svc.ImagePath
            $startMode = Format-SCStartMode -Value $svc.StartMode
            $state = [string]$svc.State
            if (-not $state) { $state = 'unknown' }
            $account = [string]$svc.Account
            if (-not $account) { $account = 'unknown' }
            $hadFinding = $false

            if ([string]::IsNullOrWhiteSpace($image)) {
                $emptyImage++
            } else {
                if (Test-SCUnquotedPath -Path $image) {
                    $exeOnly = Get-SCCommandExecutable -Command $image
                    $shown = 'not parsed'
                    if ($exeOnly) { $shown = Format-SCShortText -Text $exeOnly -Max 120 }
                    [void]$extra.Add((New-SCFinding -Level 'WEAK' -Text ("Service '{0}' ImagePath is unquoted and contains a space. Executable: {1}" -f $svc.Name, $shown)))
                    $hadFinding = $true
                }
            }

            $exeRaw = Get-SCCommandExecutable -Command $image
            $exe = $null
            if ($exeRaw) { $exe = Expand-SCSystemPath -Path $exeRaw }
            $dllRaw = $null
            $dll = $null
            $dllResult = Get-SCServiceDllPath -ServiceName $svc.Name -ImagePath $image
            if ($dllResult -and $dllResult.Error) {
                if (Test-SCAccessDenied -Message $dllResult.Error) { $dllDenied++ }
                else { $regOther++ }
            } elseif ($dllResult -and $dllResult.Path) {
                $dllRaw = [string]$dllResult.Path
                $dll = Expand-SCSystemPath -Path $dllRaw
            }

            $classPath = $exe
            if ($dll) { $classPath = $dll }
            # No executable was parsed. Do not label that as a third-party service.
            $isMicrosoft = $true
            if ($classPath) {
                $company = Get-SCCachedCompany -Cache $companyCache -Path $classPath
                $isMicrosoft = Test-SCMicrosoftBinary -Path $classPath -Company $company -WindowsDir $windowsDir
            }

            foreach ($pair in @(
                @{ Kind = 'binary'; Dir = 'binary-dir'; Path = $exe },
                @{ Kind = 'dll'; Dir = 'dll-dir'; Path = $dll }
            )) {
                $candidate = [string]$pair.Path
                if (-not $candidate) { continue }
                if (Test-SCUncPath -Path $candidate) {
                    $networkPaths++
                    [void]$extra.Add((New-SCFinding -Level 'REVIEW' -Text ("Service '{0}' uses a network path: {1}" -f $svc.Name, (Format-SCShortText -Text $candidate -Max 120))))
                    $hadFinding = $true
                    continue
                }
                if (-not (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue)) { $missingBinary++ }
                if (Add-SCPathWriteFindings -Map $grouped -Cache $pathCache -Kind $pair.Kind -DirKind $pair.Dir -Path $candidate -OwnerName $svc.Name) {
                    $hadFinding = $true
                }
            }

            if ($svc.Name -notmatch '[\\/]') {
                $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $svc.Name
                $regInfo = Get-SCRegistryWriteInfo -Path $regPath
                $regLevel = Get-SCNonAdminWriteLevel -Info $regInfo
                if ($regLevel.Error -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $regLevel.Error)) {
                    $regDenied++
                } elseif ($regLevel.Error -and $regLevel.Error -ne 'Path not found.') {
                    $regOther++
                } elseif ($regLevel.Level -eq 'WEAK' -or $regLevel.Level -eq 'REVIEW') {
                    Add-SCGroupedWrite -Map $grouped -Kind 'registry' -Level $regLevel.Level -Path $regPath -Principals $regLevel.Principals -BroadPrincipals $regLevel.BroadPrincipals -OwnerName $svc.Name
                    $hadFinding = $true
                }
            }

            if ((-not (Test-SCServiceAccountBuiltin -Account $account)) -and $startMode -ne 'Disabled') {
                [void]$extra.Add((New-SCFinding -Level 'REVIEW' -Text ("Service '{0}' runs as a user account: {1} ({2}, {3})" -f $svc.Name, (Format-SCShortText -Text $account -Max 80), $startMode, $state)))
                $hadFinding = $true
            }

            if ($isMicrosoft) {
                if (-not $hadFinding) { $quietMicrosoft++ }
            } else {
                $nonMicrosoft++
                if ($startMode -eq 'Auto') { $nonMicrosoftAuto++ }
                if (-not $hadFinding) {
                    $shownPath = 'path not parsed'
                    if ($classPath) { $shownPath = Format-SCShortText -Text $classPath -Max 100 }
                    [void]$infoRows.Add((New-Object psobject -Property @{
                        Name      = $svc.Name
                        State     = $state
                        StartMode = $startMode
                        Account   = $account
                        Path      = $shownPath
                        Rank      = $(if ($state -eq 'Running') { 0 } elseif ($startMode -eq 'Auto') { 1 } else { 2 })
                    }))
                }
            }
        } catch {
            $itemErrors++
            if (-not $firstItemError) { $firstItemError = $_.Exception.Message }
        }
    }

    $groupedBag = Get-SCGroupedFindings -Map $grouped
    $groupedItems = @()
    if ($groupedBag -and $groupedBag.Items) { $groupedItems = ConvertTo-SCArray $groupedBag.Items }
    $findingCount = $extra.Count + $groupedItems.Count
    Write-SCInfo -Message ("Services: {0} total. Microsoft with no finding: {1}. Non-Microsoft: {2} ({3} automatic). Findings: {4}." -f $total, $quietMicrosoft, $nonMicrosoft, $nonMicrosoftAuto, $findingCount)
    if ($emptyImage -gt 0) {
        Write-SCInfo -Message ("Services with an empty ImagePath: {0}." -f $emptyImage)
    }
    if ($missingBinary -gt 0) {
        Write-SCInfo -Message ("Service binaries or ServiceDll files not found on disk: {0}." -f $missingBinary)
    }
    if ($networkPaths -gt 0) {
        Write-SCInfo -Message ("Network service paths were not opened: {0}." -f $networkPaths)
    }

    $all = New-Object System.Collections.Generic.List[object]
    foreach ($item in $extra) { if ($item) { [void]$all.Add($item) } }
    foreach ($item in (ConvertTo-SCArray $groupedItems)) { if ($item) { [void]$all.Add($item) } }
    Write-SCSortedFindings -Items $all.ToArray() -Cap 30

    $shownInfo = 0
    $hiddenInfo = 0
    $orderedInfo = ConvertTo-SCArray $infoRows
    $orderedInfo = @($orderedInfo | Sort-Object -Property Rank, Name)
    foreach ($row in $orderedInfo) {
        if (-not $row) { continue }
        if ($shownInfo -ge 15) {
            $hiddenInfo++
            continue
        }
        $shownInfo++
        Write-SCInfo -Message ("Non-Microsoft service: {0} | {1} | {2} | {3} | {4}" -f $row.Name, $row.State, $row.StartMode, (Format-SCShortText -Text $row.Account -Max 40), $row.Path)
    }
    if ($hiddenInfo -gt 0) {
        Write-SCInfo -Message ("{0} additional non-Microsoft services were omitted." -f $hiddenInfo)
    }
    if ($dllDenied -gt 0) {
        Write-SCNeedsAdmin -Detail ("ServiceDll values could not be read for {0} services." -f $dllDenied)
    }
    if ($regDenied -gt 0) {
        Write-SCNeedsAdmin -Detail ("Service registry ACLs could not be read for {0} keys." -f $regDenied)
    }
    if ($regOther -gt 0) {
        Write-SCWarn -Message ("{0} service registry keys could not be read." -f $regOther)
    }
    Write-SCPathProblemSummary -Cache $pathCache
    if ($itemErrors -eq 1) {
        Write-SCWarn -Message ("1 service could not be assessed: {0}" -f (Format-SCShortText -Text $firstItemError -Max 140))
    } elseif ($itemErrors -gt 1) {
        Write-SCWarn -Message ("{0} services could not be assessed. First error: {1}" -f $itemErrors, (Format-SCShortText -Text $firstItemError -Max 140))
    }
}

function New-SCActionRecord {
    # $Unquoted is not [bool]. Windows PowerShell 5.1 mis-binds
    # -Unquoted (expression) on a bool parameter.
    param([string]$Executable, $Unquoted)
    $flag = $false
    if ($Unquoted -eq $true) { $flag = $true }
    return New-Object psobject -Property @{
        Executable = $Executable
        Unquoted   = $flag
    }
}

function New-SCTaskRecord {
    param([string]$Name, [string]$User, [string]$State, $Actions)
    $clean = New-Object System.Collections.Generic.List[object]
    foreach ($action in (ConvertTo-SCArray $Actions)) {
        if ($action) { [void]$clean.Add($action) }
    }
    return New-Object psobject -Property @{
        Name    = $Name
        User    = $User
        State   = $State
        Actions = $clean.ToArray()
    }
}

function Convert-SCSchtasksRows {
    param([string[]]$Lines)
    $kept = New-Object System.Collections.Generic.List[string]
    foreach ($line in (ConvertTo-SCArray $Lines)) {
        if ($null -eq $line) { continue }
        $trim = ([string]$line).Trim()
        if (-not $trim) { continue }
        if ($kept.Count -eq 0 -and $trim -notmatch ',') { continue }
        [void]$kept.Add($trim)
    }
    $empty = New-Object psobject -Property @{
        Items = @()
        Error = $null
    }
    if ($kept.Count -lt 2) {
        $empty.Error = 'schtasks returned no task rows.'
        return $empty
    }
    try {
        $parsed = @(($kept.ToArray() -join "`n") | ConvertFrom-Csv)
    } catch {
        $empty.Error = 'schtasks CSV could not be parsed.'
        return $empty
    }
    if ($parsed.Count -lt 1 -or -not $parsed[0]) {
        $empty.Error = 'schtasks returned no task rows.'
        return $empty
    }
    $names = ConvertTo-SCArray $parsed[0].PSObject.Properties.Name
    if (($names -notcontains 'TaskName') -or ($names -notcontains 'Task To Run')) {
        $empty.Error = 'schtasks CSV headers were not recognized. Task list was skipped.'
        return $empty
    }
    $stateName = $null
    if ($names -contains 'Scheduled Task State') { $stateName = 'Scheduled Task State' }
    elseif ($names -contains 'Status') { $stateName = 'Status' }
    $userName = $null
    if ($names -contains 'Run As User') { $userName = 'Run As User' }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($row in $parsed) {
        if (-not $row) { continue }
        $taskName = [string](Get-SCProp $row 'TaskName')
        $toRun = [string](Get-SCProp $row 'Task To Run')
        $exe = Get-SCCommandExecutable -Command $toRun
        $user = ''
        if ($userName) { $user = [string](Get-SCProp $row $userName) }
        $state = ''
        if ($stateName) { $state = [string](Get-SCProp $row $stateName) }
        $unquoted = Test-SCUnquotedPath -Path $toRun
        $action = New-SCActionRecord -Executable $exe -Unquoted:$unquoted
        [void]$rows.Add((New-SCTaskRecord -Name $taskName -User $user -State $state -Actions @($action)))
    }
    return New-Object psobject -Property @{
        Items = $rows.ToArray()
        Error = $null
    }
}

function Get-SCTaskRecords {
    $items = New-Object System.Collections.Generic.List[object]
    $schedError = $null
    $haveCmd = [bool](Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)
    if (-not $haveCmd) {
        if (Get-Command -Name Import-Module -ErrorAction SilentlyContinue) {
            try {
                Import-Module ScheduledTasks -ErrorAction Stop
                $haveCmd = [bool](Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)
            } catch {
                $importError = $_.Exception.Message
                if (Test-SCAccessDenied -Message $importError) { $schedError = $importError }
                else { $schedError = 'Get-ScheduledTask is not available.' }
            }
        }
    }
    if ($haveCmd) {
        try {
            foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
                if (-not $task) { continue }
                $taskPath = [string](Get-SCProp $task 'TaskPath')
                $taskName = [string](Get-SCProp $task 'TaskName')
                $fullName = $taskName
                if ($taskPath) { $fullName = $taskPath + $taskName }
                $state = ''
                try { $state = [string]$task.State } catch { $state = '' }
                $user = ''
                $principal = Get-SCProp $task 'Principal'
                if ($principal) { $user = [string](Get-SCProp $principal 'UserId') }
                $actions = New-Object System.Collections.Generic.List[object]
                foreach ($action in @(Get-SCProp $task 'Actions')) {
                    if (-not $action) { continue }
                    $execProp = $action.PSObject.Properties['Execute']
                    if (-not $execProp) { continue }
                    $exec = [string]$execProp.Value
                    if (-not $exec) { continue }
                    $unquoted = Test-SCUnquotedPath -Path $exec
                    [void]$actions.Add((New-SCActionRecord -Executable $exec -Unquoted:$unquoted))
                }
                [void]$items.Add((New-SCTaskRecord -Name $fullName -User $user -State $state -Actions $actions.ToArray()))
            }
            return New-Object psobject -Property @{
                Items  = $items.ToArray()
                Source = 'scheduledtask'
                Error  = $null
            }
        } catch {
            $schedError = $_.Exception.Message
            $items.Clear()
        }
    } elseif (-not $schedError) {
        $schedError = 'Get-ScheduledTask is not available.'
    }

    $native = Invoke-SCNative -FileName 'schtasks' -ArgumentList @('/Query', '/FO', 'CSV', '/V')
    if (Test-SCNativeDenied -Result $native) {
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = 'NEEDS ADMIN'
        }
    }
    if ($native.Ok) {
        $parsed = Convert-SCSchtasksRows -Lines (ConvertTo-SCArray $native.Output)
        if (-not $parsed.Error) {
            return New-Object psobject -Property @{
                Items  = (ConvertTo-SCArray $parsed.Items)
                Source = 'schtasks'
                Error  = $null
            }
        }
        $schedError = [string]$parsed.Error
    } else {
        $nativeError = [string]$native.Error
        if (-not $nativeError -and $native.Output) { $nativeError = [string]($native.Output -join ' ') }
        if (Test-SCCommandMissingText -Message $nativeError) { $nativeError = 'schtasks is not available.' }
        if ($schedError) { $schedError = $schedError + ' ' + $nativeError }
        else { $schedError = $nativeError }
    }
    return New-Object psobject -Property @{
        Items  = @()
        Source = 'none'
        Error  = $schedError
    }
}

function Invoke-SCCheckTasks {
    Start-SCSection -Title 'Scheduled tasks'
    $bag = Get-SCTaskRecords
    if ($bag.Source -eq 'none') {
        $message = [string]$bag.Error
        if ($message -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $message)) {
            Write-SCNeedsAdmin -Detail 'Scheduled tasks could not be listed.'
        } else {
            Write-SCWarn -Message ("Scheduled tasks could not be listed: {0}" -f (Format-SCShortText -Text $message -Max 180))
        }
        return
    }

    $records = ConvertTo-SCArray $bag.Items
    $pathCache = @{}
    $grouped = @{}
    $extra = New-Object System.Collections.Generic.List[object]
    $infoRows = New-Object System.Collections.Generic.List[object]
    $total = 0
    $quietMicrosoft = 0
    $nonMicrosoft = 0
    $networkPaths = 0
    $itemErrors = 0
    $firstItemError = $null

    foreach ($task in $records) {
        if (-not $task -or -not $task.Name) { continue }
        $total++
        try {
            $isMicrosoft = Test-SCMicrosoftTaskName -Name $task.Name
            $hadFinding = $false
            $exeShown = New-Object System.Collections.Generic.List[string]
            foreach ($action in (ConvertTo-SCArray $task.Actions)) {
                if (-not $action) { continue }
                $rawExe = [string]$action.Executable
                if ($action.Unquoted) {
                    $shown = 'not parsed'
                    if ($rawExe) { $shown = Format-SCShortText -Text $rawExe -Max 120 }
                    [void]$extra.Add((New-SCFinding -Level 'WEAK' -Text ("Scheduled task '{0}' action path is unquoted and contains a space. Executable: {1}" -f $task.Name, $shown)))
                    $hadFinding = $true
                }
                $exe = $null
                if ($rawExe) { $exe = Expand-SCSystemPath -Path $rawExe }
                if ($exe) { [void]$exeShown.Add((Format-SCShortText -Text $exe -Max 80)) }
                if ($exe -and (Test-SCUncPath -Path $exe)) {
                    $networkPaths++
                    [void]$extra.Add((New-SCFinding -Level 'REVIEW' -Text ("Scheduled task '{0}' uses a network path: {1}" -f $task.Name, (Format-SCShortText -Text $exe -Max 120))))
                    $hadFinding = $true
                    continue
                }
                if (Add-SCPathWriteFindings -Map $grouped -Cache $pathCache -Kind 'task' -DirKind 'task-dir' -Path $exe -OwnerName $task.Name) {
                    $hadFinding = $true
                }
            }

            if ($isMicrosoft) {
                if (-not $hadFinding) { $quietMicrosoft++ }
            } else {
                $nonMicrosoft++
                if (-not $hadFinding) {
                    $pathText = 'no executable action'
                    if ($exeShown.Count -gt 0) { $pathText = ($exeShown.ToArray() -join '; ') }
                    $user = [string]$task.User
                    if (-not $user) { $user = 'unspecified' }
                    $state = [string]$task.State
                    if (-not $state) { $state = 'unknown' }
                    [void]$infoRows.Add((New-Object psobject -Property @{
                        Name  = $task.Name
                        User  = $user
                        State = $state
                        Path  = $pathText
                    }))
                }
            }
        } catch {
            $itemErrors++
            if (-not $firstItemError) { $firstItemError = $_.Exception.Message }
        }
    }

    $groupedBag = Get-SCGroupedFindings -Map $grouped
    $groupedItems = @()
    if ($groupedBag -and $groupedBag.Items) { $groupedItems = ConvertTo-SCArray $groupedBag.Items }
    $findingCount = $extra.Count + $groupedItems.Count
    Write-SCInfo -Message ("Scheduled tasks: {0} total. Microsoft with no finding: {1}. Non-Microsoft: {2}. Findings: {3}." -f $total, $quietMicrosoft, $nonMicrosoft, $findingCount)
    if ($networkPaths -gt 0) {
        Write-SCInfo -Message ("Network task paths were not opened: {0}." -f $networkPaths)
    }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($item in $extra) { if ($item) { [void]$all.Add($item) } }
    foreach ($item in (ConvertTo-SCArray $groupedItems)) { if ($item) { [void]$all.Add($item) } }
    Write-SCSortedFindings -Items $all.ToArray() -Cap 30

    $shownInfo = 0
    $hiddenInfo = 0
    foreach ($row in (ConvertTo-SCArray $infoRows)) {
        if (-not $row) { continue }
        if ($shownInfo -ge 15) {
            $hiddenInfo++
            continue
        }
        $shownInfo++
        Write-SCInfo -Message ("Non-Microsoft task: {0} | {1} | {2} | {3}" -f (Format-SCShortText -Text $row.Name -Max 80), (Format-SCShortText -Text $row.User -Max 40), $row.State, $row.Path)
    }
    if ($hiddenInfo -gt 0) {
        Write-SCInfo -Message ("{0} additional non-Microsoft tasks were omitted." -f $hiddenInfo)
    }
    Write-SCPathProblemSummary -Cache $pathCache
    if ($itemErrors -gt 0) {
        Write-SCWarn -Message ("{0} scheduled tasks could not be assessed." -f $itemErrors)
    }
}

function Get-SCRunEntries {
    param([string]$Path)
    $result = New-Object psobject -Property @{
        Present = $false
        Items   = @()
        Error   = $null
    }
    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        $result.Error = $_.Exception.Message
        return $result
    }
    if (-not $exists) { return $result }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($name in (ConvertTo-SCArray $key.GetValueNames())) {
            if ([string]::IsNullOrWhiteSpace([string]$name)) { continue }
            $raw = $null
            try {
                $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            } catch {
                try { $raw = $key.GetValue($name) } catch { $raw = $null }
            }
            $command = ''
            if ($null -ne $raw) { $command = [string]$raw }
            $exe = Get-SCCommandExecutable -Command $command
            [void]$list.Add((New-Object psobject -Property @{
                Name       = [string]$name
                Executable = $exe
                Unquoted   = (Test-SCUnquotedPath -Path $command)
            }))
        }
        $result.Present = $true
        $result.Items = $list.ToArray()
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-SCRunKeySpecs {
    return @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Label = 'HKLM Run'; UserScope = $false }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKLM RunOnce'; UserScope = $false }
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Label = 'HKCU Run'; UserScope = $true }
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKCU RunOnce'; UserScope = $true }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Label = 'HKLM Wow64 Run'; UserScope = $false }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKLM Wow64 RunOnce'; UserScope = $false }
    )
}

function Invoke-SCCheckRunKeys {
    Start-SCSection -Title 'Run keys'
    $hive = $false
    try { $hive = Test-Path -LiteralPath 'HKLM:\' -ErrorAction Stop } catch { $hive = $false }
    $userHive = $false
    try { $userHive = Test-Path -LiteralPath 'HKCU:\' -ErrorAction Stop } catch { $userHive = $false }
    if ((-not $hive) -and (-not $userHive)) {
        Write-SCWarn -Message 'Registry is not available. Run keys were skipped.'
        return
    }

    $pathCache = @{}
    $grouped = @{}
    $extra = New-Object System.Collections.Generic.List[object]
    $infoRows = New-Object System.Collections.Generic.List[object]
    $presentKeys = 0
    $valueCount = 0
    $denied = 0
    $other = 0

    foreach ($spec in @(Get-SCRunKeySpecs)) {
        if ($spec.UserScope -and -not $userHive) { continue }
        if ((-not $spec.UserScope) -and -not $hive) { continue }
        $bag = Get-SCRunEntries -Path $spec.Path
        if ($bag.Error) {
            if (Test-SCAccessDenied -Message $bag.Error) { $denied++ }
            else { $other++ }
            continue
        }
        if (-not $bag.Present) { continue }
        $presentKeys++
        $regInfo = Get-SCRegistryWriteInfo -Path $spec.Path
        $regLevel = Get-SCNonAdminWriteLevel -Info $regInfo -IgnoreCurrentUser:([bool]$spec.UserScope)
        if ($regLevel.Error -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $regLevel.Error)) {
            $denied++
        } elseif ($regLevel.Error -and $regLevel.Error -ne 'Path not found.') {
            $other++
        } elseif ($regLevel.Level -eq 'WEAK' -or $regLevel.Level -eq 'REVIEW') {
            Add-SCGroupedWrite -Map $grouped -Kind 'run-key' -Level $regLevel.Level -Path $spec.Path -Principals $regLevel.Principals -BroadPrincipals $regLevel.BroadPrincipals -OwnerName $spec.Label
        }
        foreach ($entry in (ConvertTo-SCArray $bag.Items)) {
            if (-not $entry) { continue }
            $valueCount++
            $label = '{0} / {1}' -f $spec.Label, $entry.Name
            $exe = $null
            if ($entry.Executable) { $exe = Expand-SCSystemPath -Path $entry.Executable }
            if ($entry.Unquoted) {
                $shown = 'not parsed'
                if ($exe) { $shown = Format-SCShortText -Text $exe -Max 120 }
                [void]$extra.Add((New-SCFinding -Level 'WEAK' -Text ("Run value '{0}' is unquoted and contains a space. Executable: {1}" -f $label, $shown)))
            }
            if ($exe -and (Test-SCUncPath -Path $exe)) {
                [void]$extra.Add((New-SCFinding -Level 'REVIEW' -Text ("Run value '{0}' uses a network path: {1}" -f $label, (Format-SCShortText -Text $exe -Max 120))))
            } else {
                [void](Add-SCPathWriteFindings -Map $grouped -Cache $pathCache -Kind 'run' -DirKind 'run-dir' -Path $exe -OwnerName $label -IgnoreCurrentUser:([bool]$spec.UserScope))
            }
            $shownExe = 'path not parsed'
            if ($exe) { $shownExe = Format-SCShortText -Text $exe -Max 100 }
            [void]$infoRows.Add((New-SCFinding -Level 'INFO' -Text ("{0}: {1} -> {2}" -f $spec.Label, $entry.Name, $shownExe)))
        }
    }

    Write-SCInfo -Message ("Run keys present: {0}. Values: {1}." -f $presentKeys, $valueCount)
    $groupedBag = Get-SCGroupedFindings -Map $grouped
    $groupedItems = @()
    if ($groupedBag -and $groupedBag.Items) { $groupedItems = ConvertTo-SCArray $groupedBag.Items }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($item in $extra) { if ($item) { [void]$all.Add($item) } }
    foreach ($item in (ConvertTo-SCArray $groupedItems)) { if ($item) { [void]$all.Add($item) } }
    Write-SCSortedFindings -Items $all.ToArray() -Cap 30

    $shown = 0
    $hidden = 0
    foreach ($row in (ConvertTo-SCArray $infoRows)) {
        if (-not $row) { continue }
        if ($shown -ge 40) { $hidden++; continue }
        $shown++
        Write-SCInfo -Message $row.Text
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional Run values were omitted." -f $hidden)
    }
    if ($denied -gt 0) {
        Write-SCNeedsAdmin -Detail ("Run keys could not be read for {0} paths." -f $denied)
    }
    if ($other -gt 0) {
        Write-SCWarn -Message ("{0} Run keys could not be read." -f $other)
    }
    Write-SCPathProblemSummary -Cache $pathCache
}

function Get-SCStartupLocations {
    $list = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $userPath = $null
    $commonPath = $null
    try { $userPath = [Environment]::GetFolderPath('Startup') } catch { $userPath = $null }
    try { $commonPath = [Environment]::GetFolderPath('CommonStartup') } catch { $commonPath = $null }
    if ($userPath) {
        $key = $userPath.TrimEnd('\').ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [void]$list.Add((New-Object psobject -Property @{ Path = $userPath; Kind = 'User'; UserScope = $true }))
        }
    }
    if ($commonPath) {
        $key = $commonPath.TrimEnd('\').ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [void]$list.Add((New-Object psobject -Property @{ Path = $commonPath; Kind = 'Common'; UserScope = $false }))
        }
    }
    if ($env:ProgramData) {
        $extra = Join-SCWindowsPath -Root $env:ProgramData -Child 'Microsoft\Windows\Start Menu\Programs\Startup'
        $key = $extra.TrimEnd('\').ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [void]$list.Add((New-Object psobject -Property @{ Path = $extra; Kind = 'Common'; UserScope = $false }))
        }
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Get-SCShortcutTarget {
    param([string]$Path)
    if ($Path -notmatch '(?i)\.lnk$') { return $null }
    try {
        $shell = New-Object -ComObject WScript.Shell
        $link = $shell.CreateShortcut($Path)
        $target = [string](Get-SCProp $link 'TargetPath')
        if ($target) { return $target }
    } catch {
        return $null
    }
    return $null
}

function Invoke-SCCheckStartup {
    Start-SCSection -Title 'Startup folders'
    $locationBag = Get-SCStartupLocations
    $locations = @()
    if ($locationBag -and $locationBag.Items) { $locations = ConvertTo-SCArray $locationBag.Items }
    if ($locations.Count -eq 0) {
        Write-SCWarn -Message 'Startup folder locations were not available.'
        return
    }

    $pathCache = @{}
    $grouped = @{}
    $seenFolders = 0
    foreach ($location in $locations) {
        if (-not $location -or -not $location.Path) { continue }
        $folder = [string]$location.Path
        if (-not (Test-Path -LiteralPath $folder -ErrorAction SilentlyContinue)) {
            Write-SCInfo -Message ("{0} startup folder is not present: {1}" -f $location.Kind, $folder)
            continue
        }
        $seenFolders++
        $ignoreUser = [bool]$location.UserScope
        $folderInfo = Get-SCCachedWrite -Cache $pathCache -Path $folder
        $folderLevel = Get-SCNonAdminWriteLevel -Info $folderInfo -IgnoreCurrentUser:$ignoreUser -BroadIsReview
        if ($folderLevel.Level -eq 'WEAK' -or $folderLevel.Level -eq 'REVIEW') {
            Add-SCGroupedWrite -Map $grouped -Kind 'startup-dir' -Level $folderLevel.Level -Path $folder -Principals $folderLevel.Principals -BroadPrincipals $folderLevel.BroadPrincipals -OwnerName $location.Kind
        }
        $acl = Get-SCAclSummary -Path $folder
        $owner = [string](Get-SCProp $acl 'Owner')
        $files = @()
        $readError = $null
        try {
            $files = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop | Where-Object { $_ -and -not $_.PSIsContainer })
        } catch {
            $readError = $_.Exception.Message
        }
        if ($readError) {
            if (Test-SCAccessDenied -Message $readError) {
                Write-SCNeedsAdmin -Detail ("Startup folder could not be listed: {0}" -f $folder)
            } else {
                Write-SCWarn -Message ("Startup folder could not be listed: {0}" -f (Format-SCShortText -Text $readError -Max 120))
            }
            continue
        }
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($file in $files) {
            if (-not $file) { continue }
            [void]$names.Add([string]$file.Name)
            $filePath = [string]$file.FullName
            [void](Add-SCPathWriteFindings -Map $grouped -Cache $pathCache -Kind 'startup-file' -DirKind 'startup-dir' -Path $filePath -OwnerName $file.Name -IgnoreCurrentUser:$ignoreUser -BroadIsReview -SkipParent)
            $target = Get-SCShortcutTarget -Path $filePath
            if ($target) {
                $expanded = Expand-SCSystemPath -Path $target
                if ($expanded -and -not (Test-SCUncPath -Path $expanded)) {
                    [void](Add-SCPathWriteFindings -Map $grouped -Cache $pathCache -Kind 'startup-target' -DirKind 'startup-dir' -Path $expanded -OwnerName $file.Name -IgnoreCurrentUser:$ignoreUser -BroadIsReview)
                }
            }
        }
        $ownerText = ''
        if ($owner) { $ownerText = " Owner: $owner." }
        if ($names.Count -eq 0) {
            Write-SCInfo -Message ("{0} startup: empty.{1} {2}" -f $location.Kind, $ownerText, $folder)
        } else {
            $shownNames = Format-SCNameList -Names $names.ToArray() -Max 8
            $suffix = ''
            if ($names.Count -gt 8) { $suffix = ' (list truncated)' }
            Write-SCInfo -Message ("{0} startup: {1} files.{2} {3}{4} {5}" -f $location.Kind, $names.Count, $ownerText, $shownNames, $suffix, $folder)
        }
    }

    if ($seenFolders -eq 0) { return }
    $groupedBag = Get-SCGroupedFindings -Map $grouped
    $groupedItems = @()
    if ($groupedBag -and $groupedBag.Items) { $groupedItems = ConvertTo-SCArray $groupedBag.Items }
    Write-SCSortedFindings -Items $groupedItems -Cap 30
    Write-SCPathProblemSummary -Cache $pathCache
}

function Invoke-SCServicesCheck {
    param([string]$Name)
    # Run in this script. Test-SCStringInList is defined here so -File does not
    # depend on an older 00_common.ps1, where the command would be missing.
    try {
        if ($Name -eq 'Services') { Invoke-SCCheckServices }
        elseif ($Name -eq 'Scheduled tasks') { Invoke-SCCheckTasks }
        elseif ($Name -eq 'Run keys') { Invoke-SCCheckRunKeys }
        elseif ($Name -eq 'Startup folders') { Invoke-SCCheckStartup }
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Services'
Invoke-SCServicesCheck -Name 'Services'
Invoke-SCServicesCheck -Name 'Scheduled tasks'
Invoke-SCServicesCheck -Name 'Run keys'
Invoke-SCServicesCheck -Name 'Startup folders'
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Services' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
