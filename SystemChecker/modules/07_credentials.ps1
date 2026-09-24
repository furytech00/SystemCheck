#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only credential hygiene checks.

.DESCRIPTION
    Reports credential target names, saved RDP entry counts, auto-logon
    flags, leftover answer-file paths, Wi-Fi profile names, and cloud
    config path existence. This module does not print passwords, decrypt
    vault items, or read secret file contents.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\07_credentials.ps1
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

function Write-SCFindingItems {
    param($Items)
    $rows = @()
    if ($Items) { $rows = @($Items) }
    foreach ($item in $rows) {
        if (-not $item) { continue }
        Write-SCLevel -Level ([string]$item.Level) -Message ([string]$item.Text)
    }
}

function Format-SCShortText {
    param([string]$Text, [int]$Max = 100)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ([string]$Text -replace '[\r\n]+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max)
}

function Join-SCWindowsPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return $Child }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Join-SCProfilePath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return '' }
    if ($Root -match '^[A-Za-z]:' -or $Root.StartsWith('\\')) {
        return (Join-SCWindowsPath -Root $Root -Child $Child)
    }
    $piece = $Child -replace '\\', '/'
    return (Join-Path -Path $Root -Child $piece)
}

function Test-SCLocalPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path.StartsWith('\\')) { return $false }
    try {
        return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    } catch {
        return $false
    }
}

function Get-SCSecretPresence {
    # Returns missing, empty, present, or error. Never returns the value.
    param($Result)
    if (-not $Result) { return 'missing' }
    if ($Result.Error) { return 'error' }
    if (-not $Result.Found) { return 'missing' }
    if ($null -eq $Result.Value) { return 'empty' }
    if (([string]$Result.Value).Length -gt 0) { return 'present' }
    return 'empty'
}

function Get-SCAutoLogonFindings {
    param(
        [bool]$KeyError,
        [bool]$Enabled,
        [string]$PasswordState,
        [string]$AltPasswordState,
        [string]$UserName
    )
    $items = New-Object System.Collections.Generic.List[object]
    if ($KeyError) {
        $items.Add((New-SCFinding 'WARN' 'NEEDS ADMIN: auto-logon registry values could not be read.'))
        return New-Object psobject -Property @{ Items = $items.ToArray() }
    }
    if ($Enabled -and $PasswordState -eq 'present') {
        $items.Add((New-SCFinding 'WEAK' 'Auto-logon is enabled and DefaultPassword is present. The password value was not printed.'))
    } elseif ($Enabled -and $PasswordState -eq 'empty') {
        $items.Add((New-SCFinding 'REVIEW' 'Auto-logon is enabled and DefaultPassword is empty.'))
    } elseif ($Enabled) {
        $items.Add((New-SCFinding 'REVIEW' 'Auto-logon is enabled. DefaultPassword is not set.'))
    } elseif ($PasswordState -eq 'present') {
        $items.Add((New-SCFinding 'REVIEW' 'DefaultPassword is present while auto-logon is off. The password value was not printed.'))
    } else {
        $items.Add((New-SCFinding 'INFO' 'Auto-logon is not enabled.'))
    }
    if ($AltPasswordState -eq 'present') {
        $items.Add((New-SCFinding 'REVIEW' 'AltDefaultPassword is present. The password value was not printed.'))
    }
    if ($UserName -and ($Enabled -or $PasswordState -eq 'present')) {
        $shown = Format-SCShortText -Text $UserName -Max 80
        $items.Add((New-SCFinding 'INFO' ("Auto-logon user name: {0}" -f $shown)))
    }
    return New-Object psobject -Property @{ Items = $items.ToArray() }
}

function Get-SCCredentialTargets {
    param([string[]]$Lines)
    $list = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($line in @($Lines)) {
        if (-not $line) { continue }
        $text = [string]$line
        if ($text -notmatch '^\s*Target:\s*(.+)\s*$') { continue }
        $target = Format-SCShortText -Text $Matches[1] -Max 120
        if (-not $target) { continue }
        if ($target -match '(?i)password\s*=|pwd\s*=') { continue }
        $key = $target.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$list.Add($target)
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Get-SCWifiNamesFromText {
    param([string[]]$Lines)
    $list = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($line in @($Lines)) {
        if (-not $line) { continue }
        $text = [string]$line
        if ($text -match '(?i)key\s*content|keyMaterial') { continue }
        if ($text -notmatch '(?i)^\s*(?:All User Profile|Current User Profile|Profile)\s*:\s*(.+)\s*$') { continue }
        $name = Format-SCShortText -Text $Matches[1] -Max 80
        if (-not $name) { continue }
        if ($name -eq '<None>' -or $name -eq 'None') { continue }
        $key = $name.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$list.Add($name)
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Get-SCAnswerFilePaths {
    param([string]$WindowsDir, [string]$SystemDrive)
    $root = $WindowsDir
    if (-not $root) { $root = 'C:\Windows' }
    $drive = $SystemDrive
    if (-not $drive) { $drive = 'C:' }
    $rels = @(
        'Panther\Unattend.xml',
        'Panther\unattend.xml',
        'Panther\Unattend\Unattend.xml',
        'System32\Sysprep\Unattend.xml',
        'System32\Sysprep\unattend.xml',
        'System32\Sysprep\Panther\unattend.xml'
    )
    $list = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($rel in $rels) {
        $path = Join-SCWindowsPath -Root $root -Child $rel
        $key = $path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$list.Add($path)
    }
    foreach ($name in @('unattend.xml', 'Unattend.xml')) {
        $path = Join-SCWindowsPath -Root $drive -Child $name
        $key = $path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$list.Add($path)
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Get-SCCloudConfigPaths {
    param([string]$ProfileRoot)
    $list = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($ProfileRoot)) {
        return New-Object psobject -Property @{ Items = $list.ToArray() }
    }
    $specs = @(
        @{ Name = 'AWS config directory'; Path = '.aws' },
        @{ Name = 'AWS credentials file'; Path = '.aws\credentials' },
        @{ Name = 'Azure config directory'; Path = '.azure' },
        @{ Name = 'GCP config directory'; Path = '.config\gcloud' },
        @{ Name = 'GCP application default credentials file'; Path = '.config\gcloud\application_default_credentials.json' }
    )
    foreach ($spec in $specs) {
        $path = Join-SCProfilePath -Root $ProfileRoot -Child ([string]$spec.Path)
        if (-not $path) { continue }
        [void]$list.Add((New-Object psobject -Property @{
            Name = [string]$spec.Name
            Path = $path
        }))
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Find-SCGroupsXmlFiles {
    param(
        [string]$Root,
        [int]$MaxDomains = 5,
        [int]$MaxPolicies = 40
    )
    $result = New-Object psobject -Property @{
        Items   = @()
        Missing = $false
        Denied  = $false
        Error   = $null
    }
    if ([string]::IsNullOrWhiteSpace($Root) -or $Root.StartsWith('\\') -or -not (Test-SCLocalPath -Path $Root)) {
        $result.Missing = $true
        return $result
    }
    $found = New-Object System.Collections.Generic.List[string]
    try {
        $domains = @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop)
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
        return $result
    }
    $domainCount = 0
    foreach ($domain in $domains) {
        if (-not $domain) { continue }
        if ($domainCount -ge $MaxDomains) { break }
        $domainCount++
        $policyRoot = Join-SCProfilePath -Root $domain.FullName -Child 'Policies'
        if (-not (Test-SCLocalPath -Path $policyRoot)) { continue }
        $policies = @()
        try {
            $policies = @(Get-ChildItem -LiteralPath $policyRoot -Directory -ErrorAction Stop)
        } catch {
            $message = $_.Exception.Message
            if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
            elseif (-not $result.Error) { $result.Error = $message }
            continue
        }
        $policyCount = 0
        foreach ($policy in $policies) {
            if (-not $policy) { continue }
            if ($policyCount -ge $MaxPolicies) { break }
            $policyCount++
            foreach ($rel in @('Machine\Preferences\Groups\Groups.xml', 'User\Preferences\Groups\Groups.xml')) {
                $full = Join-SCProfilePath -Root $policy.FullName -Child $rel
                if (Test-SCLocalPath -Path $full) { [void]$found.Add($full) }
            }
        }
    }
    $result.Items = $found.ToArray()
    return $result
}

function Invoke-SCFixedCommand {
    # Fixed built-in commands only. Arguments are not taken from the caller.
    param([Parameter(Mandatory = $true)][ValidateSet('CmdkeyList', 'WlanProfiles')][string]$Name)
    $leaf = 'cmdkey'
    $argList = @('/list')
    if ($Name -eq 'WlanProfiles') {
        $leaf = 'netsh'
        $argList = @('wlan', 'show', 'profiles')
    }
    $result = New-Object psobject -Property @{
        Ok      = $false
        Missing = $false
        Output  = @()
        Error   = $null
    }
    if (-not (Get-Command -Name $leaf -CommandType Application -ErrorAction SilentlyContinue)) {
        $result.Missing = $true
        $result.Error = ($leaf + ' is not available.')
        return $result
    }
    try {
        $captured = @(& $leaf @argList 2>&1 | ForEach-Object { "$_" })
        $result.Output = $captured
        $result.Ok = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Test-SCCommandDenied {
    param($Result)
    if (-not $Result) { return $false }
    $text = ''
    if ($Result.Output) { $text = [string]($Result.Output -join "`n") }
    if ($Result.Error) { $text = $text + ' ' + [string]$Result.Error }
    if (Test-SCAccessDenied -Message $text) { return $true }
    if ($text -match 'System error 5') { return $true }
    return $false
}

function Write-SCCappedNames {
    param(
        [string]$Prefix,
        $Names,
        [int]$Cap,
        [string]$Level = 'INFO'
    )
    $rows = @()
    if ($Names) { $rows = @($Names) }
    $shown = 0
    $hidden = 0
    foreach ($name in $rows) {
        if (-not $name) { continue }
        if ($shown -ge $Cap) { $hidden++; continue }
        $shown++
        Write-SCLevel -Level $Level -Message ("{0}{1}" -f $Prefix, (Format-SCShortText -Text ([string]$name) -Max 120))
    }
    return $hidden
}

function Invoke-SCCheckCredentialManager {
    Start-SCSection -Title 'Credential Manager'
    $cmd = Invoke-SCFixedCommand -Name 'CmdkeyList'
    if ($cmd.Missing) {
        Write-SCWarn -Message 'cmdkey is not available, so credential target names were not listed.'
        return
    }
    if (Test-SCCommandDenied -Result $cmd) {
        Write-SCNeedsAdmin -Detail 'Credential Manager target names could not be read.'
        return
    }
    if ($cmd.Error -and -not $cmd.Ok) {
        Write-SCWarn -Message ("Credential Manager target names could not be read: {0}" -f (Format-SCShortText -Text $cmd.Error -Max 160))
        return
    }
    $parsed = Get-SCCredentialTargets -Lines @($cmd.Output)
    $targets = @()
    if ($parsed.Items) { $targets = @($parsed.Items) }
    if ($targets.Count -eq 0) {
        Write-SCInfo -Message 'No stored credential targets were listed.'
        return
    }
    Write-SCInfo -Message ("Stored credential targets: {0}. Passwords were not read." -f $targets.Count)
    $hidden = Write-SCCappedNames -Prefix 'Credential target: ' -Names $targets -Cap 15
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional credential targets were omitted." -f $hidden)
    }
}

function Get-SCKnownFolder {
    param([string]$Name)
    try {
        return [string][Environment]::GetFolderPath($Name)
    } catch {
        return ''
    }
}

function Get-SCRdpFileNames {
    param([string]$Directory)
    $list = New-Object System.Collections.Generic.List[string]
    if (-not (Test-SCLocalPath -Path $Directory)) {
        return New-Object psobject -Property @{ Items = $list.ToArray(); Error = $null; Denied = $false }
    }
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $Directory -Filter '*.rdp' -File -ErrorAction Stop)) {
            if (-not $file) { continue }
            $leaf = [string]$file.Name
            if ($leaf) { [void]$list.Add($leaf) }
        }
    } catch {
        $message = $_.Exception.Message
        $denied = Test-SCAccessDenied -Message $message
        return New-Object psobject -Property @{
            Items  = $list.ToArray()
            Error  = $message
            Denied = $denied
        }
    }
    return New-Object psobject -Property @{
        Items  = $list.ToArray()
        Error  = $null
        Denied = $false
    }
}

function Get-SCRdpServerNames {
    $path = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
    $list = New-Object System.Collections.Generic.List[string]
    $result = New-Object psobject -Property @{
        Items   = $list.ToArray()
        Missing = $false
        Denied  = $false
        Error   = $null
    }
    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $path -ErrorAction Stop
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
        return $result
    }
    if (-not $exists) {
        $result.Missing = $true
        return $result
    }
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath $path -ErrorAction Stop)) {
            if (-not $key) { continue }
            $name = [string]$key.PSChildName
            if ($name) { [void]$list.Add($name) }
        }
        $result.Items = $list.ToArray()
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    return $result
}

function Invoke-SCCheckSavedRdp {
    Start-SCSection -Title 'Saved RDP connections'
    $servers = Get-SCRdpServerNames
    if ($servers.Denied) {
        Write-SCNeedsAdmin -Detail 'Saved RDP server names could not be read.'
    } elseif ($servers.Error) {
        Write-SCWarn -Message ("Saved RDP server names could not be read: {0}" -f (Format-SCShortText -Text $servers.Error -Max 160))
    }
    $serverNames = @()
    if ($servers.Items) { $serverNames = @($servers.Items) }

    $folders = New-Object System.Collections.Generic.List[string]
    foreach ($kind in @('MyDocuments', 'Desktop')) {
        $folder = Get-SCKnownFolder -Name $kind
        if ($folder) { [void]$folders.Add($folder) }
    }
    $fileNames = New-Object System.Collections.Generic.List[string]
    $fileDenied = $false
    foreach ($folder in $folders) {
        $bag = Get-SCRdpFileNames -Directory $folder
        if ($bag.Denied) { $fileDenied = $true }
        if ($bag.Items) {
            foreach ($name in @($bag.Items)) {
                if ($name) { [void]$fileNames.Add([string]$name) }
            }
        }
    }
    if ($fileDenied) {
        Write-SCNeedsAdmin -Detail 'Saved .rdp file names could not be read.'
    }
    $files = @()
    if ($fileNames.Count -gt 0) { $files = @($fileNames.ToArray()) }
    if ($serverNames.Count -eq 0 -and $files.Count -eq 0 -and -not $servers.Denied -and -not $fileDenied) {
        Write-SCInfo -Message 'No saved RDP server keys or .rdp files were found for this user.'
        return
    }
    if ($serverNames.Count -gt 0) {
        Write-SCReview -Message ("Saved RDP server entries: {0}. Entry contents were not read." -f $serverNames.Count)
        $hidden = Write-SCCappedNames -Prefix 'RDP server: ' -Names $serverNames -Cap 8
        if ($hidden -gt 0) {
            Write-SCInfo -Message ("{0} additional RDP server names were omitted." -f $hidden)
        }
    }
    if ($files.Count -gt 0) {
        Write-SCReview -Message ("Saved .rdp files: {0}. File contents were not read." -f $files.Count)
        $hiddenFiles = Write-SCCappedNames -Prefix 'RDP file: ' -Names $files -Cap 8
        if ($hiddenFiles -gt 0) {
            Write-SCInfo -Message ("{0} additional .rdp file names were omitted." -f $hiddenFiles)
        }
    }
}

function Invoke-SCCheckAutoLogon {
    Start-SCSection -Title 'Auto-logon'
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto = Get-SCRegistryValue -Path $key -Name 'AutoAdminLogon'
    # Read the secret only to classify presence. Do not pass the value onward.
    $password = Get-SCRegistryValue -Path $key -Name 'DefaultPassword'
    $passwordState = Get-SCSecretPresence -Result $password
    $passwordDenied = $false
    if ($password.Error -and (Test-SCAccessDenied -Message $password.Error)) { $passwordDenied = $true }
    $password = $null
    $alt = Get-SCRegistryValue -Path $key -Name 'AltDefaultPassword'
    $altState = Get-SCSecretPresence -Result $alt
    $altDenied = $false
    if ($alt.Error -and (Test-SCAccessDenied -Message $alt.Error)) { $altDenied = $true }
    $alt = $null
    $user = Get-SCRegistryValue -Path $key -Name 'DefaultUserName'
    $keyError = $false
    if ($passwordDenied -or $altDenied) { $keyError = $true }
    if ($auto.Error -and (Test-SCAccessDenied -Message $auto.Error)) { $keyError = $true }
    $enabled = $false
    if ($auto.Found -and ([string]$auto.Value).Trim() -eq '1') { $enabled = $true }
    $userName = ''
    if ($user.Found -and $user.Value -and -not $user.Error) { $userName = [string]$user.Value }
    if ($passwordState -eq 'error') { $passwordState = 'missing' }
    if ($altState -eq 'error') { $altState = 'missing' }
    $findings = Get-SCAutoLogonFindings -KeyError $keyError -Enabled $enabled -PasswordState $passwordState -AltPasswordState $altState -UserName $userName
    Write-SCFindingItems -Items $findings.Items
    $force = Get-SCRegistryValue -Path $key -Name 'ForceAutoLogon'
    if ($force.Found -and ([string]$force.Value).Trim() -eq '1') {
        Write-SCInfo -Message 'ForceAutoLogon is 1.'
    }
}

function Invoke-SCCheckLeftovers {
    Start-SCSection -Title 'Answer files and GPP leftovers'
    $paths = @()
    $pathBag = Get-SCAnswerFilePaths -WindowsDir $env:WINDIR -SystemDrive $env:SystemDrive
    if ($pathBag.Items) { $paths = @($pathBag.Items) }
    $foundFiles = New-Object System.Collections.Generic.List[string]
    foreach ($path in $paths) {
        if (Test-SCLocalPath -Path $path) { [void]$foundFiles.Add($path) }
    }
    $winDir = $env:WINDIR
    if (-not $winDir) { $winDir = 'C:\Windows' }
    $sysvol = Join-SCWindowsPath -Root $winDir -Child 'SYSVOL\sysvol'
    $groups = Find-SCGroupsXmlFiles -Root $sysvol
    if ($groups.Denied) {
        Write-SCNeedsAdmin -Detail 'Local SYSVOL could not be listed.'
    } elseif ($groups.Error) {
        Write-SCWarn -Message ("Local SYSVOL could not be listed: {0}" -f (Format-SCShortText -Text $groups.Error -Max 160))
    }
    $groupFiles = @()
    if ($groups.Items) { $groupFiles = @($groups.Items) }
    if ($foundFiles.Count -eq 0 -and $groupFiles.Count -eq 0) {
        Write-SCInfo -Message 'No common unattend, sysprep, or local Groups.xml leftovers were found.'
        return
    }
    $shown = 0
    foreach ($path in $foundFiles) {
        if ($shown -ge 10) { break }
        $shown++
        Write-SCWeak -Message ("Leftover answer file exists: {0}. Contents were not read." -f (Format-SCShortText -Text $path -Max 140))
    }
    $shownGroups = 0
    foreach ($path in $groupFiles) {
        if ($shownGroups -ge 10) { break }
        $shownGroups++
        Write-SCWeak -Message ("GPP Groups.xml exists: {0}. The file was not opened." -f (Format-SCShortText -Text $path -Max 140))
    }
    $extra = 0
    if ($foundFiles.Count -gt 10) { $extra += ($foundFiles.Count - 10) }
    if ($groupFiles.Count -gt 10) { $extra += ($groupFiles.Count - 10) }
    if ($extra -gt 0) {
        Write-SCInfo -Message ("{0} additional leftover paths were omitted." -f $extra)
    }
}

function Get-SCWifiNamesFromRegistry {
    $base = 'HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces'
    $list = New-Object System.Collections.Generic.List[string]
    $result = New-Object psobject -Property @{
        Items   = $list.ToArray()
        Missing = $false
        Denied  = $false
        Error   = $null
    }
    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $base -ErrorAction Stop
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
        return $result
    }
    if (-not $exists) {
        $result.Missing = $true
        return $result
    }
    try {
        foreach ($iface in @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
            if (-not $iface) { continue }
            $profiles = 'Registry::{0}\Profiles' -f [string]$iface.Name
            if (-not (Test-SCLocalPath -Path $profiles)) { continue }
            foreach ($prof in @(Get-ChildItem -LiteralPath $profiles -ErrorAction Stop)) {
                if (-not $prof) { continue }
                $value = Get-SCRegistryValue -Path $prof.PSPath -Name 'ProfileName'
                if ($value.Error -and (Test-SCAccessDenied -Message $value.Error)) { $result.Denied = $true }
                if ($value.Found -and $value.Value) {
                    $name = Format-SCShortText -Text ([string]$value.Value) -Max 80
                    if ($name) { [void]$list.Add($name) }
                }
            }
        }
        $result.Items = $list.ToArray()
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    return $result
}

function Invoke-SCCheckWifi {
    Start-SCSection -Title 'Wi-Fi profiles'
    $cmd = Invoke-SCFixedCommand -Name 'WlanProfiles'
    $names = @()
    if ($cmd.Ok -and -not (Test-SCCommandDenied -Result $cmd)) {
        $parsed = Get-SCWifiNamesFromText -Lines @($cmd.Output)
        if ($parsed.Items) { $names = @($parsed.Items) }
    }
    if ($names.Count -eq 0) {
        $reg = Get-SCWifiNamesFromRegistry
        if ($reg.Denied) {
            Write-SCNeedsAdmin -Detail 'Wi-Fi profile names could not be read.'
            return
        }
        if ($reg.Items) { $names = @($reg.Items) }
        if ($names.Count -eq 0 -and $cmd.Missing -and $reg.Missing) {
            Write-SCWarn -Message 'Wi-Fi profile names could not be read on this host.'
            return
        }
        if ($names.Count -eq 0 -and $cmd.Error -and (Test-SCCommandDenied -Result $cmd)) {
            Write-SCNeedsAdmin -Detail 'Wi-Fi profile names could not be read.'
            return
        }
    }
    if ($names.Count -eq 0) {
        Write-SCInfo -Message 'No Wi-Fi profile names were listed.'
        return
    }
    Write-SCInfo -Message ("Wi-Fi profiles: {0}. Key material was not read." -f $names.Count)
    $hidden = Write-SCCappedNames -Prefix 'Wi-Fi profile: ' -Names $names -Cap 15
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional Wi-Fi profile names were omitted." -f $hidden)
    }
}

function Invoke-SCCheckCloudPaths {
    Start-SCSection -Title 'Cloud credential paths'
    $root = $env:USERPROFILE
    if (-not $root) { $root = $env:HOME }
    $bag = Get-SCCloudConfigPaths -ProfileRoot $root
    $specs = @()
    if ($bag.Items) { $specs = @($bag.Items) }
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($spec in $specs) {
        if (-not $spec) { continue }
        if (Test-SCLocalPath -Path ([string]$spec.Path)) { [void]$found.Add($spec) }
    }
    if ($found.Count -eq 0) {
        Write-SCInfo -Message 'No AWS, Azure, or GCP config paths were found under the user profile.'
        return
    }
    foreach ($spec in $found) {
        Write-SCReview -Message ("{0} exists: {1}. Contents were not read." -f $spec.Name, (Format-SCShortText -Text ([string]$spec.Path) -Max 140))
    }
}

function Invoke-SCCredCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Credentials'
Invoke-SCCredCheck -Name 'Credential Manager' -Body { Invoke-SCCheckCredentialManager }
Invoke-SCCredCheck -Name 'Saved RDP' -Body { Invoke-SCCheckSavedRdp }
Invoke-SCCredCheck -Name 'Auto-logon' -Body { Invoke-SCCheckAutoLogon }
Invoke-SCCredCheck -Name 'Answer files' -Body { Invoke-SCCheckLeftovers }
Invoke-SCCredCheck -Name 'Wi-Fi profiles' -Body { Invoke-SCCheckWifi }
Invoke-SCCredCheck -Name 'Cloud credential paths' -Body { Invoke-SCCheckCloudPaths }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Credentials' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
