#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only cloud guest-agent presence checks.

.DESCRIPTION
    Reports whether Azure, AWS, or GCP guest-agent services, install
    folders, or uninstall entries are present. Service state and start
    mode are read when CIM is available. Config checks are folder
    existence only. This module does not contact the network, read
    credential files, or change an agent. It is not part of the default
    runner.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\11_cloud.ps1
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

$script:SCCloudCimMissingNoted = $false
$script:SCCloudUninstallCap = 400

function Get-SCProp {
    param($Object, [string]$Name)
    if (-not $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if (-not $prop) { return $null }
    return $prop.Value
}

function Format-SCShortText {
    param([string]$Text, [int]$Max = 120)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ([string]$Text -replace '[\r\n]+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max)
}

function Join-SCWindowsPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return '' }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
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
        default { return (Format-SCShortText -Text $text -Max 40) }
    }
}

function Format-SCServiceState {
    param($Value)
    if ($null -eq $Value) { return 'unknown' }
    $text = ([string]$Value).Trim()
    if (-not $text) { return 'unknown' }
    return (Format-SCShortText -Text $text -Max 40)
}

function Get-SCCloudQueryKind {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return 'other' }
    if (Test-SCAccessDenied -Message $Message) { return 'denied' }
    if ($Message -match 'not recognized|not implemented|not supported|Invalid class|Invalid namespace') { return 'unavailable' }
    return 'other'
}

function Test-SCCloudServiceToken {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name.Length -gt 80) { return $false }
    return ($Name -match '^[A-Za-z][A-Za-z0-9_ ]*$')
}

function Get-SCCloudServiceFilter {
    param([string[]]$Names)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Names)) {
        if (-not (Test-SCCloudServiceToken -Name $name)) { continue }
        [void]$parts.Add(("Name='{0}'" -f $name))
    }
    return ($parts -join ' OR ')
}

function Test-SCCloudDisplayName {
    param([string]$DisplayName, [string[]]$Titles)
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $false }
    $text = $DisplayName.Trim()
    foreach ($title in @($Titles)) {
        if ([string]::IsNullOrWhiteSpace($title)) { continue }
        if ($text.Equals($title, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        $prefix = $title + ' '
        if ($text.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-SCCloudCue {
    param([string]$Manufacturer, [string]$Model, [string]$BiosText)
    $text = (([string]$Manufacturer) + ' ' + ([string]$Model) + ' ' + ([string]$BiosText)).ToLowerInvariant()
    if ($text -match 'amazon|ec2') { return 'Amazon EC2' }
    if ($text -match 'google|compute engine') { return 'Google Compute Engine' }
    if ($text -match 'qemu') { return 'QEMU' }
    if ($text -match 'vmware') { return 'VMware' }
    if ($text -match 'virtualbox|innotek') { return 'VirtualBox' }
    if ($text -match '\bxen\b') { return 'Xen' }
    if ($text -match 'microsoft' -and $text -match 'virtual machine') { return 'Hyper-V' }
    return ''
}

function New-SCCloudServiceDef {
    param([string]$Name, [string]$Label)
    return New-Object psobject -Property @{
        Name  = $Name
        Label = $Label
    }
}

function New-SCCloudVendor {
    param(
        [string]$Name,
        [object[]]$Services,
        [string[]]$InstallSpecs,
        [string[]]$ConfigSpecs,
        [string[]]$UninstallTitles
    )
    return New-Object psobject -Property @{
        Name            = $Name
        Services        = @($Services)
        InstallSpecs    = @($InstallSpecs)
        ConfigSpecs     = @($ConfigSpecs)
        UninstallTitles = @($UninstallTitles)
    }
}

function Get-SCCloudVendors {
    $list = New-Object System.Collections.Generic.List[object]
    [void]$list.Add((New-SCCloudVendor -Name 'Azure' -Services @(
        (New-SCCloudServiceDef -Name 'WindowsAzureGuestAgent' -Label 'Windows Azure Guest Agent'),
        (New-SCCloudServiceDef -Name 'RdAgent' -Label 'Azure RD Agent'),
        (New-SCCloudServiceDef -Name 'himds' -Label 'Azure Hybrid Instance Metadata Service')
    ) -InstallSpecs @(
        'Windows|WindowsAzure',
        'ProgramFiles|AzureConnectedMachineAgent'
    ) -ConfigSpecs @(
        'ProgramData|AzureConnectedMachineAgent'
    ) -UninstallTitles @(
        'Windows Azure Guest Agent',
        'Azure Connected Machine Agent'
    )))
    [void]$list.Add((New-SCCloudVendor -Name 'AWS' -Services @(
        (New-SCCloudServiceDef -Name 'AmazonSSMAgent' -Label 'Amazon SSM Agent'),
        (New-SCCloudServiceDef -Name 'EC2Launch' -Label 'EC2Launch'),
        (New-SCCloudServiceDef -Name 'Amazon EC2Launch' -Label 'Amazon EC2Launch'),
        (New-SCCloudServiceDef -Name 'EC2Config' -Label 'EC2Config')
    ) -InstallSpecs @(
        'ProgramFiles|Amazon\SSM',
        'ProgramFiles|Amazon\EC2Launch',
        'ProgramFiles|Amazon\EC2ConfigService'
    ) -ConfigSpecs @(
        'ProgramData|Amazon\SSM',
        'ProgramData|Amazon\EC2Launch',
        'ProgramData|Amazon\EC2Config'
    ) -UninstallTitles @(
        'Amazon SSM Agent',
        'Amazon EC2Launch',
        'AWS EC2Launch',
        'Amazon Web Services EC2Config Service'
    )))
    [void]$list.Add((New-SCCloudVendor -Name 'GCP' -Services @(
        (New-SCCloudServiceDef -Name 'GCEAgent' -Label 'Google Compute Engine Agent'),
        (New-SCCloudServiceDef -Name 'GoogleService' -Label 'GoogleService')
    ) -InstallSpecs @(
        'ProgramFiles|Google\Compute Engine',
        'ProgramFilesX86|Google\Compute Engine'
    ) -ConfigSpecs @(
        'ProgramData|Google\Compute Engine'
    ) -UninstallTitles @(
        'Google Compute Engine Agent',
        'Google OSConfig Agent'
    )))
    return New-Object psobject -Property @{ Items = @($list.ToArray()) }
}

function Get-SCCloudServiceNames {
    param($Vendors)
    $list = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($vendor in @($Vendors.Items)) {
        foreach ($svc in @($vendor.Services)) {
            if (-not $svc) { continue }
            $key = ([string]$svc.Name).ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            [void]$list.Add([string]$svc.Name)
        }
    }
    return New-Object psobject -Property @{ Items = @($list.ToArray()) }
}

function Get-SCCloudRoots {
    $pf86 = ''
    try { $pf86 = [string]${env:ProgramFiles(x86)} } catch { $pf86 = '' }
    return @{
        Windows          = [string]$env:SystemRoot
        ProgramFiles     = [string]$env:ProgramFiles
        ProgramFilesX86  = $pf86
        ProgramData      = [string]$env:ProgramData
    }
}

function Resolve-SCCloudSpec {
    param([string]$Spec, $Roots)
    if ([string]::IsNullOrWhiteSpace($Spec) -or -not $Roots) { return '' }
    $split = $Spec.IndexOf('|')
    if ($split -lt 1) { return '' }
    $kind = $Spec.Substring(0, $split)
    $child = $Spec.Substring($split + 1)
    if (-not $Roots.ContainsKey($kind)) { return '' }
    $root = [string]$Roots[$kind]
    if ([string]::IsNullOrWhiteSpace($root)) { return '' }
    if ($root.StartsWith('\\')) { return '' }
    return (Join-SCWindowsPath -Root $root -Child $child)
}

function New-SCCloudServiceHit {
    param([string]$Name, [string]$State, [string]$StartMode)
    return New-Object psobject -Property @{
        Name      = $Name
        State     = $State
        StartMode = $StartMode
    }
}

function Get-SCCloudServiceSnapshot {
    param([string[]]$Names)
    $map = @{}
    $snap = New-Object psobject -Property @{
        Map          = $map
        Checked      = $false
        Denied       = $false
        MissingCmd   = $false
        Unavailable  = $false
        Error        = ''
    }
    $tokens = New-Object System.Collections.Generic.List[string]
    $wanted = @{}
    foreach ($name in @($Names)) {
        if (-not (Test-SCCloudServiceToken -Name $name)) { continue }
        [void]$tokens.Add($name)
        $wanted[$name.ToLowerInvariant()] = $true
    }

    $cim = $null
    try { $cim = Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue } catch { $cim = $null }
    if (-not $cim) {
        $snap.MissingCmd = $true
    } else {
        $filter = Get-SCCloudServiceFilter -Names @($tokens.ToArray())
        if ($filter) {
            try {
                $rows = @(Get-CimInstance -ClassName Win32_Service -Filter $filter -ErrorAction Stop)
                foreach ($row in $rows) {
                    if (-not $row) { continue }
                    $name = [string](Get-SCProp $row 'Name')
                    if (-not (Test-SCCloudServiceToken -Name $name)) { continue }
                    $key = $name.ToLowerInvariant()
                    if (-not $wanted.ContainsKey($key)) { continue }
                    $map[$key] = New-SCCloudServiceHit -Name $name -State (Format-SCServiceState -Value (Get-SCProp $row 'State')) -StartMode (Format-SCStartMode -Value (Get-SCProp $row 'StartMode'))
                }
                $snap.Checked = $true
                return $snap
            } catch {
                $msg = ''
                try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
                $kind = Get-SCCloudQueryKind -Message $msg
                if ($kind -eq 'denied') { $snap.Denied = $true }
                elseif ($kind -eq 'unavailable') { $snap.Unavailable = $true }
                else { $snap.Error = $msg }
            }
        }
    }

    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $hive = $false
    try {
        $hive = [bool](Test-Path -LiteralPath $base -ErrorAction Stop)
    } catch {
        $msg = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        if (Test-SCAccessDenied -Message $msg) { $snap.Denied = $true }
        elseif ([string]::IsNullOrWhiteSpace($snap.Error)) { $snap.Error = $msg }
        return $snap
    }
    if (-not $hive) { return $snap }

    $snap.Checked = $true
    $snap.Denied = $false
    $snap.Error = ''
    foreach ($name in @($tokens.ToArray())) {
        $keyPath = Join-SCWindowsPath -Root $base -Child $name
        $exists = $false
        try {
            $exists = [bool](Test-Path -LiteralPath $keyPath -ErrorAction Stop)
        } catch {
            $msg = ''
            try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
            if (Test-SCAccessDenied -Message $msg) { $snap.Denied = $true }
            continue
        }
        if (-not $exists) { continue }
        $start = Get-SCRegistryValue -Path $keyPath -Name 'Start'
        if ($start.Error -and (Test-SCAccessDenied -Message ([string]$start.Error))) { $snap.Denied = $true }
        $mode = 'unknown'
        if ($start.Found) { $mode = Format-SCStartMode -Value $start.Value }
        $map[$name.ToLowerInvariant()] = New-SCCloudServiceHit -Name $name -State 'unknown' -StartMode $mode
    }
    return $snap
}

function Get-SCCloudPathState {
    param([string]$Path)
    $state = New-Object psobject -Property @{
        Present = $false
        Denied  = $false
        Error   = ''
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\')) { return $state }
    try {
        $state.Present = [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    } catch {
        $msg = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        if (Test-SCAccessDenied -Message $msg) { $state.Denied = $true }
        else { $state.Error = $msg }
    }
    return $state
}

function Find-SCCloudUninstallEntries {
    param($Vendors)
    $result = New-Object psobject -Property @{
        Items     = @()
        Denied    = $false
        Truncated = $false
        Error     = ''
    }
    $hits = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $hives = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($hive in $hives) {
        $exists = $false
        try {
            $exists = [bool](Test-Path -LiteralPath $hive -ErrorAction Stop)
        } catch {
            $msg = ''
            try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
            if (Test-SCAccessDenied -Message $msg) { $result.Denied = $true }
            elseif ([string]::IsNullOrWhiteSpace($result.Error)) { $result.Error = $msg }
            continue
        }
        if (-not $exists) { continue }
        $children = @()
        try {
            $children = @(Get-ChildItem -LiteralPath $hive -ErrorAction Stop)
        } catch {
            $msg = ''
            try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
            if (Test-SCAccessDenied -Message $msg) { $result.Denied = $true }
            elseif ([string]::IsNullOrWhiteSpace($result.Error)) { $result.Error = $msg }
            continue
        }
        $count = 0
        foreach ($key in $children) {
            if (-not $key) { continue }
            $count++
            if ($count -gt $script:SCCloudUninstallCap) {
                $result.Truncated = $true
                break
            }
            $keyPath = Join-SCWindowsPath -Root $hive -Child ([string]$key.PSChildName)
            $display = Get-SCRegistryValue -Path $keyPath -Name 'DisplayName'
            if ($display.Error -and (Test-SCAccessDenied -Message ([string]$display.Error))) {
                $result.Denied = $true
                continue
            }
            if (-not $display.Found) { continue }
            $title = Format-SCShortText -Text ([string]$display.Value) -Max 80
            if (-not $title) { continue }
            foreach ($vendor in @($Vendors.Items)) {
                if (-not (Test-SCCloudDisplayName -DisplayName $title -Titles @($vendor.UninstallTitles))) { continue }
                $dedupe = ($vendor.Name + '|' + $title).ToLowerInvariant()
                if ($seen.ContainsKey($dedupe)) { continue }
                $seen[$dedupe] = $true
                $version = ''
                $ver = Get-SCRegistryValue -Path $keyPath -Name 'DisplayVersion'
                if ($ver.Error -and (Test-SCAccessDenied -Message ([string]$ver.Error))) { $result.Denied = $true }
                if ($ver.Found -and $ver.Value) { $version = Format-SCShortText -Text ([string]$ver.Value) -Max 40 }
                [void]$hits.Add((New-Object psobject -Property @{
                    Vendor  = [string]$vendor.Name
                    Title   = $title
                    Version = $version
                }))
            }
        }
    }
    $result.Items = @($hits.ToArray())
    return $result
}

function Get-SCCloudMachineFacts {
    $facts = New-Object psobject -Property @{
        Manufacturer     = ''
        Model            = ''
        BiosManufacturer = ''
        BiosVersion      = ''
        HypervisorPresent = $null
        Cue              = ''
        Kind             = 'ok'
        Denied           = $false
        Error            = ''
    }
    $cim = $null
    try { $cim = Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue } catch { $cim = $null }
    if (-not $cim) {
        $facts.Kind = 'missing-cmd'
        return $facts
    }
    $saw = $false
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $saw = $true
        $facts.Manufacturer = Format-SCShortText -Text ([string](Get-SCProp $cs 'Manufacturer')) -Max 80
        $facts.Model = Format-SCShortText -Text ([string](Get-SCProp $cs 'Model')) -Max 80
        $hv = Get-SCProp $cs 'HypervisorPresent'
        if ($null -ne $hv) { $facts.HypervisorPresent = [bool]$hv }
    } catch {
        $msg = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        $kind = Get-SCCloudQueryKind -Message $msg
        if ($kind -eq 'denied') { $facts.Denied = $true }
        elseif ($kind -eq 'unavailable') { $facts.Kind = 'unavailable' }
        else { $facts.Error = $msg; $facts.Kind = 'other' }
    }
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $saw = $true
        $facts.BiosManufacturer = Format-SCShortText -Text ([string](Get-SCProp $bios 'Manufacturer')) -Max 80
        $ver = Get-SCProp $bios 'SMBIOSBIOSVersion'
        if (-not $ver) { $ver = Get-SCProp $bios 'Version' }
        $facts.BiosVersion = Format-SCShortText -Text ([string]$ver) -Max 80
        if ($facts.Kind -eq 'other' -or $facts.Kind -eq 'unavailable') { $facts.Kind = 'ok' }
    } catch {
        $msg = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        $kind = Get-SCCloudQueryKind -Message $msg
        if ($kind -eq 'denied') { $facts.Denied = $true }
        elseif (-not $saw -and $kind -eq 'unavailable') { $facts.Kind = 'unavailable' }
        elseif (-not $saw -and [string]::IsNullOrWhiteSpace($facts.Error)) { $facts.Error = $msg; $facts.Kind = 'other' }
    }
    $biosText = (([string]$facts.BiosManufacturer) + ' ' + ([string]$facts.BiosVersion)).Trim()
    $facts.Cue = Get-SCCloudCue -Manufacturer $facts.Manufacturer -Model $facts.Model -BiosText $biosText
    return $facts
}

function Invoke-SCCheckCloudAgents {
    Start-SCSection -Title 'Cloud guest agents'
    $vendors = Get-SCCloudVendors
    $names = Get-SCCloudServiceNames -Vendors $vendors
    $snap = Get-SCCloudServiceSnapshot -Names @($names.Items)
    if ($snap.MissingCmd) {
        $script:SCCloudCimMissingNoted = $true
        Write-SCWarn -Message 'Get-CimInstance is not available, so service state was not read from CIM.'
    } elseif ($snap.Unavailable) {
        Write-SCWarn -Message 'Service queries are not available on this host.'
    }
    if ($snap.Denied) {
        Write-SCNeedsAdmin -Detail 'Cloud guest-agent service state could not be read.'
    } elseif (-not [string]::IsNullOrWhiteSpace($snap.Error) -and -not $snap.Checked) {
        Write-SCWarn -Message ("Cloud guest-agent services could not be queried: {0}" -f (Format-SCShortText -Text $snap.Error -Max 160))
    }

    $roots = Get-SCCloudRoots
    $uninstall = Find-SCCloudUninstallEntries -Vendors $vendors
    if ($uninstall.Denied) {
        Write-SCNeedsAdmin -Detail 'Cloud guest-agent uninstall entries could not be read.'
    } elseif (-not [string]::IsNullOrWhiteSpace($uninstall.Error)) {
        Write-SCWarn -Message ("Cloud guest-agent uninstall entries could not be read: {0}" -f (Format-SCShortText -Text $uninstall.Error -Max 160))
    }
    if ($uninstall.Truncated) {
        Write-SCInfo -Message ("Uninstall registry scan stopped at {0} keys in one hive." -f $script:SCCloudUninstallCap)
    }

    $pathDenied = 0
    $pathErrors = 0
    foreach ($vendor in @($vendors.Items)) {
        $present = New-Object System.Collections.Generic.List[object]
        foreach ($svc in @($vendor.Services)) {
            if (-not $svc) { continue }
            $key = ([string]$svc.Name).ToLowerInvariant()
            if ($snap.Map.ContainsKey($key)) {
                [void]$present.Add((New-Object psobject -Property @{
                    Label     = [string]$svc.Label
                    Name      = [string]$svc.Name
                    State     = [string]$snap.Map[$key].State
                    StartMode = [string]$snap.Map[$key].StartMode
                }))
            }
        }

        $folders = New-Object System.Collections.Generic.List[object]
        foreach ($pair in @(
            @{ Kind = 'install'; Specs = @($vendor.InstallSpecs) },
            @{ Kind = 'config'; Specs = @($vendor.ConfigSpecs) }
        )) {
            foreach ($spec in @($pair.Specs)) {
                $path = Resolve-SCCloudSpec -Spec ([string]$spec) -Roots $roots
                if (-not $path) { continue }
                $state = Get-SCCloudPathState -Path $path
                if ($state.Denied) { $pathDenied++; continue }
                if (-not [string]::IsNullOrWhiteSpace($state.Error)) { $pathErrors++; continue }
                if (-not $state.Present) { continue }
                [void]$folders.Add((New-Object psobject -Property @{
                    Kind = [string]$pair.Kind
                    Path = $path
                }))
            }
        }

        $entries = @()
        if ($uninstall.Items) {
            $entries = @($uninstall.Items | Where-Object { $_ -and ([string]$_.Vendor -eq [string]$vendor.Name) })
        }

        $hasService = $present.Count -gt 0
        $hasFolder = $folders.Count -gt 0
        $hasEntry = @($entries).Count -gt 0
        if (-not $hasService -and -not $hasFolder -and -not $hasEntry) {
            if ($snap.Denied -or (-not $snap.Checked -and -not $snap.MissingCmd)) {
                Write-SCInfo -Message ("{0}: guest-agent service presence could not be confirmed." -f $vendor.Name)
            } else {
                Write-SCInfo -Message ("{0}: no guest-agent services, folders, or uninstall entries were found." -f $vendor.Name)
            }
            continue
        }

        foreach ($hit in @($present.ToArray())) {
            $who = [string]$hit.Label
            if ($hit.Label -ne $hit.Name) { $who = ("{0} ({1})" -f $hit.Label, $hit.Name) }
            Write-SCInfo -Message ("{0}: service {1} is present. State: {2}. StartMode: {3}." -f $vendor.Name, $who, $hit.State, $hit.StartMode)
        }
        $serviceKnownAbsent = ($snap.Checked -and -not $snap.Denied -and -not $hasService)
        foreach ($folder in @($folders.ToArray())) {
            $noun = 'Install folder'
            if ($folder.Kind -eq 'config') { $noun = 'Config folder' }
            if ($serviceKnownAbsent) {
                Write-SCReview -Message ("{0}: {1} exists and no guest-agent service was found: {2}" -f $vendor.Name, $noun.ToLowerInvariant(), $folder.Path)
            } else {
                Write-SCInfo -Message ("{0}: {1} exists: {2}" -f $vendor.Name, $noun.ToLowerInvariant(), $folder.Path)
            }
        }
        foreach ($entry in @($entries)) {
            $label = [string]$entry.Title
            if ($entry.Version) { $label = ("{0} {1}" -f $entry.Title, $entry.Version) }
            if ($serviceKnownAbsent) {
                Write-SCReview -Message ("{0}: uninstall entry exists and no guest-agent service was found: {1}" -f $vendor.Name, $label)
            } else {
                Write-SCInfo -Message ("{0}: uninstall entry: {1}" -f $vendor.Name, $label)
            }
        }
    }
    if ($pathDenied -gt 0) {
        Write-SCNeedsAdmin -Detail ("{0} cloud guest-agent folders could not be read." -f $pathDenied)
    }
    if ($pathErrors -gt 0) {
        Write-SCWarn -Message ("{0} cloud guest-agent folders could not be checked." -f $pathErrors)
    }
}

function Invoke-SCCheckCloudCues {
    Start-SCSection -Title 'Hypervisor cues'
    $facts = Get-SCCloudMachineFacts
    if ($facts.Kind -eq 'missing-cmd') {
        if ($script:SCCloudCimMissingNoted) {
            Write-SCInfo -Message 'Hypervisor cues were not read because CIM is not available.'
        } else {
            Write-SCWarn -Message 'Get-CimInstance is not available, so hypervisor cues were not read.'
        }
        return
    }
    if ($facts.Kind -eq 'unavailable') {
        Write-SCWarn -Message 'Hypervisor cues are not available on this host.'
        return
    }
    if ($facts.Denied -and [string]::IsNullOrWhiteSpace($facts.Manufacturer) -and [string]::IsNullOrWhiteSpace($facts.Model)) {
        Write-SCNeedsAdmin -Detail 'Hypervisor cues could not be read.'
        return
    }
    if ($facts.Kind -eq 'other' -and [string]::IsNullOrWhiteSpace($facts.Manufacturer) -and [string]::IsNullOrWhiteSpace($facts.Model)) {
        Write-SCWarn -Message ("Hypervisor cues could not be read: {0}" -f (Format-SCShortText -Text $facts.Error -Max 160))
        return
    }

    if ($facts.Manufacturer) { Write-SCInfo -Message ("Manufacturer: {0}." -f $facts.Manufacturer) }
    if ($facts.Model) { Write-SCInfo -Message ("Model: {0}." -f $facts.Model) }
    if ($facts.BiosManufacturer -and ($facts.BiosManufacturer -ne $facts.Manufacturer)) {
        Write-SCInfo -Message ("BIOS manufacturer: {0}." -f $facts.BiosManufacturer)
    }
    if ($facts.BiosVersion) { Write-SCInfo -Message ("BIOS version: {0}." -f $facts.BiosVersion) }
    if ($null -ne $facts.HypervisorPresent) {
        $hvText = 'No'
        if ($facts.HypervisorPresent) { $hvText = 'Yes' }
        Write-SCInfo -Message ("HypervisorPresent: {0}." -f $hvText)
    }
    if ($facts.Cue) { Write-SCInfo -Message ("Hypervisor cue: {0}." -f $facts.Cue) }
    if ($facts.Denied) {
        Write-SCNeedsAdmin -Detail 'One hypervisor cue could not be read.'
    }
    if (-not $facts.Manufacturer -and -not $facts.Model -and -not $facts.BiosVersion -and -not $facts.Cue -and $null -eq $facts.HypervisorPresent) {
        Write-SCInfo -Message 'No manufacturer or model was reported.'
    }
}

function Invoke-SCCloudCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Cloud'
Invoke-SCCloudCheck -Name 'Cloud guest agents' -Body { Invoke-SCCheckCloudAgents }
Invoke-SCCloudCheck -Name 'Hypervisor cues' -Body { Invoke-SCCheckCloudCues }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Cloud' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
