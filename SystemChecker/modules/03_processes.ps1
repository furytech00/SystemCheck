#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only process inventory.

.DESCRIPTION
    Reports running processes, vendors, privileged processes started from
    unusual paths, and a short ACL summary for those binaries.
    This module does not inject into a process, read process memory, or
    execute a binary it finds.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\03_processes.ps1
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

function Format-SCLimitedList {
    param($Items, [int]$Max = 4)
    $arr = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Items)) {
        if ($item) { [void]$arr.Add([string]$item) }
    }
    if ($arr.Count -eq 0) { return '' }
    if ($arr.Count -le $Max) { return ($arr.ToArray() -join ', ') }
    $shown = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Max; $i++) { [void]$shown.Add($arr[$i]) }
    $extra = $arr.Count - $Max
    return ('{0} (+{1})' -f ($shown.ToArray() -join ', '), $extra)
}

function Join-SCWindowsPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return $Child }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Test-SCUncPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path.StartsWith('\\?\')) { return $false }
    return $Path.StartsWith('\\')
}

function Expand-SCProcessImage {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $text = $Path.Trim()
    # Normalize NT and Win32 prefixes so a local path can be compared with
    # Program Files and Windows. Network paths stay network paths.
    if ($text.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $text = '\\' + $text.Substring(8)
    } elseif ($text.StartsWith('\\?\')) {
        $text = $text.Substring(4)
    } elseif ($text.StartsWith('\??\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $text = '\\' + $text.Substring(8)
    } elseif ($text.StartsWith('\??\')) {
        $text = $text.Substring(4)
    }
    if ($text.Length -ge 11 -and $text.Substring(0, 11).Equals('\SystemRoot', [StringComparison]::OrdinalIgnoreCase)) {
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
    return $text
}

function Test-SCPathUnderRoot {
    param([string]$Path, [string]$Root)
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
    $full = $Path.Trim()
    $base = $Root.Trim().TrimEnd('\').TrimEnd('/')
    if ($full.Length -lt $base.Length) { return $false }
    $head = $full.Substring(0, $base.Length)
    if (-not $head.Equals($base, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($full.Length -eq $base.Length) { return $true }
    $mark = $full[$base.Length]
    if ($mark -eq '\' -or $mark -eq '/') { return $true }
    return $false
}

function Get-SCStandardRoots {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('WINDIR', 'SystemRoot', 'ProgramFiles', 'ProgramW6432')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { [void]$list.Add($value) }
    }
    $x86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($x86) { [void]$list.Add($x86) }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Test-SCStandardInstallPath {
    param([string]$Path, [string[]]$Roots)
    foreach ($root in @($Roots)) {
        if (Test-SCPathUnderRoot -Path $Path -Root $root) { return $true }
    }
    return $false
}

function Test-SCMicrosoftBinary {
    param([string]$Path, [string]$Company, [string]$WindowsDir)
    if ($Company -and ($Company -match '(?i)microsoft')) { return $true }
    if ($Company -and $Company.Trim()) { return $false }
    if ($Path -and $WindowsDir) {
        if (Test-SCPathUnderRoot -Path $Path -Root $WindowsDir) { return $true }
    }
    return $false
}

function Test-SCQuietProcessName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $quiet = @('System', 'Idle', 'Registry', 'Memory Compression', 'Secure System')
    foreach ($item in $quiet) {
        if ($Name.Equals($item, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-SCPrivilegedOwner {
    param([string]$Owner)
    if ([string]::IsNullOrWhiteSpace($Owner)) { return $false }
    $leaf = $Owner.Trim()
    if ($leaf.Contains('\')) {
        $parts = $leaf.Split('\')
        $leaf = $parts[$parts.Length - 1]
    }
    $names = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'Administrator', 'Administrators')
    foreach ($name in $names) {
        if ($leaf.Equals($name, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-SCFileCompany {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (Test-SCUncPath -Path $Path) { return '' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return '' }
    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($info -and $info.CompanyName) { return [string]$info.CompanyName }
    } catch {
        return ''
    }
    return ''
}

function Get-SCCachedCompany {
    param($Cache, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $key = $Path.ToLowerInvariant()
    if ($Cache.ContainsKey($key)) { return [string]$Cache[$key] }
    $company = Get-SCFileCompany -Path $Path
    $Cache[$key] = $company
    return $company
}

function Get-SCParentPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (Test-SCUncPath -Path $Path) { return '' }
    $text = $Path.Trim().TrimEnd('\').TrimEnd('/')
    $slash = [Math]::Max($text.LastIndexOf('\'), $text.LastIndexOf('/'))
    if ($slash -le 0) { return '' }
    $parent = $text.Substring(0, $slash)
    if ($parent.EndsWith(':')) { return ($parent + '\') }
    return $parent
}

function New-SCProcessRow {
    param([string]$Name, [int]$ProcessId, [string]$Path, [string]$Owner)
    return New-Object psobject -Property @{
        Name      = $Name
        ProcessId = $ProcessId
        Path      = $Path
        Owner     = $Owner
    }
}

function Get-SCProcessPathValue {
    param($Process)
    $prop = $Process.PSObject.Properties['Path']
    if (-not $prop) { return '' }
    try {
        if ($prop.Value) { return [string]$prop.Value }
    } catch {
        return ''
    }
    return ''
}

function Get-SCProcessUserValue {
    param($Process)
    $prop = $Process.PSObject.Properties['UserName']
    if (-not $prop) { return '' }
    try {
        if ($prop.Value) { return [string]$prop.Value }
    } catch {
        return ''
    }
    return ''
}

function Get-SCProcessesFromCmdlet {
    param([switch]$WithOwner)
    $items = New-Object System.Collections.Generic.List[object]
    $errorText = $null
    try {
        $rows = @()
        if ($WithOwner) {
            $rows = @(Get-Process -IncludeUserName -ErrorAction Stop)
        } else {
            $rows = @(Get-Process -ErrorAction Stop)
        }
        foreach ($row in $rows) {
            if (-not $row) { continue }
            $name = [string]$row.ProcessName
            $procId = 0
            try { $procId = [int]$row.Id } catch { $procId = 0 }
            if (-not $name -or $procId -le 0) { continue }
            [void]$items.Add((New-SCProcessRow -Name $name -ProcessId $procId -Path (Get-SCProcessPathValue -Process $row) -Owner (Get-SCProcessUserValue -Process $row)))
        }
    } catch {
        $errorText = $_.Exception.Message
    }
    return New-Object psobject -Property @{
        Items = $items.ToArray()
        Error = $errorText
    }
}

function Get-SCProcessesFromCim {
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = 'CIM is not available.'
        }
    }
    try {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($row in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
            if (-not $row) { continue }
            $name = [string](Get-SCProp $row 'Name')
            $procId = 0
            try { $procId = [int](Get-SCProp $row 'ProcessId') } catch { $procId = 0 }
            if (-not $name -or $procId -le 0) { continue }
            $image = [string](Get-SCProp $row 'ExecutablePath')
            [void]$items.Add((New-SCProcessRow -Name $name -ProcessId $procId -Path $image -Owner ''))
        }
        return New-Object psobject -Property @{
            Items = $items.ToArray(); Source = 'cim'; Error = $null
        }
    } catch {
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = $_.Exception.Message
        }
    }
}

function Get-SCOwnerMap {
    $map = @{}
    $bag = Get-SCProcessesFromCmdlet -WithOwner
    if ($bag.Error) {
        return New-Object psobject -Property @{
            Map = $map; Error = [string]$bag.Error; Rows = @()
        }
    }
    foreach ($row in @($bag.Items)) {
        if (-not $row) { continue }
        $map[[string]$row.ProcessId] = [string]$row.Owner
    }
    return New-Object psobject -Property @{
        Map = $map; Error = $null; Rows = @($bag.Items)
    }
}

function Get-SCCimProcessOwner {
    param([int]$ProcessId)
    $result = New-Object psobject -Property @{
        Owner = ''; Denied = $false; Error = $null
    }
    if ($ProcessId -le 0) { return $result }
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        $result.Error = 'CIM is not available.'
        return $result
    }
    try {
        $filter = 'ProcessId={0}' -f $ProcessId
        $row = Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction Stop
        if (-not $row) { return $result }
        $method = Invoke-CimMethod -InputObject $row -MethodName GetOwner -ErrorAction Stop
        $code = $null
        if ($method) { $code = $method.ReturnValue }
        if ($code -eq 0) {
            $user = [string](Get-SCProp $method 'User')
            $domain = [string](Get-SCProp $method 'Domain')
            if ($domain -and $user) { $result.Owner = '{0}\{1}' -f $domain, $user }
            elseif ($user) { $result.Owner = $user }
        } elseif ($code -eq 2) {
            $result.Denied = $true
        } else {
            $result.Error = 'GetOwner returned {0}.' -f $code
        }
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    return $result
}

function Get-SCProcessSnapshot {
    $ownerBag = Get-SCOwnerMap
    $owners = $ownerBag.Map
    $includeDenied = $false
    if ($ownerBag.Error -and (Test-SCAccessDenied -Message $ownerBag.Error)) { $includeDenied = $true }

    $cim = Get-SCProcessesFromCim
    if ($cim.Source -eq 'cim') {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($row in @($cim.Items)) {
            if (-not $row) { continue }
            $owner = ''
            $key = [string]$row.ProcessId
            if ($owners.ContainsKey($key) -and $owners[$key]) { $owner = [string]$owners[$key] }
            [void]$items.Add((New-SCProcessRow -Name $row.Name -ProcessId $row.ProcessId -Path $row.Path -Owner $owner))
        }
        return New-Object psobject -Property @{
            Items = $items.ToArray(); Source = 'cim'; IncludeDenied = $includeDenied; Error = $null
        }
    }

    if ($ownerBag.Rows -and @($ownerBag.Rows).Count -gt 0 -and -not $ownerBag.Error) {
        return New-Object psobject -Property @{
            Items = @($ownerBag.Rows); Source = 'process'; IncludeDenied = $false; Error = $null
        }
    }

    $plain = Get-SCProcessesFromCmdlet
    if ($plain.Error -or -not $plain.Items -or @($plain.Items).Count -eq 0) {
        $message = [string]$plain.Error
        if (-not $message) { $message = [string]$cim.Error }
        if (-not $message) { $message = 'Process list could not be read.' }
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; IncludeDenied = $includeDenied; Error = $message
        }
    }
    return New-Object psobject -Property @{
        Items = @($plain.Items); Source = 'process'; IncludeDenied = $includeDenied; Error = $null
    }
}

function Format-SCProcessLabel {
    param([string]$Name, [int]$ProcessId)
    $label = $Name
    if (-not $label) { $label = 'process' }
    return ('{0} ({1})' -f $label, $ProcessId)
}

function Invoke-SCCheckProcesses {
    Start-SCSection -Title 'Processes'
    $snap = Get-SCProcessSnapshot
    if ($snap.Source -eq 'none') {
        $message = [string]$snap.Error
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'Process list could not be read.'
        } else {
            Write-SCWarn -Message ("Process list could not be read: {0}" -f (Format-SCShortText -Text $message -Max 160))
        }
        return
    }

    $windows = $env:WINDIR
    if (-not $windows) { $windows = $env:SystemRoot }
    $rootsBag = Get-SCStandardRoots
    $roots = @()
    if ($rootsBag -and $rootsBag.Items) { $roots = @($rootsBag.Items) }
    $companyCache = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    $noPath = 0
    $microsoft = 0
    $nonMicrosoft = 0
    $ownerDenied = 0
    if ($snap.IncludeDenied) { $ownerDenied = 1 }

    foreach ($item in @($snap.Items)) {
        if (-not $item) { continue }
        $image = Expand-SCProcessImage -Path ([string]$item.Path)
        $unc = Test-SCUncPath -Path $image
        $company = ''
        if ($image -and -not $unc) { $company = Get-SCCachedCompany -Cache $companyCache -Path $image }
        $isMicrosoft = $false
        if (-not $image) {
            $noPath++
            if (Test-SCQuietProcessName -Name $item.Name) { $isMicrosoft = $true }
        } elseif ($unc) {
            $isMicrosoft = $false
        } else {
            $isMicrosoft = Test-SCMicrosoftBinary -Path $image -Company $company -WindowsDir $windows
        }
        $standard = $false
        if ($image -and -not $unc) { $standard = Test-SCStandardInstallPath -Path $image -Roots $roots }
        $unusual = ($image -and -not $unc -and -not $standard)
        $owner = [string]$item.Owner
        $privileged = Test-SCPrivilegedOwner -Owner $owner
        if ((-not $owner) -and ($unusual -or -not $isMicrosoft) -and $image -and ($snap.Source -eq 'cim')) {
            $looked = Get-SCCimProcessOwner -ProcessId ([int]$item.ProcessId)
            if ($looked.Owner) { $owner = [string]$looked.Owner }
            if ($looked.Denied) { $ownerDenied++ }
            $privileged = Test-SCPrivilegedOwner -Owner $owner
        }
        if ($isMicrosoft) { $microsoft++ } else { $nonMicrosoft++ }
        [void]$rows.Add((New-Object psobject -Property @{
            Name         = [string]$item.Name
            ProcessId    = [int]$item.ProcessId
            Path         = $image
            Owner        = $owner
            Company      = $company
            Microsoft    = $isMicrosoft
            Unusual      = $unusual
            Unc          = $unc
            Privileged   = $privileged
            Quiet        = (Test-SCQuietProcessName -Name $item.Name)
        }))
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $infoRows = New-Object System.Collections.Generic.List[object]
    $aclTargets = New-Object System.Collections.Generic.List[object]
    $seenAcl = @{}

    foreach ($row in $rows) {
        $highlight = $false
        if ($row.Unc) {
            [void]$findings.Add((New-Object psobject -Property @{
                Level = 'REVIEW'
                Text  = ("Process '{0}' image is a network path: {1}" -f (Format-SCProcessLabel -Name $row.Name -ProcessId $row.ProcessId), (Format-SCShortText -Text $row.Path -Max 120))
            }))
            $highlight = $true
        } elseif ($row.Privileged -and $row.Unusual) {
            $ownerText = $row.Owner
            if (-not $ownerText) { $ownerText = 'privileged account' }
            [void]$findings.Add((New-Object psobject -Property @{
                Level = 'REVIEW'
                Text  = ("Process '{0}' runs as {1} from an unusual path: {2}" -f (Format-SCProcessLabel -Name $row.Name -ProcessId $row.ProcessId), (Format-SCShortText -Text $ownerText -Max 60), (Format-SCShortText -Text $row.Path -Max 120))
            }))
            $highlight = $true
        }
        if ($highlight -and $row.Path -and -not $row.Unc) {
            $key = $row.Path.ToLowerInvariant()
            if (-not $seenAcl.ContainsKey($key)) {
                $seenAcl[$key] = $true
                [void]$aclTargets.Add($row)
            }
        }
        if ((-not $row.Microsoft) -and (-not $highlight)) {
            $rank = 1
            if ($row.Unusual) { $rank = 0 }
            [void]$infoRows.Add((New-Object psobject -Property @{
                Rank = $rank
                Name = $row.Name
                Row  = $row
            }))
        }
    }

    Write-SCInfo -Message ("Processes: {0} total. Microsoft: {1}. Non-Microsoft: {2}. No image path: {3}." -f $rows.Count, $microsoft, $nonMicrosoft, $noPath)

    $shownFindings = 0
    $hiddenFindings = 0
    foreach ($finding in $findings) {
        if ($shownFindings -ge 25) { $hiddenFindings++; continue }
        $shownFindings++
        Write-SCLevel -Level $finding.Level -Message $finding.Text
    }

    $ordered = @($infoRows.ToArray() | Sort-Object -Property Rank, Name)
    $shownInfo = 0
    $hiddenInfo = 0
    $seenInfo = @{}
    $displayRows = New-Object System.Collections.Generic.List[object]
    foreach ($info in $ordered) {
        if (-not $info -or -not $info.Row) { continue }
        $row = $info.Row
        $pathKey = ''
        if ($row.Path) { $pathKey = $row.Path.ToLowerInvariant() }
        if ($pathKey -and $seenInfo.ContainsKey($pathKey) -and $shownInfo -ge 8) { $hiddenInfo++; continue }
        if ($shownInfo -ge 15) { $hiddenInfo++; continue }
        $shownInfo++
        if ($pathKey) { $seenInfo[$pathKey] = $true }
        [void]$displayRows.Add($row)
        if ($pathKey -and -not $seenAcl.ContainsKey($pathKey)) {
            $seenAcl[$pathKey] = $true
            [void]$aclTargets.Add($row)
        }
    }
    foreach ($info in $displayRows) {
        $row = $info
        $ownerText = [string]$row.Owner
        if (-not $ownerText) { $ownerText = 'owner unavailable' }
        $company = [string]$row.Company
        if (-not $company) { $company = 'company unknown' }
        $pathText = Format-SCShortText -Text ([string]$row.Path) -Max 80
        if (-not $pathText) { $pathText = 'path unavailable' }
        Write-SCInfo -Message ("Non-Microsoft: {0} | {1} | {2} | {3} | {4}" -f $row.Name, $row.ProcessId, (Format-SCShortText -Text $ownerText -Max 40), $pathText, (Format-SCShortText -Text $company -Max 40))
    }
    if ($hiddenInfo -gt 0) {
        Write-SCInfo -Message ("{0} additional non-Microsoft processes were omitted." -f $hiddenInfo)
    }

    $aclDenied = 0
    $aclOther = 0
    $aclChecked = 0
    $aclSeenPath = @{}
    $aclAvailable = [bool](Get-Command -Name Get-Acl -ErrorAction SilentlyContinue)
    if (-not $aclAvailable -and $aclTargets.Count -gt 0) {
        Write-SCWarn -Message 'ACL summary is not available on this host.'
    }
    if ($aclAvailable) {
        foreach ($target in $aclTargets) {
            if ($aclChecked -ge 40) { break }
            $aclChecked++
            $paths = New-Object System.Collections.Generic.List[string]
            [void]$paths.Add([string]$target.Path)
            $parent = Get-SCParentPath -Path ([string]$target.Path)
            if ($parent) { [void]$paths.Add($parent) }
            $index = 0
            foreach ($path in $paths) {
                $kind = 'binary'
                if ($index -gt 0) { $kind = 'directory' }
                $index++
                $pathKey = $path.ToLowerInvariant()
                if ($aclSeenPath.ContainsKey($pathKey)) { continue }
                $aclSeenPath[$pathKey] = $true
                $summary = Get-SCAclSummary -Path $path
                $err = ''
                if ($summary -and $summary.Error) { $err = [string]$summary.Error }
                if ($err) {
                    if ($err -eq 'Path not found.') { continue }
                    if ($err -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $err)) { $aclDenied++ }
                    else { $aclOther++ }
                    continue
                }
                $owner = ''
                if ($summary) { $owner = [string]$summary.Owner }
                if (-not $owner) { $owner = 'unknown' }
                $broadList = @()
                $writeList = @()
                if ($summary -and $summary.BroadWritePrincipals) { $broadList = @($summary.BroadWritePrincipals) }
                if ($summary -and $summary.NonAdminWritePrincipals) { $writeList = @($summary.NonAdminWritePrincipals) }
                $broad = ($broadList.Count -gt 0)
                $writable = ($writeList.Count -gt 0)
                $who = ''
                if ($broad) { $who = Format-SCLimitedList -Items $broadList -Max 3 }
                elseif ($writable) { $who = Format-SCLimitedList -Items $writeList -Max 3 }
                $label = Format-SCProcessLabel -Name $target.Name -ProcessId $target.ProcessId
                if ($broad) {
                    if ($shownFindings -ge 25) { $hiddenFindings++; continue }
                    $shownFindings++
                    Write-SCWeak -Message ("{0} {1} is writable by a broad principal: {2} ({3}). Owner: {4}." -f $label, $kind, (Format-SCShortText -Text $path -Max 100), $who, $owner)
                } elseif ($writable) {
                    if ($shownFindings -ge 25) { $hiddenFindings++; continue }
                    $shownFindings++
                    Write-SCReview -Message ("{0} {1} is writable by a non-admin principal: {2} ({3}). Owner: {4}." -f $label, $kind, (Format-SCShortText -Text $path -Max 100), $who, $owner)
                } elseif ($kind -eq 'binary') {
                    Write-SCInfo -Message ("ACL {0} | owner {1} | non-admin write: none" -f (Format-SCShortText -Text $path -Max 100), $owner)
                }
            }
        }
    }
    if ($hiddenFindings -gt 0) {
        Write-SCInfo -Message ("{0} additional findings were omitted." -f $hiddenFindings)
    }
    if ($ownerDenied -gt 0) {
        Write-SCNeedsAdmin -Detail 'Process owners could not be read.'
    }
    if ($aclDenied -gt 0) {
        Write-SCNeedsAdmin -Detail ("Binary or folder ACLs could not be read for {0} paths." -f $aclDenied)
    }
    if ($aclOther -gt 0) {
        Write-SCWarn -Message ("{0} binary or folder ACLs could not be read." -f $aclOther)
    }
}

function Invoke-SCProcessCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Processes'
Invoke-SCProcessCheck -Name 'Processes' -Body { Invoke-SCCheckProcesses }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Processes' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
