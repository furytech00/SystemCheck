#Requires -Version 5.1
<#
.SYNOPSIS
    Bounded, read-only file and folder hygiene checks.

.DESCRIPTION
    Checks a short fixed list of well-known folders for non-admin write
    access, plus one level of ProgramData children. Looks for a few
    sensitive file names in shallow folders only. This module does not
    read file contents, change ACLs, or search the whole disk.
    It is not part of the default runner.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\08_files.ps1
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
    param([string]$Text, [int]$Max = 120)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ([string]$Text -replace '[\r\n]+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max)
}

function Format-SCLimitedList {
    param($Items, [int]$Max = 3)
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

function Join-SCAnyPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return '' }
    if ($Root.StartsWith('\\')) { return '' }
    if ($Root -match '^[A-Za-z]:') {
        return (Join-SCWindowsPath -Root $Root -Child $Child)
    }
    $piece = ([string]$Child) -replace '\\', '/'
    return (Join-Path -Path $Root -Child $piece)
}

function Get-SCDriveRoot {
    param([string]$Drive)
    if ([string]::IsNullOrWhiteSpace($Drive)) { return '' }
    $text = $Drive.Trim().TrimEnd('\')
    if ($text -match '^[A-Za-z]:$') { return ($text + '\') }
    if ($text.StartsWith('\\')) { return '' }
    return $text
}

function Add-SCUniquePath {
    param($List, $Seen, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if ($Path.StartsWith('\\')) { return }
    $key = $Path.Trim().ToLowerInvariant()
    if ($Seen.ContainsKey($key)) { return }
    $Seen[$key] = $true
    [void]$List.Add($Path.Trim())
}

function Get-SCKnownFolder {
    param([string]$Name)
    try {
        return [string][Environment]::GetFolderPath($Name)
    } catch {
        return ''
    }
}

function Get-SCHygienePaths {
    param(
        [string]$ProgramFiles,
        [string]$ProgramFilesX86,
        [string]$ProgramData,
        [string]$WindowsDir,
        [string]$SystemDrive,
        [string]$Temp,
        [string]$UserProfile,
        [string]$Desktop,
        [string]$Documents,
        [string]$AppData,
        [string]$PublicDesktop
    )
    $paths = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($path in @(
        $ProgramFiles, $ProgramFilesX86, $ProgramData, $WindowsDir, $Temp, $UserProfile, $Desktop, $Documents, $PublicDesktop
    )) {
        Add-SCUniquePath -List $paths -Seen $seen -Path $path
    }
    $drive = Get-SCDriveRoot -Drive $SystemDrive
    Add-SCUniquePath -List $paths -Seen $seen -Path $drive
    if ($WindowsDir) {
        Add-SCUniquePath -List $paths -Seen $seen -Path (Join-SCAnyPath -Root $WindowsDir -Child 'Temp')
    }
    if ($UserProfile) {
        Add-SCUniquePath -List $paths -Seen $seen -Path (Join-SCAnyPath -Root $UserProfile -Child 'Downloads')
    }
    $startup = 'Microsoft\Windows\Start Menu\Programs\Startup'
    if ($ProgramData) {
        Add-SCUniquePath -List $paths -Seen $seen -Path (Join-SCAnyPath -Root $ProgramData -Child $startup)
    }
    if ($AppData) {
        Add-SCUniquePath -List $paths -Seen $seen -Path (Join-SCAnyPath -Root $AppData -Child $startup)
    }

    $search = New-Object System.Collections.Generic.List[string]
    $searchSeen = @{}
    foreach ($path in @($drive, $UserProfile, $Desktop, $Documents)) {
        Add-SCUniquePath -List $search -Seen $searchSeen -Path $path
    }
    if ($UserProfile) {
        Add-SCUniquePath -List $search -Seen $searchSeen -Path (Join-SCAnyPath -Root $UserProfile -Child 'Downloads')
    }
    return New-Object psobject -Property @{
        Items  = $paths.ToArray()
        Search = $search.ToArray()
    }
}

function Test-SCSensitiveFileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $leaf = $Name.Trim()
    if ($leaf -match '(?i)password|unattend') { return $true }
    if ($leaf -match '(?i)\.kdbx$') { return $true }
    if ($leaf -match '(?i)\.ppk$') { return $true }
    if ($leaf -match '(?i)^id_(rsa|dsa|ecdsa)($|\.)') { return $true }
    return $false
}

function Format-SCWriteFinding {
    param(
        [string]$Path,
        [string]$Owner,
        [bool]$Broad,
        [bool]$Writable,
        $BroadPrincipals,
        $Principals
    )
    if (-not $Writable) { return $null }
    $who = ''
    $level = 'REVIEW'
    $kind = 'a non-admin principal'
    if ($Broad) {
        $level = 'WEAK'
        $kind = 'a broad principal'
        $who = Format-SCLimitedList -Items $BroadPrincipals -Max 3
    } else {
        $who = Format-SCLimitedList -Items $Principals -Max 3
    }
    if (-not $who) { $who = 'name unavailable' }
    if (-not $Owner) { $Owner = 'unknown' }
    $text = '{0} is writable by {1}: {2}. Owner: {3}.' -f (Format-SCShortText -Text $Path -Max 140), $kind, $who, (Format-SCShortText -Text $Owner -Max 60)
    return New-Object psobject -Property @{
        Level = $level
        Text  = $text
    }
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

function Get-SCChildDirectories {
    param([string]$Root, [int]$Max = 20)
    $result = New-Object psobject -Property @{
        Items     = @()
        Missing   = $false
        Denied    = $false
        Error     = $null
        Truncated = $false
    }
    if (-not (Test-SCLocalPath -Path $Root)) {
        $result.Missing = $true
        return $result
    }
    $list = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($child in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop)) {
            if (-not $child) { continue }
            if ($list.Count -ge $Max) {
                $result.Truncated = $true
                break
            }
            $name = [string]$child.Name
            if (-not $name) { continue }
            $full = Join-SCAnyPath -Root $Root -Child $name
            if ($full) { [void]$list.Add($full) }
        }
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    $result.Items = $list.ToArray()
    return $result
}

function Find-SCShallowSensitiveNames {
    param([string]$Directory, [int]$MaxScan = 200)
    $result = New-Object psobject -Property @{
        Items     = @()
        Scanned   = 0
        Missing   = $false
        Denied    = $false
        Error     = $null
        Truncated = $false
    }
    if (-not (Test-SCLocalPath -Path $Directory)) {
        $result.Missing = $true
        return $result
    }
    $list = New-Object System.Collections.Generic.List[string]
    $scanned = 0
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop)) {
            if (-not $file) { continue }
            if ($scanned -ge $MaxScan) {
                $result.Truncated = $true
                break
            }
            $scanned++
            $name = [string]$file.Name
            if (-not (Test-SCSensitiveFileName -Name $name)) { continue }
            $full = Join-SCAnyPath -Root $Directory -Child $name
            if ($full) { [void]$list.Add($full) }
        }
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    $result.Scanned = $scanned
    $result.Items = $list.ToArray()
    return $result
}

function Get-SCPathAclState {
    param([string]$Path)
    $summary = Get-SCAclSummary -Path $Path
    $state = New-Object psobject -Property @{
        Owner     = ''
        Broad     = $false
        Writable  = $false
        BroadPrincipals = @()
        Principals = @()
        Error     = $null
        Missing   = $false
    }
    if ($summary -and $summary.Error) {
        $state.Error = [string]$summary.Error
        if ($state.Error -eq 'Path not found.') { $state.Missing = $true }
        return $state
    }
    if ($summary -and $summary.Owner) { $state.Owner = [string]$summary.Owner }
    $write = Test-SCWritableByNonAdmin -Path $Path
    if ($write -and $write.Error) {
        $state.Error = [string]$write.Error
        if ($state.Error -eq 'Path not found.') { $state.Missing = $true }
        return $state
    }
    if ($write) {
        $state.Broad = [bool]$write.BroadWritable
        $state.Writable = [bool]$write.Writable
        if ($write.BroadPrincipals) { $state.BroadPrincipals = @($write.BroadPrincipals) }
        if ($write.Principals) { $state.Principals = @($write.Principals) }
    }
    return $state
}

function Invoke-SCCheckWritablePaths {
    Start-SCSection -Title 'Writable locations'
    if (-not (Get-Command -Name Get-Acl -ErrorAction SilentlyContinue)) {
        Write-SCWarn -Message 'ACL summary is not available on this host.'
        return
    }
    $bag = Get-SCHygienePaths -ProgramFiles $env:ProgramFiles -ProgramFilesX86 ${env:ProgramFiles(x86)} -ProgramData $env:ProgramData -WindowsDir $env:WINDIR -SystemDrive $env:SystemDrive -Temp $env:TEMP -UserProfile $(if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }) -Desktop (Get-SCKnownFolder -Name 'Desktop') -Documents (Get-SCKnownFolder -Name 'MyDocuments') -AppData $env:APPDATA -PublicDesktop $(if ($env:PUBLIC) { (Join-SCAnyPath -Root $env:PUBLIC -Child 'Desktop') } else { '' })
    $paths = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    if ($bag.Items) {
        foreach ($path in @($bag.Items)) {
            Add-SCUniquePath -List $paths -Seen $seen -Path $path
        }
    }
    $programData = $env:ProgramData
    $childNote = $false
    if ($programData -and (Test-SCLocalPath -Path $programData)) {
        $children = Get-SCChildDirectories -Root $programData -Max 20
        if ($children.Denied) {
            Write-SCNeedsAdmin -Detail 'ProgramData children could not be listed.'
        } elseif ($children.Error) {
            Write-SCWarn -Message ("ProgramData children could not be listed: {0}" -f (Format-SCShortText -Text $children.Error -Max 160))
        }
        if ($children.Truncated) { $childNote = $true }
        if ($children.Items) {
            foreach ($path in @($children.Items)) {
                Add-SCUniquePath -List $paths -Seen $seen -Path $path
            }
        }
    }

    $checked = 0
    $missing = 0
    $denied = 0
    $other = 0
    $writable = 0
    $shown = 0
    $hidden = 0
    foreach ($path in $paths) {
        if (-not (Test-SCLocalPath -Path $path)) { $missing++; continue }
        $checked++
        $state = Get-SCPathAclState -Path $path
        if ($state.Missing) { $missing++; continue }
        if ($state.Error) {
            if ($state.Error -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $state.Error)) { $denied++ }
            else { $other++ }
            continue
        }
        if (-not $state.Writable) { continue }
        $writable++
        if ($shown -ge 15) { $hidden++; continue }
        $finding = Format-SCWriteFinding -Path $path -Owner $state.Owner -Broad $state.Broad -Writable $true -BroadPrincipals $state.BroadPrincipals -Principals $state.Principals
        if (-not $finding) { continue }
        $shown++
        Write-SCLevel -Level $finding.Level -Message $finding.Text
    }
    Write-SCInfo -Message ("Checked {0} paths. Non-admin writable: {1}. Missing: {2}." -f $checked, $writable, $missing)
    if ($childNote) {
        Write-SCInfo -Message 'ProgramData child scan stopped after 20 directories.'
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional writable paths were omitted." -f $hidden)
    }
    if ($denied -gt 0) {
        Write-SCNeedsAdmin -Detail ("Folder ACLs could not be read for {0} paths." -f $denied)
    }
    if ($other -gt 0) {
        Write-SCWarn -Message ("{0} folder ACLs could not be read." -f $other)
    }
}

function Invoke-SCCheckSensitiveNames {
    Start-SCSection -Title 'Shallow file names'
    $profile = $env:USERPROFILE
    if (-not $profile) { $profile = $env:HOME }
    $bag = Get-SCHygienePaths -ProgramFiles '' -ProgramFilesX86 '' -ProgramData '' -WindowsDir '' -SystemDrive $env:SystemDrive -Temp '' -UserProfile $profile -Desktop (Get-SCKnownFolder -Name 'Desktop') -Documents (Get-SCKnownFolder -Name 'MyDocuments') -AppData '' -PublicDesktop ''
    $dirs = @()
    if ($bag.Search) { $dirs = @($bag.Search) }
    $matches = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $scanned = 0
    $folders = 0
    $denied = 0
    $other = 0
    $truncated = 0
    foreach ($dir in $dirs) {
        if (-not $dir) { continue }
        $folders++
        $found = Find-SCShallowSensitiveNames -Directory $dir -MaxScan 200
        $scanned += [int]$found.Scanned
        if ($found.Truncated) { $truncated++ }
        if ($found.Denied) { $denied++ }
        elseif ($found.Error) { $other++ }
        if (-not $found.Items) { continue }
        foreach ($path in @($found.Items)) {
            if (-not $path) { continue }
            $key = $path.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            [void]$matches.Add($path)
        }
    }
    $shown = 0
    foreach ($path in $matches) {
        if ($shown -ge 15) { break }
        $shown++
        Write-SCReview -Message ("Sensitive file name exists: {0}. Contents were not read." -f (Format-SCShortText -Text $path -Max 140))
    }
    $hidden = 0
    if ($matches.Count -gt $shown) { $hidden = $matches.Count - $shown }
    if ($matches.Count -eq 0 -and $denied -eq 0 -and $other -eq 0) {
        Write-SCInfo -Message 'No sensitive file names were found in the shallow folders.'
    }
    Write-SCInfo -Message ("Shallow name scan: {0} folders, {1} files, {2} matches. Depth is one folder. Cap is 200 files per folder." -f $folders, $scanned, $matches.Count)
    if ($truncated -gt 0) {
        Write-SCInfo -Message ("{0} folders were stopped at the 200-file cap." -f $truncated)
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional sensitive file names were omitted." -f $hidden)
    }
    if ($denied -gt 0) {
        Write-SCNeedsAdmin -Detail ("{0} shallow folders could not be listed." -f $denied)
    }
    if ($other -gt 0) {
        Write-SCWarn -Message ("{0} shallow folders could not be listed." -f $other)
    }
}

function Invoke-SCFileCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Files'
Invoke-SCFileCheck -Name 'Writable locations' -Body { Invoke-SCCheckWritablePaths }
Invoke-SCFileCheck -Name 'Shallow file names' -Body { Invoke-SCCheckSensitiveNames }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Files' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
