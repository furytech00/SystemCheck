#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only browser presence checks.

.DESCRIPTION
    Reports installed browsers, versions, and whether profile folders exist.
    Profile and extension checks are counts and folder names only.
    This module does not read session databases, decrypt stored data, or
    launch a browser. It is not part of the default runner.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\09_browser.ps1
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

function Join-SCWindowsPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return '' }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Join-SCAnyPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return '' }
    if ($Root.StartsWith('\\')) { return '' }
    # Windows drive paths and registry paths both use backslashes.
    # Join-Path treats HKLM: as a drive and throws on a non-Windows host.
    if ($Root.Contains('\') -or $Root -match '^[A-Za-z]:$') {
        return (Join-SCWindowsPath -Root $Root -Child $Child)
    }
    $piece = ([string]$Child) -replace '\\', '/'
    return (Join-Path -Path $Root -Child $piece)
}

function New-SCBrowserDef {
    param(
        [string]$Name,
        [string]$Kind,
        [string]$ExeName,
        [string[]]$UninstallKeys,
        [string[]]$InstallSpecs,
        [string]$ProfileSpec,
        [string]$ExtensionChild
    )
    return New-Object psobject -Property @{
        Name            = $Name
        Kind            = $Kind
        ExeName         = $ExeName
        UninstallKeys   = @($UninstallKeys)
        InstallSpecs    = @($InstallSpecs)
        ProfileSpec     = $ProfileSpec
        ExtensionChild  = $ExtensionChild
    }
}

function Get-SCBrowserDefinitions {
    $list = New-Object System.Collections.Generic.List[object]
    [void]$list.Add((New-SCBrowserDef -Name 'Microsoft Edge' -Kind 'chromium' -ExeName 'msedge.exe' -UninstallKeys @('Microsoft Edge') -InstallSpecs @(
        'ProgramFiles|Microsoft\Edge\Application\msedge.exe',
        'ProgramFilesX86|Microsoft\Edge\Application\msedge.exe'
    ) -ProfileSpec 'LocalAppData|Microsoft\Edge\User Data' -ExtensionChild 'Extensions'))
    [void]$list.Add((New-SCBrowserDef -Name 'Google Chrome' -Kind 'chromium' -ExeName 'chrome.exe' -UninstallKeys @('Google Chrome') -InstallSpecs @(
        'ProgramFiles|Google\Chrome\Application\chrome.exe',
        'ProgramFilesX86|Google\Chrome\Application\chrome.exe',
        'LocalAppData|Google\Chrome\Application\chrome.exe'
    ) -ProfileSpec 'LocalAppData|Google\Chrome\User Data' -ExtensionChild 'Extensions'))
    [void]$list.Add((New-SCBrowserDef -Name 'Mozilla Firefox' -Kind 'firefox' -ExeName 'firefox.exe' -UninstallKeys @('Mozilla Firefox') -InstallSpecs @(
        'ProgramFiles|Mozilla Firefox\firefox.exe',
        'ProgramFilesX86|Mozilla Firefox\firefox.exe'
    ) -ProfileSpec 'AppData|Mozilla\Firefox\Profiles' -ExtensionChild 'extensions'))
    [void]$list.Add((New-SCBrowserDef -Name 'Brave' -Kind 'chromium' -ExeName 'brave.exe' -UninstallKeys @('Brave') -InstallSpecs @(
        'ProgramFiles|BraveSoftware\Brave-Browser\Application\brave.exe',
        'ProgramFilesX86|BraveSoftware\Brave-Browser\Application\brave.exe',
        'LocalAppData|BraveSoftware\Brave-Browser\Application\brave.exe'
    ) -ProfileSpec 'LocalAppData|BraveSoftware\Brave-Browser\User Data' -ExtensionChild 'Extensions'))
    [void]$list.Add((New-SCBrowserDef -Name 'Opera' -Kind 'opera' -ExeName 'opera.exe' -UninstallKeys @('Opera Stable') -InstallSpecs @(
        'ProgramFiles|Opera\opera.exe',
        'LocalAppData|Programs\Opera\opera.exe'
    ) -ProfileSpec 'AppData|Opera Software\Opera Stable' -ExtensionChild ''))
    [void]$list.Add((New-SCBrowserDef -Name 'Opera GX' -Kind 'opera' -ExeName 'opera.exe' -UninstallKeys @('Opera GX Stable') -InstallSpecs @(
        'LocalAppData|Programs\Opera GX\opera.exe'
    ) -ProfileSpec 'AppData|Opera Software\Opera GX Stable' -ExtensionChild ''))
    [void]$list.Add((New-SCBrowserDef -Name 'Vivaldi' -Kind 'chromium' -ExeName 'vivaldi.exe' -UninstallKeys @('Vivaldi') -InstallSpecs @(
        'ProgramFiles|Vivaldi\Application\vivaldi.exe',
        'LocalAppData|Vivaldi\Application\vivaldi.exe'
    ) -ProfileSpec 'LocalAppData|Vivaldi\User Data' -ExtensionChild 'Extensions'))
    [void]$list.Add((New-SCBrowserDef -Name 'Chromium' -Kind 'chromium' -ExeName 'chrome.exe' -UninstallKeys @('Chromium') -InstallSpecs @(
        'ProgramFiles|Chromium\Application\chrome.exe',
        'LocalAppData|Chromium\Application\chrome.exe'
    ) -ProfileSpec 'LocalAppData|Chromium\User Data' -ExtensionChild 'Extensions'))
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Get-SCBrowserRoots {
    $profile = $env:USERPROFILE
    if (-not $profile) { $profile = $env:HOME }
    return New-Object psobject -Property @{
        ProgramFiles    = [string]$env:ProgramFiles
        ProgramFilesX86 = [string]${env:ProgramFiles(x86)}
        LocalAppData    = [string]$env:LOCALAPPDATA
        AppData         = [string]$env:APPDATA
        UserProfile     = [string]$profile
    }
}

function Resolve-SCRootedPath {
    param($Roots, [string]$Spec)
    if ([string]::IsNullOrWhiteSpace($Spec) -or -not $Roots) { return '' }
    $bar = $Spec.IndexOf('|')
    if ($bar -lt 1) { return '' }
    $rootName = $Spec.Substring(0, $bar)
    $child = $Spec.Substring($bar + 1)
    $root = ''
    $prop = $Roots.PSObject.Properties[$rootName]
    if ($prop -and $prop.Value) { $root = [string]$prop.Value }
    if (-not $root) { return '' }
    return (Join-SCAnyPath -Root $root -Child $child)
}

function Test-SCChromiumProfileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -eq 'Default') { return $true }
    if ($Name -eq 'Guest Profile') { return $true }
    if ($Name -eq 'System Profile') { return $true }
    if ($Name -match '^Profile \d+$') { return $true }
    return $false
}

function Select-SCProfileNames {
    param([string[]]$Names, [string]$Kind, [int]$Max = 8)
    $matched = New-Object System.Collections.Generic.List[string]
    foreach ($name in @($Names)) {
        if (-not $name) { continue }
        $keep = $false
        if ($Kind -eq 'firefox') { $keep = $true }
        elseif ($Kind -eq 'chromium') { $keep = Test-SCChromiumProfileName -Name $name }
        if (-not $keep) { continue }
        [void]$matched.Add([string]$name)
    }
    $shown = New-Object System.Collections.Generic.List[string]
    $limit = $matched.Count
    if ($limit -gt $Max) { $limit = $Max }
    for ($i = 0; $i -lt $limit; $i++) { [void]$shown.Add($matched[$i]) }
    return New-Object psobject -Property @{
        Shown = $shown.ToArray()
        Total = $matched.Count
    }
}

function Select-SCBrowserInstall {
    param(
        [string]$RegistryVersion,
        [string]$FileVersion,
        [string]$ExePath,
        [bool]$AppPathKey
    )
    $installed = $false
    if ($ExePath) { $installed = $true }
    elseif ($RegistryVersion) { $installed = $true }
    elseif ($AppPathKey) { $installed = $true }
    $version = ''
    if ($RegistryVersion) { $version = $RegistryVersion }
    elseif ($FileVersion) { $version = $FileVersion }
    return New-Object psobject -Property @{
        Installed = $installed
        Version   = $version
        ExePath   = [string]$ExePath
    }
}

function Test-SCLocalPath {
    param([string]$Path, [switch]$Leaf)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path.StartsWith('\\')) { return $false }
    try {
        if ($Leaf) { return [bool](Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop) }
        return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    } catch {
        return $false
    }
}

function Get-SCFileVersionText {
    param([string]$Path)
    if (-not (Test-SCLocalPath -Path $Path -Leaf)) { return '' }
    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($info -and $info.FileVersion) { return (Format-SCShortText -Text ([string]$info.FileVersion) -Max 40) }
        if ($info -and $info.ProductVersion) { return (Format-SCShortText -Text ([string]$info.ProductVersion) -Max 40) }
    } catch {
        return ''
    }
    return ''
}

function Get-SCUninstallVersion {
    param([string[]]$KeyNames)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $denied = $false
    foreach ($keyName in @($KeyNames)) {
        if (-not $keyName) { continue }
        foreach ($root in $roots) {
            $path = Join-SCAnyPath -Root $root -Child $keyName
            if (-not $path) { $path = ($root.TrimEnd('\') + '\' + $keyName) }
            $value = Get-SCRegistryValue -Path $path -Name 'DisplayVersion'
            if ($value.Error -and (Test-SCAccessDenied -Message $value.Error)) { $denied = $true }
            if ($value.Found -and $value.Value) {
                return New-Object psobject -Property @{
                    Version = (Format-SCShortText -Text ([string]$value.Value) -Max 40)
                    Denied  = $denied
                }
            }
        }
    }
    return New-Object psobject -Property @{
        Version = ''
        Denied  = $denied
    }
}

function Get-SCAppPathHit {
    param([string]$ExeName)
    $result = New-Object psobject -Property @{
        Present = $false
        ExePath = ''
        Denied  = $false
    }
    if ([string]::IsNullOrWhiteSpace($ExeName)) { return $result }
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
    )
    foreach ($root in $roots) {
        $path = $root.TrimEnd('\') + '\' + $ExeName
        $exists = $false
        try {
            $exists = Test-Path -LiteralPath $path -ErrorAction Stop
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) { $result.Denied = $true }
            continue
        }
        if (-not $exists) { continue }
        $result.Present = $true
        try {
            $item = Get-Item -LiteralPath $path -ErrorAction Stop
            $raw = $null
            if ($item -and ($item.PSObject.Methods['GetValue'])) {
                $raw = $item.GetValue('')
            }
            if ($raw) {
                $text = ([string]$raw).Trim().Trim('"')
                if ($text -and -not $text.StartsWith('\\') -and (Test-SCLocalPath -Path $text -Leaf)) {
                    $result.ExePath = $text
                }
            }
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) { $result.Denied = $true }
        }
        if ($result.ExePath) { break }
    }
    return $result
}

function Get-SCChildDirectoryNames {
    param([string]$Root, [int]$Max = 30)
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
            if ($name) { [void]$list.Add($name) }
        }
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    $result.Items = $list.ToArray()
    return $result
}

function Invoke-SCCheckBrowsers {
    Start-SCSection -Title 'Installed browsers'
    $defs = @()
    $defBag = Get-SCBrowserDefinitions
    if ($defBag.Items) { $defs = @($defBag.Items) }
    $roots = Get-SCBrowserRoots
    $found = 0
    $denied = $false
    foreach ($def in $defs) {
        if (-not $def) { continue }
        $exePath = ''
        if ($def.InstallSpecs) {
            foreach ($spec in @($def.InstallSpecs)) {
                $candidate = Resolve-SCRootedPath -Roots $roots -Spec ([string]$spec)
                if ($candidate -and (Test-SCLocalPath -Path $candidate -Leaf)) {
                    $exePath = $candidate
                    break
                }
            }
        }
        $uninstall = Get-SCUninstallVersion -KeyNames @($def.UninstallKeys)
        if ($uninstall.Denied) { $denied = $true }
        $app = Get-SCAppPathHit -ExeName ([string]$def.ExeName)
        if ($app.Denied) { $denied = $true }
        if (-not $exePath -and $app.ExePath) { $exePath = [string]$app.ExePath }
        $fileVersion = ''
        if ($exePath) { $fileVersion = Get-SCFileVersionText -Path $exePath }
        $install = Select-SCBrowserInstall -RegistryVersion ([string]$uninstall.Version) -FileVersion $fileVersion -ExePath $exePath -AppPathKey ([bool]$app.Present)
        if (-not $install.Installed) { continue }
        $found++
        $version = [string]$install.Version
        if (-not $version) { $version = 'version unavailable' }
        $where = [string]$install.ExePath
        if (-not $where) { $where = 'path unavailable' }
        Write-SCInfo -Message ("{0} | {1} | {2}" -f $def.Name, (Format-SCShortText -Text $version -Max 40), (Format-SCShortText -Text $where -Max 100))
    }
    if ($found -eq 0) {
        Write-SCInfo -Message 'No installed browsers were found from the fixed locations.'
    } else {
        Write-SCInfo -Message ("Installed browsers: {0}." -f $found)
    }
    if ($denied) {
        Write-SCNeedsAdmin -Detail 'Some browser registration keys could not be read.'
    }
}

function Invoke-SCCheckBrowserProfiles {
    Start-SCSection -Title 'Browser profiles'
    $defs = @()
    $defBag = Get-SCBrowserDefinitions
    if ($defBag.Items) { $defs = @($defBag.Items) }
    $roots = Get-SCBrowserRoots
    $present = 0
    $denied = 0
    $other = 0
    foreach ($def in $defs) {
        if (-not $def -or -not $def.ProfileSpec) { continue }
        $root = Resolve-SCRootedPath -Roots $roots -Spec ([string]$def.ProfileSpec)
        if (-not $root) { continue }
        if (-not (Test-SCLocalPath -Path $root)) { continue }
        $present++
        $installed = $false
        if ($def.InstallSpecs) {
            foreach ($spec in @($def.InstallSpecs)) {
                $candidate = Resolve-SCRootedPath -Roots $roots -Spec ([string]$spec)
                if ($candidate -and (Test-SCLocalPath -Path $candidate -Leaf)) { $installed = $true; break }
            }
        }
        if (-not $installed) {
            $app = Get-SCAppPathHit -ExeName ([string]$def.ExeName)
            if ($app.Present) { $installed = $true }
        }
        $level = 'INFO'
        $extra = 'Profile folder exists'
        if (-not $installed) {
            $level = 'REVIEW'
            $extra = 'Profile folder exists and the install was not found in the fixed locations'
        }
        Write-SCLevel -Level $level -Message ("{0}: {1}: {2}" -f $def.Name, $extra, (Format-SCShortText -Text $root -Max 120))
        if ($def.Kind -eq 'opera') { continue }
        $children = Get-SCChildDirectoryNames -Root $root -Max 30
        if ($children.Denied) { $denied++ }
        elseif ($children.Error) { $other++ }
        $names = @()
        if ($children.Items) { $names = @($children.Items) }
        $picked = Select-SCProfileNames -Names $names -Kind ([string]$def.Kind) -Max 8
        $shown = @()
        if ($picked.Shown) { $shown = @($picked.Shown) }
        $total = [int]$picked.Total
        if ($children.Truncated -and $total -ge 30) {
            Write-SCInfo -Message ("{0} profiles: 30 or more. Names: {1}." -f $def.Name, ($(if ($shown.Count -gt 0) { $shown -join ', ' } else { 'none matched' })))
        } elseif ($total -gt 0) {
            $nameText = 'none listed'
            if ($shown.Count -gt 0) { $nameText = $shown -join ', ' }
            $suffix = ''
            if ($total -gt $shown.Count) { $suffix = ' Additional names were omitted.' }
            Write-SCInfo -Message ("{0} profiles: {1}. Names: {2}.{3}" -f $def.Name, $total, $nameText, $suffix)
        }
        if ($def.ExtensionChild -and $shown.Count -gt 0) {
            $extCount = 0
            $extTruncated = $false
            $checked = 0
            foreach ($profileName in $shown) {
                if ($checked -ge 3) { break }
                $checked++
                $extRoot = Join-SCAnyPath -Root (Join-SCAnyPath -Root $root -Child $profileName) -Child ([string]$def.ExtensionChild)
                $ext = Get-SCChildDirectoryNames -Root $extRoot -Max 40
                if ($ext.Denied) { $denied++ }
                elseif ($ext.Error) { $other++ }
                if ($ext.Missing) { continue }
                $extHere = 0
                if ($ext.Items) { $extHere = @($ext.Items).Count }
                $extCount += $extHere
                if ($ext.Truncated) { $extTruncated = $true }
            }
            if ($extCount -gt 0 -or $extTruncated) {
                $label = [string]$extCount
                if ($extTruncated) { $label = ($label + ' or more') }
                Write-SCInfo -Message ("{0} extension folders: {1}. Extension contents were not read." -f $def.Name, $label)
            }
        }
    }
    if ($present -eq 0) {
        Write-SCInfo -Message 'No browser profile folders were found for this user.'
    }
    if ($denied -gt 0) {
        Write-SCNeedsAdmin -Detail ("{0} browser profile folders could not be listed." -f $denied)
    }
    if ($other -gt 0) {
        Write-SCWarn -Message ("{0} browser profile folders could not be listed." -f $other)
    }
}

function Invoke-SCBrowserCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Browser'
Invoke-SCBrowserCheck -Name 'Installed browsers' -Body { Invoke-SCCheckBrowsers }
Invoke-SCBrowserCheck -Name 'Browser profiles' -Body { Invoke-SCCheckBrowserProfiles }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Browser' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
