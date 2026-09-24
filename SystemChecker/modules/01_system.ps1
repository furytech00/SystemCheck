#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only operating system configuration checks.

.DESCRIPTION
    Reports identity, servicing posture, UAC, installer policy, LSA settings,
    PowerShell logging, antivirus registration, and application-control presence.
    Lifecycle text is informational. It is not an exploit map.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\01_system.ps1

    Pattern for later modules:
      Start-SCSection opens a group. Write-SCInfo / Write-SCReview / Write-SCWeak
      record findings. The next Start-SCSection closes the previous group.
      Complete-SCSection closes the last one. Empty groups print "Nothing notable".
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

function Format-SCUptime {
    param($TimeSpan)
    if ($null -eq $TimeSpan) { return 'unknown' }
    try {
        $span = [timespan]$TimeSpan
        return ('{0}d {1}h {2}m' -f $span.Days, $span.Hours, $span.Minutes)
    } catch {
        return 'unknown'
    }
}

function Get-SCDomainRoleLabel {
    param($Role)
    if ($null -eq $Role) { return 'unknown' }
    switch ([int]$Role) {
        0 { return 'standalone workstation' }
        1 { return 'domain member workstation' }
        2 { return 'standalone server' }
        3 { return 'domain member server' }
        4 { return 'backup domain controller' }
        5 { return 'primary domain controller' }
        default { return ("code {0}" -f $Role) }
    }
}

function Write-SCRegistryProblem {
    param($Result, [string]$Label)
    if (-not $Result -or -not $Result.Error) { return $false }
    if ($Result.Error -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $Result.Error)) {
        Write-SCNeedsAdmin -Detail ("{0} could not be read" -f $Label)
    } else {
        Write-SCWarn -Message ("{0} could not be read: {1}" -f $Label, $Result.Error)
    }
    return $true
}

function Get-SCConsentAdminLabel {
    param($Value)
    switch ([string]$Value) {
        '0' { return 'elevate without prompting' }
        '1' { return 'prompt for credentials on the secure desktop' }
        '2' { return 'prompt for consent on the secure desktop' }
        '3' { return 'prompt for credentials' }
        '4' { return 'prompt for consent' }
        '5' { return 'prompt for consent for non-Windows binaries' }
        default { return 'unrecognized value' }
    }
}

function Get-SCServicingNote {
    # Lifecycle wording only. Do not extend this into CVE or exploit guidance.
    param($Caption, $Build)
    $text = [string]$Caption
    $buildNum = 0
    [void][int]::TryParse([string]$Build, [ref]$buildNum)
    $suffix = ' This check does not map builds to exploits.'

    if ($text -match 'Windows 7') {
        return @{
            Level = 'REVIEW'
            Text  = ('Windows 7 is past its published end of support (2020-01-14). Plan an upgrade.{0}' -f $suffix)
        }
    }
    if ($text -match 'Windows 8') {
        return @{
            Level = 'REVIEW'
            Text  = ('Windows 8 or 8.1 is past its published end of support (Windows 8: 2016-01-12, Windows 8.1: 2023-01-10). Plan an upgrade.{0}' -f $suffix)
        }
    }
    if ($text -match 'Server 2012') {
        return @{
            Level = 'REVIEW'
            Text  = ('Windows Server 2012 or 2012 R2 is past its published end of support (2023-10-10). Plan an upgrade.{0}' -f $suffix)
        }
    }
    if ($text -match 'Windows 10') {
        if ($text -match 'LTSC|LTSB') {
            return @{
                Level = 'REVIEW'
                Text  = ('Windows 10 LTSC or LTSB was detected. Confirm that edition on the Microsoft lifecycle page.{0}' -f $suffix)
            }
        }
        if ($buildNum -eq 19045) {
            return @{
                Level = 'REVIEW'
                Text  = ('Windows 10 22H2 (build 19045) reached end of support on 2025-10-14.{0}' -f $suffix)
            }
        }
        if ($buildNum -gt 0 -and $buildNum -lt 19045) {
            return @{
                Level = 'REVIEW'
                Text  = ('This Windows 10 build is older than 22H2. Releases before 22H2 are past consumer support. LTSC dates differ, so confirm the edition.{0}' -f $suffix)
            }
        }
    }
    if ($text -match 'Windows 11') {
        if ($buildNum -eq 22000) {
            return @{
                Level = 'REVIEW'
                Text  = ('Windows 11 21H2 (build 22000) reached end of support on 2023-10-10.{0}' -f $suffix)
            }
        }
        if ($buildNum -ge 22621 -and $buildNum -lt 22631) {
            return @{
                Level = 'REVIEW'
                Text  = ('Windows 11 22H2 Home and Pro reached end of support on 2024-10-08. Enterprise and Education dates differ. Confirm the edition.{0}' -f $suffix)
            }
        }
        if ($buildNum -ge 22631 -and $buildNum -lt 26100) {
            return @{
                Level = 'REVIEW'
                Text  = ('Windows 11 23H2 consumer support ended on 2025-11-11. Enterprise and Education dates differ.{0}' -f $suffix)
            }
        }
    }

    $shown = $Build
    if (-not $shown) { $shown = 'unknown' }
    return @{
        Level = 'INFO'
        Text  = ('Compare build {0} with the current Microsoft lifecycle and cumulative update.{1}' -f $shown, $suffix)
    }
}

function Get-SCDotNetReleaseName {
    param($Release)
    $key = 0
    if (-not [int]::TryParse([string]$Release, [ref]$key)) { return $null }
    # Values published by Microsoft for the v4 Release DWORD. Unknown numbers stay raw.
    switch ($key) {
        378389 { return '4.5' }
        378675 { return '4.5.1' }
        378758 { return '4.5.1' }
        379893 { return '4.5.2' }
        393295 { return '4.6' }
        393297 { return '4.6' }
        394254 { return '4.6.1' }
        394271 { return '4.6.1' }
        394802 { return '4.6.2' }
        394806 { return '4.6.2' }
        460798 { return '4.7' }
        460805 { return '4.7' }
        461308 { return '4.7.1' }
        461310 { return '4.7.1' }
        461808 { return '4.7.2' }
        461814 { return '4.7.2' }
        528040 { return '4.8' }
        528049 { return '4.8' }
        528372 { return '4.8' }
        533320 { return '4.8.1' }
        533325 { return '4.8.1' }
        default { return $null }
    }
}

function Split-SCPathEntries {
    param([string]$Text)
    $list = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    foreach ($part in ($Text -split ';')) {
        $trimmed = $part.Trim().Trim('"')
        if ($trimmed) { [void]$list.Add($trimmed) }
    }
    # Unary comma keeps a 0- or 1-element array from unrolling on return.
    return ,$list.ToArray()
}

function Invoke-SCCheckIdentity {
    Start-SCSection -Title 'Identity'
    $ctx = Get-SCContext
    Write-SCInfo -Message ("Hostname: {0}" -f $ctx.ComputerName)
    if ($ctx.OsCaption) {
        Write-SCInfo -Message ("OS: {0}" -f $ctx.OsCaption)
    } else {
        Write-SCWarn -Message 'Operating system caption could not be read from CIM.'
    }
    $version = 'unknown'
    $build = 'unknown'
    $arch = 'unknown'
    if ($ctx.OsVersion) { $version = [string]$ctx.OsVersion }
    if ($ctx.OsBuild) { $build = [string]$ctx.OsBuild }
    if ($ctx.Architecture) { $arch = [string]$ctx.Architecture }
    Write-SCInfo -Message ("Version: {0}  Build: {1}  Arch: {2}" -f $version, $build, $arch)
    Write-SCInfo -Message ("Install date: {0}  Last boot: {1}  Uptime: {2}" -f (Format-SCDate $ctx.InstallDate), (Format-SCDate $ctx.LastBoot), (Format-SCUptime $ctx.Uptime))
}

function Invoke-SCCheckDomain {
    Start-SCSection -Title 'Domain'
    $ctx = Get-SCContext
    if ($null -eq $ctx.PartOfDomain) {
        Write-SCWarn -Message 'Domain membership could not be read from CIM.'
        return
    }
    $role = Get-SCDomainRoleLabel -Role $ctx.DomainRole
    if ($ctx.PartOfDomain) {
        $name = $ctx.Domain
        if (-not $name) { $name = 'unknown' }
        Write-SCInfo -Message ("Domain: {0} ({1})" -f $name, $role)
    } else {
        $group = $ctx.Workgroup
        if (-not $group) { $group = $ctx.Domain }
        if (-not $group) { $group = 'unknown' }
        Write-SCInfo -Message ("Workgroup: {0} ({1})" -f $group, $role)
    }
}

function Invoke-SCCheckHotfixes {
    Start-SCSection -Title 'Updates'
    if (-not (Get-Command -Name Get-HotFix -ErrorAction SilentlyContinue)) {
        Write-SCWarn -Message 'Hotfix enumeration is not available on this host.'
        return
    }
    try {
        $fixes = @(Get-HotFix -ErrorAction Stop)
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'hotfix list could not be read'
        } else {
            Write-SCWarn -Message ("Hotfix list could not be read: {0}" -f $_.Exception.Message)
        }
        return
    }
    Write-SCInfo -Message ("Installed hotfixes: {0}" -f $fixes.Count)
    if ($fixes.Count -eq 0) {
        Write-SCReview -Message 'No installed hotfixes were returned.'
        return
    }
    $newest = $null
    $newestWhen = $null
    foreach ($fix in $fixes) {
        $when = $null
        $raw = Get-SCProp -Object $fix -Name 'InstalledOn'
        if ($raw -is [datetime]) {
            $when = [datetime]$raw
        } elseif ($raw) {
            try { $when = [datetime]$raw } catch { $when = $null }
        }
        if ($when -and (($null -eq $newestWhen) -or ($when -gt $newestWhen))) {
            $newest = $fix
            $newestWhen = $when
        }
    }
    if ($newestWhen) {
        $kb = Get-SCProp -Object $newest -Name 'HotFixID'
        if (-not $kb) { $kb = 'unknown' }
        Write-SCInfo -Message ("Newest hotfix date: {0} ({1})" -f (Format-SCDate $newestWhen), $kb)
    } else {
        Write-SCInfo -Message 'Hotfix install dates were not available.'
    }
}

function Invoke-SCCheckServicing {
    Start-SCSection -Title 'Servicing posture'
    $ctx = Get-SCContext
    if (-not $ctx.OsCaption -and -not $ctx.OsBuild) {
        Write-SCWarn -Message 'Build and caption were not available, so no lifecycle comparison was made.'
        return
    }
    $note = Get-SCServicingNote -Caption $ctx.OsCaption -Build $ctx.OsBuild
    if ($note.Level -eq 'REVIEW') {
        Write-SCReview -Message $note.Text
    } else {
        Write-SCInfo -Message $note.Text
    }
}

function Invoke-SCCheckUac {
    Start-SCSection -Title 'UAC'
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enable = Get-SCRegistryValue -Path $key -Name 'EnableLUA'
    if (Write-SCRegistryProblem -Result $enable -Label 'EnableLUA') {
        # Keep going. Other values in the same key may still be readable.
    } elseif (-not $enable.Found) {
        Write-SCReview -Message 'EnableLUA is not set.'
    } elseif ([string]$enable.Value -eq '0') {
        Write-SCWeak -Message 'EnableLUA is 0. User Account Control is turned off.'
    } else {
        Write-SCInfo -Message ("EnableLUA: {0} (UAC enabled)" -f $enable.Value)
    }

    $consent = Get-SCRegistryValue -Path $key -Name 'ConsentPromptBehaviorAdmin'
    if (Write-SCRegistryProblem -Result $consent -Label 'ConsentPromptBehaviorAdmin') {
        # reported above
    } elseif ($consent.Found) {
        $label = Get-SCConsentAdminLabel -Value $consent.Value
        if ([string]$consent.Value -eq '0') {
            Write-SCWeak -Message ("ConsentPromptBehaviorAdmin is 0 ({0})." -f $label)
        } elseif ([string]$consent.Value -eq '5') {
            Write-SCReview -Message ("ConsentPromptBehaviorAdmin is 5 ({0})." -f $label)
        } else {
            Write-SCInfo -Message ("ConsentPromptBehaviorAdmin: {0} ({1})" -f $consent.Value, $label)
        }
    } else {
        Write-SCInfo -Message 'ConsentPromptBehaviorAdmin is not set.'
    }

    $filter = Get-SCRegistryValue -Path $key -Name 'LocalAccountTokenFilterPolicy'
    if (Write-SCRegistryProblem -Result $filter -Label 'LocalAccountTokenFilterPolicy') {
        return
    }
    if (-not $filter.Found -or [string]$filter.Value -eq '0') {
        Write-SCInfo -Message 'LocalAccountTokenFilterPolicy is not enabled.'
    } else {
        Write-SCReview -Message 'LocalAccountTokenFilterPolicy is 1. Remote logons that use a local account on this host receive a full administrator token. Leave this unset unless remote administration requires it.'
    }
}

function Invoke-SCCheckInstaller {
    Start-SCSection -Title 'Installer elevation'
    $hklm = Get-SCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $hkcu = Get-SCRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $failed = $false
    if (Write-SCRegistryProblem -Result $hklm -Label 'HKLM AlwaysInstallElevated') { $failed = $true }
    if (Write-SCRegistryProblem -Result $hkcu -Label 'HKCU AlwaysInstallElevated') { $failed = $true }
    if ($failed) { return }

    $hklmOn = ($hklm.Found -and [string]$hklm.Value -eq '1')
    $hkcuOn = ($hkcu.Found -and [string]$hkcu.Value -eq '1')
    if ($hklmOn -and $hkcuOn) {
        Write-SCWeak -Message 'AlwaysInstallElevated is 1 in both HKLM and HKCU. Windows Installer packages can run elevated. Turn this policy off unless a documented deployment process requires it.'
    } elseif ($hklmOn -or $hkcuOn) {
        $which = 'HKLM'
        if ($hkcuOn) { $which = 'HKCU' }
        Write-SCReview -Message ("AlwaysInstallElevated is 1 in {0} only. Remove the stray value. Both hives must be 1 before the policy takes effect." -f $which)
    } else {
        Write-SCInfo -Message 'AlwaysInstallElevated is not enabled.'
    }
}

function Invoke-SCCheckLsa {
    Start-SCSection -Title 'LSA and credential configuration'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ppl = Get-SCRegistryValue -Path $lsa -Name 'RunAsPPL'
    if (Write-SCRegistryProblem -Result $ppl -Label 'RunAsPPL') {
        # continue
    } elseif ($ppl.Found -and ([string]$ppl.Value -eq '1' -or [string]$ppl.Value -eq '2')) {
        Write-SCInfo -Message ("LSA protection RunAsPPL: {0}" -f $ppl.Value)
    } else {
        Write-SCReview -Message 'LSA protection (RunAsPPL) is not enabled.'
    }

    $cfg = Get-SCRegistryValue -Path $lsa -Name 'LsaCfgFlags'
    $policyCfg = Get-SCRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags'
    $cfgValue = $null
    $cfgSource = $null
    if ($policyCfg.Found) {
        $cfgValue = $policyCfg.Value
        $cfgSource = 'policy'
    } elseif ($cfg.Found) {
        $cfgValue = $cfg.Value
        $cfgSource = 'LSA key'
    }
    $cfgFailed = (Write-SCRegistryProblem -Result $cfg -Label 'LsaCfgFlags') -or (Write-SCRegistryProblem -Result $policyCfg -Label 'policy LsaCfgFlags')
    if ($null -eq $cfgValue) {
        if (-not $cfgFailed) {
            Write-SCInfo -Message 'Credential Guard LsaCfgFlags is not set.'
        }
    } elseif ([string]$cfgValue -eq '1' -or [string]$cfgValue -eq '2') {
        Write-SCInfo -Message ("Credential Guard LsaCfgFlags: {0} ({1})" -f $cfgValue, $cfgSource)
    } else {
        Write-SCInfo -Message ("Credential Guard LsaCfgFlags: {0} ({1})" -f $cfgValue, $cfgSource)
    }

    $vbs = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity'
    if (-not (Write-SCRegistryProblem -Result $vbs -Label 'EnableVirtualizationBasedSecurity')) {
        if ($vbs.Found) {
            Write-SCInfo -Message ("EnableVirtualizationBasedSecurity: {0}" -f $vbs.Value)
        } else {
            Write-SCInfo -Message 'EnableVirtualizationBasedSecurity is not set.'
        }
    }

    $digest = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    if (Write-SCRegistryProblem -Result $digest -Label 'WDigest UseLogonCredential') {
        # continue
    } elseif ($digest.Found -and [string]$digest.Value -eq '1') {
        Write-SCWeak -Message 'WDigest UseLogonCredential is 1. Windows is configured to keep WDigest credentials in a reversible form. Set this to 0 unless a documented legacy application requires it.'
    } elseif ($digest.Found) {
        Write-SCInfo -Message ("WDigest UseLogonCredential: {0}" -f $digest.Value)
    } else {
        Write-SCInfo -Message 'WDigest UseLogonCredential is not set (cleartext caching is not enabled).'
    }

    $cached = Get-SCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount'
    if (Write-SCRegistryProblem -Result $cached -Label 'CachedLogonsCount') {
        # continue
    } elseif (-not $cached.Found) {
        Write-SCInfo -Message 'Cached logon count is not set.'
    } else {
        $count = 0
        $parsed = [int]::TryParse([string]$cached.Value, [ref]$count)
        if (-not $parsed) {
            Write-SCInfo -Message ("Cached logon count: {0}" -f $cached.Value)
        } elseif ($count -eq 0) {
            Write-SCInfo -Message 'Cached logon count: 0 (cached logons disabled).'
        } elseif ($count -gt 10) {
            Write-SCReview -Message ("Cached logon count is {0}, above the common default of 10." -f $count)
        } else {
            Write-SCInfo -Message ("Cached logon count: {0}" -f $count)
        }
    }

    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
            $runningRaw = Get-SCProp -Object $guard -Name 'SecurityServicesRunning'
            $configRaw = Get-SCProp -Object $guard -Name 'SecurityServicesConfigured'
            Write-SCInfo -Message ("Device Guard services configured: {0}" -f (Format-SCIdList $configRaw))
            Write-SCInfo -Message ("Device Guard services running: {0}" -f (Format-SCIdList $runningRaw))
            if (Test-SCIdListContains -Values $runningRaw -Expected '1') {
                Write-SCInfo -Message 'Credential Guard is reported as running (service id 1).'
            }
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) {
                Write-SCNeedsAdmin -Detail 'Device Guard status could not be read'
            } else {
                Write-SCInfo -Message 'Device Guard WMI class was not available.'
            }
        }
    }
}

function Format-SCIdList {
    param($Values)
    if ($null -eq $Values) { return 'none reported' }
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Values)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        if ($text -eq '') { continue }
        [void]$items.Add($text)
    }
    if ($items.Count -eq 0) { return 'none reported' }
    return ($items -join ', ')
}

function Test-SCIdListContains {
    param($Values, [string]$Expected)
    if ($null -eq $Values) { return $false }
    foreach ($item in @($Values)) {
        if ([string]$item -eq $Expected) { return $true }
    }
    return $false
}

function Invoke-SCCheckPowerShell {
    Start-SCSection -Title 'PowerShell'
    $edition = 'Desktop'
    if ($PSVersionTable.PSEdition) { $edition = [string]$PSVersionTable.PSEdition }
    Write-SCInfo -Message ("Host: {0} {1}" -f $edition, $PSVersionTable.PSVersion)
    try {
        $mode = [string]$ExecutionContext.SessionState.LanguageMode
        Write-SCInfo -Message ("Language mode: {0}" -f $mode)
    } catch {
        Write-SCWarn -Message 'Language mode could not be read.'
    }
    if ($env:__PSLockdownPolicy) {
        Write-SCInfo -Message ("__PSLockdownPolicy: {0}" -f $env:__PSLockdownPolicy)
    }

    try {
        $effective = [string](Get-ExecutionPolicy -ErrorAction Stop)
        Write-SCInfo -Message ("Effective execution policy: {0}" -f $effective)
        if ($effective -eq 'Bypass' -or $effective -eq 'Unrestricted') {
            Write-SCReview -Message ("Effective execution policy is {0}." -f $effective)
        }
        foreach ($entry in @(Get-ExecutionPolicy -List -ErrorAction Stop)) {
            Write-SCInfo -Message ("Policy scope {0}: {1}" -f $entry.Scope, $entry.ExecutionPolicy)
        }
    } catch {
        Write-SCWarn -Message ("Execution policy could not be read: {0}" -f $_.Exception.Message)
    }

    $scriptLog = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $scriptBlock = Get-SCRegistryValue -Path $scriptLog -Name 'EnableScriptBlockLogging'
    if (Write-SCRegistryProblem -Result $scriptBlock -Label 'Script block logging') {
        # continue
    } elseif ($scriptBlock.Found -and [string]$scriptBlock.Value -eq '1') {
        Write-SCInfo -Message 'Script block logging is enabled.'
    } else {
        Write-SCReview -Message 'Script block logging is not enabled.'
    }

    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    $trans = Get-SCRegistryValue -Path $transPath -Name 'EnableTranscripting'
    if (Write-SCRegistryProblem -Result $trans -Label 'PowerShell transcription') {
        return
    }
    if ($trans.Found -and [string]$trans.Value -eq '1') {
        $dir = Get-SCRegistryValue -Path $transPath -Name 'OutputDirectory'
        if ($dir.Found -and $dir.Value) {
            Write-SCInfo -Message ("PowerShell transcription is enabled. Output directory: {0}" -f $dir.Value)
        } else {
            Write-SCInfo -Message 'PowerShell transcription is enabled.'
        }
    } else {
        Write-SCReview -Message 'PowerShell transcription is not enabled.'
    }
}

function Invoke-SCCheckAntivirus {
    Start-SCSection -Title 'Antivirus'
    $sawProduct = $false
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
            if ($products.Count -eq 0) {
                Write-SCReview -Message 'Security Center returned no antivirus products.'
            }
            foreach ($product in $products) {
                $sawProduct = $true
                $name = Get-SCProp -Object $product -Name 'displayName'
                if (-not $name) { $name = 'unnamed product' }
                $state = Get-SCProp -Object $product -Name 'productState'
                if ($null -eq $state) {
                    Write-SCInfo -Message ("Security Center product: {0}" -f $name)
                } else {
                    $hex = [string]$state
                    try { $hex = '{0:X}' -f [uint32]$state } catch { $hex = [string]$state }
                    Write-SCInfo -Message ("Security Center product: {0} (productState 0x{1})" -f $name, $hex)
                }
            }
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) {
                Write-SCNeedsAdmin -Detail 'Security Center antivirus query failed'
            } else {
                Write-SCInfo -Message 'Security Center antivirus query was not available.'
            }
        }
    } else {
        Write-SCWarn -Message 'CIM is not available, so Security Center could not be queried.'
    }

    if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        if (-not $sawProduct) {
            Write-SCInfo -Message 'Defender cmdlets are not available in this session.'
        }
        return
    }
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'Defender status could not be read'
        } else {
            Write-SCWarn -Message ("Defender status could not be read: {0}" -f $_.Exception.Message)
        }
        return
    }
    $rtp = Get-SCProp -Object $status -Name 'RealTimeProtectionEnabled'
    $av = Get-SCProp -Object $status -Name 'AntivirusEnabled'
    $sig = Get-SCProp -Object $status -Name 'AntivirusSignatureLastUpdated'
    $productVersion = Get-SCProp -Object $status -Name 'AMProductVersion'
    if ($productVersion) {
        Write-SCInfo -Message ("Defender platform version: {0}" -f $productVersion)
    }
    if ($null -ne $av) {
        Write-SCInfo -Message ("Defender antivirus enabled: {0}" -f $av)
    }
    if ($null -eq $rtp) {
        Write-SCInfo -Message 'Defender real-time protection status was not returned.'
    } elseif ($rtp) {
        Write-SCInfo -Message 'Defender real-time protection: enabled'
    } else {
        Write-SCReview -Message 'Defender real-time protection is disabled.'
    }
    if ($sig) {
        Write-SCInfo -Message ("Defender signature update: {0}" -f (Format-SCDate $sig))
    }
}

function Invoke-SCCheckAppControl {
    Start-SCSection -Title 'Application control'
    $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    $areas = @()
    $policyError = $false
    try {
        if (Test-Path -LiteralPath $policyRoot -ErrorAction Stop) {
            foreach ($child in @(Get-ChildItem -LiteralPath $policyRoot -ErrorAction Stop)) {
                $areas += [string]$child.PSChildName
            }
        }
    } catch {
        $policyError = $true
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'AppLocker policy could not be read'
        } else {
            Write-SCWarn -Message ("AppLocker policy could not be read: {0}" -f $_.Exception.Message)
        }
    }
    if ($areas.Count -gt 0) {
        Write-SCInfo -Message ("AppLocker policy areas: {0}" -f ($areas -join ', '))
    } elseif (-not $policyError) {
        Write-SCInfo -Message 'AppLocker policy not detected.'
    }

    if (Get-Command -Name Get-Service -ErrorAction SilentlyContinue) {
        try {
            $appId = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
            Write-SCInfo -Message ("AppIDSvc status: {0}" -f $appId.Status)
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) {
                Write-SCNeedsAdmin -Detail 'AppIDSvc status could not be read'
            } elseif ($_.Exception.Message -match 'not supported|not implemented') {
                Write-SCWarn -Message 'Service enumeration is not supported on this host.'
            } else {
                Write-SCInfo -Message 'AppIDSvc service was not found.'
            }
        }
    }

    $windir = $env:WINDIR
    if (-not $windir) { $windir = $env:SystemRoot }
    if (-not $windir) {
        Write-SCInfo -Message 'WDAC policy folder could not be located (WINDIR is unset).'
        return
    }
    $active = Join-Path $windir 'System32\CodeIntegrity\CiPolicies\Active'
    if (-not (Test-Path -LiteralPath $active)) {
        Write-SCInfo -Message 'WDAC active policy folder not found.'
        return
    }
    try {
        $files = @(Get-ChildItem -LiteralPath $active -File -ErrorAction Stop)
        if ($files.Count -eq 0) {
            Write-SCInfo -Message 'WDAC active policy folder is empty.'
        } else {
            Write-SCInfo -Message ("WDAC active policy files: {0}" -f $files.Count)
        }
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'WDAC policy folder could not be read'
        } else {
            Write-SCWarn -Message ("WDAC policy folder could not be read: {0}" -f $_.Exception.Message)
        }
    }
}

function Write-SCPathReview {
    param(
        [string]$Label,
        [string[]]$Entries,
        [switch]$FlagUserWritable
    )
    $present = 0
    $missing = 0
    $reported = 0
    $hidden = 0
    foreach ($entry in @($Entries)) {
        if (-not $entry) { continue }
        if (-not (Test-Path -LiteralPath $entry)) {
            $missing++
            continue
        }
        $present++
        $writable = Test-SCWritableByNonAdmin -Path $entry
        if ($writable.Error) {
            if ($writable.Error -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $writable.Error)) {
                Write-SCNeedsAdmin -Detail ("ACL could not be read for {0}" -f $entry)
            }
            continue
        }
        $names = @()
        $interesting = $false
        if ($FlagUserWritable -and $writable.Writable) {
            $interesting = $true
            $names = @($writable.Principals)
        } elseif ($writable.BroadWritable) {
            $interesting = $true
            $names = @($writable.BroadPrincipals)
        }
        if (-not $interesting) { continue }
        if ($reported -ge 15) {
            $hidden++
            continue
        }
        $reported++
        Write-SCReview -Message ("{0} PATH entry is writable by a non-admin principal: {1} ({2})" -f $Label, $entry, ($names -join ', '))
    }
    Write-SCInfo -Message ("{0} PATH entries: {1} present, {2} missing" -f $Label, $present, $missing)
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional writable {1} PATH entries were omitted from the list." -f $hidden, $Label)
    }
}

function Invoke-SCCheckEnvironment {
    Start-SCSection -Title 'Environment'
    $profile = $env:USERPROFILE
    $temp = $env:TEMP
    if (-not $profile) { $profile = 'unset' }
    if (-not $temp) { $temp = 'unset' }
    Write-SCInfo -Message ("USERPROFILE: {0}" -f $profile)
    Write-SCInfo -Message ("TEMP: {0}" -f $temp)
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) {
        $tempAcl = Test-SCWritableByNonAdmin -Path $env:TEMP
        if ($tempAcl.BroadWritable) {
            Write-SCReview -Message ("TEMP is writable by a broad principal: {0} ({1})" -f $env:TEMP, ($tempAcl.BroadPrincipals -join ', '))
        }
    }

    $machinePath = $null
    $userPath = $null
    $machineOk = $true
    $userOk = $true
    try {
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    } catch {
        $machineOk = $false
        Write-SCWarn -Message 'Machine PATH could not be read.'
    }
    try {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    } catch {
        $userOk = $false
        Write-SCWarn -Message 'User PATH could not be read.'
    }
    # Machine PATH writable by a normal user is the interesting case.
    # A user PATH entry that the same user owns is expected, so only broad ACEs are listed.
    if ($machineOk) {
        Write-SCPathReview -Label 'Machine' -Entries (Split-SCPathEntries -Text $machinePath) -FlagUserWritable
    }
    if ($userOk) {
        Write-SCPathReview -Label 'User' -Entries (Split-SCPathEntries -Text $userPath)
    }
}

function Invoke-SCCheckDotNet {
    Start-SCSection -Title '.NET Framework'
    $root = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) {
        Write-SCInfo -Message '.NET Framework Setup registry key was not found.'
        return
    }
    $foundAny = $false
    foreach ($pair in @(
            @{ Name = 'v2.0.50727'; Legacy = $true }
            @{ Name = 'v3.0'; Legacy = $false }
            @{ Name = 'v3.5'; Legacy = $true }
        )) {
        $path = Join-Path $root $pair.Name
        $install = Get-SCRegistryValue -Path $path -Name 'Install'
        $version = Get-SCRegistryValue -Path $path -Name 'Version'
        if ($install.Error -or $version.Error) {
            Write-SCRegistryProblem -Result $install -Label ('.NET ' + $pair.Name)
            continue
        }
        $isInstalled = ($install.Found -and [string]$install.Value -eq '1')
        if (-not $isInstalled -and -not $version.Found) { continue }
        $foundAny = $true
        $versionText = 'unknown'
        if ($version.Found) { $versionText = [string]$version.Value }
        if ($pair.Legacy -and $isInstalled) {
            Write-SCReview -Message (".NET Framework {0} is installed ({1}). Review whether this legacy runtime is still required." -f $pair.Name, $versionText)
        } else {
            Write-SCInfo -Message (".NET Framework {0}: {1}" -f $pair.Name, $versionText)
        }
    }

    $v4 = Join-Path (Join-Path $root 'v4') 'Full'
    $release = Get-SCRegistryValue -Path $v4 -Name 'Release'
    $v4Version = Get-SCRegistryValue -Path $v4 -Name 'Version'
    if ($release.Error -or $v4Version.Error) {
        Write-SCRegistryProblem -Result $release -Label '.NET 4 release'
        Write-SCRegistryProblem -Result $v4Version -Label '.NET 4 version'
    } elseif ($release.Found -or $v4Version.Found) {
        $foundAny = $true
        $releaseText = 'unknown'
        $mapped = $null
        if ($release.Found) {
            $releaseText = [string]$release.Value
            $mapped = Get-SCDotNetReleaseName -Release $release.Value
        }
        $versionText = 'unknown'
        if ($v4Version.Found) { $versionText = [string]$v4Version.Value }
        if ($mapped) {
            Write-SCInfo -Message (".NET Framework 4 release {0} ({1}), version value {2}" -f $releaseText, $mapped, $versionText)
        } else {
            Write-SCInfo -Message (".NET Framework 4 release {0}, version value {1}. Compare an unrecognized release number with Microsoft's table." -f $releaseText, $versionText)
        }
    }
    if (-not $foundAny) {
        Write-SCInfo -Message 'No installed .NET Framework versions were found under NDP.'
    }
}

function Invoke-SCCheckSysmon {
    Start-SCSection -Title 'Sysmon'
    if (-not (Get-Command -Name Get-Service -ErrorAction SilentlyContinue)) {
        Write-SCWarn -Message 'Service enumeration is not available on this host.'
        return
    }
    $found = $false
    foreach ($name in @('Sysmon', 'Sysmon64')) {
        try {
            $service = Get-Service -Name $name -ErrorAction Stop
            $found = $true
            Write-SCInfo -Message ("Sysmon service {0}: {1}" -f $service.Name, $service.Status)
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) {
                Write-SCNeedsAdmin -Detail 'Sysmon service status could not be read'
                return
            }
            if ($_.Exception.Message -match 'not supported|not implemented') {
                Write-SCWarn -Message 'Service enumeration is not supported on this host.'
                return
            }
        }
    }
    if (-not $found) {
        Write-SCInfo -Message 'Sysmon service not found.'
    }
}

Write-SCHeader -Title 'System'
Invoke-SCCheckIdentity
Invoke-SCCheckDomain
Invoke-SCCheckHotfixes
Invoke-SCCheckServicing
Invoke-SCCheckUac
Invoke-SCCheckInstaller
Invoke-SCCheckLsa
Invoke-SCCheckPowerShell
Invoke-SCCheckAntivirus
Invoke-SCCheckAppControl
Invoke-SCCheckEnvironment
Invoke-SCCheckDotNet
Invoke-SCCheckSysmon
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: System' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
