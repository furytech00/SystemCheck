#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only security baseline and hardening posture.

.DESCRIPTION
    Reports registry and feature settings an owner can compare with a
    stricter baseline. Findings name the current value and the preferred
    setting. They do not describe attacks.

    These checks stay in other modules and are not repeated here:
      system  - UAC, AlwaysInstallElevated, RunAsPPL, Credential Guard,
                WDigest, cached logons, Defender real-time protection,
                AppLocker, and WDAC
      users   - auto-logon, Guest, password expiry, local Administrators
      network - listeners and firewall profile defaults

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\13_hardening.ps1
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

function Format-SCTrim {
    param([string]$Text, [int]$Max = 100)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ([string]$Text -replace '[\r\n]+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max)
}

function Format-SCRegActual {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return (Format-SCTrim -Text $Value -Max 120) }
    $enumerable = ($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])
    if (-not $enumerable) { return (Format-SCTrim -Text ([string]$Value) -Max 80) }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Value) {
        if ($null -eq $item) { continue }
        [void]$parts.Add([string]$item)
        if ($parts.Count -ge 4) { break }
    }
    return (Format-SCTrim -Text ($parts.ToArray() -join '; ') -Max 120)
}

function Format-SCUrlText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = [regex]::Replace($Text, '(?i)([a-z][a-z0-9+\-.]*://)[^/\s:@]+:[^/\s@]+@', '$1')
    return (Format-SCTrim -Text $clean -Max 120)
}

function Test-SCRegistryRoot {
    param([string]$Root)
    try {
        return [bool](Test-Path -LiteralPath $Root -ErrorAction Stop)
    } catch {
        return $false
    }
}

function Join-SCRegPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return $Child }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Write-SCExpectLine {
    param([string]$Level, [string]$Text)
    if ($Level -eq 'WEAK') { Write-SCWeak -Message $Text }
    elseif ($Level -eq 'REVIEW') { Write-SCReview -Message $Text }
    elseif ($Level -eq 'WARN') { Write-SCWarn -Message $Text }
    else { Write-SCInfo -Message $Text }
}

function New-SCExpect {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Label,
        [string]$Mode,
        $Good,
        $Weak = $null,
        [string]$MissingLevel = 'REVIEW',
        [string]$MissingText = '',
        [string]$GoodText = '',
        [string]$BadLevel = 'REVIEW',
        [string]$BadText = ''
    )
    return New-Object psobject -Property @{
        Path         = $Path
        Name         = $Name
        Label        = $Label
        Mode         = $Mode
        Good         = $Good
        Weak         = $Weak
        MissingLevel = $MissingLevel
        MissingText  = $MissingText
        GoodText     = $GoodText
        BadLevel     = $BadLevel
        BadText      = $BadText
    }
}

function Test-SCValueListed {
    param($Value, $Set)
    $actual = [string]$Value
    foreach ($item in (ConvertTo-SCArray $Set)) {
        if ($null -eq $item) { continue }
        if ([string]::Equals($actual, [string]$item, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Test-SCExpectGood {
    param($Spec, [bool]$Found, $Value)
    if ($Spec.Mode -eq 'Absent') {
        if (-not $Found) { return $true }
        return [string]::IsNullOrWhiteSpace([string]$Value)
    }
    if (-not $Found) { return $false }
    if ($Spec.Mode -eq 'Min' -or $Spec.Mode -eq 'Max') {
        $need = 0
        $have = 0
        $floor = $null
        foreach ($item in (ConvertTo-SCArray $Spec.Good)) { $floor = $item; break }
        $needOk = [int]::TryParse([string]$floor, [ref]$need)
        $haveOk = [int]::TryParse([string]$Value, [ref]$have)
        if (-not $needOk -or -not $haveOk) { return $false }
        if ($Spec.Mode -eq 'Min') { return ($have -ge $need) }
        if ($have -le 0) { return $false }
        return ($have -le $need)
    }
    return (Test-SCValueListed -Value $Value -Set $Spec.Good)
}

function Format-SCExpectText {
    param([string]$Template, [string]$Actual)
    if ([string]::IsNullOrWhiteSpace($Template)) { return $Actual }
    if ($Template -match '\{0\}') { return ($Template -f $Actual) }
    return $Template
}

function Get-SCLmCompatibilityLabel {
    param($Value)
    switch ([string]$Value) {
        '0' { return 'send LM and NTLM responses' }
        '1' { return 'send LM and NTLM; use NTLMv2 session security if negotiated' }
        '2' { return 'send NTLM responses only' }
        '3' { return 'send NTLMv2 responses only' }
        '4' { return 'send NTLMv2 only and refuse LM' }
        '5' { return 'send NTLMv2 only and refuse LM and NTLM' }
        default { return '' }
    }
}

function Get-SCRdpEncryptionLabel {
    param($Value)
    switch ([string]$Value) {
        '1' { return 'Low' }
        '2' { return 'Client Compatible' }
        '3' { return 'High' }
        '4' { return 'FIPS' }
        default { return '' }
    }
}

function Format-SCExpectActual {
    param($Spec, $Value)
    $shown = Format-SCRegActual -Value $Value
    $label = ''
    if ($Spec.Name -eq 'LmCompatibilityLevel') { $label = Get-SCLmCompatibilityLabel -Value $Value }
    elseif ($Spec.Name -eq 'MinEncryptionLevel') { $label = Get-SCRdpEncryptionLabel -Value $Value }
    if ($label) { return ('{0} ({1})' -f $shown, $label) }
    return $shown
}

function Get-SCExpectResult {
    param($Spec, [bool]$Found, $Value)
    $shown = ''
    if ($Found) { $shown = Format-SCExpectActual -Spec $Spec -Value $Value }
    $good = Test-SCExpectGood -Spec $Spec -Found $Found -Value $Value
    if ($good) {
        $text = Format-SCExpectText -Template $Spec.GoodText -Actual $shown
        return New-Object psobject -Property @{ Level = 'INFO'; Text = $text }
    }
    if (-not $Found) {
        return New-Object psobject -Property @{
            Level = $Spec.MissingLevel
            Text  = $Spec.MissingText
        }
    }
    $level = $Spec.BadLevel
    if (Test-SCValueListed -Value $Value -Set $Spec.Weak) { $level = 'WEAK' }
    $text = Format-SCExpectText -Template $Spec.BadText -Actual $shown
    return New-Object psobject -Property @{ Level = $level; Text = $text }
}

function Write-SCRegistryIssue {
    param($Result, [string]$Label)
    if (-not $Result -or -not $Result.Error) { return $false }
    if (Test-SCAccessDenied -Message $Result.Error) {
        Write-SCNeedsAdmin -Detail ("{0} could not be read" -f $Label)
    } else {
        Write-SCWarn -Message ("{0} could not be read: {1}" -f $Label, (Format-SCTrim -Text $Result.Error -Max 140))
    }
    return $true
}

function Write-SCExpect {
    param($Spec)
    $result = Get-SCRegistryValue -Path $Spec.Path -Name $Spec.Name
    if (Write-SCRegistryIssue -Result $result -Label $Spec.Label) { return }
    $finding = Get-SCExpectResult -Spec $Spec -Found ([bool]$result.Found) -Value $result.Value
    Write-SCExpectLine -Level $finding.Level -Text $finding.Text
}

function Write-SCExpectTable {
    param($Specs)
    foreach ($spec in (ConvertTo-SCArray $Specs)) {
        if (-not $spec) { continue }
        try {
            Write-SCExpect -Spec $spec
        } catch {
            Write-SCWarn -Message ("{0} could not be read: {1}" -f $spec.Label, (Format-SCTrim -Text $_.Exception.Message -Max 140))
        }
    }
}

function Write-SCHiveSkip {
    param([string]$Root, [string]$What)
    Write-SCWarn -Message ("Registry hive {0} is not available. {1} was skipped." -f $Root, $What)
}

function Get-SCServiceStartLabel {
    param($Value)
    switch ([string]$Value) {
        '2' { return 'start automatic' }
        '3' { return 'start manual' }
        '4' { return 'start disabled' }
        default { return ('start type {0}' -f [string]$Value) }
    }
}

function Write-SCWindowsService {
    param([string]$Name, [string]$Label)
    $startText = 'start type unknown'
    $reg = Get-SCRegistryValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $Name) -Name 'Start'
    if ($reg.Error) {
        Write-SCRegistryIssue -Result $reg -Label $Label | Out-Null
    } elseif ($reg.Found) {
        $startText = Get-SCServiceStartLabel -Value $reg.Value
    }
    $status = 'status unknown'
    if (Get-Command -Name Get-Service -ErrorAction SilentlyContinue) {
        try {
            $svc = Get-Service -Name $Name -ErrorAction Stop
            $status = [string]$svc.Status
        } catch {
            $message = $_.Exception.Message
            if ($message -match 'Cannot find any service|not found') { $status = 'not installed' }
            elseif (Test-SCAccessDenied -Message $message) { $status = 'NEEDS ADMIN' }
            else { $status = 'unreadable' }
        }
    }
    if ($status -eq 'NEEDS ADMIN') {
        Write-SCNeedsAdmin -Detail ("{0} service status could not be read" -f $Label)
        return
    }
    Write-SCInfo -Message ("{0}: {1}, {2}." -f $Label, $status, $startText)
}

function Get-SCLeafName {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = $Text.Trim().Trim('"').Trim()
    $slash = [Math]::Max($clean.LastIndexOf('\'), $clean.LastIndexOf('/'))
    if ($slash -ge 0 -and $slash -lt ($clean.Length - 1)) { return $clean.Substring($slash + 1) }
    return $clean
}

function Invoke-SCCheckCredentialPolicy {
    Start-SCSection -Title 'Credential policy'
    if (-not (Test-SCRegistryRoot -Root 'HKLM:\')) {
        Write-SCHiveSkip -Root 'HKLM' -What 'Credential policy'
        return
    }
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Write-SCExpectTable -Specs @(
        (New-SCExpect -Path $lsa -Name 'NoLMHash' -Label 'NoLMHash' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'NoLMHash is not set. Prefer 1 so LM hashes are not stored.' `
            -GoodText 'NoLMHash is 1. LM hash storage is disabled.' `
            -BadLevel 'REVIEW' -BadText 'NoLMHash is {0}. Prefer 1 so LM hashes are not stored.')
        (New-SCExpect -Path $lsa -Name 'LmCompatibilityLevel' -Label 'LmCompatibilityLevel' -Mode 'Equals' -Good 5 -Weak @(0, 1) `
            -MissingLevel 'REVIEW' -MissingText 'LmCompatibilityLevel is not set. Prefer 5 (send NTLMv2 only and refuse LM and NTLM).' `
            -GoodText 'LmCompatibilityLevel is {0}.' `
            -BadLevel 'REVIEW' -BadText 'LmCompatibilityLevel is {0}. Prefer 5 (send NTLMv2 only and refuse LM and NTLM).')
        (New-SCExpect -Path $lsa -Name 'RestrictAnonymous' -Label 'RestrictAnonymous' -Mode 'OneOf' -Good @(1, 2) -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'RestrictAnonymous is not set. Prefer 1 or 2 to limit anonymous enumeration.' `
            -GoodText 'RestrictAnonymous is {0}.' `
            -BadLevel 'REVIEW' -BadText 'RestrictAnonymous is {0}. Prefer 1 or 2 to limit anonymous enumeration.')
        (New-SCExpect -Path $lsa -Name 'RestrictAnonymousSAM' -Label 'RestrictAnonymousSAM' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'RestrictAnonymousSAM is not set. Prefer 1 to block anonymous SAM accounts enumeration.' `
            -GoodText 'RestrictAnonymousSAM is 1. Anonymous SAM account enumeration is restricted.' `
            -BadLevel 'REVIEW' -BadText 'RestrictAnonymousSAM is {0}. Prefer 1 to block anonymous SAM accounts enumeration.')
        (New-SCExpect -Path $lsa -Name 'EveryoneIncludesAnonymous' -Label 'EveryoneIncludesAnonymous' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'EveryoneIncludesAnonymous is not set.' `
            -GoodText 'EveryoneIncludesAnonymous is 0. Anonymous logons are not added to the Everyone group.' `
            -BadLevel 'REVIEW' -BadText 'EveryoneIncludesAnonymous is {0}. Prefer 0 so anonymous logons are not in Everyone.')
    )
}

function Write-SCSecureBoot {
    if (-not (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        Write-SCInfo -Message 'Secure Boot state is not available from this session.'
        return
    }
    try {
        $on = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($on) {
            Write-SCInfo -Message 'Secure Boot is enabled.'
        } else {
            Write-SCReview -Message 'Secure Boot is disabled. Prefer enabled on UEFI firmware.'
        }
    } catch {
        $message = $_.Exception.Message
        if ($message -match 'not supported|Cmdlet not supported|EFI') {
            Write-SCInfo -Message 'Secure Boot state is not supported on this firmware.'
        } elseif (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'Secure Boot state could not be read'
        } else {
            Write-SCWarn -Message ("Secure Boot state could not be read: {0}" -f (Format-SCTrim -Text $message -Max 140))
        }
    }
}

function Format-SCBitLockerState {
    param($Value)
    $text = [string]$Value
    if ($text -eq '1' -or $text -eq 'On') { return 'protected' }
    if ($text -eq '0' -or $text -eq 'Off') { return 'unprotected' }
    if ($text -eq '2' -or $text -eq 'Unknown') { return 'unknown' }
    if (-not $text) { return 'unknown' }
    return $text
}

function Write-SCBitLockerVolume {
    param([string]$Name, [string]$State, [string]$Method)
    $label = $Name
    if (-not $label) { $label = 'volume without a drive letter' }
    $extra = ''
    if ($Method) { $extra = (' Method: {0}.' -f (Format-SCTrim -Text $Method -Max 40)) }
    if ($State -eq 'unprotected') {
        Write-SCReview -Message ("BitLocker protection is off for {0}.{1} Prefer protection on operating-system and fixed data volumes." -f $label, $extra)
    } elseif ($State -eq 'protected') {
        Write-SCInfo -Message ("BitLocker protection is on for {0}.{1}" -f $label, $extra)
    } else {
        Write-SCInfo -Message ("BitLocker protection for {0}: {1}.{2}" -f $label, $State, $extra)
    }
}

function Write-SCBitLocker {
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $rows = ConvertTo-SCArray (Get-BitLockerVolume -ErrorAction Stop)
            if ($rows.Count -eq 0) {
                Write-SCInfo -Message 'BitLocker returned no volumes.'
                return
            }
            $shown = 0
            foreach ($row in $rows) {
                if (-not $row) { continue }
                if ($shown -ge 8) { break }
                $shown++
                $mount = [string](Get-SCPropSafe -Object $row -Name 'MountPoint')
                $state = Format-SCBitLockerState -Value (Get-SCPropSafe -Object $row -Name 'ProtectionStatus')
                $method = [string](Get-SCPropSafe -Object $row -Name 'EncryptionMethod')
                Write-SCBitLockerVolume -Name $mount -State $state -Method $method
            }
            if ($rows.Count -gt $shown) {
                Write-SCInfo -Message ("{0} additional BitLocker volumes were omitted." -f ($rows.Count - $shown))
            }
            return
        } catch {
            $message = $_.Exception.Message
            if (Test-SCAccessDenied -Message $message) {
                Write-SCNeedsAdmin -Detail 'BitLocker volume status could not be read'
                return
            }
        }
    }
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        Write-SCInfo -Message 'BitLocker volume status is not available from this session.'
        return
    }
    try {
        $rows = ConvertTo-SCArray (Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop)
        if ($rows.Count -eq 0) {
            Write-SCInfo -Message 'BitLocker returned no volumes.'
            return
        }
        $shown = 0
        foreach ($row in $rows) {
            if (-not $row) { continue }
            if ($shown -ge 8) { break }
            $shown++
            $letter = [string](Get-SCPropSafe -Object $row -Name 'DriveLetter')
            $state = Format-SCBitLockerState -Value (Get-SCPropSafe -Object $row -Name 'ProtectionStatus')
            $method = [string](Get-SCPropSafe -Object $row -Name 'EncryptionMethod')
            Write-SCBitLockerVolume -Name $letter -State $state -Method $method
        }
        if ($rows.Count -gt $shown) {
            Write-SCInfo -Message ("{0} additional BitLocker volumes were omitted." -f ($rows.Count - $shown))
        }
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'BitLocker volume status could not be read'
        } else {
            Write-SCInfo -Message 'BitLocker volume status is not available from this session.'
        }
    }
}

function Get-SCPropSafe {
    param($Object, [string]$Name)
    if (-not $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if (-not $prop) { return $null }
    return $prop.Value
}

function Invoke-SCCheckPlatform {
    Start-SCSection -Title 'Platform protection'
    if (Test-SCRegistryRoot -Root 'HKLM:\') {
        $hvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        Write-SCExpect -Spec (New-SCExpect -Path $hvci -Name 'Enabled' -Label 'HVCI' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'Memory integrity (HVCI) is not set. Prefer Enabled 1 where the hardware supports it.' `
            -GoodText 'Memory integrity (HVCI) Enabled is 1.' `
            -BadLevel 'REVIEW' -BadText 'Memory integrity (HVCI) Enabled is {0}. Prefer 1 where the hardware supports it.')
    } else {
        Write-SCHiveSkip -Root 'HKLM' -What 'HVCI policy'
    }
    Write-SCSecureBoot
    Write-SCBitLocker
}

function Invoke-SCCheckRemoteAccess {
    Start-SCSection -Title 'Remote access'
    if (-not (Test-SCRegistryRoot -Root 'HKLM:\')) {
        Write-SCHiveSkip -Root 'HKLM' -What 'Remote access policy'
        return
    }
    $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $winrmSvc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $winrmClient = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    Write-SCExpectTable -Specs @(
        (New-SCExpect -Path $rdp -Name 'fDenyTSConnections' -Label 'fDenyTSConnections' -Mode 'Equals' -Good 1 `
            -MissingLevel 'INFO' -MissingText 'fDenyTSConnections is not set.' `
            -GoodText 'Remote Desktop connections are denied (fDenyTSConnections is 1).' `
            -BadLevel 'REVIEW' -BadText 'Remote Desktop connections are allowed (fDenyTSConnections is {0}). Prefer 1 unless remote desktop is required, and then require network level authentication.')
        (New-SCExpect -Path $tcp -Name 'UserAuthentication' -Label 'UserAuthentication' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'RDP network level authentication (UserAuthentication) is not set. Prefer 1.' `
            -GoodText 'RDP network level authentication (UserAuthentication) is 1.' `
            -BadLevel 'REVIEW' -BadText 'RDP network level authentication (UserAuthentication) is {0}. Prefer 1.')
        (New-SCExpect -Path $tcp -Name 'SecurityLayer' -Label 'SecurityLayer' -Mode 'Equals' -Good 2 -Weak 0 `
            -MissingLevel 'INFO' -MissingText 'RDP SecurityLayer is not set.' `
            -GoodText 'RDP SecurityLayer is 2 (TLS).' `
            -BadLevel 'REVIEW' -BadText 'RDP SecurityLayer is {0}. Prefer 2 (TLS).')
        (New-SCExpect -Path $tcp -Name 'MinEncryptionLevel' -Label 'MinEncryptionLevel' -Mode 'Min' -Good 3 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'RDP MinEncryptionLevel is not set.' `
            -GoodText 'RDP MinEncryptionLevel is {0}.' `
            -BadLevel 'REVIEW' -BadText 'RDP MinEncryptionLevel is {0}. Prefer 3 (High) or 4 (FIPS).')
        (New-SCExpect -Path $winrmSvc -Name 'AllowUnencrypted' -Label 'WinRM service AllowUnencrypted' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'WinRM service AllowUnencrypted is not set.' `
            -GoodText 'WinRM service AllowUnencrypted is 0.' `
            -BadLevel 'REVIEW' -BadText 'WinRM service AllowUnencrypted is {0}. Prefer 0 so WinRM traffic is encrypted.')
        (New-SCExpect -Path $winrmClient -Name 'AllowUnencrypted' -Label 'WinRM client AllowUnencrypted' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'WinRM client AllowUnencrypted is not set.' `
            -GoodText 'WinRM client AllowUnencrypted is 0.' `
            -BadLevel 'REVIEW' -BadText 'WinRM client AllowUnencrypted is {0}. Prefer 0 so WinRM traffic is encrypted.')
        (New-SCExpect -Path $winrmSvc -Name 'AllowBasic' -Label 'WinRM service AllowBasic' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'WinRM service AllowBasic is not set.' `
            -GoodText 'WinRM service AllowBasic is 0.' `
            -BadLevel 'REVIEW' -BadText 'WinRM service basic authentication is allowed (AllowBasic is {0}). Prefer 0.')
    )
    Write-SCWindowsService -Name 'TermService' -Label 'Remote Desktop Services'
    Write-SCWindowsService -Name 'WinRM' -Label 'WinRM'
}

function Write-SCNetBiosOptions {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    if (-not (Test-SCRegistryRoot -Root $root)) {
        Write-SCInfo -Message 'NetBIOS interface parameters were not found.'
        return
    }
    $disabled = 0
    $enabled = 0
    $defaulted = 0
    $other = 0
    $seen = 0
    $truncated = $false
    try {
        $keys = ConvertTo-SCArray (Get-ChildItem -LiteralPath $root -ErrorAction Stop)
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'NetBIOS interface options could not be read'
        } else {
            Write-SCWarn -Message ("NetBIOS interface options could not be read: {0}" -f (Format-SCTrim -Text $message -Max 140))
        }
        return
    }
    foreach ($key in $keys) {
        if (-not $key) { continue }
        $seen++
        if ($seen -gt 30) { $truncated = $true; break }
        $opt = Get-SCRegistryValue -Path (Join-SCRegPath -Root $root -Child ([string]$key.PSChildName)) -Name 'NetbiosOptions'
        if ($opt.Error) { continue }
        if (-not $opt.Found) { continue }
        $text = [string]$opt.Value
        if ($text -eq '2') { $disabled++ }
        elseif ($text -eq '1') { $enabled++ }
        elseif ($text -eq '0') { $defaulted++ }
        else { $other++ }
    }
    $total = $disabled + $enabled + $defaulted + $other
    if ($total -eq 0) {
        Write-SCInfo -Message 'NetBIOS interface options were not found.'
        return
    }
    Write-SCInfo -Message ("NetBIOS over TCP/IP adapters: {0} disabled, {1} enabled, {2} default, {3} other." -f $disabled, $enabled, $defaulted, $other)
    if ($enabled -gt 0) {
        Write-SCReview -Message ("{0} adapters have NetBIOS enabled (NetbiosOptions 1). Prefer 2 to disable it." -f $enabled)
    }
    if ($defaulted -gt 0) {
        Write-SCReview -Message ("{0} adapters leave NetBIOS at the default (NetbiosOptions 0). Prefer 2 to disable it." -f $defaulted)
    }
    if ($truncated) {
        Write-SCInfo -Message 'Additional NetBIOS adapters were not inspected.'
    }
}

function Invoke-SCCheckSmbName {
    Start-SCSection -Title 'SMB and name resolution'
    if (-not (Test-SCRegistryRoot -Root 'HKLM:\')) {
        Write-SCHiveSkip -Root 'HKLM' -What 'SMB and name resolution'
        return
    }
    $server = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $client = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $dns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $mdns = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    $smb1 = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    Write-SCExpectTable -Specs @(
        (New-SCExpect -Path $server -Name 'RequireSecuritySignature' -Label 'Server RequireSecuritySignature' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'SMB server signing is not required. Prefer RequireSecuritySignature 1 where clients support it.' `
            -GoodText 'SMB server RequireSecuritySignature is 1.' `
            -BadLevel 'REVIEW' -BadText 'SMB server RequireSecuritySignature is {0}. Prefer 1 where clients support it.')
        (New-SCExpect -Path $server -Name 'EnableSecuritySignature' -Label 'Server EnableSecuritySignature' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'SMB server signing is not enabled by policy value. Prefer EnableSecuritySignature 1.' `
            -GoodText 'SMB server EnableSecuritySignature is 1.' `
            -BadLevel 'REVIEW' -BadText 'SMB server EnableSecuritySignature is {0}. Prefer 1.')
        (New-SCExpect -Path $client -Name 'RequireSecuritySignature' -Label 'Client RequireSecuritySignature' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'SMB client signing is not required. Prefer RequireSecuritySignature 1.' `
            -GoodText 'SMB client RequireSecuritySignature is 1.' `
            -BadLevel 'REVIEW' -BadText 'SMB client RequireSecuritySignature is {0}. Prefer 1.')
        (New-SCExpect -Path $client -Name 'EnableSecuritySignature' -Label 'Client EnableSecuritySignature' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'SMB client signing is not enabled by policy value. Prefer EnableSecuritySignature 1.' `
            -GoodText 'SMB client EnableSecuritySignature is 1.' `
            -BadLevel 'REVIEW' -BadText 'SMB client EnableSecuritySignature is {0}. Prefer 1.')
        (New-SCExpect -Path $client -Name 'EnablePlainTextPassword' -Label 'EnablePlainTextPassword' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'SMB client EnablePlainTextPassword is not set.' `
            -GoodText 'SMB client EnablePlainTextPassword is 0.' `
            -BadLevel 'REVIEW' -BadText 'SMB client EnablePlainTextPassword is {0}. Prefer 0.')
        (New-SCExpect -Path $server -Name 'SMB1' -Label 'SMB1' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'REVIEW' -MissingText 'SMB1 server value is not set. Prefer SMB1 0.' `
            -GoodText 'SMB1 server value is 0.' `
            -BadLevel 'REVIEW' -BadText 'SMB1 server value is {0}. Prefer 0.')
        (New-SCExpect -Path $smb1 -Name 'Start' -Label 'mrxsmb10 Start' -Mode 'Equals' -Good 4 `
            -MissingLevel 'INFO' -MissingText 'SMB1 client service mrxsmb10 is not present.' `
            -GoodText 'SMB1 client service mrxsmb10 start type is disabled.' `
            -BadLevel 'REVIEW' -BadText 'SMB1 client service mrxsmb10 start type is {0}. Prefer 4 (disabled).')
        (New-SCExpect -Path $dns -Name 'EnableMulticast' -Label 'EnableMulticast' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'REVIEW' -MissingText 'LLMNR policy EnableMulticast is not set. Prefer 0 to disable LLMNR.' `
            -GoodText 'LLMNR policy EnableMulticast is 0.' `
            -BadLevel 'REVIEW' -BadText 'LLMNR policy EnableMulticast is {0}. Prefer 0 to disable LLMNR.')
        (New-SCExpect -Path $mdns -Name 'EnableMDNS' -Label 'EnableMDNS' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'REVIEW' -MissingText 'mDNS EnableMDNS is not set. Prefer 0 to disable multicast DNS.' `
            -GoodText 'mDNS EnableMDNS is 0.' `
            -BadLevel 'REVIEW' -BadText 'mDNS EnableMDNS is {0}. Prefer 0 to disable multicast DNS.')
    )
    Write-SCNetBiosOptions
}

function Write-SCScreenSetting {
    param([string]$Name, [string]$Label, $SpecUser, $SpecPolicy)
    $policyPath = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
    $userPath = 'HKCU:\Control Panel\Desktop'
    $policy = Get-SCRegistryValue -Path $policyPath -Name $Name
    if (Write-SCRegistryIssue -Result $policy -Label ($Label + ' policy')) { return }
    if ($policy.Found) {
        $spec = $SpecPolicy
        $spec.Path = $policyPath
        $spec.Name = $Name
        $finding = Get-SCExpectResult -Spec $spec -Found $true -Value $policy.Value
        Write-SCExpectLine -Level $finding.Level -Text ('Policy: ' + $finding.Text)
        return
    }
    $user = Get-SCRegistryValue -Path $userPath -Name $Name
    if (Write-SCRegistryIssue -Result $user -Label $Label) { return }
    $specUser = $SpecUser
    $specUser.Path = $userPath
    $specUser.Name = $Name
    $findingUser = Get-SCExpectResult -Spec $specUser -Found ([bool]$user.Found) -Value $user.Value
    Write-SCExpectLine -Level $findingUser.Level -Text $findingUser.Text
}

function Invoke-SCCheckSession {
    Start-SCSection -Title 'Session lock'
    $hkcu = Test-SCRegistryRoot -Root 'HKCU:\'
    $hklm = Test-SCRegistryRoot -Root 'HKLM:\'
    if (-not $hkcu -and -not $hklm) {
        Write-SCHiveSkip -Root 'HKCU/HKLM' -What 'Session lock'
        return
    }
    if ($hkcu) {
        $activeGood = 'Screen saver is active.'
        $activeMissing = 'Screen saver is not set. Prefer ScreenSaveActive 1 and a secure lock.'
        $activeBad = 'ScreenSaveActive is {0}. Prefer 1 so the lock can engage.'
        Write-SCScreenSetting -Name 'ScreenSaveActive' -Label 'ScreenSaveActive' `
            -SpecUser (New-SCExpect -Path 'x' -Name 'ScreenSaveActive' -Label 'ScreenSaveActive' -Mode 'Equals' -Good 1 -Weak 0 -MissingLevel 'REVIEW' -MissingText $activeMissing -GoodText $activeGood -BadText $activeBad) `
            -SpecPolicy (New-SCExpect -Path 'x' -Name 'ScreenSaveActive' -Label 'ScreenSaveActive' -Mode 'Equals' -Good 1 -Weak 0 -MissingLevel 'REVIEW' -MissingText $activeMissing -GoodText $activeGood -BadText $activeBad)
        $secureGood = 'Screen saver lock is required (ScreenSaverIsSecure is 1).'
        $secureMissing = 'ScreenSaverIsSecure is not set. Prefer 1 so the screen saver locks the session.'
        $secureBad = 'ScreenSaverIsSecure is {0}. Prefer 1 so the screen saver locks the session.'
        Write-SCScreenSetting -Name 'ScreenSaverIsSecure' -Label 'ScreenSaverIsSecure' `
            -SpecUser (New-SCExpect -Path 'x' -Name 'ScreenSaverIsSecure' -Label 'ScreenSaverIsSecure' -Mode 'Equals' -Good 1 -Weak 0 -MissingLevel 'REVIEW' -MissingText $secureMissing -GoodText $secureGood -BadText $secureBad) `
            -SpecPolicy (New-SCExpect -Path 'x' -Name 'ScreenSaverIsSecure' -Label 'ScreenSaverIsSecure' -Mode 'Equals' -Good 1 -Weak 0 -MissingLevel 'REVIEW' -MissingText $secureMissing -GoodText $secureGood -BadText $secureBad)
        $timeGood = 'Screen saver timeout is {0} seconds.'
        $timeMissing = 'ScreenSaveTimeOut is not set. Prefer 900 seconds or less.'
        $timeBad = 'Screen saver timeout is {0} seconds. Prefer 900 or less, and not 0.'
        Write-SCScreenSetting -Name 'ScreenSaveTimeOut' -Label 'ScreenSaveTimeOut' `
            -SpecUser (New-SCExpect -Path 'x' -Name 'ScreenSaveTimeOut' -Label 'ScreenSaveTimeOut' -Mode 'Max' -Good 900 -Weak 0 -MissingLevel 'REVIEW' -MissingText $timeMissing -GoodText $timeGood -BadText $timeBad) `
            -SpecPolicy (New-SCExpect -Path 'x' -Name 'ScreenSaveTimeOut' -Label 'ScreenSaveTimeOut' -Mode 'Max' -Good 900 -Weak 0 -MissingLevel 'REVIEW' -MissingText $timeMissing -GoodText $timeGood -BadText $timeBad)
    } else {
        Write-SCHiveSkip -Root 'HKCU' -What 'Screen saver settings'
    }
    if ($hklm) {
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Write-SCExpect -Spec (New-SCExpect -Path $winlogon -Name 'DisableCAD' -Label 'DisableCAD' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'DisableCAD is not set.' `
            -GoodText 'Secure attention sequence is required (DisableCAD is 0).' `
            -BadLevel 'REVIEW' -BadText 'DisableCAD is {0}. Prefer 0 so the secure attention sequence stays available.')
    } else {
        Write-SCHiveSkip -Root 'HKLM' -What 'DisableCAD'
    }
}

function Get-SCAsrStateLabel {
    param($Value)
    switch ([string]$Value) {
        '0' { return 'off' }
        '1' { return 'block' }
        '2' { return 'audit' }
        '6' { return 'warn' }
        default { return 'other' }
    }
}

function Get-SCAsrRuleLabel {
    param([string]$Id)
    $key = $Id.ToLower()
    switch ($key) {
        '56a863a9-875e-4185-98a7-b882c64b5ce5' { return 'vulnerable signed drivers' }
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' { return 'Adobe Reader child processes' }
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' { return 'Office child processes' }
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' { return 'LSASS protection' }
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' { return 'Office executable content' }
        '01443614-cd74-433a-b99e-2ecdc07bfc25' { return 'executable content from email' }
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' { return 'obfuscated scripts' }
        'd3e037e1-3eb8-44c8-a917-57927947596d' { return 'script hosts' }
        '3b576869-a4ec-4529-8536-b80a7769e899' { return 'Office process injection' }
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' { return 'Office from other processes' }
        '26190899-1602-49e8-8b27-eb1d0a1ce869' { return 'Office communication child processes' }
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' { return 'WMI event subscription' }
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' { return 'PSExec and WMI process creation' }
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' { return 'untrusted USB processes' }
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' { return 'Win32 API from Office macros' }
        'c1db55ab-c21a-4637-bb3f-a12568109d35' { return 'advanced ransomware protection' }
        default { return 'unlisted rule' }
    }
}

function Write-SCDefenderNameList {
    param([string]$Title, $Values)
    $items = ConvertTo-SCArray $Values
    $count = 0
    $shown = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        if ([string]::IsNullOrWhiteSpace([string]$item)) { continue }
        $count++
        if ($shown.Count -lt 8) { [void]$shown.Add((Format-SCTrim -Text ([string]$item) -Max 80)) }
    }
    if ($count -eq 0) {
        Write-SCInfo -Message ("{0}: 0." -f $Title)
        return
    }
    $suffix = ''
    if ($count -gt $shown.Count) { $suffix = ' (list truncated)' }
    Write-SCReview -Message ("{0}: {1}. Prefer reviewing whether each entry is still required. Names: {2}{3}" -f $Title, $count, ($shown.ToArray() -join ', '), $suffix)
}

function Invoke-SCCheckDefenderExtras {
    Start-SCSection -Title 'Defender additions'
    Write-SCInfo -Message 'Defender real-time protection, AppLocker, and WDAC are reported by the system module.'
    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-SCInfo -Message 'Defender preference cmdlet is not available in this session.'
        return
    }
    try {
        $pref = Get-MpPreference -ErrorAction Stop
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'Defender preferences could not be read'
        } else {
            Write-SCWarn -Message ("Defender preferences could not be read: {0}" -f (Format-SCTrim -Text $message -Max 140))
        }
        return
    }
    if (-not $pref) {
        Write-SCInfo -Message 'Defender preferences were not returned.'
        return
    }
    $mapsProp = $pref.PSObject.Properties['MAPSReporting']
    if ($mapsProp) {
        $maps = [string]$mapsProp.Value
        if ($maps -eq '0' -or $maps -eq 'Disabled') {
            Write-SCReview -Message 'Cloud-delivered protection reporting is disabled (MAPSReporting 0). Prefer 1 (basic) or 2 (advanced).'
        } elseif ($maps -eq '1' -or $maps -eq 'Basic') {
            Write-SCInfo -Message 'Cloud-delivered protection reporting is basic (MAPSReporting 1).'
        } elseif ($maps -eq '2' -or $maps -eq 'Advanced') {
            Write-SCInfo -Message 'Cloud-delivered protection reporting is advanced (MAPSReporting 2).'
        } elseif ($maps) {
            Write-SCInfo -Message ("Cloud-delivered protection MAPSReporting: {0}." -f $maps)
        } else {
            Write-SCInfo -Message 'Cloud-delivered protection MAPSReporting was not set.'
        }
    }
    $sampleProp = $pref.PSObject.Properties['SubmitSamplesConsent']
    if ($sampleProp -and [string]$sampleProp.Value) {
        $sample = [string]$sampleProp.Value
        $sampleLabel = 'unrecognized'
        if ($sample -eq '0' -or $sample -eq 'AlwaysPrompt') { $sampleLabel = 'always prompt' }
        elseif ($sample -eq '1' -or $sample -eq 'SendSafeSamplesAutomatically') { $sampleLabel = 'send safe samples automatically' }
        elseif ($sample -eq '2' -or $sample -eq 'NeverSend') { $sampleLabel = 'never send' }
        elseif ($sample -eq '3' -or $sample -eq 'SendAllSamplesAutomatically') { $sampleLabel = 'send all samples automatically' }
        Write-SCInfo -Message ("Defender sample submission: {0} ({1})." -f $sample, $sampleLabel)
    }
    $pathProp = $pref.PSObject.Properties['ExclusionPath']
    $extProp = $pref.PSObject.Properties['ExclusionExtension']
    $procProp = $pref.PSObject.Properties['ExclusionProcess']
    if ($pathProp) { Write-SCDefenderNameList -Title 'Defender path exclusions' -Values $pathProp.Value }
    if ($extProp) { Write-SCDefenderNameList -Title 'Defender extension exclusions' -Values $extProp.Value }
    if ($procProp) { Write-SCDefenderNameList -Title 'Defender process exclusions' -Values $procProp.Value }

    $idProp = $pref.PSObject.Properties['AttackSurfaceReductionRules_Ids']
    $actProp = $pref.PSObject.Properties['AttackSurfaceReductionRules_Actions']
    if (-not $idProp) {
        Write-SCInfo -Message 'No ASR rules were returned.'
        return
    }
    $ids = ConvertTo-SCArray $idProp.Value
    $actions = @()
    if ($actProp) { $actions = ConvertTo-SCArray $actProp.Value }
    if ($ids.Count -eq 0) {
        Write-SCInfo -Message 'No ASR rules were returned.'
        return
    }
    $block = 0
    $audit = 0
    $off = 0
    $other = 0
    $details = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $id = [string]$ids[$i]
        if (-not $id) { continue }
        $action = $null
        if ($i -lt $actions.Count) { $action = $actions[$i] }
        $state = Get-SCAsrStateLabel -Value $action
        if ($state -eq 'block') { $block++ }
        elseif ($state -eq 'audit') { $audit++ }
        elseif ($state -eq 'off') { $off++ }
        else { $other++ }
        if (($state -eq 'off' -or $state -eq 'audit') -and $details.Count -lt 12) {
            $ruleName = Get-SCAsrRuleLabel -Id $id
            [void]$details.Add(('{0} ({1})' -f $ruleName, $state))
        }
    }
    Write-SCInfo -Message ("ASR rules: {0} block, {1} audit, {2} off, {3} other." -f $block, $audit, $off, $other)
    if ($off -gt 0) {
        Write-SCReview -Message 'One or more ASR rules are off. Prefer block where the installed applications allow it.'
    }
    if ($details.Count -gt 0) {
        Write-SCInfo -Message ("ASR rules not set to block: {0}." -f ($details.ToArray() -join ', '))
    }
}

function Test-SCFilterAny {
    param($Value)
    foreach ($item in (ConvertTo-SCArray $Value)) {
        $text = [string]$item
        if ($text -eq 'Any' -or $text -eq '*') { return $true }
    }
    return $false
}

function Invoke-SCCheckFirewallRules {
    Start-SCSection -Title 'Firewall allow rules'
    Write-SCInfo -Message 'Firewall profile enablement and default inbound action are reported by the network module.'
    $have = [bool](Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)
    if (-not $have -and (Get-Command -Name Import-Module -ErrorAction SilentlyContinue)) {
        try {
            Import-Module NetSecurity -ErrorAction Stop
            $have = [bool](Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)
        } catch {
            $have = $false
        }
    }
    if (-not $have) {
        Write-SCInfo -Message 'Inbound allow rules could not be listed from this session.'
        return
    }
    try {
        $rules = ConvertTo-SCArray (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'Inbound allow rules could not be read'
        } else {
            Write-SCWarn -Message ("Inbound allow rules could not be read: {0}" -f (Format-SCTrim -Text $message -Max 140))
        }
        return
    }
    if ($rules.Count -eq 0) {
        Write-SCInfo -Message 'No enabled inbound allow rules were returned.'
        return
    }
    $checked = 0
    $broad = 0
    $shown = New-Object System.Collections.Generic.List[string]
    $portCmd = [bool](Get-Command -Name Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
    $addrCmd = [bool](Get-Command -Name Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)
    if (-not $portCmd -or -not $addrCmd) {
        Write-SCInfo -Message ("Enabled inbound allow rules: {0}. Port and address filters were not available." -f $rules.Count)
        return
    }
    foreach ($rule in $rules) {
        if (-not $rule) { continue }
        if ($checked -ge 40) { break }
        $checked++
        try {
            $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        } catch {
            continue
        }
        $localAny = Test-SCFilterAny -Value (Get-SCPropSafe -Object $port -Name 'LocalPort')
        $remoteAny = Test-SCFilterAny -Value (Get-SCPropSafe -Object $addr -Name 'RemoteAddress')
        if ($localAny -and $remoteAny) {
            $broad++
            if ($shown.Count -lt 8) {
                $display = [string](Get-SCPropSafe -Object $rule -Name 'DisplayName')
                if (-not $display) { $display = [string](Get-SCPropSafe -Object $rule -Name 'Name') }
                [void]$shown.Add((Format-SCTrim -Text $display -Max 80))
            }
        }
    }
    Write-SCInfo -Message ("Enabled inbound allow rules: {0}. Inspected {1} for any local port and any remote address." -f $rules.Count, $checked)
    if ($broad -eq 0) {
        Write-SCInfo -Message 'None of the inspected inbound allow rules were any-port and any-remote.'
    } else {
        $suffix = ''
        if ($broad -gt $shown.Count) { $suffix = ' (list truncated)' }
        Write-SCReview -Message ("{0} inspected inbound allow rules are any local port and any remote address. Prefer a specific port and remote scope. Names: {1}{2}" -f $broad, ($shown.ToArray() -join ', '), $suffix)
    }
    if ($rules.Count -gt $checked) {
        Write-SCInfo -Message ("{0} additional inbound allow rules were not inspected." -f ($rules.Count - $checked))
    }
}

function Write-SCWinlogonCommand {
    param([string]$Path)
    $shell = Get-SCRegistryValue -Path $Path -Name 'Shell'
    if (Write-SCRegistryIssue -Result $shell -Label 'Winlogon Shell') { return }
    if (-not $shell.Found -or [string]::IsNullOrWhiteSpace([string]$shell.Value)) {
        Write-SCReview -Message 'Winlogon Shell is not set. The usual value is explorer.exe.'
    } else {
        $leaf = Get-SCLeafName -Text ([string]$shell.Value)
        if ([string]::Equals($leaf, 'explorer.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-SCInfo -Message 'Winlogon Shell is explorer.exe.'
        } else {
            Write-SCReview -Message ("Winlogon Shell is {0}. The usual value is explorer.exe." -f (Format-SCTrim -Text ([string]$shell.Value) -Max 100))
        }
    }
    $userinit = Get-SCRegistryValue -Path $Path -Name 'Userinit'
    if (Write-SCRegistryIssue -Result $userinit -Label 'Winlogon Userinit') { return }
    if (-not $userinit.Found -or [string]::IsNullOrWhiteSpace([string]$userinit.Value)) {
        Write-SCReview -Message 'Winlogon Userinit is not set. The usual value ends with userinit.exe.'
        return
    }
    $pieces = New-Object System.Collections.Generic.List[string]
    $unexpected = New-Object System.Collections.Generic.List[string]
    foreach ($part in ([string]$userinit.Value).Split(',')) {
        $token = $part.Trim().Trim('"')
        if (-not $token) { continue }
        [void]$pieces.Add($token)
        $leaf = Get-SCLeafName -Text $token
        if (-not [string]::Equals($leaf, 'userinit.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$unexpected.Add((Format-SCTrim -Text $token -Max 80))
        }
    }
    if ($pieces.Count -eq 0) {
        Write-SCReview -Message 'Winlogon Userinit is empty. The usual value ends with userinit.exe.'
    } elseif ($unexpected.Count -eq 0) {
        Write-SCInfo -Message 'Winlogon Userinit points at userinit.exe.'
    } else {
        Write-SCReview -Message ("Winlogon Userinit includes values other than userinit.exe: {0}." -f ($unexpected.ToArray() -join ', '))
    }
}

function Get-SCIfeoDebuggerCount {
    param([string]$Root)
    $result = New-Object psobject -Property @{
        Found = 0
        Lines = (New-Object System.Collections.Generic.List[string])
        Error = $null
    }
    if (-not (Test-SCRegistryRoot -Root $Root)) { return $result }
    try {
        $keys = ConvertTo-SCArray (Get-ChildItem -LiteralPath $Root -ErrorAction Stop)
    } catch {
        $result.Error = $_.Exception.Message
        return $result
    }
    $seen = 0
    foreach ($key in $keys) {
        if (-not $key) { continue }
        $seen++
        if ($seen -gt 200) { break }
        $name = [string]$key.PSChildName
        if (-not $name) { continue }
        $dbg = Get-SCRegistryValue -Path (Join-SCRegPath -Root $Root -Child $name) -Name 'Debugger'
        if ($dbg.Error -or -not $dbg.Found) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$dbg.Value)) { continue }
        $result.Found++
        if ($result.Lines.Count -lt 15) {
            [void]$result.Lines.Add(('{0}: {1}' -f $name, (Format-SCTrim -Text ([string]$dbg.Value) -Max 80)))
        }
    }
    return $result
}

function Invoke-SCCheckStartupRegistry {
    Start-SCSection -Title 'Startup registry values'
    if (-not (Test-SCRegistryRoot -Root 'HKLM:\')) {
        Write-SCHiveSkip -Root 'HKLM' -What 'Startup registry values'
        return
    }
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Write-SCWinlogonCommand -Path $winlogon
    $windowsKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $windowsWow = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    Write-SCExpectTable -Specs @(
        (New-SCExpect -Path $windowsKey -Name 'LoadAppInit_DLLs' -Label 'LoadAppInit_DLLs' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'LoadAppInit_DLLs is not set.' `
            -GoodText 'LoadAppInit_DLLs is 0.' `
            -BadLevel 'REVIEW' -BadText 'LoadAppInit_DLLs is {0}. Prefer 0.')
        (New-SCExpect -Path $windowsKey -Name 'AppInit_DLLs' -Label 'AppInit_DLLs' -Mode 'Absent' `
            -MissingLevel 'INFO' -MissingText 'AppInit_DLLs is not set.' `
            -GoodText 'AppInit_DLLs is not set.' `
            -BadLevel 'REVIEW' -BadText 'AppInit_DLLs is set: {0}. Prefer this value empty and LoadAppInit_DLLs 0.')
        (New-SCExpect -Path $windowsWow -Name 'LoadAppInit_DLLs' -Label 'Wow64 LoadAppInit_DLLs' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'Wow64 LoadAppInit_DLLs is not set.' `
            -GoodText 'Wow64 LoadAppInit_DLLs is 0.' `
            -BadLevel 'REVIEW' -BadText 'Wow64 LoadAppInit_DLLs is {0}. Prefer 0.')
        (New-SCExpect -Path $windowsWow -Name 'AppInit_DLLs' -Label 'Wow64 AppInit_DLLs' -Mode 'Absent' `
            -MissingLevel 'INFO' -MissingText 'Wow64 AppInit_DLLs is not set.' `
            -GoodText 'Wow64 AppInit_DLLs is not set.' `
            -BadLevel 'REVIEW' -BadText 'Wow64 AppInit_DLLs is set: {0}. Prefer this value empty.')
    )
    $ifeoRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )
    $total = 0
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($root in $ifeoRoots) {
        $bag = Get-SCIfeoDebuggerCount -Root $root
        if ($bag.Error) {
            if (Test-SCAccessDenied -Message $bag.Error) {
                Write-SCNeedsAdmin -Detail 'Image File Execution Options could not be read'
            } else {
                Write-SCWarn -Message ("Image File Execution Options could not be read: {0}" -f (Format-SCTrim -Text $bag.Error -Max 140))
            }
            continue
        }
        $total += [int]$bag.Found
        foreach ($line in (ConvertTo-SCArray $bag.Lines)) {
            if ($lines.Count -ge 15) { break }
            if ($line) { [void]$lines.Add([string]$line) }
        }
    }
    if ($total -eq 0) {
        Write-SCInfo -Message 'No Image File Execution Options Debugger values were found.'
    } else {
        Write-SCReview -Message ("Image File Execution Options Debugger values: {0}." -f $total)
        foreach ($line in $lines) {
            Write-SCInfo -Message ("Debugger entry: {0}" -f $line)
        }
        if ($total -gt $lines.Count) {
            Write-SCInfo -Message ("{0} additional Debugger entries were omitted." -f ($total - $lines.Count))
        }
    }
    $print = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    Write-SCExpectTable -Specs @(
        (New-SCExpect -Path $print -Name 'NoWarningNoElevationOnInstall' -Label 'NoWarningNoElevationOnInstall' -Mode 'Equals' -Good 0 -Weak 1 `
            -MissingLevel 'INFO' -MissingText 'Point and Print NoWarningNoElevationOnInstall is not set.' `
            -GoodText 'Point and Print NoWarningNoElevationOnInstall is 0.' `
            -BadLevel 'REVIEW' -BadText 'Point and Print NoWarningNoElevationOnInstall is {0}. Prefer 0 so driver install still prompts.')
        (New-SCExpect -Path $print -Name 'UpdatePromptSettings' -Label 'UpdatePromptSettings' -Mode 'Min' -Good 2 -Weak 0 `
            -MissingLevel 'INFO' -MissingText 'Point and Print UpdatePromptSettings is not set.' `
            -GoodText 'Point and Print UpdatePromptSettings is {0}.' `
            -BadLevel 'REVIEW' -BadText 'Point and Print UpdatePromptSettings is {0}. Prefer 2 so updates show a warning.')
        (New-SCExpect -Path $print -Name 'RestrictDriverInstallationToAdministrators' -Label 'RestrictDriverInstallationToAdministrators' -Mode 'Equals' -Good 1 -Weak 0 `
            -MissingLevel 'REVIEW' -MissingText 'RestrictDriverInstallationToAdministrators is not set. Prefer 1 so only administrators install printer drivers.' `
            -GoodText 'RestrictDriverInstallationToAdministrators is 1.' `
            -BadLevel 'REVIEW' -BadText 'RestrictDriverInstallationToAdministrators is {0}. Prefer 1 so only administrators install printer drivers.')
    )
}

function Write-SCPendingReboot {
    $pending = 0
    $rebootKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $cbsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if (Test-SCRegistryRoot -Root $rebootKey) {
        $pending++
        Write-SCReview -Message 'A Windows Update reboot is pending (RebootRequired is present).'
    }
    if (Test-SCRegistryRoot -Root $cbsKey) {
        $pending++
        Write-SCReview -Message 'Component Based Servicing reports a pending reboot.'
    }
    $rename = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($rename.Error) {
        Write-SCRegistryIssue -Result $rename -Label 'PendingFileRenameOperations' | Out-Null
    } elseif ($rename.Found) {
        $count = 0
        $items = ConvertTo-SCArray $rename.Value
        foreach ($item in $items) {
            if (-not [string]::IsNullOrWhiteSpace([string]$item)) { $count++ }
        }
        if ($count -gt 0) {
            $pending++
            Write-SCReview -Message ("Pending file rename operations: {0}. Paths were not printed. A reboot may still be required." -f $count)
        }
    }
    if ($pending -eq 0) {
        Write-SCInfo -Message 'No pending-reboot indicators were found.'
    }
}

function Invoke-SCCheckUpdates {
    Start-SCSection -Title 'Update posture'
    if (-not (Test-SCRegistryRoot -Root 'HKLM:\')) {
        Write-SCHiveSkip -Root 'HKLM' -What 'Update posture'
        return
    }
    Write-SCPendingReboot
    $install = Get-SCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -Name 'LastSuccessTime'
    if ($install.Error) {
        Write-SCRegistryIssue -Result $install -Label 'Last Windows Update success' | Out-Null
    } elseif ($install.Found -and $install.Value) {
        Write-SCInfo -Message ("Last successful Windows Update install time: {0}." -f (Format-SCTrim -Text ([string]$install.Value) -Max 40))
    } else {
        Write-SCInfo -Message 'Last successful Windows Update install time was not found in the result key.'
    }
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    Write-SCExpect -Spec (New-SCExpect -Path $au -Name 'NoAutoUpdate' -Label 'NoAutoUpdate' -Mode 'Equals' -Good 0 -Weak 1 `
        -MissingLevel 'INFO' -MissingText 'NoAutoUpdate policy is not set.' `
        -GoodText 'NoAutoUpdate policy is 0.' `
        -BadLevel 'REVIEW' -BadText 'Automatic updates are disabled by policy (NoAutoUpdate is {0}). Prefer 0 unless updates are managed another way.')
    $options = Get-SCRegistryValue -Path $au -Name 'AUOptions'
    if ($options.Error) {
        Write-SCRegistryIssue -Result $options -Label 'AUOptions' | Out-Null
    } elseif ($options.Found) {
        $label = 'unrecognized'
        switch ([string]$options.Value) {
            '2' { $label = 'notify before download' }
            '3' { $label = 'download automatically and notify before install' }
            '4' { $label = 'download and schedule install' }
            '5' { $label = 'allow the local administrator to choose' }
        }
        Write-SCInfo -Message ("Windows Update AUOptions: {0} ({1})." -f [string]$options.Value, $label)
    } else {
        Write-SCInfo -Message 'Windows Update AUOptions policy is not set.'
    }
    $useServer = Get-SCRegistryValue -Path $au -Name 'UseWUServer'
    if ($useServer.Error) {
        Write-SCRegistryIssue -Result $useServer -Label 'UseWUServer' | Out-Null
    } elseif ($useServer.Found -and [string]$useServer.Value -eq '1') {
        $server = Get-SCRegistryValue -Path $wu -Name 'WUServer'
        $status = Get-SCRegistryValue -Path $wu -Name 'WUStatusServer'
        $serverText = 'not set'
        $statusText = 'not set'
        if ($server.Found) { $serverText = Format-SCUrlText -Text ([string]$server.Value) }
        if ($status.Found) { $statusText = Format-SCUrlText -Text ([string]$status.Value) }
        Write-SCInfo -Message ("WSUS is enabled (UseWUServer is 1). Server: {0}. Status server: {1}." -f $serverText, $statusText)
    } elseif ($useServer.Found) {
        Write-SCInfo -Message ("UseWUServer is {0}." -f [string]$useServer.Value)
    } else {
        Write-SCInfo -Message 'UseWUServer policy is not set. This check does not scan for missing updates.'
    }
}

function Write-SCOfficeMacros {
    $products = @('word', 'excel', 'powerpoint')
    $hives = @('HKLM:\', 'HKCU:\')
    $found = 0
    foreach ($hive in $hives) {
        if (-not (Test-SCRegistryRoot -Root $hive)) { continue }
        foreach ($product in $products) {
            $path = $hive + 'SOFTWARE\Policies\Microsoft\Office\16.0\' + $product + '\security'
            $value = Get-SCRegistryValue -Path $path -Name 'VBAWarnings'
            if ($value.Error) { continue }
            if (-not $value.Found) { continue }
            $found++
            $code = [string]$value.Value
            $label = 'unrecognized'
            $level = 'REVIEW'
            if ($code -eq '1') { $label = 'enable all'; $level = 'WEAK' }
            elseif ($code -eq '2') { $label = 'disable with notification'; $level = 'INFO' }
            elseif ($code -eq '3') { $label = 'disable except digitally signed'; $level = 'INFO' }
            elseif ($code -eq '4') { $label = 'disable all'; $level = 'INFO' }
            $hiveName = 'HKLM'
            if ($hive -eq 'HKCU:\') { $hiveName = 'HKCU' }
            $text = ("Office {0} VBAWarnings ({1}) is {2} ({3})." -f $product, $hiveName, $code, $label)
            if ($level -eq 'WEAK') {
                $text = $text + ' Prefer 2, 3, or 4 so unsigned macros are not enabled for every document.'
                Write-SCWeak -Message $text
            } elseif ($level -eq 'REVIEW') {
                $text = $text + ' Prefer 2, 3, or 4.'
                Write-SCReview -Message $text
            } else {
                Write-SCInfo -Message $text
            }
        }
    }
    if ($found -eq 0) {
        Write-SCInfo -Message 'Office 16.0 macro policy keys were not set.'
    }
}

function Write-SCEnrollment {
    $enroll = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-SCRegistryRoot -Root $enroll)) {
        Write-SCInfo -Message 'No MDM enrollment key was found.'
    } else {
        $count = 0
        try {
            foreach ($key in (ConvertTo-SCArray (Get-ChildItem -LiteralPath $enroll -ErrorAction Stop))) {
                if ($key -and $key.PSChildName) { $count++ }
            }
            Write-SCInfo -Message ("MDM enrollment keys: {0}." -f $count)
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) {
                Write-SCNeedsAdmin -Detail 'MDM enrollment keys could not be read'
            } else {
                Write-SCWarn -Message ("MDM enrollment keys could not be read: {0}" -f (Format-SCTrim -Text $_.Exception.Message -Max 120))
            }
        }
    }
    $join = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    if (-not (Test-SCRegistryRoot -Root $join)) {
        Write-SCInfo -Message 'Azure AD join info was not found.'
        return
    }
    $joinCount = 0
    try {
        foreach ($key in (ConvertTo-SCArray (Get-ChildItem -LiteralPath $join -ErrorAction Stop))) {
            if ($key -and $key.PSChildName) { $joinCount++ }
        }
        Write-SCInfo -Message ("Azure AD join info entries: {0}." -f $joinCount)
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'Azure AD join info could not be read'
        } else {
            Write-SCInfo -Message 'Azure AD join info could not be read.'
        }
    }
}

function Invoke-SCCheckAdditional {
    Start-SCSection -Title 'Additional policy'
    $hklm = Test-SCRegistryRoot -Root 'HKLM:\'
    $hkcu = Test-SCRegistryRoot -Root 'HKCU:\'
    if (-not $hklm -and -not $hkcu) {
        Write-SCHiveSkip -Root 'HKLM/HKCU' -What 'Additional policy'
        return
    }
    if ($hklm) {
        $ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
        $explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Write-SCExpectTable -Specs @(
            (New-SCExpect -Path $ci -Name 'VulnerableDriverBlocklistEnable' -Label 'VulnerableDriverBlocklistEnable' -Mode 'Equals' -Good 1 -Weak 0 `
                -MissingLevel 'REVIEW' -MissingText 'Vulnerable driver blocklist is not set. Prefer VulnerableDriverBlocklistEnable 1.' `
                -GoodText 'Vulnerable driver blocklist is enabled.' `
                -BadLevel 'REVIEW' -BadText 'Vulnerable driver blocklist Enabled is {0}. Prefer 1.')
            (New-SCExpect -Path $explorer -Name 'NoDriveTypeAutoRun' -Label 'NoDriveTypeAutoRun' -Mode 'Equals' -Good 255 -Weak 0 `
                -MissingLevel 'REVIEW' -MissingText 'NoDriveTypeAutoRun is not set. Prefer 255 to disable AutoRun on all drive types.' `
                -GoodText 'NoDriveTypeAutoRun is 255. AutoRun is disabled for all drive types.' `
                -BadLevel 'REVIEW' -BadText 'NoDriveTypeAutoRun is {0}. Prefer 255 to disable AutoRun on all drive types.')
            (New-SCExpect -Path $explorer -Name 'NoAutorun' -Label 'NoAutorun' -Mode 'Equals' -Good 1 -Weak 0 `
                -MissingLevel 'REVIEW' -MissingText 'NoAutorun is not set. Prefer 1.' `
                -GoodText 'NoAutorun is 1.' `
                -BadLevel 'REVIEW' -BadText 'NoAutorun is {0}. Prefer 1.')
        )
        Write-SCEnrollment
    } else {
        Write-SCHiveSkip -Root 'HKLM' -What 'Driver blocklist, AutoRun, and enrollment'
    }
    if ($hklm -or $hkcu) {
        Write-SCOfficeMacros
    }
}

function Invoke-SCHardeningCheck {
    param([string]$Name)
    try {
        if ($Name -eq 'Credential policy') { Invoke-SCCheckCredentialPolicy }
        elseif ($Name -eq 'Platform protection') { Invoke-SCCheckPlatform }
        elseif ($Name -eq 'Remote access') { Invoke-SCCheckRemoteAccess }
        elseif ($Name -eq 'SMB and name resolution') { Invoke-SCCheckSmbName }
        elseif ($Name -eq 'Session lock') { Invoke-SCCheckSession }
        elseif ($Name -eq 'Defender additions') { Invoke-SCCheckDefenderExtras }
        elseif ($Name -eq 'Firewall allow rules') { Invoke-SCCheckFirewallRules }
        elseif ($Name -eq 'Startup registry values') { Invoke-SCCheckStartupRegistry }
        elseif ($Name -eq 'Update posture') { Invoke-SCCheckUpdates }
        elseif ($Name -eq 'Additional policy') { Invoke-SCCheckAdditional }
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCTrim -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Hardening'
Invoke-SCHardeningCheck -Name 'Credential policy'
Invoke-SCHardeningCheck -Name 'Platform protection'
Invoke-SCHardeningCheck -Name 'Remote access'
Invoke-SCHardeningCheck -Name 'SMB and name resolution'
Invoke-SCHardeningCheck -Name 'Session lock'
Invoke-SCHardeningCheck -Name 'Defender additions'
Invoke-SCHardeningCheck -Name 'Firewall allow rules'
Invoke-SCHardeningCheck -Name 'Startup registry values'
Invoke-SCHardeningCheck -Name 'Update posture'
Invoke-SCHardeningCheck -Name 'Additional policy'
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Hardening' -Style Dim

if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
