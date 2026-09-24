#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only bounded event-log summary.

.DESCRIPTION
    Counts recent errors, warnings, and a few high-signal event IDs.
    Lookback is 7 days. Each query stops at a hard event cap.
    Event record text is not printed. Logs are not cleared and audit
    policy is not changed. This module is not part of the default runner.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\10_events.ps1
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

$script:SCEventLookbackDays = 7
$script:SCEventChannelMax = 100
$script:SCEventSignalMax = 50
$script:SCEventSupport = $null
$script:SCSecurityDenied = $false

function Format-SCShortText {
    param([string]$Text, [int]$Max = 120)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = ([string]$Text -replace '[\r\n]+', ' ').Trim()
    if ($clean.Length -le $Max) { return $clean }
    return $clean.Substring(0, $Max)
}

function Get-SCEventQueryKind {
    param([string]$Message, [string]$ErrorId)
    if ($ErrorId -match 'NoMatchingEventsFound') { return 'empty' }
    if ([string]::IsNullOrWhiteSpace($Message)) { return 'other' }
    if ($Message -match 'No events were found') { return 'empty' }
    if (Test-SCAccessDenied -Message $Message) { return 'denied' }
    if ($Message -match 'Attempted to perform an unauthorized') { return 'denied' }
    if ($Message -match 'does not exist|Cannot find path|could not be found|There is not an event log') { return 'missing' }
    return 'other'
}

function Format-SCEventCount {
    param([int]$Count, [bool]$Capped, [int]$Max)
    if ($Capped) { return ('{0} or more' -f $Max) }
    return ([string]$Count)
}

function New-SCEventChannel {
    param([string]$LogName, [string]$Label, [bool]$Security)
    return New-Object psobject -Property @{
        LogName  = $LogName
        Label    = $Label
        Security = $Security
    }
}

function Get-SCEventChannels {
    $list = New-Object System.Collections.Generic.List[object]
    [void]$list.Add((New-SCEventChannel -LogName 'System' -Label 'System' -Security $false))
    [void]$list.Add((New-SCEventChannel -LogName 'Application' -Label 'Application' -Security $false))
    [void]$list.Add((New-SCEventChannel -LogName 'Security' -Label 'Security' -Security $true))
    [void]$list.Add((New-SCEventChannel -LogName 'Microsoft-Windows-Windows Defender/Operational' -Label 'Windows Defender Operational' -Security $false))
    [void]$list.Add((New-SCEventChannel -LogName 'Windows PowerShell' -Label 'Windows PowerShell' -Security $false))
    [void]$list.Add((New-SCEventChannel -LogName 'Microsoft-Windows-PowerShell/Operational' -Label 'PowerShell Operational' -Security $false))
    [void]$list.Add((New-SCEventChannel -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Label 'Task Scheduler Operational' -Security $false))
    return New-Object psobject -Property @{ Items = @($list.ToArray()) }
}

function New-SCEventSignal {
    param([int]$Id, [string]$LogName, [string]$Label, [string]$LevelName, [bool]$Security)
    return New-Object psobject -Property @{
        Id        = $Id
        LogName   = $LogName
        Label     = $Label
        LevelName = $LevelName
        Security  = $Security
    }
}

function Get-SCEventSignals {
    $list = New-Object System.Collections.Generic.List[object]
    [void]$list.Add((New-SCEventSignal -Id 4625 -LogName 'Security' -Label 'Failed logon' -LevelName 'REVIEW' -Security $true))
    [void]$list.Add((New-SCEventSignal -Id 4648 -LogName 'Security' -Label 'Explicit credential logon' -LevelName 'REVIEW' -Security $true))
    [void]$list.Add((New-SCEventSignal -Id 7045 -LogName 'System' -Label 'Service installed' -LevelName 'INFO' -Security $false))
    [void]$list.Add((New-SCEventSignal -Id 4104 -LogName 'Microsoft-Windows-PowerShell/Operational' -Label 'PowerShell script block' -LevelName 'INFO' -Security $false))
    return New-Object psobject -Property @{ Items = @($list.ToArray()) }
}

function Initialize-SCEventSupport {
    if ($null -ne $script:SCEventSupport) { return $script:SCEventSupport }
    $support = New-Object psobject -Property @{
        Available = $false
        Reason    = ''
    }
    $cmd = $null
    try { $cmd = Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue } catch { $cmd = $null }
    if (-not $cmd) {
        $support.Reason = 'missing-cmd'
        $script:SCEventSupport = $support
        return $support
    }
    try {
        $null = Get-WinEvent -ListLog System -ErrorAction Stop
        $support.Available = $true
    } catch {
        $msg = ''
        $errorId = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        try { $errorId = [string]$_.FullyQualifiedErrorId } catch { $errorId = '' }
        $kind = Get-SCEventQueryKind -Message $msg -ErrorId $errorId
        if ($kind -eq 'denied' -or $kind -eq 'missing' -or $kind -eq 'empty') {
            $support.Available = $true
        } else {
            $support.Reason = 'unavailable'
        }
    }
    $script:SCEventSupport = $support
    return $support
}

function Get-SCEventLogState {
    param([string]$LogName)
    $state = New-Object psobject -Property @{
        Exists   = $false
        Disabled = $false
        Kind     = 'other'
        Error    = ''
    }
    try {
        $found = $null
        foreach ($item in @(Get-WinEvent -ListLog $LogName -ErrorAction Stop)) {
            if ($null -ne $item) { $found = $item; break }
        }
        if ($null -eq $found) {
            $state.Kind = 'missing'
            return $state
        }
        $state.Exists = $true
        $state.Kind = 'ok'
        try {
            if (-not $found.IsEnabled) { $state.Disabled = $true }
        } catch { }
    } catch {
        $msg = ''
        $errorId = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        try { $errorId = [string]$_.FullyQualifiedErrorId } catch { $errorId = '' }
        $state.Kind = Get-SCEventQueryKind -Message $msg -ErrorId $errorId
        $state.Error = $msg
        if ($state.Kind -eq 'denied') { $state.Exists = $true }
    }
    return $state
}

function Measure-SCWinEvents {
    param(
        [string]$LogName,
        [int]$Days,
        [int]$MaxEvents,
        [int]$Level = 0,
        [int]$Id = 0
    )
    $limit = $MaxEvents
    if ($limit -lt 1) { $limit = 1 }
    if ($limit -gt 100) { $limit = 100 }
    $window = $Days
    if ($window -lt 1) { $window = 1 }
    if ($window -gt 7) { $window = 7 }

    $result = New-Object psobject -Property @{
        Count  = 0
        Capped = $false
        Kind   = 'ok'
        Error  = ''
        Max    = $limit
    }

    $filter = @{
        LogName   = $LogName
        StartTime = (Get-Date).AddDays(-1 * $window)
    }
    if ($Level -gt 0) { $filter['Level'] = $Level }
    if ($Id -gt 0) { $filter['Id'] = $Id }

    try {
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents $limit -ErrorAction Stop
        $count = 0
        foreach ($item in @($raw)) {
            if ($null -ne $item) { $count++ }
        }
        $result.Count = $count
        if ($count -ge $limit) { $result.Capped = $true }
        $result.Kind = 'ok'
    } catch {
        $msg = ''
        $errorId = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        try { $errorId = [string]$_.FullyQualifiedErrorId } catch { $errorId = '' }
        $kind = Get-SCEventQueryKind -Message $msg -ErrorId $errorId
        if ($kind -eq 'empty') {
            $result.Count = 0
            $result.Capped = $false
            $result.Kind = 'ok'
            $result.Error = ''
        } else {
            $result.Kind = $kind
            $result.Error = $msg
        }
    }
    return $result
}

function Invoke-SCCheckEventChannels {
    Start-SCSection -Title 'Event channels'
    $support = Initialize-SCEventSupport
    if (-not $support.Available) {
        if ($support.Reason -eq 'missing-cmd') {
            Write-SCWarn -Message 'Get-WinEvent is not available, so event logs were not read.'
        } else {
            Write-SCWarn -Message 'Event log queries are not available on this host.'
        }
        return
    }

    Write-SCInfo -Message ("Lookback: {0} days. Each count stops at {1} events." -f $script:SCEventLookbackDays, $script:SCEventChannelMax)
    Write-SCInfo -Message 'Event messages were not printed.'

    $defs = Get-SCEventChannels
    foreach ($ch in @($defs.Items)) {
        $state = Get-SCEventLogState -LogName $ch.LogName
        if ($state.Kind -eq 'missing') {
            Write-SCInfo -Message ("{0}: not present." -f $ch.Label)
            continue
        }
        if ($state.Kind -eq 'denied') {
            if ($ch.Security) { $script:SCSecurityDenied = $true }
            Write-SCNeedsAdmin -Detail ("{0} log could not be read." -f $ch.Label)
            continue
        }
        if ($state.Kind -ne 'ok') {
            Write-SCWarn -Message ("{0} log could not be listed: {1}" -f $ch.Label, (Format-SCShortText -Text $state.Error -Max 160))
            continue
        }

        $disabled = ''
        if ($state.Disabled) { $disabled = ' The log is disabled.' }

        if ($ch.Security) {
            $recent = Measure-SCWinEvents -LogName $ch.LogName -Days $script:SCEventLookbackDays -MaxEvents $script:SCEventChannelMax
            if ($recent.Kind -eq 'denied') {
                $script:SCSecurityDenied = $true
                Write-SCNeedsAdmin -Detail 'Security log could not be read.'
                continue
            }
            if ($recent.Kind -eq 'missing') {
                Write-SCInfo -Message 'Security: not present.'
                continue
            }
            if ($recent.Kind -ne 'ok') {
                Write-SCWarn -Message ("Security log could not be counted: {0}" -f (Format-SCShortText -Text $recent.Error -Max 160))
                continue
            }
            $countText = Format-SCEventCount -Count $recent.Count -Capped $recent.Capped -Max $recent.Max
            Write-SCInfo -Message ("Security: present and readable. Recent events: {0}.{1}" -f $countText, $disabled)
            continue
        }

        $errors = Measure-SCWinEvents -LogName $ch.LogName -Days $script:SCEventLookbackDays -MaxEvents $script:SCEventChannelMax -Level 2
        $warnings = Measure-SCWinEvents -LogName $ch.LogName -Days $script:SCEventLookbackDays -MaxEvents $script:SCEventChannelMax -Level 3
        if ($errors.Kind -eq 'denied' -or $warnings.Kind -eq 'denied') {
            Write-SCNeedsAdmin -Detail ("{0} log could not be read." -f $ch.Label)
            continue
        }
        if ($errors.Kind -eq 'missing' -or $warnings.Kind -eq 'missing') {
            Write-SCInfo -Message ("{0}: not present." -f $ch.Label)
            continue
        }
        if ($errors.Kind -ne 'ok' -or $warnings.Kind -ne 'ok') {
            $detail = $errors.Error
            if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $warnings.Error }
            Write-SCWarn -Message ("{0} log could not be counted: {1}" -f $ch.Label, (Format-SCShortText -Text $detail -Max 160))
            continue
        }
        $errText = Format-SCEventCount -Count $errors.Count -Capped $errors.Capped -Max $errors.Max
        $warnText = Format-SCEventCount -Count $warnings.Count -Capped $warnings.Capped -Max $warnings.Max
        Write-SCInfo -Message ("{0}: present. Errors: {1}. Warnings: {2}.{3}" -f $ch.Label, $errText, $warnText, $disabled)
    }
}

function Invoke-SCCheckEventSignals {
    $support = Initialize-SCEventSupport
    if (-not $support.Available) { return }

    Start-SCSection -Title 'High-signal event IDs'
    $securityBlocked = $script:SCSecurityDenied
    if ($securityBlocked) {
        Write-SCInfo -Message 'Failed logon (4625) and explicit credential logon (4648) were not counted because the Security log needs admin.'
    }

    $defs = Get-SCEventSignals
    foreach ($sig in @($defs.Items)) {
        if ($sig.Security -and $script:SCSecurityDenied) {
            if (-not $securityBlocked) {
                Write-SCInfo -Message ("{0} ({1}) was not counted because the Security log needs admin." -f $sig.Label, $sig.Id)
            }
            continue
        }

        $measured = Measure-SCWinEvents -LogName $sig.LogName -Days $script:SCEventLookbackDays -MaxEvents $script:SCEventSignalMax -Id $sig.Id
        if ($measured.Kind -eq 'denied') {
            if ($sig.Security) {
                $script:SCSecurityDenied = $true
                Write-SCNeedsAdmin -Detail 'Security log could not be read.'
                Write-SCInfo -Message ("{0} ({1}) was not counted because the Security log needs admin." -f $sig.Label, $sig.Id)
            } else {
                Write-SCNeedsAdmin -Detail ("{0} ({1}) was not counted because the log needs admin." -f $sig.Label, $sig.Id)
            }
            continue
        }
        if ($measured.Kind -eq 'missing') {
            Write-SCInfo -Message ("{0} ({1}): log is not present." -f $sig.Label, $sig.Id)
            continue
        }
        if ($measured.Kind -ne 'ok') {
            Write-SCWarn -Message ("{0} ({1}) could not be counted: {2}" -f $sig.Label, $sig.Id, (Format-SCShortText -Text $measured.Error -Max 160))
            continue
        }

        $countText = Format-SCEventCount -Count $measured.Count -Capped $measured.Capped -Max $measured.Max
        $msg = ("{0} ({1}): {2} in the last {3} days." -f $sig.Label, $sig.Id, $countText, $script:SCEventLookbackDays)
        if ($sig.LevelName -eq 'REVIEW' -and $measured.Count -gt 0) {
            Write-SCReview -Message $msg
        } else {
            Write-SCInfo -Message $msg
        }
    }
}

function Invoke-SCEventsCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Events'
Invoke-SCEventsCheck -Name 'Event channels' -Body { Invoke-SCCheckEventChannels }
Invoke-SCEventsCheck -Name 'High-signal event IDs' -Body { Invoke-SCCheckEventSignals }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Events' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
