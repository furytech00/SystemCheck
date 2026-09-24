#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Active Directory context for a joined computer.

.DESCRIPTION
    Reports domain join, computer role, the locally stored site name, and
    the logon server or Group Policy domain controller name. When a single
    domain controller hostname is already known, it checks ping and TCP
    389/636 for that host only. This module does not query the directory,
    list domain users or groups, or change the computer. It is not part of
    the default runner.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\12_ad_optional.ps1
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

$script:SCAdJoinKind = 'unknown'
$script:SCAdPolicyCap = 8

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

function Get-SCDomainRoleLabel {
    param($Role)
    if ($null -eq $Role) { return '' }
    if ($Role -is [string] -and [string]::IsNullOrWhiteSpace([string]$Role)) { return '' }
    switch ([int]$Role) {
        0 { return 'standalone workstation' }
        1 { return 'domain member workstation' }
        2 { return 'standalone server' }
        3 { return 'domain member server' }
        4 { return 'backup domain controller' }
        5 { return 'primary domain controller' }
        default { return ('code {0}' -f $Role) }
    }
}

function Get-SCProductTypeLabel {
    param([string]$ProductType)
    switch ([string]$ProductType) {
        'WinNT' { return 'workstation' }
        'ServerNT' { return 'server' }
        'LanmanNT' { return 'domain controller' }
        default { return '' }
    }
}

function Get-SCAdJoinKind {
    param($PartOfDomain)
    if ($null -eq $PartOfDomain) { return 'unknown' }
    if ([bool]$PartOfDomain) { return 'domain' }
    return 'workgroup'
}

function Convert-SCLogonServerName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $text = $Value.Trim()
    while ($text.StartsWith('\')) { $text = $text.Substring(1) }
    return (Format-SCShortText -Text $text -Max 253)
}

function Test-SCDcHostName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $text = $Name.Trim()
    if ($text.Length -gt 253) { return $false }
    if ($text -notmatch '^[A-Za-z0-9._-]+$') { return $false }
    if ($text.StartsWith('.') -or $text.EndsWith('.')) { return $false }
    if ($text.StartsWith('-') -or $text.EndsWith('-')) { return $false }
    if ($text.Contains('..')) { return $false }
    return $true
}

function Test-SCSameComputer {
    param([string]$Name, [string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    $left = $Name.Trim().TrimEnd('.')
    $right = $ComputerName.Trim().TrimEnd('.')
    if ($left.Equals($right, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $leftShort = $left.Split('.')[0]
    $rightShort = $right.Split('.')[0]
    if ([string]::IsNullOrWhiteSpace($leftShort) -or [string]::IsNullOrWhiteSpace($rightShort)) { return $false }
    return $leftShort.Equals($rightShort, [System.StringComparison]::OrdinalIgnoreCase)
}

function Select-SCDcProbeTarget {
    param([string]$LogonServer, [string]$ComputerName, [string[]]$Controllers)
    $logon = Convert-SCLogonServerName -Value $LogonServer
    if ($logon -and -not (Test-SCSameComputer -Name $logon -ComputerName $ComputerName) -and (Test-SCDcHostName -Name $logon)) {
        return $logon
    }
    foreach ($controller in @($Controllers)) {
        $name = Convert-SCLogonServerName -Value ([string]$controller)
        if (-not $name) { continue }
        if (Test-SCSameComputer -Name $name -ComputerName $ComputerName) { continue }
        if (Test-SCDcHostName -Name $name) { return $name }
    }
    return ''
}

function Format-SCDcReachability {
    param([string]$HostName, $PingTried, $PingReachable, $Tcp389, $Tcp636)
    $bits = New-Object System.Collections.Generic.List[string]
    if (-not $PingTried) {
        [void]$bits.Add('ping not available')
    } elseif ($PingReachable) {
        [void]$bits.Add('ping reachable')
    } else {
        [void]$bits.Add('ping unreachable')
    }
    if ($Tcp389) { [void]$bits.Add('TCP 389 reachable') } else { [void]$bits.Add('TCP 389 unreachable') }
    if ($Tcp636) { [void]$bits.Add('TCP 636 reachable') } else { [void]$bits.Add('TCP 636 unreachable') }
    return ('Domain controller {0}: {1}.' -f $HostName, ($bits.ToArray() -join '. '))
}

function Format-SCLimitedNames {
    param([string[]]$Items, [int]$Max = 3)
    $clean = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($item in @($Items)) {
        $text = Format-SCShortText -Text ([string]$item) -Max 80
        if (-not $text) { continue }
        $key = $text.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$clean.Add($text)
    }
    if ($clean.Count -eq 0) { return '' }
    if ($clean.Count -le $Max) { return ($clean.ToArray() -join ', ') }
    $shown = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Max; $i++) { [void]$shown.Add($clean[$i]) }
    $extra = $clean.Count - $Max
    return ('{0} (+{1})' -f ($shown.ToArray() -join ', '), $extra)
}

function Add-SCUniqueText {
    param($List, $Seen, [string]$Value)
    $text = Format-SCShortText -Text $Value -Max 80
    if (-not $text) { return }
    $key = $text.ToLowerInvariant()
    if ($Seen.ContainsKey($key)) { return }
    $Seen[$key] = $true
    [void]$List.Add($text)
}

function Get-SCAdRegistryState {
    param([string]$Path)
    $state = New-Object psobject -Property @{
        Exists = $false
        Denied = $false
        Error  = ''
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $state }
    try {
        $state.Exists = [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    } catch {
        $msg = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        if (Test-SCAccessDenied -Message $msg) { $state.Denied = $true }
        else { $state.Error = $msg }
    }
    return $state
}

function Get-SCAdPolicyHints {
    $result = New-Object psobject -Property @{
        DcItems   = @()
        SiteItems = @()
        Denied    = $false
        Truncated = $false
        Error     = ''
    }
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
    $root = Get-SCAdRegistryState -Path $base
    if ($root.Denied) { $result.Denied = $true; return $result }
    if ($root.Error) { $result.Error = $root.Error; return $result }
    if (-not $root.Exists) { return $result }

    $paths = New-Object System.Collections.Generic.List[string]
    [void]$paths.Add($base)
    try {
        $count = 0
        foreach ($child in @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
            if (-not $child) { continue }
            $count++
            if ($count -gt $script:SCAdPolicyCap) {
                $result.Truncated = $true
                break
            }
            $childPath = Join-SCWindowsPath -Root $base -Child ([string]$child.PSChildName)
            if ($childPath) { [void]$paths.Add($childPath) }
        }
    } catch {
        $msg = ''
        try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
        if (Test-SCAccessDenied -Message $msg) { $result.Denied = $true }
        elseif ([string]::IsNullOrWhiteSpace($result.Error)) { $result.Error = $msg }
    }

    $dcs = New-Object System.Collections.Generic.List[string]
    $sites = New-Object System.Collections.Generic.List[string]
    $seenDc = @{}
    $seenSite = @{}
    foreach ($path in @($paths.ToArray())) {
        $dc = Get-SCRegistryValue -Path $path -Name 'DCName'
        if ($dc.Error -and (Test-SCAccessDenied -Message ([string]$dc.Error))) { $result.Denied = $true }
        elseif ($dc.Error -and [string]::IsNullOrWhiteSpace($result.Error)) { $result.Error = [string]$dc.Error }
        if ($dc.Found) { Add-SCUniqueText -List $dcs -Seen $seenDc -Value ([string]$dc.Value) }
        $site = Get-SCRegistryValue -Path $path -Name 'SiteName'
        if ($site.Error -and (Test-SCAccessDenied -Message ([string]$site.Error))) { $result.Denied = $true }
        if ($site.Found) { Add-SCUniqueText -List $sites -Seen $seenSite -Value ([string]$site.Value) }
    }
    $result.DcItems = @($dcs.ToArray())
    $result.SiteItems = @($sites.ToArray())
    return $result
}

function Test-SCPingHost {
    param([string]$HostName)
    $result = New-Object psobject -Property @{
        Tried     = $false
        Reachable = $false
    }
    if (-not (Test-SCDcHostName -Name $HostName)) { return $result }
    $cmd = $null
    try { $cmd = Get-Command -Name Test-Connection -ErrorAction SilentlyContinue } catch { $cmd = $null }
    if (-not $cmd) { return $result }
    $result.Tried = $true
    try {
        $result.Reachable = [bool](Test-Connection -ComputerName $HostName -Count 1 -Quiet -ErrorAction Stop)
    } catch {
        $result.Reachable = $false
    }
    return $result
}

function Test-SCTcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 1500)
    if (-not (Test-SCDcHostName -Name $HostName)) { return $false }
    if ($Port -ne 389 -and $Port -ne 636) { return $false }
    if ($TimeoutMs -lt 200) { $TimeoutMs = 200 }
    if ($TimeoutMs -gt 3000) { $TimeoutMs = 3000 }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($HostName, $Port, $null, $null)
        $done = $pending.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $done) { return $false }
        $client.EndConnect($pending)
        return [bool]$client.Connected
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch { }
    }
}

function Get-SCDcReachability {
    param([string]$HostName)
    $ping = Test-SCPingHost -HostName $HostName
    return New-Object psobject -Property @{
        HostName      = $HostName
        PingTried     = [bool]$ping.Tried
        PingReachable = [bool]$ping.Reachable
        Tcp389        = [bool](Test-SCTcpPort -HostName $HostName -Port 389)
        Tcp636        = [bool](Test-SCTcpPort -HostName $HostName -Port 636)
    }
}

function Invoke-SCCheckAdJoin {
    Start-SCSection -Title 'Domain membership'
    $ctx = Get-SCContext
    $script:SCAdJoinKind = Get-SCAdJoinKind -PartOfDomain $ctx.PartOfDomain
    if ($script:SCAdJoinKind -eq 'unknown') {
        $cim = $null
        try { $cim = Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue } catch { $cim = $null }
        if (-not $cim) {
            Write-SCWarn -Message 'Get-CimInstance is not available, so domain join state was not read.'
        } else {
            Write-SCWarn -Message 'Domain join state could not be read.'
        }
        Write-SCInfo -Message 'Domain join state could not be confirmed.'
        return
    }

    if ($script:SCAdJoinKind -eq 'workgroup') {
        Write-SCInfo -Message 'Not domain-joined.'
        $workgroup = Format-SCShortText -Text ([string]$ctx.Workgroup) -Max 80
        if ($workgroup) { Write-SCInfo -Message ("Workgroup: {0}." -f $workgroup) }
    } else {
        Write-SCInfo -Message 'Domain-joined.'
        $domain = Format-SCShortText -Text ([string]$ctx.Domain) -Max 80
        if ($domain) { Write-SCInfo -Message ("Domain: {0}." -f $domain) }
        else { Write-SCInfo -Message 'Domain name was not available.' }
        $dns = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'Domain'
        if ($dns.Error -and (Test-SCAccessDenied -Message ([string]$dns.Error))) {
            Write-SCNeedsAdmin -Detail 'The local DNS domain name could not be read.'
        } elseif ($dns.Found) {
            $dnsName = Format-SCShortText -Text ([string]$dns.Value) -Max 80
            if ($dnsName -and -not $dnsName.Equals([string]$domain, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-SCInfo -Message ("DNS domain: {0}." -f $dnsName)
            }
        }
    }

    $role = Get-SCDomainRoleLabel -Role $ctx.DomainRole
    if ($role) {
        Write-SCInfo -Message ("Computer role: {0}." -f $role)
    } else {
        $product = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -Name 'ProductType'
        if ($product.Error -and (Test-SCAccessDenied -Message ([string]$product.Error))) {
            Write-SCNeedsAdmin -Detail 'The local product type could not be read.'
        } elseif ($product.Found) {
            $label = Get-SCProductTypeLabel -ProductType ([string]$product.Value)
            if ($label) { Write-SCInfo -Message ("Product type: {0}." -f $label) }
        }
    }
}

function Invoke-SCCheckAdLocation {
    Start-SCSection -Title 'Site and domain controller'
    if ($script:SCAdJoinKind -eq 'workgroup') {
        Write-SCInfo -Message 'Site, logon server, and domain controller checks were skipped because this computer is not domain-joined.'
        return
    }
    if ($script:SCAdJoinKind -ne 'domain') {
        Write-SCInfo -Message 'Site, logon server, and domain controller checks were skipped because domain join state is unknown.'
        return
    }

    $ctx = Get-SCContext
    $denied = $false
    $site = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DynamicSiteName'
    if ($site.Error -and (Test-SCAccessDenied -Message ([string]$site.Error))) { $denied = $true }
    $siteName = ''
    if ($site.Found) { $siteName = Format-SCShortText -Text ([string]$site.Value) -Max 80 }

    $hints = Get-SCAdPolicyHints
    if ($hints.Denied) { $denied = $true }
    if ($hints.Truncated) {
        Write-SCInfo -Message ("Group Policy history scan stopped at {0} keys." -f $script:SCAdPolicyCap)
    }
    if (-not $siteName -and $hints.SiteItems) {
        $siteName = Format-SCLimitedNames -Items @($hints.SiteItems) -Max 2
    }
    if ($siteName) { Write-SCInfo -Message ("Site: {0}." -f $siteName) }
    else { Write-SCInfo -Message 'Site name was not stored locally.' }

    $logonRaw = ''
    if ($env:LOGONSERVER) { $logonRaw = [string]$env:LOGONSERVER }
    $logon = Convert-SCLogonServerName -Value $logonRaw
    $computer = [string]$ctx.ComputerName
    if (-not $computer) { $computer = [string]$env:COMPUTERNAME }
    if ($logon -and (Test-SCSameComputer -Name $logon -ComputerName $computer)) {
        Write-SCInfo -Message 'Logon server: this computer (local logon).'
    } elseif ($logon) {
        Write-SCInfo -Message ("Logon server: {0}." -f $logon)
    } else {
        Write-SCInfo -Message 'Logon server was not set in the environment.'
    }

    $controllers = @()
    if ($hints.DcItems) { $controllers = @($hints.DcItems) }
    if (@($controllers).Count -eq 0) {
        Write-SCInfo -Message 'No Group Policy domain controller name was stored locally.'
    } else {
        $shown = Format-SCLimitedNames -Items $controllers -Max 3
        Write-SCInfo -Message ("Group Policy domain controller: {0}." -f $shown)
    }

    $target = Select-SCDcProbeTarget -LogonServer $logonRaw -ComputerName $computer -Controllers $controllers
    if (-not $target) {
        Write-SCInfo -Message 'No domain controller hostname was available locally, so reachability was not checked.'
    } else {
        $reach = $null
        try {
            $reach = Get-SCDcReachability -HostName $target
        } catch {
            $msg = ''
            try { $msg = [string]$_.Exception.Message } catch { $msg = '' }
            Write-SCWarn -Message ("Domain controller reachability could not be checked: {0}" -f (Format-SCShortText -Text $msg -Max 160))
        }
        if ($reach) {
            $line = Format-SCDcReachability -HostName $reach.HostName -PingTried $reach.PingTried -PingReachable $reach.PingReachable -Tcp389 $reach.Tcp389 -Tcp636 $reach.Tcp636
            if ((-not $reach.Tcp389) -and (-not $reach.Tcp636)) {
                Write-SCReview -Message $line
            } else {
                Write-SCInfo -Message $line
            }
        }
    }

    if ($denied) {
        Write-SCNeedsAdmin -Detail 'Local Active Directory context could not be read.'
    } elseif ($hints.Error -and -not (Test-SCAccessDenied -Message ([string]$hints.Error))) {
        Write-SCWarn -Message ("Local Active Directory context could not be read: {0}" -f (Format-SCShortText -Text $hints.Error -Max 160))
    }
}

function Invoke-SCAdCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Active Directory'
Invoke-SCAdCheck -Name 'Domain membership' -Body { Invoke-SCCheckAdJoin }
Invoke-SCAdCheck -Name 'Site and domain controller' -Body { Invoke-SCCheckAdLocation }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Active Directory' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
