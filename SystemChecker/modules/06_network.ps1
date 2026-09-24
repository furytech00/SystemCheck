#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only network configuration checks.

.DESCRIPTION
    Reports adapters, listeners, firewall profiles, shares, mapped drives,
    hosts-file entries, proxy settings, and domain-controller hints.
    This module does not scan the network, download files, or execute
    binaries named in the configuration.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\06_network.ps1
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

function Test-SCRegistryHive {
    param([string]$Root)
    try {
        return [bool](Test-Path -LiteralPath $Root -ErrorAction Stop)
    } catch {
        return $false
    }
}

function Join-SCWindowsPath {
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Root)) { return $Child }
    if ([string]::IsNullOrWhiteSpace($Child)) { return $Root }
    return ($Root.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

function Convert-SCStringList {
    param($Value)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        $text = ([string]$item).Trim()
        if ($text) { [void]$list.Add($text) }
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
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

function Format-SCEndpointAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return '' }
    $text = $Address.Trim()
    if ($text.StartsWith('[') -and $text.EndsWith(']') -and $text.Length -gt 2) {
        $text = $text.Substring(1, $text.Length - 2)
    }
    return $text
}

function Test-SCLoopbackAddress {
    param([string]$Address)
    $text = Format-SCEndpointAddress -Address $Address
    if (-not $text) { return $false }
    if ($text -eq '::1') { return $true }
    if ($text -match '(?i)^127\.') { return $true }
    return $false
}

function Test-SCAnyAddress {
    param([string]$Address)
    $text = Format-SCEndpointAddress -Address $Address
    if ($text -eq '0.0.0.0') { return $true }
    if ($text -eq '::') { return $true }
    return $false
}

function Test-SCApipaAddress {
    param([string]$Address)
    $text = Format-SCEndpointAddress -Address $Address
    return ($text -match '^169\.254\.')
}

function Test-SCLinkLocalV6 {
    param([string]$Address)
    $text = Format-SCEndpointAddress -Address $Address
    return ($text -match '(?i)^fe80:')
}

function Test-SCRoutableV4 {
    param([string]$Address)
    $text = Format-SCEndpointAddress -Address $Address
    if (-not $text) { return $false }
    if ($text -match ':') { return $false }
    if ($text -eq '0.0.0.0') { return $false }
    if (Test-SCLoopbackAddress -Address $text) { return $false }
    if (Test-SCApipaAddress -Address $text) { return $false }
    return ($text -match '^\d{1,3}(\.\d{1,3}){3}$')
}

function Test-SCTunnelDescription {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?i)teredo|isatap|6to4|tunnel')
}

function Format-SCProxyValue {
    # Drop userinfo (user:password@) before the value is printed.
    param([string]$Text, [int]$Max = 100)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $clean = [regex]::Replace($Text, '(?i)([a-z][a-z0-9+\-.]*://)[^/\s:@]+:[^/\s@]+@', '$1')
    $clean = [regex]::Replace($clean, '(?i)(^|[\s;])[^;\s:@]+:[^;\s@]+@', '$1')
    return (Format-SCShortText -Text $clean -Max $Max)
}

function Convert-SCHostsLine {
    param([string]$Line)
    if ($null -eq $Line) { return $null }
    $text = $Line.Trim()
    if (-not $text) { return $null }
    if ($text.StartsWith('#')) { return $null }
    $hash = $text.IndexOf('#')
    if ($hash -ge 0) { $text = $text.Substring(0, $hash).Trim() }
    if (-not $text) { return $null }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($part in @($text -split '\s+')) {
        if ($part) { [void]$parts.Add([string]$part) }
    }
    if ($parts.Count -lt 2) { return $null }
    $names = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -lt $parts.Count; $i++) { [void]$names.Add($parts[$i]) }
    return New-Object psobject -Property @{
        Address = Format-SCEndpointAddress -Address $parts[0]
        Names   = $names.ToArray()
    }
}

function Test-SCDefaultHostsName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match '(?i)^localhost(\.localdomain)?$')
}

function Get-SCHostsEntryLevel {
    param([string]$Address, [string[]]$Names)
    $nonDefault = $false
    foreach ($name in @($Names)) {
        if (-not (Test-SCDefaultHostsName -Name $name)) { $nonDefault = $true }
    }
    $loop = Test-SCLoopbackAddress -Address $Address
    if ((-not $loop) -and (-not $nonDefault)) { return 'WEAK' }
    if (-not $loop) { return 'REVIEW' }
    if ($nonDefault) { return 'REVIEW' }
    return 'NONE'
}

function Format-SCFirewallEnable {
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    $number = 0
    $parsed = [int]::TryParse([string]$Value, [ref]$number)
    if (-not $parsed) { return $null }
    if ($number -eq 1) { return 'enabled' }
    if ($number -eq 0) { return 'disabled' }
    return $null
}

function Format-SCFirewallInbound {
    # Registry and policy DWORD: 0 allows inbound by default, 1 blocks it.
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    $number = 0
    $parsed = [int]::TryParse([string]$Value, [ref]$number)
    if (-not $parsed) { return $null }
    if ($number -eq 0) { return 'Allow' }
    if ($number -eq 1) { return 'Block' }
    return $null
}

function Format-SCFirewallActionText {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ($text -match '(?i)allow') { return 'Allow' }
    if ($text -match '(?i)block') { return 'Block' }
    if ($text -eq '2') { return 'Allow' }
    if ($text -eq '4') { return 'Block' }
    return $null
}

function Test-SCFirewallOn {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    $text = [string]$Value
    if ($text -eq '1') { return $true }
    if ($text -match '^(?i)true$') { return $true }
    return $false
}

function Format-SCFirewallState {
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return 'unknown' }
    if ($Value -is [bool]) {
        if ($Value) { return 'enabled' }
        return 'disabled'
    }
    $text = [string]$Value
    if ($text -eq 'enabled' -or $text -eq 'disabled') { return $text }
    if (Test-SCFirewallOn -Value $Value) { return 'enabled' }
    $parsed = Format-SCFirewallEnable -Value $Value
    if ($parsed) { return $parsed }
    return 'unknown'
}

function Test-SCAdminShareName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return $Name.Trim().EndsWith('$')
}

function Test-SCNotableUdp {
    param([string]$Address, [int]$Port)
    if (Test-SCAnyAddress -Address $Address) { return $true }
    if ($Port -gt 0 -and $Port -lt 1024) { return $true }
    return $false
}

function Get-SCListenerRank {
    param([string]$Address)
    if (Test-SCAnyAddress -Address $Address) { return 0 }
    if (Test-SCLoopbackAddress -Address $Address) { return 2 }
    return 1
}

function Format-SCListenerEndpoint {
    param([string]$Address, [int]$Port)
    $text = Format-SCEndpointAddress -Address $Address
    if ($text.Contains(':')) { return ('[{0}]:{1}' -f $text, $Port) }
    return ('{0}:{1}' -f $text, $Port)
}

function Convert-SCNetTable {
    param([string[]]$Lines)
    $rows = New-Object System.Collections.Generic.List[object]
    $started = $false
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        $text = ([string]$line).TrimEnd()
        $trim = $text.Trim()
        if (-not $trim) { continue }
        if (-not $started) {
            if ($trim -match '^-{3,}') { $started = $true }
            continue
        }
        if ($trim -match '^-{3,}') { continue }
        if ($trim -match '(?i)command completed|no entries in the list') { continue }
        $cols = New-Object System.Collections.Generic.List[string]
        foreach ($col in @($text -split '\s{2,}')) {
            $piece = ([string]$col).Trim()
            if ($piece) { [void]$cols.Add($piece) }
        }
        if ($cols.Count -eq 0) { continue }
        [void]$rows.Add((New-Object psobject -Property @{
            Columns = $cols.ToArray()
        }))
    }
    return New-Object psobject -Property @{
        Started = $started
        Items   = $rows.ToArray()
    }
}

function Get-SCAdapterRecordsFromCim {
    $items = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = 'CIM is not available.'
        }
    }
    try {
        $rows = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' -ErrorAction Stop)
        foreach ($row in $rows) {
            if (-not $row) { continue }
            $addresses = @( (Convert-SCStringList -Value (Get-SCProp $row 'IPAddress')).Items )
            $gateways = @( (Convert-SCStringList -Value (Get-SCProp $row 'DefaultIPGateway')).Items )
            $dns = @( (Convert-SCStringList -Value (Get-SCProp $row 'DNSServerSearchOrder')).Items )
            $description = [string](Get-SCProp $row 'Description')
            $dhcp = $false
            $dhcpValue = Get-SCProp $row 'DHCPEnabled'
            if ($dhcpValue -is [bool]) { $dhcp = [bool]$dhcpValue }
            elseif ([string]$dhcpValue -match '^(?i)true|1$') { $dhcp = $true }
            [void]$items.Add((New-Object psobject -Property @{
                Name        = $description
                Dhcp        = $dhcp
                Addresses   = $addresses
                Gateways    = $gateways
                DnsServers  = $dns
                Tunnel      = (Test-SCTunnelDescription -Text $description)
            }))
        }
        return New-Object psobject -Property @{
            Items  = $items.ToArray()
            Source = 'cim'
            Error  = $null
        }
    } catch {
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = $_.Exception.Message
        }
    }
}

function Split-SCDnsText {
    param([string]$Text)
    $list = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return New-Object psobject -Property @{ Items = @() }
    }
    foreach ($part in @($Text -split '[,\s]+')) {
        $piece = ([string]$part).Trim()
        if ($piece) { [void]$list.Add($piece) }
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Get-SCAdapterConnectionName {
    param([string]$Guid)
    if ([string]::IsNullOrWhiteSpace($Guid)) { return $null }
    $classId = '{4D36E972-E325-11CE-BFC1-08002BE10318}'
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{0}\{1}\Connection' -f $classId, $Guid
    $value = Get-SCRegistryValue -Path $path -Name 'Name'
    if ($value.Found -and $value.Value) { return [string]$value.Value }
    return $null
}

function Get-SCAdapterRecordsFromRegistry {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    $hive = Test-SCRegistryHive -Root $base
    if (-not $hive) {
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = 'Adapter registry key was not found.'
        }
    }
    $items = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
            if (-not $key) { continue }
            $path = $key.PSPath
            $dhcpOn = $false
            $dhcpValue = Get-SCRegistryValue -Path $path -Name 'EnableDHCP'
            if ($dhcpValue.Found -and ([string]$dhcpValue.Value -eq '1')) { $dhcpOn = $true }
            $addresses = New-Object System.Collections.Generic.List[string]
            $staticIp = Get-SCRegistryValue -Path $path -Name 'IPAddress'
            if ($staticIp.Found) {
                foreach ($ip in @((Convert-SCStringList -Value $staticIp.Value).Items)) {
                    if ($ip -and $ip -ne '0.0.0.0') { [void]$addresses.Add($ip) }
                }
            }
            if ($addresses.Count -eq 0 -and $dhcpOn) {
                $dhcpIp = Get-SCRegistryValue -Path $path -Name 'DhcpIPAddress'
                if ($dhcpIp.Found -and $dhcpIp.Value -and ([string]$dhcpIp.Value -ne '0.0.0.0')) {
                    [void]$addresses.Add([string]$dhcpIp.Value)
                }
            }
            if ($addresses.Count -eq 0) { continue }
            $gateways = New-Object System.Collections.Generic.List[string]
            $gw = Get-SCRegistryValue -Path $path -Name 'DefaultGateway'
            if ((-not $gw.Found) -or (-not $gw.Value)) {
                $gw = Get-SCRegistryValue -Path $path -Name 'DhcpDefaultGateway'
            }
            if ($gw.Found) {
                foreach ($item in @((Convert-SCStringList -Value $gw.Value).Items)) {
                    if ($item -and $item -ne '0.0.0.0') { [void]$gateways.Add($item) }
                }
            }
            $dnsText = ''
            $dns = Get-SCRegistryValue -Path $path -Name 'NameServer'
            if ($dns.Found -and $dns.Value) { $dnsText = [string]$dns.Value }
            if (-not $dnsText) {
                $dns = Get-SCRegistryValue -Path $path -Name 'DhcpNameServer'
                if ($dns.Found -and $dns.Value) { $dnsText = [string]$dns.Value }
            }
            $dnsItems = @((Split-SCDnsText -Text $dnsText).Items)
            $name = Get-SCAdapterConnectionName -Guid ([string]$key.PSChildName)
            if (-not $name) { $name = [string]$key.PSChildName }
            [void]$items.Add((New-Object psobject -Property @{
                Name       = $name
                Dhcp       = $dhcpOn
                Addresses  = $addresses.ToArray()
                Gateways   = $gateways.ToArray()
                DnsServers = $dnsItems
                Tunnel     = (Test-SCTunnelDescription -Text $name)
            }))
        }
    } catch {
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = $_.Exception.Message
        }
    }
    return New-Object psobject -Property @{
        Items  = $items.ToArray()
        Source = 'registry'
        Error  = $null
    }
}

function Invoke-SCCheckAdapters {
    Start-SCSection -Title 'Adapters'
    $bag = Get-SCAdapterRecordsFromCim
    if ($bag.Source -eq 'none') {
        $fallback = Get-SCAdapterRecordsFromRegistry
        if ($fallback.Source -eq 'none') {
            $message = [string]$bag.Error
            if ($fallback.Error) {
                if ($message) { $message = $message + ' ' + [string]$fallback.Error }
                else { $message = [string]$fallback.Error }
            }
            if (Test-SCAccessDenied -Message $message) {
                Write-SCNeedsAdmin -Detail 'Network adapters could not be read.'
            } else {
                Write-SCWarn -Message ("Network adapters could not be read: {0}" -f (Format-SCShortText -Text $message -Max 160))
            }
            return
        }
        $bag = $fallback
        Write-SCInfo -Message 'Adapter list was read from the registry. IPv6 addresses may be missing.'
    }

    $records = @()
    if ($bag.Items) { $records = @($bag.Items) }
    $shown = 0
    $hidden = 0
    $tunnel = 0
    $withAddress = 0
    foreach ($adapter in $records) {
        if (-not $adapter) { continue }
        $withAddress++
        if ($adapter.Tunnel) {
            $tunnel++
            continue
        }
        if ($shown -ge 12) {
            $hidden++
            continue
        }
        $shown++
        $v4 = New-Object System.Collections.Generic.List[string]
        $v6 = New-Object System.Collections.Generic.List[string]
        $routable = $false
        $apipaOnly = $true
        $sawV4 = $false
        foreach ($address in @($adapter.Addresses)) {
            if (-not $address) { continue }
            if (([string]$address).Contains(':')) {
                if (-not (Test-SCLinkLocalV6 -Address $address)) { [void]$v6.Add([string]$address) }
            } else {
                $sawV4 = $true
                [void]$v4.Add([string]$address)
                if (Test-SCRoutableV4 -Address $address) {
                    $routable = $true
                    $apipaOnly = $false
                } elseif (-not (Test-SCApipaAddress -Address $address)) {
                    $apipaOnly = $false
                }
            }
        }
        if (-not $sawV4) { $apipaOnly = $false }
        $v6Text = 'none'
        if ($v6.Count -gt 0) { $v6Text = Format-SCLimitedList -Items $v6.ToArray() -Max 3 }
        elseif (@($adapter.Addresses) -match '(?i)^fe80:') { $v6Text = 'link-local' }
        $v4Text = 'none'
        if ($v4.Count -gt 0) { $v4Text = Format-SCLimitedList -Items $v4.ToArray() -Max 4 }
        $dnsItems = @($adapter.DnsServers)
        $dnsText = 'none'
        if ($dnsItems.Count -gt 0) { $dnsText = Format-SCLimitedList -Items $dnsItems -Max 3 }
        $gwItems = @($adapter.Gateways)
        $gwText = 'none'
        if ($gwItems.Count -gt 0) { $gwText = Format-SCLimitedList -Items $gwItems -Max 2 }
        $dhcpText = 'no'
        if ($adapter.Dhcp) { $dhcpText = 'yes' }
        $label = Format-SCShortText -Text ([string]$adapter.Name) -Max 40
        if (-not $label) { $label = 'adapter' }
        Write-SCInfo -Message ("{0} | IPv4 {1} | IPv6 {2} | DNS {3} | gateway {4} | DHCP {5}" -f $label, $v4Text, $v6Text, $dnsText, $gwText, $dhcpText)
        if ($dnsItems.Count -eq 0 -and ($routable -or $v6.Count -gt 0)) {
            Write-SCReview -Message ("Adapter '{0}' has an address and no DNS servers." -f $label)
        }
        if ($gwItems.Count -eq 0 -and $routable) {
            Write-SCReview -Message ("Adapter '{0}' has a routable IPv4 address and no gateway." -f $label)
        }
        if ($apipaOnly -and $v4.Count -gt 0) {
            Write-SCReview -Message ("Adapter '{0}' has only an automatic private IPv4 address." -f $label)
        }
    }
    Write-SCInfo -Message ("Adapters with an address: {0}. Listed: {1}. Tunnel adapters omitted: {2}." -f $withAddress, $shown, $tunnel)
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional adapters were omitted." -f $hidden)
    }
}

function New-SCListener {
    param([string]$Protocol, [string]$Address, [int]$Port, [int]$ProcessId)
    $addr = Format-SCEndpointAddress -Address $Address
    return New-Object psobject -Property @{
        Protocol  = $Protocol
        Address   = $addr
        Port      = $Port
        ProcessId = $ProcessId
        Rank      = (Get-SCListenerRank -Address $addr)
    }
}

function Get-SCListenerRecords {
    $items = New-Object System.Collections.Generic.List[object]
    $udpOmitted = 0
    $haveTcp = [bool](Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)
    if (-not $haveTcp -and (Get-Command -Name Import-Module -ErrorAction SilentlyContinue)) {
        try {
            Import-Module NetTCPIP -ErrorAction Stop
            $haveTcp = [bool](Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)
        } catch {
            $haveTcp = $false
        }
    }
    if ($haveTcp) {
        try {
            foreach ($row in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                if (-not $row) { continue }
                $pidValue = 0
                try { $pidValue = [int](Get-SCProp $row 'OwningProcess') } catch { $pidValue = 0 }
                $port = 0
                try { $port = [int](Get-SCProp $row 'LocalPort') } catch { $port = 0 }
                [void]$items.Add((New-SCListener -Protocol 'TCP' -Address ([string](Get-SCProp $row 'LocalAddress')) -Port $port -ProcessId $pidValue))
            }
            if (Get-Command -Name Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
                foreach ($row in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
                    if (-not $row) { continue }
                    $pidValue = 0
                    try { $pidValue = [int](Get-SCProp $row 'OwningProcess') } catch { $pidValue = 0 }
                    $port = 0
                    try { $port = [int](Get-SCProp $row 'LocalPort') } catch { $port = 0 }
                    $address = [string](Get-SCProp $row 'LocalAddress')
                    if (-not (Test-SCNotableUdp -Address $address -Port $port)) {
                        $udpOmitted++
                        continue
                    }
                    [void]$items.Add((New-SCListener -Protocol 'UDP' -Address $address -Port $port -ProcessId $pidValue))
                }
            }
            return New-Object psobject -Property @{
                Items            = $items.ToArray()
                Source           = 'nettcpip'
                ProcessNames     = $true
                UdpOmitted       = $udpOmitted
                Error            = $null
            }
        } catch {
            $items.Clear()
            $udpOmitted = 0
            $cmdError = $_.Exception.Message
            if (-not (Test-SCAccessDenied -Message $cmdError)) {
                # Fall through to the socket table when the cmdlet is present but failed.
                $cmdError = $null
            } else {
                return New-Object psobject -Property @{
                    Items        = @()
                    Source       = 'none'
                    ProcessNames = $false
                    UdpOmitted   = 0
                    Error        = 'NEEDS ADMIN'
                }
            }
        }
    }

    try {
        $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        foreach ($endPoint in @($props.GetActiveTcpListeners())) {
            if (-not $endPoint) { continue }
            $port = 0
            try { $port = [int]$endPoint.Port } catch { $port = 0 }
            $address = ''
            if ($endPoint.Address) { $address = [string]$endPoint.Address }
            [void]$items.Add((New-SCListener -Protocol 'TCP' -Address $address -Port $port -ProcessId 0))
        }
        foreach ($endPoint in @($props.GetActiveUdpListeners())) {
            if (-not $endPoint) { continue }
            $port = 0
            try { $port = [int]$endPoint.Port } catch { $port = 0 }
            $address = ''
            if ($endPoint.Address) { $address = [string]$endPoint.Address }
            if (-not (Test-SCNotableUdp -Address $address -Port $port)) {
                $udpOmitted++
                continue
            }
            [void]$items.Add((New-SCListener -Protocol 'UDP' -Address $address -Port $port -ProcessId 0))
        }
        return New-Object psobject -Property @{
            Items        = $items.ToArray()
            Source       = 'socket'
            ProcessNames = $false
            UdpOmitted   = $udpOmitted
            Error        = $null
        }
    } catch {
        return New-Object psobject -Property @{
            Items        = @()
            Source       = 'none'
            ProcessNames = $false
            UdpOmitted   = 0
            Error        = $_.Exception.Message
        }
    }
}

function Get-SCProcessLabel {
    param([int]$ProcessId, $Cache)
    if ($ProcessId -le 0) { return '' }
    $key = [string]$ProcessId
    if ($Cache.ContainsKey($key)) { return [string]$Cache[$key] }
    $label = "pid $ProcessId"
    if (Get-Command -Name Get-Process -ErrorAction SilentlyContinue) {
        try {
            $proc = Get-Process -Id $ProcessId -ErrorAction Stop
            $name = [string]$proc.ProcessName
            if ($name) { $label = '{0} ({1})' -f $name, $ProcessId }
        } catch {
            $label = "pid $ProcessId"
        }
    }
    $Cache[$key] = $label
    return $label
}

function Invoke-SCCheckListeners {
    Start-SCSection -Title 'Listeners'
    $bag = Get-SCListenerRecords
    if ($bag.Source -eq 'none') {
        $message = [string]$bag.Error
        if ($message -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $message)) {
            Write-SCNeedsAdmin -Detail 'Listening ports could not be read.'
        } else {
            Write-SCWarn -Message ("Listening ports could not be read: {0}" -f (Format-SCShortText -Text $message -Max 160))
        }
        return
    }
    $records = @()
    if ($bag.Items) { $records = @($bag.Items) }
    $tcp = 0
    $udp = 0
    foreach ($row in $records) {
        if (-not $row) { continue }
        if ($row.Protocol -eq 'UDP') { $udp++ } else { $tcp++ }
    }
    $ordered = @($records | Sort-Object -Property Rank, Protocol, Port, Address)
    $shown = 0
    $hidden = 0
    $cache = @{}
    foreach ($row in $ordered) {
        if (-not $row) { continue }
        if ($shown -ge 20) {
            $hidden++
            continue
        }
        $shown++
        $proc = ''
        if ($bag.ProcessNames) { $proc = Get-SCProcessLabel -ProcessId ([int]$row.ProcessId) -Cache $cache }
        $suffix = ''
        if ($proc) { $suffix = ' ' + $proc }
        $endpoint = Format-SCListenerEndpoint -Address ([string]$row.Address) -Port ([int]$row.Port)
        Write-SCInfo -Message ("{0} {1}{2}" -f $row.Protocol, $endpoint, $suffix)
    }
    Write-SCInfo -Message ("Listeners: {0} TCP, {1} notable UDP. Other UDP endpoints omitted: {2}." -f $tcp, $udp, [int]$bag.UdpOmitted)
    if (-not $bag.ProcessNames) {
        Write-SCInfo -Message 'Owning process names were not available from this listener source.'
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional listeners were omitted." -f $hidden)
    }
    if ($tcp -eq 0 -and $udp -eq 0) {
        Write-SCInfo -Message 'No listening TCP or notable UDP endpoints were returned.'
    }
}

function Get-SCFirewallProfileFromCmdlet {
    $have = [bool](Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    if (-not $have -and (Get-Command -Name Import-Module -ErrorAction SilentlyContinue)) {
        try {
            Import-Module NetSecurity -ErrorAction Stop
            $have = [bool](Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)
        } catch {
            $have = $false
        }
    }
    if (-not $have) {
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = 'Get-NetFirewallProfile is not available.'
        }
    }
    try {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($row in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            if (-not $row) { continue }
            $name = [string](Get-SCProp $row 'Name')
            $enabled = Test-SCFirewallOn -Value (Get-SCProp $row 'Enabled')
            $inbound = Format-SCFirewallActionText -Value (Get-SCProp $row 'DefaultInboundAction')
            [void]$items.Add((New-Object psobject -Property @{
                Name    = $name
                Enabled = $enabled
                Inbound = $inbound
                Source  = 'effective'
            }))
        }
        return New-Object psobject -Property @{
            Items  = $items.ToArray()
            Source = 'cmdlet'
            Error  = $null
        }
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $message = 'NEEDS ADMIN' }
        return New-Object psobject -Property @{
            Items  = @()
            Source = 'none'
            Error  = $message
        }
    }
}

function Get-SCFirewallRegistryProfile {
    param([string]$PolicyPath, [string]$LocalPath, [string]$Name)
    $enable = $null
    $inbound = $null
    $source = $null
    $policyEnable = Get-SCRegistryValue -Path $PolicyPath -Name 'EnableFirewall'
    if ($policyEnable.Error) {
        return New-Object psobject -Property @{
            Name = $Name; Enabled = $null; Inbound = $null; Source = $null; Error = $policyEnable.Error
        }
    }
    if ($policyEnable.Found) {
        $enable = Format-SCFirewallEnable -Value $policyEnable.Value
        $source = 'policy'
        $policyInbound = Get-SCRegistryValue -Path $PolicyPath -Name 'DefaultInboundAction'
        if ($policyInbound.Found) { $inbound = Format-SCFirewallInbound -Value $policyInbound.Value }
    } else {
        $localEnable = Get-SCRegistryValue -Path $LocalPath -Name 'EnableFirewall'
        if ($localEnable.Error) {
            return New-Object psobject -Property @{
                Name = $Name; Enabled = $null; Inbound = $null; Source = $null; Error = $localEnable.Error
            }
        }
        if ($localEnable.Found) {
            $enable = Format-SCFirewallEnable -Value $localEnable.Value
            $source = 'local'
            $localInbound = Get-SCRegistryValue -Path $LocalPath -Name 'DefaultInboundAction'
            if ($localInbound.Found) { $inbound = Format-SCFirewallInbound -Value $localInbound.Value }
        }
    }
    return New-Object psobject -Property @{
        Name    = $Name
        Enabled = $enable
        Inbound = $inbound
        Source  = $source
        Error   = $null
    }
}

function Invoke-SCCheckFirewall {
    Start-SCSection -Title 'Firewall profiles'
    $bag = Get-SCFirewallProfileFromCmdlet
    $profiles = @()
    if ($bag.Source -eq 'cmdlet' -and $bag.Items) {
        $profiles = @($bag.Items)
    } else {
        if (-not (Test-SCRegistryHive -Root 'HKLM:\')) {
            $message = [string]$bag.Error
            if (-not $message) { $message = 'Registry is not available.' }
            if ($message -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $message)) {
                Write-SCNeedsAdmin -Detail 'Firewall profiles could not be read.'
            } else {
                Write-SCWarn -Message ("Firewall profiles could not be read: {0}" -f (Format-SCShortText -Text $message -Max 160))
            }
            return
        }
        $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
        $localRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
        $specs = @(
            @{ Name = 'Domain';  Policy = 'DomainProfile';  Local = 'DomainProfile' }
            @{ Name = 'Private'; Policy = 'PrivateProfile'; Local = 'StandardProfile' }
            @{ Name = 'Public';  Policy = 'PublicProfile';  Local = 'PublicProfile' }
        )
        $denied = 0
        $found = 0
        foreach ($spec in $specs) {
            $fw = Get-SCFirewallRegistryProfile -PolicyPath (Join-SCWindowsPath -Root $policyRoot -Child $spec.Policy) -LocalPath (Join-SCWindowsPath -Root $localRoot -Child $spec.Local) -Name $spec.Name
            if ($fw.Error) {
                if (Test-SCAccessDenied -Message $fw.Error) { $denied++ }
                continue
            }
            if ($fw.Source) {
                $found++
                $profiles += $fw
            }
        }
        if ($found -eq 0) {
            if ($denied -gt 0) {
                Write-SCNeedsAdmin -Detail 'Firewall profiles could not be read.'
            } else {
                Write-SCWarn -Message 'Firewall profiles were not found.'
            }
            return
        }
        if ($denied -gt 0) {
            Write-SCNeedsAdmin -Detail ("Firewall profile values could not be read for {0} profiles." -f $denied)
        }
    }

    $ctx = Get-SCContext
    $joined = $false
    if ($null -ne $ctx.PartOfDomain) { $joined = [bool]$ctx.PartOfDomain }
    foreach ($fw in $profiles) {
        if (-not $fw) { continue }
        $name = [string]$fw.Name
        $state = Format-SCFirewallState -Value $fw.Enabled
        $inbound = [string]$fw.Inbound
        if (-not $inbound) { $inbound = 'unknown' }
        $source = [string]$fw.Source
        if (-not $source) { $source = 'effective' }
        Write-SCInfo -Message ("{0} profile: {1}, default inbound {2} ({3})." -f $name, $state, $inbound, $source)
        $disabledMatters = $true
        if ($name -eq 'Domain' -and -not $joined) { $disabledMatters = $false }
        if ($state -eq 'disabled' -and $disabledMatters) {
            Write-SCWeak -Message ("Firewall profile {0} is disabled." -f $name)
        } elseif ($state -eq 'disabled') {
            Write-SCInfo -Message ("Firewall profile {0} is disabled. The computer is not domain-joined." -f $name)
        }
        if ($inbound -eq 'Allow') {
            Write-SCReview -Message ("Firewall profile {0} allows inbound connections by default." -f $name)
        }
    }
}

function Get-SCShareRecordsFromCim {
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = 'CIM is not available.'
        }
    }
    try {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($row in @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop)) {
            if (-not $row) { continue }
            $name = [string](Get-SCProp $row 'Name')
            if (-not $name) { continue }
            [void]$items.Add((New-Object psobject -Property @{
                Name = $name
                Path = [string](Get-SCProp $row 'Path')
                Note = [string](Get-SCProp $row 'Description')
            }))
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

function Get-SCShareRecordsFromNet {
    $native = Invoke-SCNative -FileName 'net' -ArgumentList @('share')
    if (Test-SCNativeDenied -Result $native) {
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = 'NEEDS ADMIN'
        }
    }
    if (-not $native.Ok) {
        $message = [string]$native.Error
        if (-not $message -and $native.Output) { $message = [string]($native.Output -join ' ') }
        if (Test-SCCommandMissingText -Message $message) { $message = 'net is not available.' }
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = $message
        }
    }
    $table = Convert-SCNetTable -Lines @($native.Output)
    if (-not $table.Started) {
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = 'Share list could not be parsed.'
        }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($table.Items)) {
        if (-not $row) { continue }
        $cols = @($row.Columns)
        if ($cols.Count -eq 0) { continue }
        $path = ''
        if ($cols.Count -ge 2 -and $cols[1] -match '^[A-Za-z]:\\') { $path = $cols[1] }
        $note = ''
        if ($cols.Count -ge 3) { $note = $cols[2] }
        [void]$items.Add((New-Object psobject -Property @{
            Name = $cols[0]
            Path = $path
            Note = $note
        }))
    }
    return New-Object psobject -Property @{
        Items = $items.ToArray(); Source = 'net'; Error = $null
    }
}

function Get-SCMappedDriveRecords {
    $items = New-Object System.Collections.Generic.List[object]
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            foreach ($row in @(Get-CimInstance -ClassName Win32_MappedLogicalDisk -ErrorAction Stop)) {
                if (-not $row) { continue }
                $local = [string](Get-SCProp $row 'Name')
                $remote = [string](Get-SCProp $row 'ProviderName')
                if ($local -or $remote) {
                    [void]$items.Add((New-Object psobject -Property @{
                        Local = $local; Remote = $remote
                    }))
                }
            }
            return New-Object psobject -Property @{
                Items = $items.ToArray(); Source = 'cim'; Error = $null
            }
        } catch {
            $items.Clear()
        }
        try {
            foreach ($row in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 4' -ErrorAction Stop)) {
                if (-not $row) { continue }
                [void]$items.Add((New-Object psobject -Property @{
                    Local  = [string](Get-SCProp $row 'DeviceID')
                    Remote = [string](Get-SCProp $row 'ProviderName')
                }))
            }
            if ($items.Count -gt 0) {
                return New-Object psobject -Property @{
                    Items = $items.ToArray(); Source = 'cim'; Error = $null
                }
            }
        } catch {
            $items.Clear()
        }
    }
    $native = Invoke-SCNative -FileName 'net' -ArgumentList @('use')
    if (Test-SCNativeDenied -Result $native) {
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = 'NEEDS ADMIN'
        }
    }
    if (-not $native.Ok) {
        $message = [string]$native.Error
        if (-not $message -and $native.Output) { $message = [string]($native.Output -join ' ') }
        if (Test-SCCommandMissingText -Message $message) { $message = 'net is not available.' }
        if ($message -match '(?i)no entries') {
            return New-Object psobject -Property @{
                Items = @(); Source = 'net'; Error = $null
            }
        }
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = $message
        }
    }
    $table = Convert-SCNetTable -Lines @($native.Output)
    if (-not $table.Started) {
        $blob = [string]($native.Output -join "`n")
        if ($blob -match '(?i)no entries') {
            return New-Object psobject -Property @{
                Items = @(); Source = 'net'; Error = $null
            }
        }
        return New-Object psobject -Property @{
            Items = @(); Source = 'none'; Error = 'Mapped drive list could not be parsed.'
        }
    }
    foreach ($row in @($table.Items)) {
        if (-not $row) { continue }
        $cols = @($row.Columns)
        if ($cols.Count -lt 2) { continue }
        $local = ''
        $remote = ''
        foreach ($col in $cols) {
            if ($col -match '^[A-Za-z]:$') { $local = $col }
            elseif ($col -match '^\\\\') { $remote = $col }
        }
        if ($local -or $remote) {
            [void]$items.Add((New-Object psobject -Property @{
                Local = $local; Remote = $remote
            }))
        }
    }
    return New-Object psobject -Property @{
        Items = $items.ToArray(); Source = 'net'; Error = $null
    }
}

function Test-SCLocalDrivePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '^[A-Za-z]:\\')
}

function Invoke-SCCheckShares {
    Start-SCSection -Title 'Shares and mapped drives'
    $shares = Get-SCShareRecordsFromCim
    if ($shares.Source -eq 'none') { $shares = Get-SCShareRecordsFromNet }
    if ($shares.Source -eq 'none') {
        $message = [string]$shares.Error
        if ($message -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $message)) {
            Write-SCNeedsAdmin -Detail 'Shares could not be listed.'
        } else {
            Write-SCWarn -Message ("Shares could not be listed: {0}" -f (Format-SCShortText -Text $message -Max 160))
        }
    } else {
        $rows = @()
        if ($shares.Items) { $rows = @($shares.Items) }
        $admin = 0
        $other = 0
        $shown = 0
        $hidden = 0
        $pathCache = @{}
        foreach ($share in $rows) {
            if (-not $share -or -not $share.Name) { continue }
            $isAdmin = Test-SCAdminShareName -Name $share.Name
            if ($isAdmin) { $admin++ } else { $other++ }
            $path = [string]$share.Path
            if ((Test-SCLocalDrivePath -Path $path) -and (-not $pathCache.ContainsKey($path.ToLowerInvariant()))) {
                $pathCache[$path.ToLowerInvariant()] = (Test-SCWritableByNonAdmin -Path $path)
            }
            $write = $null
            if ($path -and $pathCache.ContainsKey($path.ToLowerInvariant())) {
                $write = $pathCache[$path.ToLowerInvariant()]
            }
            $broad = $false
            $writable = $false
            if ($write -and -not $write.Error) {
                $broad = [bool]$write.BroadWritable
                $writable = [bool]$write.Writable
            }
            if ($broad) {
                $who = Format-SCLimitedList -Items $write.BroadPrincipals -Max 3
                Write-SCWeak -Message ("Share '{0}' folder is writable by a broad principal: {1} ({2})" -f $share.Name, $path, $who)
            } elseif ($writable) {
                $who = Format-SCLimitedList -Items $write.Principals -Max 3
                Write-SCReview -Message ("Share '{0}' folder is writable by a non-admin principal: {1} ({2})" -f $share.Name, $path, $who)
            }
            if ($isAdmin) { continue }
            if ($shown -ge 15) { $hidden++; continue }
            $shown++
            $pathText = 'no local path'
            if ($path) { $pathText = Format-SCShortText -Text $path -Max 80 }
            Write-SCInfo -Message ("Share {0} | {1}" -f $share.Name, $pathText)
        }
        Write-SCInfo -Message ("Shares: {0} administrative, {1} other." -f $admin, $other)
        if ($hidden -gt 0) {
            Write-SCInfo -Message ("{0} additional shares were omitted." -f $hidden)
        }
    }

    $drives = Get-SCMappedDriveRecords
    if ($drives.Source -eq 'none') {
        $message = [string]$drives.Error
        if ($message -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $message)) {
            Write-SCNeedsAdmin -Detail 'Mapped drives could not be listed.'
        } else {
            Write-SCWarn -Message ("Mapped drives could not be listed: {0}" -f (Format-SCShortText -Text $message -Max 160))
        }
        return
    }
    $maps = @()
    if ($drives.Items) { $maps = @($drives.Items) }
    $shownDrives = 0
    $hiddenDrives = 0
    foreach ($drive in $maps) {
        if (-not $drive) { continue }
        if ($shownDrives -ge 15) { $hiddenDrives++; continue }
        $shownDrives++
        $local = [string]$drive.Local
        if (-not $local) { $local = 'unmapped' }
        $remote = Format-SCShortText -Text ([string]$drive.Remote) -Max 80
        if (-not $remote) { $remote = 'unknown' }
        Write-SCInfo -Message ("Mapped drive {0} -> {1}" -f $local, $remote)
    }
    Write-SCInfo -Message ("Mapped drives: {0}." -f $maps.Count)
    if ($hiddenDrives -gt 0) {
        Write-SCInfo -Message ("{0} additional mapped drives were omitted." -f $hiddenDrives)
    }
}

function Get-SCHostsPath {
    $root = $env:SystemRoot
    if (-not $root) { $root = $env:WINDIR }
    if (-not $root) { $root = 'C:\Windows' }
    return (Join-SCWindowsPath -Root $root -Child 'System32\drivers\etc\hosts')
}

function Invoke-SCCheckHosts {
    Start-SCSection -Title 'Hosts file'
    $path = Get-SCHostsPath
    if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
        Write-SCWarn -Message ("Hosts file was not found: {0}" -f $path)
        return
    }
    $write = Test-SCWritableByNonAdmin -Path $path
    if ($write -and -not $write.Error -and $write.BroadWritable) {
        $who = Format-SCLimitedList -Items $write.BroadPrincipals -Max 3
        Write-SCWeak -Message ("Hosts file is writable by a broad principal: {0} ({1})" -f $path, $who)
    } elseif ($write -and -not $write.Error -and $write.Writable) {
        $who = Format-SCLimitedList -Items $write.Principals -Max 3
        Write-SCReview -Message ("Hosts file is writable by a non-admin principal: {0} ({1})" -f $path, $who)
    } elseif ($write -and $write.Error -and ((Test-SCAccessDenied -Message $write.Error) -or $write.Error -eq 'NEEDS ADMIN')) {
        Write-SCNeedsAdmin -Detail 'Hosts file ACL could not be read.'
    }
    $lines = @()
    try {
        $lines = @(Get-Content -LiteralPath $path -TotalCount 500 -ErrorAction Stop)
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) {
            Write-SCNeedsAdmin -Detail 'Hosts file could not be read.'
        } else {
            Write-SCWarn -Message ("Hosts file could not be read: {0}" -f (Format-SCShortText -Text $message -Max 140))
        }
        return
    }
    $notable = 0
    $shown = 0
    $hidden = 0
    foreach ($line in $lines) {
        $entry = Convert-SCHostsLine -Line ([string]$line)
        if (-not $entry) { continue }
        $level = Get-SCHostsEntryLevel -Address $entry.Address -Names $entry.Names
        if ($level -eq 'NONE') { continue }
        $notable++
        if ($shown -ge 20) { $hidden++; continue }
        $shown++
        $names = Format-SCLimitedList -Items $entry.Names -Max 4
        $text = ("Hosts entry {0} -> {1}" -f $entry.Address, $names)
        Write-SCLevel -Level $level -Message $text
    }
    if ($notable -eq 0) {
        Write-SCInfo -Message 'Hosts file has no extra entries.'
    } else {
        Write-SCInfo -Message ("Notable hosts entries: {0}." -f $notable)
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional hosts entries were omitted." -f $hidden)
    }
}

function Get-SCProxySide {
    param([string]$Path, [string]$Label)
    $enable = Get-SCRegistryValue -Path $Path -Name 'ProxyEnable'
    $server = Get-SCRegistryValue -Path $Path -Name 'ProxyServer'
    $auto = Get-SCRegistryValue -Path $Path -Name 'AutoConfigURL'
    $errorText = $null
    foreach ($item in @($enable, $server, $auto)) {
        if ($item -and $item.Error) {
            if (Test-SCAccessDenied -Message $item.Error) { $errorText = 'NEEDS ADMIN' }
            elseif (-not $errorText) { $errorText = [string]$item.Error }
        }
    }
    $enabled = $false
    if ($enable.Found -and ([string]$enable.Value -eq '1')) { $enabled = $true }
    $serverText = ''
    if ($server.Found -and $server.Value) { $serverText = Format-SCProxyValue -Text ([string]$server.Value) -Max 100 }
    $autoText = ''
    if ($auto.Found -and $auto.Value) { $autoText = Format-SCProxyValue -Text ([string]$auto.Value) -Max 120 }
    return New-Object psobject -Property @{
        Label   = $Label
        Present = ($enable.Found -or $server.Found -or $auto.Found)
        Enabled = $enabled
        Server  = $serverText
        Auto    = $autoText
        Error   = $errorText
    }
}

function Invoke-SCCheckProxy {
    Start-SCSection -Title 'Proxy'
    if (-not (Test-SCRegistryHive -Root 'HKLM:\') -and -not (Test-SCRegistryHive -Root 'HKCU:\')) {
        Write-SCWarn -Message 'Registry is not available. Proxy settings were skipped.'
        return
    }
    $sides = @(
        (Get-SCProxySide -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Label 'User')
        (Get-SCProxySide -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Label 'Machine')
    )
    $denied = 0
    $enabledCount = 0
    foreach ($side in $sides) {
        if (-not $side) { continue }
        if ($side.Error -eq 'NEEDS ADMIN') { $denied++; continue }
        if ($side.Error) {
            Write-SCWarn -Message ("{0} proxy settings could not be read." -f $side.Label)
            continue
        }
        if ($side.Enabled) {
            $enabledCount++
            $server = [string]$side.Server
            if (-not $server) { $server = 'server not set' }
            Write-SCReview -Message ("{0} Internet proxy is enabled: {1}" -f $side.Label, $server)
        }
        if ($side.Auto) {
            Write-SCReview -Message ("{0} automatic proxy configuration URL is set: {1}" -f $side.Label, $side.Auto)
        }
    }
    if ($denied -gt 0) {
        Write-SCNeedsAdmin -Detail 'Proxy settings could not be read.'
    }
    if ($enabledCount -eq 0 -and $denied -eq 0) {
        Write-SCInfo -Message 'No Internet proxy is enabled.'
    }
}

function Get-SCGroupPolicyHints {
    $names = New-Object System.Collections.Generic.List[string]
    $sites = New-Object System.Collections.Generic.List[string]
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
    if (-not (Test-SCRegistryHive -Root $base)) {
        return New-Object psobject -Property @{
            DomainControllers = @()
            Sites             = @()
            Error             = $null
        }
    }
    $targets = New-Object System.Collections.Generic.List[string]
    [void]$targets.Add($base)
    try {
        foreach ($child in @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
            if ($child) { [void]$targets.Add([string]$child.PSPath) }
        }
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            return New-Object psobject -Property @{
                DomainControllers = @()
                Sites             = @()
                Error             = 'NEEDS ADMIN'
            }
        }
    }
    foreach ($path in $targets) {
        $dc = Get-SCRegistryValue -Path $path -Name 'DCName'
        if ($dc.Error -and (Test-SCAccessDenied -Message $dc.Error)) {
            return New-Object psobject -Property @{
                DomainControllers = @()
                Sites             = @()
                Error             = 'NEEDS ADMIN'
            }
        }
        if ($dc.Found -and $dc.Value) {
            $text = [string]$dc.Value
            if ($text -and ($names -notcontains $text)) { [void]$names.Add($text) }
        }
        $site = Get-SCRegistryValue -Path $path -Name 'SiteName'
        if ($site.Found -and $site.Value) {
            $text = [string]$site.Value
            if ($text -and ($sites -notcontains $text)) { [void]$sites.Add($text) }
        }
    }
    return New-Object psobject -Property @{
        DomainControllers = $names.ToArray()
        Sites             = $sites.ToArray()
        Error             = $null
    }
}

function Invoke-SCCheckDomainHints {
    Start-SCSection -Title 'Domain controller'
    $ctx = Get-SCContext
    if ($null -eq $ctx.PartOfDomain) {
        Write-SCWarn -Message 'Domain join state could not be read. Domain controller hints were skipped.'
        return
    }
    if (-not $ctx.PartOfDomain) {
        Write-SCInfo -Message 'Not domain-joined. Domain controller hints were skipped.'
        return
    }
    $domain = [string]$ctx.Domain
    if (-not $domain) { $domain = 'unknown' }
    Write-SCInfo -Message ("Domain: {0}" -f $domain)
    if ($ctx.DomainRole -eq 4 -or $ctx.DomainRole -eq 5) {
        Write-SCInfo -Message 'This computer is a domain controller.'
    }
    $site = Get-SCRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DynamicSiteName'
    if ($site.Found -and $site.Value) {
        Write-SCInfo -Message ("Site: {0}" -f (Format-SCShortText -Text ([string]$site.Value) -Max 80))
    }
    $hints = Get-SCGroupPolicyHints
    if ($hints.Error -eq 'NEEDS ADMIN') {
        Write-SCNeedsAdmin -Detail 'Group Policy domain controller hint could not be read.'
        return
    }
    $controllers = @()
    if ($hints.DomainControllers) { $controllers = @($hints.DomainControllers) }
    if ($controllers.Count -eq 0) {
        Write-SCInfo -Message 'No Group Policy domain controller name was stored locally.'
    } else {
        $shown = Format-SCLimitedList -Items $controllers -Max 3
        Write-SCInfo -Message ("Group Policy domain controller: {0}" -f $shown)
    }
    if ((-not $site.Found) -and $hints.Sites) {
        $siteText = Format-SCLimitedList -Items $hints.Sites -Max 2
        if ($siteText) { Write-SCInfo -Message ("Group Policy site: {0}" -f $siteText) }
    }
}

function Invoke-SCNetworkCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

Write-SCHeader -Title 'Network'
Invoke-SCNetworkCheck -Name 'Adapters' -Body { Invoke-SCCheckAdapters }
Invoke-SCNetworkCheck -Name 'Listeners' -Body { Invoke-SCCheckListeners }
Invoke-SCNetworkCheck -Name 'Firewall' -Body { Invoke-SCCheckFirewall }
Invoke-SCNetworkCheck -Name 'Shares' -Body { Invoke-SCCheckShares }
Invoke-SCNetworkCheck -Name 'Hosts file' -Body { Invoke-SCCheckHosts }
Invoke-SCNetworkCheck -Name 'Proxy' -Body { Invoke-SCCheckProxy }
Invoke-SCNetworkCheck -Name 'Domain controller' -Body { Invoke-SCCheckDomainHints }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Network' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
