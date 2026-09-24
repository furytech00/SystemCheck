#Requires -Version 5.1
<#
.SYNOPSIS
    Run SystemChecker configuration modules.

.DESCRIPTION
    Read-only assessment driver for Windows PowerShell 5.1.
    Default modules are system, users, services, and network.
    File searches, event-log sweeps, cloud guest-agent checks, and Active Directory context stay opt-in.

.PARAMETER Modules
    Aliases to run. Accepts a comma-separated string or repeated values.
    Aliases: system, users, processes, services, apps, network, creds,
    files, browser, events, cloud, ad. Numeric prefixes such as 01 also work.
    The token "all" selects every ready module.

.PARAMETER All
    Run every ready module. If -Modules is also set, -All wins.

.PARAMETER Plain
    Disable ANSI color. Sets $script:SCPlain for this process.

.PARAMETER Log
    Append a plain-text transcript to this path. No file is written without it.

.PARAMETER Html
    Write a self-contained HTML report to this path after the run.
    No file is written without it.

.PARAMETER List
    Print the module catalog and exit.

.EXAMPLE
    .\Run-SystemChecker.ps1

.EXAMPLE
    .\Run-SystemChecker.ps1 -Modules system,users,services

.EXAMPLE
    .\Run-SystemChecker.ps1 -All

.EXAMPLE
    .\Run-SystemChecker.ps1 -Modules all

.EXAMPLE
    .\Run-SystemChecker.ps1 -Plain

.EXAMPLE
    .\Run-SystemChecker.ps1 -Log .\systemchecker.log

.EXAMPLE
    .\Run-SystemChecker.ps1 -Html .\report.html

.EXAMPLE
    .\Run-SystemChecker.ps1 -List
#>
[CmdletBinding()]
param(
    [Alias('Module')]
    [string[]]$Modules,
    [switch]$All,
    [switch]$Plain,
    [string]$Log,
    [string]$Html,
    [switch]$List
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$moduleDir = Join-Path $PSScriptRoot 'modules'
$commonPath = Join-Path $moduleDir '00_common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host ("Missing helper library: {0}" -f $commonPath)
    exit 1
}
. $commonPath

function Get-SCCatalog {
    # Status: ready (real checks) or stub (prints "not implemented yet").
    # Add a row when a new module file is introduced. Keep numeric order.
    return @(
        @{ Name = 'system';    File = '01_system.ps1';       Status = 'ready'; Purpose = 'OS, UAC, LSA, Defender, application control' }
        @{ Name = 'users';     File = '02_users_tokens.ps1'; Status = 'ready'; Purpose = 'Accounts, groups, and privilege names' }
        @{ Name = 'processes'; File = '03_processes.ps1';    Status = 'ready'; Purpose = 'Process inventory' }
        @{ Name = 'services';  File = '04_services.ps1';     Status = 'ready'; Purpose = 'Service configuration and path checks' }
        @{ Name = 'apps';      File = '05_applications.ps1'; Status = 'ready'; Purpose = 'Installed application inventory' }
        @{ Name = 'network';   File = '06_network.ps1';      Status = 'ready'; Purpose = 'Listeners, shares, and firewall profile' }
        @{ Name = 'creds';     File = '07_credentials.ps1';  Status = 'ready'; Purpose = 'Credential names and leftover paths' }
        @{ Name = 'files';     File = '08_files.ps1';        Status = 'ready'; Purpose = 'Bounded folder ACLs and file names' }
        @{ Name = 'browser';   File = '09_browser.ps1';      Status = 'ready'; Purpose = 'Installed browsers and profile folders' }
        @{ Name = 'events';    File = '10_events.ps1';       Status = 'ready'; Purpose = 'Bounded event-log counts' }
        @{ Name = 'cloud';     File = '11_cloud.ps1';        Status = 'ready'; Purpose = 'Cloud guest-agent presence' }
        @{ Name = 'ad';        File = '12_ad_optional.ps1';  Status = 'ready'; Purpose = 'Domain join, site, and DC reachability' }
    )
}

function Get-SCModuleAliases {
    param($Item)
    $stem = $Item.File -replace '\.ps1$', ''
    $prefix = $Item.File.Substring(0, 2)
    return @(
        ([string]$Item.Name).ToLower()
        $stem.ToLower()
        ([string]$Item.File).ToLower()
        $prefix
    )
}

function Find-SCModule {
    param([string]$Token, $Catalog)
    $key = $Token.Trim().ToLower()
    foreach ($item in @($Catalog)) {
        $aliases = @(Get-SCModuleAliases -Item $item)
        if ($aliases -contains $key) { return $item }
    }
    return $null
}

function Show-SCModuleList {
    $catalog = @(Get-SCCatalog)
    Write-Host 'SystemChecker modules'
    Write-Host ''
    Write-Host '  Alias       File                     State   Purpose'
    Write-Host '  -----       ----                     -----   -------'
    foreach ($item in $catalog) {
        $line = '  {0,-11} {1,-24} {2,-7} {3}' -f $item.Name, $item.File, $item.Status, $item.Purpose
        Write-Host $line
    }
    Write-Host ''
    Write-Host 'Default run: system, users, services, network'
    Write-Host 'Aliases also accept 01..12 and the script file name.'
    Write-Host 'Run every ready module: .\Run-SystemChecker.ps1 -All'
    Write-Host '                      .\Run-SystemChecker.ps1 -Modules all'
    Write-Host 'If -All and -Modules are both set, -All wins.'
    Write-Host 'HTML report: .\Run-SystemChecker.ps1 -Html .\report.html'
    Write-Host '             .\Export-SystemCheckerHtml.ps1 -Log .\systemchecker.log -Out .\report.html'
    Write-Host 'files, browser, events, cloud, and ad are not part of the default run.'
}

function Get-SCReadyCatalog {
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in @(Get-SCCatalog)) {
        if ([string]$item.Status -eq 'ready') { [void]$list.Add($item) }
    }
    return New-Object psobject -Property @{
        Items = @($list.ToArray())
    }
}

function Resolve-SCSelection {
    param([string[]]$Requested)
    $catalog = @(Get-SCCatalog)
    $tokens = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Requested)) {
        if (-not $item) { continue }
        foreach ($part in ($item -split ',')) {
            $text = $part.Trim()
            if ($text) { [void]$tokens.Add($text) }
        }
    }

    $selected = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $unknown = New-Object System.Collections.Generic.List[string]
    $usedAll = $false
    foreach ($token in $tokens) {
        if ($token.Trim().ToLower() -eq 'all') {
            $usedAll = $true
            continue
        }
        $match = Find-SCModule -Token $token -Catalog $catalog
        if (-not $match) {
            [void]$unknown.Add($token)
            continue
        }
        if ($seen.ContainsKey($match.Name)) { continue }
        $seen[$match.Name] = $true
        [void]$selected.Add($match)
    }
    if ($usedAll -and @($unknown.ToArray()).Count -eq 0) {
        $ready = Get-SCReadyCatalog
        return New-Object psobject -Property @{
            Selected = @($ready.Items)
            Unknown  = @()
            UsedAll  = $true
        }
    }
    return New-Object psobject -Property @{
        Selected = @($selected.ToArray())
        Unknown  = @($unknown.ToArray())
        UsedAll  = $usedAll
    }
}

function Get-SCRunPlan {
    param(
        [switch]$All,
        [switch]$ModulesSpecified,
        [string[]]$Modules
    )
    if ($All) {
        $ready = Get-SCReadyCatalog
        return New-Object psobject -Property @{
            Selected = @($ready.Items)
            Unknown  = @()
            Override = [bool]$ModulesSpecified
            Mode     = 'all'
        }
    }
    $requested = $Modules
    $mode = 'named'
    if (-not $ModulesSpecified) {
        $requested = @('system', 'users', 'services', 'network')
        $mode = 'default'
    }
    $selection = Resolve-SCSelection -Requested $requested
    if ($selection.UsedAll -and @($selection.Unknown).Count -eq 0) { $mode = 'all' }
    return New-Object psobject -Property @{
        Selected = @($selection.Selected)
        Unknown  = @($selection.Unknown)
        Override = $false
        Mode     = $mode
    }
}

if ($List) {
    Show-SCModuleList
    exit 0
}

$modulesSpecified = $PSBoundParameters.ContainsKey('Modules')
$plan = Get-SCRunPlan -All:$All -ModulesSpecified:$modulesSpecified -Modules $Modules
if (@($plan.Unknown).Count -gt 0) {
    Write-Host ("Unknown module: {0}" -f ($plan.Unknown -join ', '))
    Write-Host 'Run .\Run-SystemChecker.ps1 -List for aliases.'
    exit 1
}
if (@($plan.Selected).Count -eq 0) {
    Write-Host 'No modules selected. Run .\Run-SystemChecker.ps1 -List for aliases.'
    exit 1
}

foreach ($item in @($plan.Selected)) {
    $full = Join-Path $moduleDir $item.File
    if (-not (Test-Path -LiteralPath $full)) {
        Write-Host ("Missing module file: {0}" -f $full)
        exit 1
    }
}

Reset-SCReport
Initialize-SCRuntime -Plain:$Plain -LogPath $Log

$names = New-Object System.Collections.Generic.List[string]
foreach ($item in @($plan.Selected)) { [void]$names.Add([string]$item.Name) }
Write-SCHeader -Title 'Runner'
Start-SCSection -Title 'Run'
Write-SCInfo -Message ("Selected modules: {0}" -f ($names -join ', '))
if ($plan.Override) {
    Write-SCInfo -Message '-All overrides -Modules. Every ready module was selected.'
}
if ($Plain) {
    Write-SCInfo -Message 'Plain output: ANSI color is off.'
}
if ($script:SCLogPath) {
    Write-SCInfo -Message ("Log: {0}" -f $script:SCLogPath)
}
Complete-SCSection

$env:SYSTEMCHECKER_NESTED = '1'
try {
    foreach ($item in @($plan.Selected)) {
        $full = Join-Path $moduleDir $item.File
        try {
            # Call, do not dot-source. A module's top-level return must not unwind the runner.
            & $full
        } catch {
            Write-SCWarn -Message ("Module {0} stopped: {1}" -f $item.Name, $_.Exception.Message)
        }
    }
} finally {
    if (Test-Path -Path 'Env:SYSTEMCHECKER_NESTED') {
        Remove-Item -Path 'Env:SYSTEMCHECKER_NESTED' -ErrorAction SilentlyContinue
    }
}

Write-SCLine -Text ''
Write-SCLine -Text 'SystemChecker finished.' -Style Dim

if (-not [string]::IsNullOrWhiteSpace($Html)) {
    $htmlResult = $null
    try {
        $rows = @()
        if ($global:SCReportFindings) { $rows = $global:SCReportFindings.ToArray() }
        $htmlResult = Export-SCHtmlReport -Path $Html -Findings $rows -Computer $global:SCReportComputer -User $global:SCReportUser -Time $global:SCReportTime -Admin $global:SCReportAdmin
    } catch {
        $htmlResult = New-Object psobject -Property @{
            Ok       = $false
            Error    = [string]$_.Exception.Message
            FullPath = ''
        }
    }
    if ($htmlResult -and $htmlResult.Ok) {
        Write-SCLine -Text ("HTML report: {0}" -f $htmlResult.FullPath) -Style Dim
    } else {
        $detail = 'HTML report was not written.'
        if ($htmlResult -and $htmlResult.Error) { $detail = $htmlResult.Error }
        Write-SCWarn -Message ("HTML report was not written: {0}" -f $detail)
    }
}
exit 0
