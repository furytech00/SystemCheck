#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only installed-application inventory.

.DESCRIPTION
    Reads uninstall registry keys and reports product name, version, and
    publisher. Remote-access, backup, database, security, and development
    tools are called out. Common config locations are checked for existence
    only. This module does not read config contents, run uninstall commands,
    execute binaries, or download anything.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\05_applications.ps1
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

function New-SCAppRule {
    param(
        [string]$Id,
        [string]$Category,
        [string]$Level,
        [string]$Label,
        [string]$Pattern,
        [bool]$NameOnly = $false,
        [string[]]$Paths = @()
    )
    return New-Object psobject -Property @{
        Id       = $Id
        Category = $Category
        Level    = $Level
        Label    = $Label
        Pattern  = $Pattern
        NameOnly = $NameOnly
        Paths    = @($Paths)
    }
}

function Get-SCAppRules {
    $list = New-Object System.Collections.Generic.List[object]
    # Remote access is first so names such as RustDesk are not treated as dev tools.
    [void]$list.Add((New-SCAppRule -Id 'teamviewer' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)teamviewer' -Paths @('ProgramFiles|TeamViewer', 'ProgramFilesX86|TeamViewer', 'ProgramData|TeamViewer')))
    [void]$list.Add((New-SCAppRule -Id 'anydesk' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)anydesk' -Paths @('ProgramFiles|AnyDesk', 'ProgramFilesX86|AnyDesk', 'ProgramData|AnyDesk', 'AppData|AnyDesk')))
    [void]$list.Add((New-SCAppRule -Id 'rustdesk' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)rustdesk' -Paths @('ProgramFiles|RustDesk', 'AppData|RustDesk')))
    [void]$list.Add((New-SCAppRule -Id 'screenconnect' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)screenconnect|connectwise' -Paths @('ProgramFiles|ScreenConnect Client', 'ProgramFilesX86|ScreenConnect Client', 'ProgramData|ScreenConnect')))
    [void]$list.Add((New-SCAppRule -Id 'splashtop' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)splashtop' -Paths @('ProgramFiles|Splashtop', 'ProgramFilesX86|Splashtop')))
    [void]$list.Add((New-SCAppRule -Id 'vnc' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)realvnc|tightvnc|ultravnc|tigervnc|\bvnc\b' -Paths @('ProgramFiles|RealVNC', 'ProgramFiles|TightVNC', 'ProgramFiles|UltraVNC', 'ProgramFilesX86|TightVNC', 'ProgramFilesX86|UltraVNC')))
    [void]$list.Add((New-SCAppRule -Id 'remote' -Category 'remote' -Level 'REVIEW' -Label 'Remote access' -Pattern '(?i)logmein|chrome remote desktop|radmin|dameware|beyondtrust|bomgar|remotepc|zoho assist|ammyy|supremo|dwservice|dwagent|meshcentral|\bparsec\b|gotomypc|gotoassist|nomachine|royal ts|mremoteng|remote utilities|litemanager|lite manager|\batera\b|ninjaone|ninjarmm|ninja rmm|\bkaseya\b|datto rmm|pulseway|action1|simplehelp|isl online|netsupport|rdpwrap|remote desktop'))

    [void]$list.Add((New-SCAppRule -Id 'veeam' -Category 'backup' -Level 'INFO' -Label 'Backup' -Pattern '(?i)\bveeam\b' -Paths @('ProgramFiles|Veeam', 'ProgramFilesX86|Veeam', 'ProgramData|Veeam')))
    [void]$list.Add((New-SCAppRule -Id 'acronis' -Category 'backup' -Level 'INFO' -Label 'Backup' -Pattern '(?i)\bacronis\b' -Paths @('ProgramFiles|Acronis', 'ProgramFilesX86|Acronis', 'ProgramData|Acronis')))
    [void]$list.Add((New-SCAppRule -Id 'macrium' -Category 'backup' -Level 'INFO' -Label 'Backup' -Pattern '(?i)macrium' -Paths @('ProgramFiles|Macrium', 'ProgramFilesX86|Macrium')))
    [void]$list.Add((New-SCAppRule -Id 'backup' -Category 'backup' -Level 'INFO' -Label 'Backup' -Pattern '(?i)commvault|backup exec|windows server backup|duplicati|\bcobian\b|crashplan|carbonite|backblaze|urbackup|shadowprotect|storagecraft|\baltaro\b|\bnakivo\b|netbackup|veritas system recovery|easeus todo backup|aomei backupper|novabackup|\bidrive\b|msp360|cloudberry' -NameOnly $true))
    [void]$list.Add((New-SCAppRule -Id 'backup-name' -Category 'backup' -Level 'INFO' -Label 'Backup' -Pattern '(?i)\bbackup\b' -NameOnly $true))

    [void]$list.Add((New-SCAppRule -Id 'sqlserver' -Category 'database' -Level 'INFO' -Label 'Database' -Pattern '(?i)sql server|mysql workbench|azure data studio|pgadmin|dbeaver|heidisql' -Paths @('ProgramFiles|Microsoft SQL Server', 'ProgramFilesX86|Microsoft SQL Server')))
    [void]$list.Add((New-SCAppRule -Id 'mysql' -Category 'database' -Level 'INFO' -Label 'Database' -Pattern '(?i)\bmysql\b|mariadb' -Paths @('ProgramFiles|MySQL', 'ProgramFilesX86|MySQL', 'ProgramData|MySQL', 'ProgramFiles|MariaDB', 'ProgramFilesX86|MariaDB')))
    [void]$list.Add((New-SCAppRule -Id 'postgres' -Category 'database' -Level 'INFO' -Label 'Database' -Pattern '(?i)postgres' -Paths @('ProgramFiles|PostgreSQL', 'ProgramFilesX86|PostgreSQL')))
    [void]$list.Add((New-SCAppRule -Id 'mongo' -Category 'database' -Level 'INFO' -Label 'Database' -Pattern '(?i)\bmongodb\b' -Paths @('ProgramFiles|MongoDB', 'ProgramData|MongoDB')))
    [void]$list.Add((New-SCAppRule -Id 'database' -Category 'database' -Level 'INFO' -Label 'Database' -Pattern '(?i)oracle database|\bredis\b|\bcassandra\b|\bcouchbase\b|elasticsearch'))

    [void]$list.Add((New-SCAppRule -Id 'wireshark' -Category 'security' -Level 'INFO' -Label 'Security' -Pattern '(?i)wireshark' -Paths @('ProgramFiles|Wireshark', 'ProgramFilesX86|Wireshark', 'AppData|Wireshark')))
    [void]$list.Add((New-SCAppRule -Id 'sysmon' -Category 'security' -Level 'INFO' -Label 'Security' -Pattern '(?i)\bsysmon\b'))
    [void]$list.Add((New-SCAppRule -Id 'security' -Category 'security' -Level 'INFO' -Label 'Security' -Pattern '(?i)crowdstrike|falcon sensor|sentinelone|sentinel agent|carbon black|symantec|\bnorton\b|\bmcafee\b|trellix|\bsophos\b|trend micro|\beset\b|kaspersky|bitdefender|malwarebytes|cylance|cortex xdr|globalprotect|\btanium\b|\bnmap\b|defender for endpoint|microsoft defender|windows defender|\bantivirus\b|anti-virus'))

    [void]$list.Add((New-SCAppRule -Id 'vscode' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)visual studio code|\bvscode\b' -Paths @('AppData|Code', 'UserProfile|.vscode', 'LocalAppData|Programs\Microsoft VS Code')))
    [void]$list.Add((New-SCAppRule -Id 'visualstudio' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)visual studio' -Paths @('ProgramFiles|Microsoft Visual Studio', 'ProgramFilesX86|Microsoft Visual Studio', 'LocalAppData|Microsoft\VisualStudio')))
    [void]$list.Add((New-SCAppRule -Id 'git' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)\bgit\b|tortoisegit|github desktop' -Paths @('ProgramFiles|Git', 'ProgramFilesX86|Git', 'UserProfile|.gitconfig')))
    [void]$list.Add((New-SCAppRule -Id 'python' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)\bpython\b' -Paths @('LocalAppData|Programs\Python', 'ProgramFiles|Python', 'ProgramFilesX86|Python')))
    [void]$list.Add((New-SCAppRule -Id 'nodejs' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)node\.?js|\bnodejs\b' -Paths @('ProgramFiles|nodejs', 'ProgramFilesX86|nodejs')))
    [void]$list.Add((New-SCAppRule -Id 'java' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)\bjdk\b|\bjre\b|\bjava\b|openjdk' -Paths @('ProgramFiles|Java', 'ProgramFilesX86|Java', 'ProgramFiles|Eclipse Adoptium', 'ProgramFilesX86|Eclipse Adoptium')))
    [void]$list.Add((New-SCAppRule -Id 'docker' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)\bdocker\b' -Paths @('ProgramFiles|Docker', 'ProgramFilesX86|Docker', 'UserProfile|.docker')))
    [void]$list.Add((New-SCAppRule -Id 'dev' -Category 'dev' -Level 'INFO' -Label 'Dev tool' -Pattern '(?i)windows sdk|software development kit|android studio|intellij|pycharm|webstorm|phpstorm|\brider\b|\beclipse\b|\bcmake\b|mingw|cygwin|\bruby\b|\bphp\b|\bperl\b|\.net sdk|dotnet sdk|powershell 7|\bterraform\b'))

    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Find-SCAppRule {
    param([string]$Name, [string]$Publisher, $Rules)
    $nameText = [string]$Name
    $both = ('{0} {1}' -f $nameText, ([string]$Publisher)).Trim()
    foreach ($rule in @($Rules)) {
        if (-not $rule) { continue }
        $target = $both
        if ($rule.NameOnly) { $target = $nameText }
        if ($target -and $target -match [string]$rule.Pattern) { return $rule }
    }
    return $null
}

function Test-SCSystemComponent {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $false }
    return ([string]$Value -eq '1')
}

function Test-SCUpdateEntry {
    param(
        [string]$Name,
        $SystemComponent,
        [string]$ReleaseType,
        [string]$ParentKeyName
    )
    if (Test-SCSystemComponent -Value $SystemComponent) { return 'component' }
    if ($ParentKeyName -and $ParentKeyName.Trim()) { return 'update' }
    if ($ReleaseType -and ($ReleaseType -match '(?i)hotfix|update|service pack|rollup')) { return 'update' }
    if ($Name -match '(?i)^kb\d+') { return 'update' }
    if ($Name -match '(?i)\(kb\d+\)') { return 'update' }
    if ($Name -match '(?i)^(security update|update for|hotfix for)\b') { return 'update' }
    return ''
}

function Test-SCRuntimeEntry {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $patterns = @(
        '(?i)redistributable',
        '(?i)visual c\+\+',
        '(?i)\.net framework',
        '(?i)\.net (runtime|host|desktop runtime|targeting pack)',
        '(?i)microsoft asp\.net',
        '(?i)webview2',
        '(?i)^microsoft edge\b',
        '(?i)update health tools'
    )
    foreach ($pattern in $patterns) {
        if ($Name -match $pattern) { return $true }
    }
    return $false
}

function Convert-SCUninstallEntry {
    param($Props, [string]$Scope)
    $name = [string](Get-SCProp $Props 'DisplayName')
    $name = Format-SCShortText -Text $name -Max 160
    if (-not $name) { return $null }
    $version = Format-SCShortText -Text ([string](Get-SCProp $Props 'DisplayVersion')) -Max 40
    $publisher = Format-SCShortText -Text ([string](Get-SCProp $Props 'Publisher')) -Max 80
    $location = Format-SCShortText -Text ([string](Get-SCProp $Props 'InstallLocation')) -Max 180
    $release = Format-SCShortText -Text ([string](Get-SCProp $Props 'ReleaseType')) -Max 40
    $parent = Format-SCShortText -Text ([string](Get-SCProp $Props 'ParentKeyName')) -Max 80
    return New-Object psobject -Property @{
        Name            = $name
        Version         = $version
        Publisher       = $publisher
        Location        = $location
        SystemComponent = (Get-SCProp $Props 'SystemComponent')
        ReleaseType     = $release
        ParentKeyName   = $parent
        Scope           = $Scope
    }
}

function Select-SCUniqueApps {
    param($Items)
    $seen = @{}
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Items)) {
        if (-not $item -or -not $item.Name) { continue }
        $key = '{0}|{1}' -f $item.Name.ToLowerInvariant(), ([string]$item.Version).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$list.Add($item)
    }
    return New-Object psobject -Property @{
        Items = $list.ToArray()
    }
}

function Build-SCAppReport {
    param($Entries, $Rules)
    $highlights = New-Object System.Collections.Generic.List[object]
    $others = New-Object System.Collections.Generic.List[object]
    $matched = New-Object System.Collections.Generic.List[object]
    $seenRule = @{}
    $updates = 0
    $components = 0
    $runtimes = 0
    foreach ($entry in @($Entries)) {
        if (-not $entry -or -not $entry.Name) { continue }
        $kind = Test-SCUpdateEntry -Name $entry.Name -SystemComponent $entry.SystemComponent -ReleaseType $entry.ReleaseType -ParentKeyName $entry.ParentKeyName
        if ($kind -eq 'component') { $components++; continue }
        if ($kind -eq 'update') { $updates++; continue }
        $rule = Find-SCAppRule -Name $entry.Name -Publisher $entry.Publisher -Rules $Rules
        if ($rule) {
            [void]$highlights.Add((New-Object psobject -Property @{
                Name      = [string]$entry.Name
                Version   = [string]$entry.Version
                Publisher = [string]$entry.Publisher
                Location  = [string]$entry.Location
                Category  = [string]$rule.Category
                Level     = [string]$rule.Level
                Label     = [string]$rule.Label
            }))
            if (-not $seenRule.ContainsKey([string]$rule.Id)) {
                $seenRule[[string]$rule.Id] = $true
                [void]$matched.Add($rule)
            }
            continue
        }
        if (Test-SCRuntimeEntry -Name $entry.Name) { $runtimes++; continue }
        [void]$others.Add($entry)
    }
    return New-Object psobject -Property @{
        Highlights   = $highlights.ToArray()
        Others       = $others.ToArray()
        MatchedRules = $matched.ToArray()
        Updates      = $updates
        Components   = $components
        Runtimes     = $runtimes
        Kept         = ($highlights.Count + $others.Count)
    }
}

function Format-SCAppText {
    param($App, [switch]$WithLocation)
    $version = [string]$App.Version
    if (-not $version) { $version = 'version unknown' }
    $publisher = [string]$App.Publisher
    if (-not $publisher) { $publisher = 'publisher unknown' }
    $line = '{0} | {1} | {2}' -f (Format-SCShortText -Text ([string]$App.Name) -Max 80), (Format-SCShortText -Text $version -Max 40), (Format-SCShortText -Text $publisher -Max 60)
    if ($WithLocation) {
        $loc = [string]$App.Location
        if ($loc -and -not (Test-SCUncPath -Path $loc) -and ($loc -notmatch '(?i)password|secret|pwd=')) {
            $line = '{0} | {1}' -f $line, (Format-SCShortText -Text $loc -Max 80)
        }
    }
    return $line
}

function Get-SCKnownRoot {
    param([string]$Name)
    switch ($Name) {
        'ProgramFiles' { return [string]$env:ProgramFiles }
        'ProgramFilesX86' { return [string]${env:ProgramFiles(x86)} }
        'ProgramW6432' { return [string]$env:ProgramW6432 }
        'ProgramData' { return [string]$env:ProgramData }
        'AppData' { return [string]$env:APPDATA }
        'LocalAppData' { return [string]$env:LOCALAPPDATA }
        'UserProfile' { return [string]$env:USERPROFILE }
        'WinDir' { return [string]$env:WINDIR }
        default { return '' }
    }
}

function Resolve-SCConfigSpec {
    param([string]$Spec)
    if ([string]::IsNullOrWhiteSpace($Spec)) { return '' }
    $bar = $Spec.IndexOf('|')
    if ($bar -lt 1 -or $bar -ge ($Spec.Length - 1)) { return '' }
    $root = Get-SCKnownRoot -Name $Spec.Substring(0, $bar)
    if (-not $root) { return '' }
    $child = $Spec.Substring($bar + 1)
    return (Join-SCWindowsPath -Root $root -Child $child)
}

function Test-SCConfigPathExists {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (Test-SCUncPath -Path $Path) { return $false }
    try {
        return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    } catch {
        return $false
    }
}

function Get-SCUninstallHiveResult {
    param([string]$Scope, [string]$Path)
    $result = New-Object psobject -Property @{
        Items   = @()
        Found   = $false
        Missing = $false
        Denied  = $false
        Error   = $null
    }
    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
        return $result
    }
    if (-not $exists) {
        $result.Missing = $true
        return $result
    }
    $items = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath $Path -ErrorAction Stop)) {
            if (-not $key) { continue }
            try {
                $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            } catch {
                $message = $_.Exception.Message
                if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
                elseif (-not $result.Error) { $result.Error = $message }
                continue
            }
            $entry = Convert-SCUninstallEntry -Props $props -Scope $Scope
            if ($entry) { [void]$items.Add($entry) }
        }
        $result.Found = $true
        $result.Items = $items.ToArray()
    } catch {
        $message = $_.Exception.Message
        if (Test-SCAccessDenied -Message $message) { $result.Denied = $true }
        else { $result.Error = $message }
    }
    return $result
}

function Get-SCUninstallPrograms {
    $hives = @(
        @{ Scope = 'HKLM'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Scope = 'HKLM32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Scope = 'HKCU'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    $items = New-Object System.Collections.Generic.List[object]
    $found = 0
    $denied = $false
    $errorText = $null
    foreach ($hive in $hives) {
        $bag = Get-SCUninstallHiveResult -Scope ([string]$hive.Scope) -Path ([string]$hive.Path)
        if ($bag.Found) { $found++ }
        if ($bag.Denied) { $denied = $true }
        if ($bag.Error -and -not $errorText) { $errorText = [string]$bag.Error }
        foreach ($entry in @($bag.Items)) {
            if ($entry) { [void]$items.Add($entry) }
        }
    }
    $unique = Select-SCUniqueApps -Items $items.ToArray()
    $uniqueItems = @()
    if ($unique.Items) { $uniqueItems = @($unique.Items) }
    return New-Object psobject -Property @{
        Items = $uniqueItems
        Found = $found
        Denied = $denied
        Error = $errorText
    }
}

function Write-SCAppGroup {
    param(
        $Rows,
        [string]$Category,
        [int]$Cap,
        [ref]$Hidden
    )
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($Rows)) {
        if ($row -and $row.Category -eq $Category) { [void]$matched.Add($row) }
    }
    $ordered = @($matched.ToArray() | Sort-Object -Property Name)
    $shown = 0
    foreach ($row in $ordered) {
        if (-not $row) { continue }
        if ($shown -ge $Cap) { $Hidden.Value++; continue }
        $shown++
        $text = '{0}: {1}' -f $row.Label, (Format-SCAppText -App $row -WithLocation)
        Write-SCLevel -Level $row.Level -Message $text
    }
}

function Invoke-SCCheckApplications {
    Start-SCSection -Title 'Installed programs'
    $bag = Get-SCUninstallPrograms
    $script:SCMatchedAppRules = @()
    if ($bag.Found -eq 0 -and $bag.Denied) {
        Write-SCNeedsAdmin -Detail 'Uninstall registry keys could not be read.'
        return
    }
    if ($bag.Found -eq 0) {
        $detail = 'Uninstall registry keys were not found.'
        if ($bag.Error) { $detail = Format-SCShortText -Text ([string]$bag.Error) -Max 160 }
        Write-SCWarn -Message $detail
        return
    }

    $rules = @()
    $ruleBag = Get-SCAppRules
    if ($ruleBag.Items) { $rules = @($ruleBag.Items) }
    $entries = @()
    if ($bag.Items) { $entries = @($bag.Items) }
    $report = Build-SCAppReport -Entries $entries -Rules $rules
    $script:SCMatchedAppRules = @()
    if ($report.MatchedRules) { $script:SCMatchedAppRules = @($report.MatchedRules) }
    $remote = 0
    $backup = 0
    $database = 0
    $security = 0
    $dev = 0
    foreach ($row in @($report.Highlights)) {
        if (-not $row) { continue }
        switch ($row.Category) {
            'remote' { $remote++ }
            'backup' { $backup++ }
            'database' { $database++ }
            'security' { $security++ }
            'dev' { $dev++ }
        }
    }
    $others = @()
    if ($report.Others) { $others = @($report.Others) }
    Write-SCInfo -Message ("Installed programs: {0}. Remote access: {1}. Backup: {2}. Database: {3}. Security: {4}. Dev tools: {5}. Other: {6}. Updates skipped: {7}. Components skipped: {8}. Runtimes skipped: {9}." -f $report.Kept, $remote, $backup, $database, $security, $dev, $others.Count, $report.Updates, $report.Components, $report.Runtimes)

    $hidden = 0
    $highlightRows = @()
    if ($report.Highlights) { $highlightRows = @($report.Highlights) }
    foreach ($category in @('remote', 'backup', 'database', 'security', 'dev')) {
        Write-SCAppGroup -Rows $highlightRows -Category $category -Cap 12 -Hidden ([ref]$hidden)
    }
    $orderedOther = @($others | Sort-Object -Property Name)
    $shownOther = 0
    foreach ($row in $orderedOther) {
        if (-not $row) { continue }
        if ($shownOther -ge 20) { $hidden++; continue }
        $shownOther++
        Write-SCInfo -Message ("Other: {0}" -f (Format-SCAppText -App $row))
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional programs were omitted." -f $hidden)
    }
    if ($bag.Denied) {
        Write-SCNeedsAdmin -Detail 'Some uninstall keys could not be read.'
    } elseif ($bag.Error) {
        Write-SCWarn -Message ("Some uninstall keys could not be read: {0}" -f (Format-SCShortText -Text ([string]$bag.Error) -Max 160))
    }
}

function Invoke-SCCheckAppConfigs {
    Start-SCSection -Title 'Application config paths'
    $rules = @()
    if ($script:SCMatchedAppRules) { $rules = @($script:SCMatchedAppRules) }
    if ($rules.Count -eq 0) { return }
    $shown = 0
    $hidden = 0
    $seen = @{}
    foreach ($rule in $rules) {
        if (-not $rule) { continue }
        foreach ($spec in @($rule.Paths)) {
            $path = Resolve-SCConfigSpec -Spec ([string]$spec)
            if (-not $path) { continue }
            $key = $path.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            if (-not (Test-SCConfigPathExists -Path $path)) { continue }
            $seen[$key] = $true
            if ($shown -ge 15) { $hidden++; continue }
            $shown++
            Write-SCInfo -Message ("Config path exists ({0}): {1}" -f $rule.Label, (Format-SCShortText -Text $path -Max 120))
        }
    }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional config paths were omitted." -f $hidden)
    }
}

function Invoke-SCAppCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, (Format-SCShortText -Text $_.Exception.Message -Max 160))
    }
}

$script:SCMatchedAppRules = @()
Write-SCHeader -Title 'Applications'
Invoke-SCAppCheck -Name 'Installed programs' -Body { Invoke-SCCheckApplications }
Invoke-SCAppCheck -Name 'Application config paths' -Body { Invoke-SCCheckAppConfigs }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Applications' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
