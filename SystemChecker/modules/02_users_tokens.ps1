#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only account, group, and privilege-name checks.

.DESCRIPTION
    Reports the current token, local users, local groups, password policy,
    auto-logon configuration, logon sessions, and profile-folder ACLs.
    Privilege names are labeled. This module does not capture tokens, print
    passwords, or describe how to use a privilege.

    Run alone:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\02_users_tokens.ps1
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

function New-SCFinding {
    param([string]$Level, [string]$Text)
    return New-Object psobject -Property @{
        Level = $Level
        Text  = $Text
    }
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

function Write-SCFindingItems {
    param($Items)
    foreach ($item in @($Items)) {
        if (-not $item) { continue }
        Write-SCLevel -Level ([string]$item.Level) -Message ([string]$item.Text)
    }
}

function Format-SCShortText {
    param([string]$Text, [int]$Max = 80)
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

function Convert-SCWhoamiCsv {
    # Positional columns so localized headers still work.
    param([string[]]$Lines)
    $kept = New-Object System.Collections.Generic.List[string]
    $started = $false
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        $trim = ([string]$line).Trim()
        if (-not $trim) { continue }
        if (-not $started) {
            if ($trim.StartsWith('"') -or $trim -match '^[^,]+,[^,]+') { $started = $true }
            else { continue }
        }
        if ($started) { [void]$kept.Add($trim) }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    if ($kept.Count -lt 2) {
        return New-Object psobject -Property @{ Items = $rows.ToArray() }
    }
    try {
        $parsed = @(($kept.ToArray() -join "`n") | ConvertFrom-Csv)
    } catch {
        return New-Object psobject -Property @{ Items = $rows.ToArray() }
    }
    foreach ($row in @($parsed)) {
        if (-not $row) { continue }
        $vals = New-Object System.Collections.Generic.List[string]
        foreach ($prop in @($row.PSObject.Properties)) {
            [void]$vals.Add([string]$prop.Value)
        }
        while ($vals.Count -lt 4) { [void]$vals.Add('') }
        $rows.Add((New-Object psobject -Property @{
            C1 = $vals[0]
            C2 = $vals[1]
            C3 = $vals[2]
            C4 = $vals[3]
        }))
    }
    return New-Object psobject -Property @{ Items = $rows.ToArray() }
}

function Get-SCPrivilegeState {
    # Disabled is tested first. "Deaktiviert" contains "aktiviert".
    param([string]$State)
    $text = ''
    if ($State) { $text = $State.Trim() }
    if (-not $text) { return 'unknown' }
    if ($text -match '(?i)disabled|deaktiviert|deactiv|desactiv|desabilit|disabilit|uitgeschakeld|deaktiver|inaktiverad') {
        return 'disabled'
    }
    if ($text -match '(?i)enabled|aktiviert|activ|habilit|abilit|ingeschakeld|aktiverad|aktiveret|aktivoitu') {
        return 'enabled'
    }
    return 'unknown'
}

function Get-SCPrivilegeImpact {
    # Names only. No description of how a privilege can be used.
    param([string]$Name)
    $key = ''
    if ($Name) { $key = $Name.Trim() }
    $weak = @(
        'SeDebugPrivilege',
        'SeTcbPrivilege',
        'SeCreateTokenPrivilege',
        'SeLoadDriverPrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeTrustedCredManAccessPrivilege'
    )
    $review = @(
        'SeImpersonatePrivilege',
        'SeBackupPrivilege',
        'SeRestorePrivilege',
        'SeTakeOwnershipPrivilege',
        'SeRelabelPrivilege',
        'SeEnableDelegationPrivilege'
    )
    foreach ($item in $weak) {
        if ($key -eq $item) { return 'weak' }
    }
    foreach ($item in $review) {
        if ($key -eq $item) { return 'review' }
    }
    return 'info'
}

function Get-SCIntegrityLabel {
    param([string]$Sid)
    switch ($Sid) {
        'S-1-16-0'     { return 'Untrusted' }
        'S-1-16-4096'  { return 'Low' }
        'S-1-16-8192'  { return 'Medium' }
        'S-1-16-8448'  { return 'Medium Plus' }
        'S-1-16-12288' { return 'High' }
        'S-1-16-16384' { return 'System' }
        default        { return $null }
    }
}

function Get-SCGroupUse {
    param([string]$Attributes)
    $text = ''
    if ($Attributes) { $text = $Attributes }
    if ($text -match '(?i)deny only|nur verweigern|pour refuser|solo para denegar') { return 'deny-only' }
    if ($text -match '(?i)enabled group|aktivierte gruppe|groupe activ|grupo habilitado') { return 'enabled' }
    return 'listed'
}

function Get-SCLogonLabel {
    param($Type)
    if ($null -eq $Type -or [string]$Type -eq '') { return $null }
    $number = 0
    if (-not [int]::TryParse([string]$Type, [ref]$number)) { return $null }
    switch ($number) {
        2  { return 'Interactive' }
        10 { return 'Remote interactive' }
        11 { return 'Cached remote interactive' }
        default { return $null }
    }
}

function Convert-SCAccountPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'unknown' }
    $match = [regex]::Match($Path, 'Domain="([^"]*)",Name="([^"]*)"')
    if ($match.Success) {
        $domain = $match.Groups[1].Value
        $name = $match.Groups[2].Value
        if ($domain -and $name) { return ('{0}\{1}' -f $domain, $name) }
        if ($name) { return $name }
    }
    return 'unknown'
}

function Get-SCLabeledValue {
    param([string[]]$Lines, [string]$LabelRegex)
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        if ($line -match $LabelRegex) {
            if ($line -match ':\s*(.+?)\s*$') { return $Matches[1].Trim() }
        }
    }
    return $null
}

function Get-SCPaddedValue {
    param([string[]]$Lines, [string]$Label)
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        if ($line.StartsWith($Label)) {
            $rest = $line.Substring($Label.Length).Trim()
            if ($rest) { return $rest }
        }
    }
    return $null
}

function Get-SCPasswordPolicyFindings {
    param([string[]]$Lines)
    $items = New-Object System.Collections.Generic.List[object]
    $minLen = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)Minimum password length'
    $maxAge = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)Maximum password age'
    $minAge = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)Minimum password age'
    $history = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)password history'
    $lockout = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)Lockout threshold'
    $duration = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)Lockout duration'
    $window = Get-SCLabeledValue -Lines $Lines -LabelRegex '(?i)Lockout observation window'

    if ($minLen) {
        $number = 0
        if ([int]::TryParse($minLen, [ref]$number)) {
            if ($number -le 0) {
                $items.Add((New-SCFinding 'WEAK' 'Minimum password length: 0'))
            } elseif ($number -lt 8) {
                $items.Add((New-SCFinding 'REVIEW' ("Minimum password length: {0}" -f $number)))
            } else {
                $items.Add((New-SCFinding 'INFO' ("Minimum password length: {0}" -f $number)))
            }
        } else {
            $items.Add((New-SCFinding 'INFO' ("Minimum password length: {0}" -f (Format-SCShortText $minLen))))
        }
    }
    if ($maxAge) {
        if ($maxAge -match '(?i)^(0|never|none|unlimited)$') {
            $items.Add((New-SCFinding 'REVIEW' ("Maximum password age: {0}" -f $maxAge)))
        } else {
            $items.Add((New-SCFinding 'INFO' ("Maximum password age: {0}" -f (Format-SCShortText $maxAge))))
        }
    }
    if ($minAge) {
        $items.Add((New-SCFinding 'INFO' ("Minimum password age: {0}" -f (Format-SCShortText $minAge))))
    }
    if ($history) {
        $number = 0
        $parsed = [int]::TryParse($history, [ref]$number)
        if ($history -match '(?i)^(0|never|none|unlimited)$' -or ($parsed -and $number -lt 5)) {
            $items.Add((New-SCFinding 'REVIEW' ("Password history: {0}" -f (Format-SCShortText $history))))
        } else {
            $items.Add((New-SCFinding 'INFO' ("Password history: {0}" -f (Format-SCShortText $history))))
        }
    }
    if ($lockout) {
        if ($lockout -match '(?i)^(0|never|none|unlimited)$') {
            $items.Add((New-SCFinding 'REVIEW' ("Lockout threshold: {0}" -f $lockout)))
        } else {
            $items.Add((New-SCFinding 'INFO' ("Lockout threshold: {0}" -f (Format-SCShortText $lockout))))
        }
    }
    if ($duration) {
        $items.Add((New-SCFinding 'INFO' ("Lockout duration: {0}" -f (Format-SCShortText $duration))))
    }
    if ($window) {
        $items.Add((New-SCFinding 'INFO' ("Lockout observation window: {0}" -f (Format-SCShortText $window))))
    }
    if ($items.Count -eq 0) {
        $items.Add((New-SCFinding 'WARN' 'Password policy output could not be parsed.'))
    }
    return New-Object psobject -Property @{ Items = $items.ToArray() }
}

function Get-SCSecretPresence {
    # Returns missing, empty, present, or error. Never returns the value.
    param($Result)
    if (-not $Result) { return 'missing' }
    if ($Result.Error) { return 'error' }
    if (-not $Result.Found) { return 'missing' }
    if ($null -eq $Result.Value) { return 'empty' }
    if (([string]$Result.Value).Length -gt 0) { return 'present' }
    return 'empty'
}

function Get-SCAutoLogonFindings {
    param(
        [bool]$KeyError,
        [bool]$Enabled,
        [string]$PasswordState,
        [string]$AltPasswordState,
        [string]$UserName
    )
    $items = New-Object System.Collections.Generic.List[object]
    if ($KeyError) {
        $items.Add((New-SCFinding 'WARN' 'NEEDS ADMIN: auto-logon registry values could not be read'))
        return New-Object psobject -Property @{ Items = $items.ToArray() }
    }
    if ($Enabled -and $PasswordState -eq 'present') {
        $items.Add((New-SCFinding 'WEAK' 'Auto-logon is enabled and DefaultPassword is present. The password value was not printed.'))
    } elseif ($Enabled -and $PasswordState -eq 'empty') {
        $items.Add((New-SCFinding 'REVIEW' 'Auto-logon is enabled and DefaultPassword is empty.'))
    } elseif ($Enabled) {
        $items.Add((New-SCFinding 'REVIEW' 'Auto-logon is enabled. DefaultPassword is not set.'))
    } elseif ($PasswordState -eq 'present') {
        $items.Add((New-SCFinding 'REVIEW' 'DefaultPassword is present while auto-logon is off. The password value was not printed.'))
    } else {
        $items.Add((New-SCFinding 'INFO' 'Auto-logon is not enabled.'))
    }
    if ($AltPasswordState -eq 'present') {
        $items.Add((New-SCFinding 'REVIEW' 'AltDefaultPassword is present. The password value was not printed.'))
    }
    if ($UserName -and ($Enabled -or $PasswordState -eq 'present')) {
        $shown = Format-SCShortText -Text $UserName -Max 80
        $items.Add((New-SCFinding 'INFO' ("Auto-logon user name: {0}" -f $shown)))
    }
    return New-Object psobject -Property @{ Items = $items.ToArray() }
}

function Get-SCUserFinding {
    param($User)
    $bits = New-Object System.Collections.Generic.List[string]
    $enabled = Get-SCProp -Object $User -Name 'Enabled'
    if ($enabled -eq $true) { [void]$bits.Add('enabled') }
    elseif ($enabled -eq $false) { [void]$bits.Add('disabled') }
    else { [void]$bits.Add('enabled state unknown') }

    $required = Get-SCProp -Object $User -Name 'PasswordRequired'
    if ($required -eq $false) { [void]$bits.Add('password not required') }
    elseif ($required -eq $true) { [void]$bits.Add('password required') }

    $never = Get-SCProp -Object $User -Name 'PasswordNeverExpires'
    if ($never -eq $true) { [void]$bits.Add('password set to never expire') }
    elseif ($never -eq $false) { [void]$bits.Add('password can expire') }

    $lastSet = Get-SCProp -Object $User -Name 'PasswordLastSet'
    if ($lastSet) { [void]$bits.Add(('password last set ' + (Format-SCDate $lastSet))) }

    $sid = [string](Get-SCProp -Object $User -Name 'Sid')
    $name = [string](Get-SCProp -Object $User -Name 'Name')
    if (-not $name) { $name = 'unknown' }
    $rid500 = ($sid -match '-500$') -or ($name -eq 'Administrator')
    $rid501 = ($sid -match '-501$') -or ($name -eq 'Guest')

    $level = 'INFO'
    if ($enabled -eq $true -and $never -eq $true) { $level = 'REVIEW' }
    if ($enabled -eq $true -and $rid500) { $level = 'REVIEW' }
    if ($enabled -eq $true -and $required -eq $false) { $level = 'WEAK' }
    if ($enabled -eq $true -and $rid501) { $level = 'WEAK' }

    $prefix = $name
    if ($rid500) { $prefix = '{0} (built-in Administrator)' -f $name }
    if ($rid501) { $prefix = '{0} (Guest)' -f $name }
    $text = '{0}: {1}' -f $prefix, ($bits -join ', ')
    return New-SCFinding -Level $level -Text $text
}

function New-SCUserRecord {
    param(
        [string]$Name,
        [string]$Sid,
        $Enabled,
        $PasswordRequired,
        $PasswordNeverExpires,
        $PasswordLastSet
    )
    return New-Object psobject -Property @{
        Name                 = $Name
        Sid                  = $Sid
        Enabled              = $Enabled
        PasswordRequired     = $PasswordRequired
        PasswordNeverExpires = $PasswordNeverExpires
        PasswordLastSet      = $PasswordLastSet
    }
}

function Get-SCNetUserNames {
    param([string[]]$Lines)
    $names = New-Object System.Collections.Generic.List[string]
    $inTable = $false
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        if ($line -match '^-{5,}') { $inTable = $true; continue }
        if (-not $inTable) { continue }
        if ($line -match '(?i)command completed|system error') { break }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        foreach ($part in ($line -split '\s{2,}')) {
            $trim = $part.Trim()
            if ($trim) { [void]$names.Add($trim) }
        }
    }
    return New-Object psobject -Property @{ Items = $names.ToArray() }
}

function Get-SCYesNo {
    param([string]$Value)
    if ($Value -match '(?i)^yes$') { return $true }
    if ($Value -match '(?i)^no$') { return $false }
    return $null
}

function Get-SCNetUserRecord {
    param([string]$Name, [string[]]$Lines)
    $active = Get-SCPaddedValue -Lines $Lines -Label 'Account active'
    $required = Get-SCPaddedValue -Lines $Lines -Label 'Password required'
    $expires = Get-SCPaddedValue -Lines $Lines -Label 'Password expires'
    $lastSetRaw = Get-SCPaddedValue -Lines $Lines -Label 'Password last set'
    if (-not $active -and -not $required -and -not $expires) { return $null }
    $enabled = Get-SCYesNo -Value $active
    $passwordRequired = Get-SCYesNo -Value $required
    $never = $null
    if ($expires -match '(?i)^never$') { $never = $true }
    elseif ($expires) { $never = $false }
    $lastSet = $null
    if ($lastSetRaw -and $lastSetRaw -notmatch '(?i)^never$') {
        try { $lastSet = [datetime]$lastSetRaw } catch { $lastSet = $null }
    }
    return New-SCUserRecord -Name $Name -Sid '' -Enabled $enabled -PasswordRequired $passwordRequired -PasswordNeverExpires $never -PasswordLastSet $lastSet
}

function Add-SCUserRecord {
    param($Bag, $Record)
    if (-not $Record) { return }
    $name = [string](Get-SCProp -Object $Record -Name 'Name')
    if (-not $name) { return }
    if ($Bag.ContainsKey($name)) { return }
    $Bag[$name] = $Record
}

function Get-SCUsersFromLocalAccounts {
    $bag = @{}
    if (-not (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)) {
        try { Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop } catch { return ,$bag }
    }
    if (-not (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)) { return ,$bag }
    $users = @(Get-LocalUser -ErrorAction Stop)
    foreach ($user in $users) {
        $sid = ''
        $sidObj = Get-SCProp -Object $user -Name 'SID'
        if ($sidObj) {
            $sidValue = Get-SCProp -Object $sidObj -Name 'Value'
            if ($sidValue) { $sid = [string]$sidValue }
            elseif ($sidObj) { $sid = [string]$sidObj }
        }
        $never = $null
        if ($user.PSObject.Properties['PasswordExpires']) {
            if ($null -eq $user.PasswordExpires) { $never = $true } else { $never = $false }
        }
        $record = New-SCUserRecord -Name ([string]$user.Name) -Sid $sid -Enabled $user.Enabled -PasswordRequired $user.PasswordRequired -PasswordNeverExpires $never -PasswordLastSet (Get-SCProp -Object $user -Name 'PasswordLastSet')
        Add-SCUserRecord -Bag $bag -Record $record
    }
    # Comma keeps the hashtable from being enumerated on return.
    return ,$bag
}

function Get-SCUsersFromCim {
    $bag = @{}
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) { return ,$bag }
    $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
    foreach ($user in $users) {
        $disabled = Get-SCProp -Object $user -Name 'Disabled'
        $enabled = $null
        if ($disabled -eq $true) { $enabled = $false }
        elseif ($disabled -eq $false) { $enabled = $true }
        $required = Get-SCProp -Object $user -Name 'PasswordRequired'
        $expires = Get-SCProp -Object $user -Name 'PasswordExpires'
        $never = $null
        if ($expires -eq $false) { $never = $true }
        elseif ($expires -eq $true) { $never = $false }
        $record = New-SCUserRecord -Name ([string](Get-SCProp -Object $user -Name 'Name')) -Sid ([string](Get-SCProp -Object $user -Name 'SID')) -Enabled $enabled -PasswordRequired $required -PasswordNeverExpires $never -PasswordLastSet $null
        Add-SCUserRecord -Bag $bag -Record $record
    }
    return ,$bag
}

function Invoke-SCCheckToken {
    Start-SCSection -Title 'Current token'
    $userName = $null
    $userSid = $null
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($identity.Name) { $userName = [string]$identity.Name }
        if ($identity.User) { $userSid = [string]$identity.User.Value }
    } catch {
        $userName = $null
    }
    if (-not $userName) {
        $ctx = Get-SCContext
        $userName = [string]$ctx.UserName
    }
    Write-SCInfo -Message ("User: {0}" -f $userName)
    if ($userSid) { Write-SCInfo -Message ("SID: {0}" -f $userSid) }
    $adminText = 'No'
    if (Test-SCAdmin) { $adminText = 'Yes' }
    Write-SCInfo -Message ("Elevated process: {0}" -f $adminText)

    $result = Invoke-SCNative -FileName 'whoami' -ArgumentList @('/groups', '/fo', 'csv')
    if (Test-SCNativeDenied -Result $result) {
        Write-SCNeedsAdmin -Detail 'group list could not be read'
        return
    }
    $table = Convert-SCWhoamiCsv -Lines @($result.Output)
    $rows = @($table.Items)
    if ($rows.Count -eq 0) {
        Write-SCWarn -Message 'whoami /groups did not return group rows.'
        return
    }

    $integrity = $null
    $integritySid = $null
    $adminUse = $null
    $adminAttr = ''
    $names = New-Object System.Collections.Generic.List[string]
    $capability = 0
    foreach ($row in $rows) {
        $sid = [string]$row.C3
        $name = [string]$row.C1
        if ($sid -like 'S-1-16-*') {
            $label = Get-SCIntegrityLabel -Sid $sid
            if ($label) {
                $integrity = $label
                $integritySid = $sid
            }
            continue
        }
        if ($sid -like 'S-1-5-5-*') { continue }
        if ($sid -like 'S-1-15-3-*') { $capability++; continue }
        if ($sid -eq 'S-1-5-32-544' -or $name -match '(?i)\\Administrators$' -or $name -eq 'Administrators') {
            $adminUse = Get-SCGroupUse -Attributes ([string]$row.C4)
            $adminAttr = Format-SCShortText -Text ([string]$row.C4) -Max 100
            continue
        }
        if ($name) { [void]$names.Add($name) }
    }

    if ($integrity) {
        $line = "Integrity: {0} ({1})" -f $integrity, $integritySid
        if ($integrity -eq 'Low' -or $integrity -eq 'Untrusted') {
            Write-SCReview -Message $line
        } else {
            Write-SCInfo -Message $line
        }
    } else {
        Write-SCInfo -Message 'Integrity level was not present in whoami /groups.'
    }

    if ($adminUse -eq 'enabled') {
        Write-SCInfo -Message 'Administrators is enabled on this token.'
    } elseif ($adminUse -eq 'deny-only') {
        Write-SCInfo -Message 'Administrators is present on this token for deny only.'
    } elseif ($adminAttr) {
        Write-SCInfo -Message ("Administrators attributes: {0}" -f $adminAttr)
    } else {
        Write-SCInfo -Message 'Administrators was not listed on this token.'
    }

    $shown = 0
    foreach ($name in @($names | Sort-Object -Unique)) {
        if ($shown -ge 20) { break }
        $shown++
        Write-SCInfo -Message ("Group: {0}" -f $name)
    }
    $hidden = @($names | Sort-Object -Unique).Count - $shown
    if ($hidden -lt 0) { $hidden = 0 }
    if ($hidden -gt 0) {
        Write-SCInfo -Message ("{0} additional groups were omitted." -f $hidden)
    }
    if ($capability -gt 0) {
        Write-SCInfo -Message ("Capability SIDs omitted: {0}" -f $capability)
    }
    if ($names.Count -eq 0 -and -not $adminUse) {
        Write-SCInfo -Message 'No group names were returned.'
    }
}

function Invoke-SCCheckPrivileges {
    Start-SCSection -Title 'Privileges'
    $result = Invoke-SCNative -FileName 'whoami' -ArgumentList @('/priv', '/fo', 'csv')
    if (Test-SCNativeDenied -Result $result) {
        Write-SCNeedsAdmin -Detail 'privilege list could not be read'
        return
    }
    $table = Convert-SCWhoamiCsv -Lines @($result.Output)
    $enabled = 0
    $present = 0
    $disabledHigh = New-Object System.Collections.Generic.List[string]
    $sawPrivilege = $false
    foreach ($row in @($table.Items)) {
        $name = [string]$row.C1
        if ($name -notmatch '^Se[A-Za-z]+Privilege$') { continue }
        $sawPrivilege = $true
        $present++
        $state = Get-SCPrivilegeState -State ([string]$row.C3)
        $impact = Get-SCPrivilegeImpact -Name $name
        $desc = Format-SCShortText -Text ([string]$row.C2) -Max 80
        if ($state -eq 'enabled') {
            $enabled++
            $text = "Enabled privilege {0}" -f $name
            if ($desc) { $text = "{0} ({1})" -f $text, $desc }
            if ($impact -eq 'weak') { Write-SCWeak -Message $text }
            elseif ($impact -eq 'review') { Write-SCReview -Message $text }
            else { Write-SCInfo -Message $text }
        } elseif ($state -eq 'disabled' -and $impact -ne 'info') {
            [void]$disabledHigh.Add($name)
        } elseif ($state -eq 'unknown' -and $impact -ne 'info') {
            $raw = Format-SCShortText -Text ([string]$row.C3) -Max 40
            Write-SCInfo -Message ("Privilege {0} state was not classified: {1}" -f $name, $raw)
        }
    }
    if (-not $sawPrivilege) {
        Write-SCWarn -Message 'whoami /priv did not return privilege rows.'
        return
    }
    Write-SCInfo -Message ("Privileges: {0} present, {1} enabled" -f $present, $enabled)
    if ($disabledHigh.Count -gt 0) {
        $joined = (@($disabledHigh | Sort-Object -Unique) -join ', ')
        Write-SCInfo -Message ("High-impact privileges present but not enabled: {0}" -f $joined)
    } elseif ($enabled -eq 0) {
        Write-SCInfo -Message 'No privileges are enabled.'
    }
}

function Invoke-SCCheckLocalUsers {
    Start-SCSection -Title 'Local users'
    $bag = @{}
    $source = $null
    try {
        $bag = Get-SCUsersFromLocalAccounts
        if (@($bag.Keys).Count -gt 0) { $source = 'LocalAccounts' }
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'local users could not be read'
            return
        }
        $bag = @{}
    }
    if (-not $source) {
        try {
            $bag = Get-SCUsersFromCim
            if (@($bag.Keys).Count -gt 0) { $source = 'CIM' }
        } catch {
            if (Test-SCAccessDenied -Message $_.Exception.Message) {
                Write-SCNeedsAdmin -Detail 'local users could not be read'
                return
            }
            $bag = @{}
        }
    }
    if (-not $source) {
        $listed = Invoke-SCNative -FileName 'net' -ArgumentList @('user')
        if (Test-SCNativeDenied -Result $listed) {
            Write-SCNeedsAdmin -Detail 'local users could not be read'
            return
        }
        $names = Get-SCNetUserNames -Lines @($listed.Output)
        $count = 0
        foreach ($name in @($names.Items)) {
            if ($count -ge 40) { break }
            if ($name -notmatch '^[\w .$-]{1,64}$') { continue }
            $count++
            $detail = Invoke-SCNative -FileName 'net' -ArgumentList @('user', $name)
            if (Test-SCNativeDenied -Result $detail) {
                Write-SCNeedsAdmin -Detail 'local user details could not be read'
                return
            }
            $record = Get-SCNetUserRecord -Name $name -Lines @($detail.Output)
            if ($record) { Add-SCUserRecord -Bag $bag -Record $record }
            else { Add-SCUserRecord -Bag $bag -Record (New-SCUserRecord -Name $name -Sid '' -Enabled $null -PasswordRequired $null -PasswordNeverExpires $null -PasswordLastSet $null) }
        }
        if (@($bag.Keys).Count -gt 0) { $source = 'net user' }
    }
    if (-not $source) {
        Write-SCWarn -Message 'Local users could not be listed.'
        return
    }
    $records = @($bag.Values | Sort-Object -Property Name)
    Write-SCInfo -Message ("Local accounts: {0}" -f $records.Count)
    foreach ($record in $records) {
        $finding = Get-SCUserFinding -User $record
        Write-SCLevel -Level $finding.Level -Message $finding.Text
    }
}

function Get-SCGroupMembersFromLinks {
    param($Links, [string]$GroupName, [string]$Domain)
    $members = New-Object System.Collections.Generic.List[string]
    $needleDomain = ''
    $needleName = ''
    if ($Domain) { $needleDomain = [regex]::Escape($Domain) }
    if ($GroupName) { $needleName = [regex]::Escape($GroupName) }
    foreach ($link in @($Links)) {
        $groupPath = [string](Get-SCProp -Object $link -Name 'GroupComponent')
        $domainOk = $true
        if ($needleDomain) { $domainOk = $groupPath -match ('Domain="' + $needleDomain + '"') }
        $nameOk = $false
        if ($needleName) { $nameOk = $groupPath -match ('Name="' + $needleName + '"') }
        if (-not ($domainOk -and $nameOk)) { continue }
        $part = [string](Get-SCProp -Object $link -Name 'PartComponent')
        $account = Convert-SCAccountPath -Path $part
        if ($account -and $account -ne 'unknown') { [void]$members.Add($account) }
    }
    return New-Object psobject -Property @{ Items = $members.ToArray() }
}

function Test-SCBroadMemberName {
    param([string]$Name)
    if (-not $Name) { return $false }
    $leaf = $Name
    if ($Name -match '\\') {
        $parts = $Name.Split('\')
        $leaf = $parts[$parts.Length - 1]
    }
    $broad = @('Everyone', 'Users', 'Authenticated Users', 'Guests', 'ANONYMOUS LOGON', 'INTERACTIVE')
    return ($broad -contains $leaf)
}

function Write-SCMemberList {
    param([string]$Title, $Members, [switch]$FlagBroad)
    $items = @($Members | Sort-Object -Unique)
    if ($items.Count -eq 0 -or ($items.Count -eq 1 -and -not $items[0])) {
        Write-SCInfo -Message ("{0}: no members" -f $Title)
        return
    }
    $shown = 0
    foreach ($member in $items) {
        if (-not $member) { continue }
        if ($shown -ge 20) { break }
        $shown++
        if ($FlagBroad -and (Test-SCBroadMemberName -Name ([string]$member))) {
            Write-SCWeak -Message ("{0} member is a broad principal: {1}" -f $Title, $member)
        } else {
            Write-SCInfo -Message ("{0} member: {1}" -f $Title, $member)
        }
    }
    if ($items.Count -gt $shown) {
        Write-SCInfo -Message ("{0} additional {1} members were omitted." -f ($items.Count - $shown), $Title)
    }
}

function Invoke-SCCheckLocalGroups {
    Start-SCSection -Title 'Local groups'
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        Write-SCWarn -Message 'CIM is not available, so local groups could not be queried.'
        return
    }
    try {
        $groups = @(Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=True' -ErrorAction Stop)
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'local groups could not be read'
        } else {
            Write-SCWarn -Message ("Local groups could not be read: {0}" -f $_.Exception.Message)
        }
        return
    }
    if ($groups.Count -eq 0) {
        Write-SCInfo -Message 'No local groups were returned.'
        return
    }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($group in $groups) {
        $name = [string](Get-SCProp -Object $group -Name 'Name')
        if ($name) { [void]$names.Add($name) }
    }
    Write-SCInfo -Message ("Local groups: {0}" -f $names.Count)
    $shown = 0
    foreach ($name in @($names | Sort-Object)) {
        if ($shown -ge 20) { break }
        $shown++
        Write-SCInfo -Message ("Group: {0}" -f $name)
    }
    if ($names.Count -gt $shown) {
        Write-SCInfo -Message ("{0} additional group names were omitted." -f ($names.Count - $shown))
    }

    $links = @()
    try {
        $links = @(Get-CimInstance -ClassName Win32_GroupUser -ErrorAction Stop)
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'local group members could not be read'
        } else {
            Write-SCWarn -Message ("Local group members could not be read: {0}" -f $_.Exception.Message)
        }
        return
    }

    $interesting = @(
        @{ Sid = 'S-1-5-32-544'; Title = 'Administrators'; Flag = $true }
        @{ Sid = 'S-1-5-32-555'; Title = 'Remote Desktop Users'; Flag = $false }
        @{ Sid = 'S-1-5-32-551'; Title = 'Backup Operators'; Flag = $true }
    )
    foreach ($spec in $interesting) {
        $match = $null
        foreach ($group in $groups) {
            if ([string](Get-SCProp -Object $group -Name 'SID') -eq $spec.Sid) {
                $match = $group
                break
            }
        }
        if (-not $match) {
            Write-SCInfo -Message ("{0}: group not found" -f $spec.Title)
            continue
        }
        $found = Get-SCGroupMembersFromLinks -Links $links -GroupName ([string]$match.Name) -Domain ([string]$match.Domain)
        if ($spec.Flag) {
            Write-SCMemberList -Title $spec.Title -Members $found.Items -FlagBroad
        } else {
            Write-SCMemberList -Title $spec.Title -Members $found.Items
        }
    }
}

function Invoke-SCCheckAutoLogon {
    Start-SCSection -Title 'Auto-logon'
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto = Get-SCRegistryValue -Path $key -Name 'AutoAdminLogon'
    # Read the secret only to classify presence. Do not pass the value onward.
    $password = Get-SCRegistryValue -Path $key -Name 'DefaultPassword'
    $passwordState = Get-SCSecretPresence -Result $password
    $passwordDenied = $false
    if ($password.Error -and (Test-SCAccessDenied -Message $password.Error)) { $passwordDenied = $true }
    $password = $null
    $alt = Get-SCRegistryValue -Path $key -Name 'AltDefaultPassword'
    $altState = Get-SCSecretPresence -Result $alt
    $altDenied = $false
    if ($alt.Error -and (Test-SCAccessDenied -Message $alt.Error)) { $altDenied = $true }
    $alt = $null
    $user = Get-SCRegistryValue -Path $key -Name 'DefaultUserName'
    $keyError = $false
    if ($passwordDenied -or $altDenied) { $keyError = $true }
    if ($auto.Error -and (Test-SCAccessDenied -Message $auto.Error)) { $keyError = $true }
    $enabled = $false
    if ($auto.Found -and [string]$auto.Value -eq '1') { $enabled = $true }
    $userName = ''
    if ($user.Found -and $user.Value -and -not $user.Error) { $userName = [string]$user.Value }
    if ($passwordState -eq 'error') { $passwordState = 'missing' }
    if ($altState -eq 'error') { $altState = 'missing' }
    $findings = Get-SCAutoLogonFindings -KeyError $keyError -Enabled $enabled -PasswordState $passwordState -AltPasswordState $altState -UserName $userName
    Write-SCFindingItems -Items $findings.Items
    $force = Get-SCRegistryValue -Path $key -Name 'ForceAutoLogon'
    if ($force.Found -and [string]$force.Value -eq '1') {
        Write-SCInfo -Message 'ForceAutoLogon is 1.'
    }
}

function Invoke-SCCheckSessions {
    Start-SCSection -Title 'Logon sessions'
    if (-not (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        Write-SCWarn -Message 'CIM is not available, so logon sessions could not be queried.'
        return
    }
    try {
        $sessions = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop)
        $links = @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop)
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'logon sessions could not be read'
        } else {
            Write-SCWarn -Message ("Logon sessions could not be read: {0}" -f $_.Exception.Message)
        }
        return
    }
    $byId = @{}
    foreach ($session in $sessions) {
        $id = [string](Get-SCProp -Object $session -Name 'LogonId')
        if ($id) { $byId[$id] = $session }
    }
    $shown = 0
    $extra = 0
    $otherTypes = 0
    $seen = @{}
    foreach ($link in $links) {
        $dependent = [string](Get-SCProp -Object $link -Name 'Dependent')
        $antecedent = [string](Get-SCProp -Object $link -Name 'Antecedent')
        $id = $null
        $match = [regex]::Match($dependent, 'LogonId="([^"]+)"')
        if (-not $match.Success) { $match = [regex]::Match($dependent, 'LogonId=(\d+)') }
        if ($match.Success) { $id = $match.Groups[1].Value }
        $session = $null
        if ($id -and $byId.ContainsKey($id)) { $session = $byId[$id] }
        $type = $null
        if ($session) { $type = Get-SCProp -Object $session -Name 'LogonType' }
        $label = Get-SCLogonLabel -Type $type
        if (-not $label) {
            $otherTypes++
            continue
        }
        $account = Convert-SCAccountPath -Path $antecedent
        $key = '{0}|{1}' -f $account, $label
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if ($shown -ge 20) { $extra++; continue }
        $shown++
        $started = 'unknown'
        if ($session) { $started = Format-SCDate (Get-SCProp -Object $session -Name 'StartTime') }
        Write-SCInfo -Message ("{0}: {1}, started {2}" -f $account, $label, $started)
    }
    if ($shown -eq 0) {
        Write-SCInfo -Message 'No interactive or remote interactive sessions were returned.'
        try {
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $console = [string](Get-SCProp -Object $computer -Name 'UserName')
            if ($console) { Write-SCInfo -Message ("Console user: {0}" -f $console) }
        } catch {
            # The session query already succeeded. A missing console name is not fatal.
        }
    }
    if ($extra -gt 0) {
        Write-SCInfo -Message ("{0} additional interactive sessions were omitted." -f $extra)
    }
    if ($otherTypes -gt 0) {
        Write-SCInfo -Message ("Other logon types omitted: {0}" -f $otherTypes)
    }
}

function Invoke-SCCheckPasswordPolicy {
    Start-SCSection -Title 'Password policy'
    $result = Invoke-SCNative -FileName 'net' -ArgumentList @('accounts')
    if (Test-SCNativeDenied -Result $result) {
        Write-SCNeedsAdmin -Detail 'password policy could not be read'
        return
    }
    if (-not $result.Ok -and @($result.Output).Count -eq 0) {
        $detail = 'net accounts failed'
        if ($result.Error) { $detail = [string]$result.Error }
        if ($detail -match 'not recognized|CommandNotFound|cannot find') {
            $detail = 'net accounts is not available on this host'
        }
        Write-SCWarn -Message ("Password policy could not be read: {0}" -f (Format-SCShortText -Text $detail -Max 120))
        return
    }
    $findings = Get-SCPasswordPolicyFindings -Lines @($result.Output)
    Write-SCFindingItems -Items $findings.Items
}

function Test-SCSamePath {
    param([string]$Left, [string]$Right)
    if (-not $Left -or -not $Right) { return $false }
    $a = $Left.Trim().TrimEnd('\')
    $b = $Right.Trim().TrimEnd('\')
    return ($a -eq $b)
}

function Write-SCProfileAcl {
    param([string]$Path, [switch]$Current)
    if (-not (Test-Path -LiteralPath $Path)) { return 'missing' }
    $summary = Get-SCAclSummary -Path $Path
    if ($summary.Error) {
        if ($summary.Error -eq 'NEEDS ADMIN' -or (Test-SCAccessDenied -Message $summary.Error)) {
            Write-SCNeedsAdmin -Detail ("profile ACL could not be read for {0}" -f $Path)
        } else {
            Write-SCWarn -Message ("Profile ACL could not be read for {0}: {1}" -f $Path, (Format-SCShortText $summary.Error))
        }
        return 'error'
    }
    $owner = [string]$summary.Owner
    if (-not $owner) { $owner = 'unknown' }
    Write-SCInfo -Message ("Profile {0} owner {1}" -f $Path, $owner)
    $broad = @()
    if ($summary.BroadWritePrincipals) { $broad = @($summary.BroadWritePrincipals) }
    if ($broad.Count -gt 0) {
        $sample = @($broad | Select-Object -First 5)
        Write-SCReview -Message ("Profile {0} is writable by a broad principal: {1}" -f $Path, ($sample -join ', '))
    }
    if (-not $Current) {
        $writers = @()
        if ($summary.NonAdminWritePrincipals) { $writers = @($summary.NonAdminWritePrincipals) }
        $extra = New-Object System.Collections.Generic.List[string]
        foreach ($writer in $writers) {
            $text = [string]$writer
            if (-not $text) { continue }
            if ($broad -contains $text) { continue }
            if ($owner -eq $text) { continue }
            [void]$extra.Add($text)
        }
        if ($extra.Count -gt 0) {
            $sample = @($extra | Select-Object -First 5)
            Write-SCReview -Message ("Profile {0} is writable by a non-admin principal: {1}" -f $Path, ($sample -join ', '))
        }
    }
    return 'ok'
}

function Invoke-SCCheckProfiles {
    Start-SCSection -Title 'Profile folders'
    $paths = New-Object System.Collections.Generic.List[object]
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $sawKey = $false
    try {
        if (Test-Path -LiteralPath $root -ErrorAction Stop) {
            $sawKey = $true
            foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $sid = [string]$child.PSChildName
                if ($sid -notmatch '^S-1-5-21-\d') { continue }
                if ($sid -match '\.bak$') { continue }
                $key = Join-Path $root $sid
                $value = Get-SCRegistryValue -Path $key -Name 'ProfileImagePath'
                if ($value.Error) {
                    if (Test-SCAccessDenied -Message $value.Error) {
                        Write-SCNeedsAdmin -Detail 'profile list could not be read'
                        return
                    }
                    continue
                }
                if ($value.Found -and $value.Value) {
                    $paths.Add((New-Object psobject -Property @{
                        Sid  = $sid
                        Path = [string]$value.Value
                    }))
                }
            }
        }
    } catch {
        if (Test-SCAccessDenied -Message $_.Exception.Message) {
            Write-SCNeedsAdmin -Detail 'profile list could not be read'
            return
        }
        Write-SCWarn -Message ("Profile list could not be read: {0}" -f $_.Exception.Message)
    }
    $current = $env:USERPROFILE
    if ($current) {
        $already = $false
        foreach ($entry in @($paths)) {
            if (Test-SCSamePath -Left $current -Right ([string]$entry.Path)) { $already = $true }
        }
        if (-not $already) {
            $paths.Insert(0, (New-Object psobject -Property @{ Sid = ''; Path = [string]$current }))
        }
    }
    if ($paths.Count -eq 0) {
        if (-not $sawKey) {
            Write-SCInfo -Message 'No user profile directories were found.'
        }
        return
    }
    $checked = 0
    $missing = 0
    foreach ($entry in @($paths)) {
        if ($checked -ge 15) { break }
        $path = [string]$entry.Path
        if (-not $path) { continue }
        $isCurrent = Test-SCSamePath -Left $path -Right $current
        $status = Write-SCProfileAcl -Path $path -Current:$isCurrent
        if ($status -eq 'missing') { $missing++; continue }
        $checked++
    }
    $remaining = $paths.Count - $checked - $missing
    if ($remaining -lt 0) { $remaining = 0 }
    if ($remaining -gt 0) {
        Write-SCInfo -Message ("{0} additional profiles were omitted." -f $remaining)
    }
    if ($missing -gt 0) {
        Write-SCInfo -Message ("Profile paths missing on disk: {0}" -f $missing)
    }
}

function Invoke-SCUsersCheck {
    param([scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-SCWarn -Message ("{0} check failed: {1}" -f $Name, $_.Exception.Message)
    }
}

Write-SCHeader -Title 'Users / Tokens'
Invoke-SCUsersCheck -Name 'Current token' -Body { Invoke-SCCheckToken }
Invoke-SCUsersCheck -Name 'Privileges' -Body { Invoke-SCCheckPrivileges }
Invoke-SCUsersCheck -Name 'Local users' -Body { Invoke-SCCheckLocalUsers }
Invoke-SCUsersCheck -Name 'Local groups' -Body { Invoke-SCCheckLocalGroups }
Invoke-SCUsersCheck -Name 'Auto-logon' -Body { Invoke-SCCheckAutoLogon }
Invoke-SCUsersCheck -Name 'Logon sessions' -Body { Invoke-SCCheckSessions }
Invoke-SCUsersCheck -Name 'Password policy' -Body { Invoke-SCCheckPasswordPolicy }
Invoke-SCUsersCheck -Name 'Profile folders' -Body { Invoke-SCCheckProfiles }
Complete-SCSection
Write-SCLine -Text ''
Write-SCLine -Text 'Module complete: Users / Tokens' -Style Dim

# The runner sets SYSTEMCHECKER_NESTED and invokes this file with &.
# exit would close the whole PowerShell process, including later modules.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
