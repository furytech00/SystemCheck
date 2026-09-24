#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for account, group, and privilege-name checks.

.NOTES
    Next module to implement. Report local accounts, group membership, and
    privilege names only. Do not capture tokens, passwords, or ticket data.
    Follow the section pattern in 01_system.ps1.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$commonPath = Join-Path $PSScriptRoot '00_common.ps1'
if (Test-Path -LiteralPath $commonPath) {
    . $commonPath
}

Write-Host 'not implemented yet'

# Nested runs return so the runner can continue. A direct -File run exits 0.
if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
