#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for network configuration checks.

.NOTES
    Report listeners, shares, and firewall profile state. Read-only.
    This module is in the default runner set, so keep it from hanging on
    wide network scans.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$commonPath = Join-Path $PSScriptRoot '00_common.ps1'
if (Test-Path -LiteralPath $commonPath) {
    . $commonPath
}

Write-Host 'not implemented yet'

if ($env:SYSTEMCHECKER_NESTED -eq '1') { return }
exit 0
