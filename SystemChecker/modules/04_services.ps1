#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for service configuration checks.

.NOTES
    Later checks can use Test-SCUnquotedPath and Get-SCAclSummary -ServiceName.
    Report path and permission facts only. Do not start or stop services, and
    do not include exploit recipes.
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
