#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for an optional event-log summary.

.NOTES
    Keep this off the default runner. Summarize counts for a few log channels.
    Do not dump full logs by default.
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
