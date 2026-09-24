#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for optional file and folder review.

.NOTES
    Keep this off the default runner. Any search must be bounded and read-only.
    Use Get-SCAclSummary and Test-SCWritableByNonAdmin. Do not print secret contents.
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
