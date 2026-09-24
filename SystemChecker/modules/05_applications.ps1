#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for an installed-application inventory.

.NOTES
    Read uninstall registry keys and report names and versions.
    Do not execute binaries found on disk.
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
