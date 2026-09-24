#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for a read-only process inventory.

.NOTES
    List process names, owners, and integrity when available.
    Do not inject into a process or read another process's memory.
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
