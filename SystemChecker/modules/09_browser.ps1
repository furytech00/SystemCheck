#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for browser presence checks.

.NOTES
    Report installed browsers and profile folder presence only.
    Do not decrypt passwords, copy cookies, or read session databases.
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
