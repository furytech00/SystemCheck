#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for optional Active Directory context.

.NOTES
    Read-only domain context for a joined host: domain name, site, and DC
    reachability. Do not run attack techniques against Active Directory.
    Leave this module out of the default runner.
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
