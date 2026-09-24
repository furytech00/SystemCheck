#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for credential-related configuration.

.NOTES
    Configuration only: whether features are enabled, not the secrets themselves.
    Do not dump LSASS, extract the SAM, or decrypt stored passwords.
    WDigest and cached logon count already have a first check in 01_system.ps1.
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
