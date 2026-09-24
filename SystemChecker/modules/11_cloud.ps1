#Requires -Version 5.1
<#
.SYNOPSIS
    Stub for cloud guest-agent presence.

.NOTES
    Report whether Azure, AWS, or GCP guest-agent services are installed.
    Do not call instance metadata and do not collect cloud credentials.
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
