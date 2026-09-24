#Requires -Version 5.1
<#
.SYNOPSIS
    Turn a SystemChecker plain-text log into one HTML file.

.DESCRIPTION
    Reads the transcript written by -Log and writes a self-contained HTML
    report. It does not run assessment checks and it does not contact the
    network. The terminal log remains the source of truth.

.PARAMETER Log
    Plain-text transcript from Run-SystemChecker.ps1 -Log.

.PARAMETER Out
    HTML file to write. The parent directory must already exist.

.EXAMPLE
    .\Export-SystemCheckerHtml.ps1 -Log .\systemchecker.log -Out .\report.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Log,
    [Parameter(Mandatory = $true)]
    [string]$Out
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$commonPath = Join-Path $PSScriptRoot 'modules'
$commonPath = Join-Path $commonPath '00_common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host ("Missing helper library: {0}" -f $commonPath)
    exit 1
}
. $commonPath

if ([string]::IsNullOrWhiteSpace($Log) -or -not (Test-Path -LiteralPath $Log)) {
    Write-Host ("Log file was not found: {0}" -f $Log)
    exit 1
}
if ((Test-Path -LiteralPath $Log) -and (Get-Item -LiteralPath $Log).PSIsContainer) {
    Write-Host ("Log path is a directory: {0}" -f $Log)
    exit 1
}

$text = ''
try {
    $utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
    $text = [System.IO.File]::ReadAllText($Log, $utf8)
} catch {
    Write-Host ("Log file could not be read: {0}" -f $_.Exception.Message)
    exit 1
}

$parsed = ConvertFrom-SCReportLog -Text $text
$result = Export-SCHtmlReport -Path $Out -Findings $parsed.Findings -Computer $parsed.Computer -User $parsed.User -Time $parsed.Time -Admin $parsed.Admin
if (-not $result.Ok) {
    $detail = $result.Error
    if (-not $detail) { $detail = 'HTML report was not written.' }
    Write-Host ("[WARN] {0}" -f $detail)
    exit 1
}

Write-Host ("HTML report: {0}" -f $result.FullPath)
exit 0
