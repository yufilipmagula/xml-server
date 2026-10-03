#requires -Version 5.1
<#
.SYNOPSIS
    Runs the Pester v5 unit suite for the pure-logic modules.
.DESCRIPTION
    Works on PS7/macOS (fast dev loop) and Windows PowerShell 5.1 (parity check).
    Requires Pester v5:  Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
.EXAMPLE
    pwsh ./tests/Invoke-Tests.ps1          # on macOS
    powershell -File .\tests\Invoke-Tests.ps1   # on Windows 5.1
#>
[CmdletBinding()]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 } | Select-Object -First 1
if (-not $pester) {
    throw "Pester v5+ is required. Install with: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force"
}
Import-Module Pester -MinimumVersion 5.0 -Force

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Output.Verbosity = 'Detailed'
$config.Run.Exit = $true

Invoke-Pester -Configuration $config
