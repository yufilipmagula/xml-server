#requires -Version 5.1
#requires -PSEdition Desktop
<#
.SYNOPSIS
    Runs the Pester 3.4 unit suite for the pure-logic modules.
.DESCRIPTION
    Runs under Windows PowerShell 5.1.
    Requires Pester 3.4.0, included with Windows PowerShell 5.1 on supported Windows versions.
.EXAMPLE
    powershell -File .\tests\Invoke-Tests.ps1
#>
[CmdletBinding()]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -eq [version]'3.4.0' } | Select-Object -First 1
if (-not $pester) {
    throw 'Pester 3.4.0 is required. Confirm that the Windows PowerShell Pester module is installed with: Get-Module -ListAvailable Pester'
}
Import-Module $pester.Path -Force
Invoke-Pester -Script $PSScriptRoot -EnableExit -Verbose
