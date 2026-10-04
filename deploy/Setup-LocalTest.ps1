#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepares a local Windows 11 box for integration testing (self-signed cert +
    HTTP.sys bindings). Run in an elevated Windows PowerShell 5.1 prompt.
.DESCRIPTION
    This is for LOCAL TESTING ONLY. Production uses a customer-provided
    certificate (spec 7.1) and must not use a self-signed cert.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\deploy\Setup-LocalTest.ps1 -Port 8443
#>
[CmdletBinding()]
param (
    [int]$Port = 8443,
    [string]$DnsName = 'localhost'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$appId = '{a1b2c3d4-e5f6-7890-abcd-1234567890ab}'

Write-Host "Creating self-signed certificate for $DnsName ..."
$cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'XmlDistService LocalTest'
$thumb = $cert.Thumbprint
Write-Host "Thumbprint: $thumb"

Write-Host "Reserving URL ACL for https://+:$Port/api/v1/ ..."
& netsh http add urlacl url="https://+:$Port/api/v1/" user="$env:USERDOMAIN\$env:USERNAME" | Out-Host

Write-Host "Binding certificate to 0.0.0.0:$Port ..."
& netsh http add sslcert ipport="0.0.0.0:$Port" certhash="$thumb" appid="$appId" | Out-Host

Write-Host ''
Write-Host "Local test environment ready. Start the service with:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\server.ps1"
Write-Host ''
Write-Host "To tear down afterwards:"
Write-Host "  netsh http delete sslcert ipport=0.0.0.0:$Port"
Write-Host "  netsh http delete urlacl url=https://+:$Port/api/v1/"
Write-Host "  Remove-Item Cert:\LocalMachine\My\$thumb"
