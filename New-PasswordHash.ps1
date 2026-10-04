#requires -Version 5.1
#requires -PSEdition Desktop
<#
.SYNOPSIS
    Generates a PBKDF2-SHA256 salt + derived key for config.json (spec 7.2).
.DESCRIPTION
    Operators run this to produce the Base64 salt and hash to paste into
    config.json. Plaintext is never persisted. Reuses Get-Pbkdf2Hash and
    New-PasswordSalt from Authentication.psm1 with explicit SHA-256.
.EXAMPLE
    .\New-PasswordHash.ps1 -PlainPassword 'S3cret!' -Iterations 100000
.EXAMPLE
    .\New-PasswordHash.ps1
    # Securely prompts for password without exposing it in terminal history
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword', Justification = 'Mandated by spec 7.2 CLI signature')]
param (
    [Parameter(Position = 0, ValueFromPipeline)]
    [string]$PlainPassword,

    [int]$Iterations = 100000
)

begin {
    Set-StrictMode -Version Latest
    $authModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'modules\Authentication.psm1'
    Import-Module -Name $authModulePath -Force
}

process {
    if ($Iterations -lt 100000) {
        throw "Iterations must be at least 100000 (got $Iterations)."
    }

    if ([string]::IsNullOrEmpty($PlainPassword)) {
        $sec = Read-Host -Prompt 'Enter password' -AsSecureString
        if ($null -eq $sec) {
            throw 'Password cannot be empty.'
        }
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try {
            $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    if ([string]::IsNullOrEmpty($PlainPassword)) {
        throw 'Password cannot be empty.'
    }

    $saltBytes = New-PasswordSalt -Length 32
    $hashBytes = Get-Pbkdf2Hash -Password $PlainPassword -Salt $saltBytes -Iterations $Iterations -Length 32

    [pscustomobject]@{
        PasswordSaltBase64 = [Convert]::ToBase64String($saltBytes)
        PasswordHashBase64 = [Convert]::ToBase64String($hashBytes)
        Pbkdf2Iterations   = $Iterations
    }
}
