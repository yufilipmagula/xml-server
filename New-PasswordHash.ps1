#requires -Version 5.1
<#
.SYNOPSIS
    Generates a PBKDF2-SHA256 salt + derived key for config.json (spec 7.2).
.DESCRIPTION
    Operators run this to produce the Base64 salt and hash to paste into
    config.json. Plaintext is never persisted. Uses the explicit-SHA256
    Rfc2898DeriveBytes constructor; the legacy overload defaults to SHA1 and
    must not be used.
.EXAMPLE
    .\New-PasswordHash.ps1 -PlainPassword 'S3cret!' -Iterations 100000
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword', Justification = 'Mandated by spec 7.2 CLI signature')]
param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string]$PlainPassword,

    [int]$Iterations = 100000
)

begin {
    Set-StrictMode -Version Latest
}

process {
    $saltBytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($saltBytes)
    }
    finally {
        $rng.Dispose()
    }

    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $PlainPassword,
        $saltBytes,
        $Iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)   # explicit SHA256 - do NOT use the legacy overload
    try {
        $hashBytes = $pbkdf2.GetBytes(32)
    }
    finally {
        $pbkdf2.Dispose()
    }

    [pscustomobject]@{
        PasswordSaltBase64 = [Convert]::ToBase64String($saltBytes)
        PasswordHashBase64 = [Convert]::ToBase64String($hashBytes)
        Pbkdf2Iterations   = $Iterations
    }
}
