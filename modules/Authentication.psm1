#requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    PBKDF2-SHA256 key derivation and constant-time credential verification.
.DESCRIPTION
    Implements spec section 3.2. The explicit-SHA256 Rfc2898DeriveBytes
    constructor is mandatory; the legacy three-argument overload silently
    defaults to SHA1 and must never be used.
#>

function Get-Pbkdf2Hash {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [byte[]]$Salt,

        [Parameter(Mandatory)]
        [int]$Iterations,

        [int]$Length = 32
    )

    $deriver = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password,
        $Salt,
        $Iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)   # explicit SHA256 - do NOT use the legacy overload
    try {
        return $deriver.GetBytes($Length)
    }
    finally {
        $deriver.Dispose()
    }
}

function Test-ConstantTimeEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Expected,

        [Parameter(Mandatory)]
        [byte[]]$Actual
    )

    # A length mismatch cannot be a match. Comparing against $Expected's length
    # keeps the loop cost tied to the stored hash, not to attacker-controlled input.
    $diff = $Expected.Length -bxor $Actual.Length
    for ($i = 0; $i -lt $Expected.Length; $i++) {
        $actualByte = if ($i -lt $Actual.Length) { $Actual[$i] } else { 0 }
        $diff = $diff -bor ($Expected[$i] -bxor $actualByte)
    }
    return ($diff -eq 0)
}

function Read-BasicAuthorization {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AuthorizationHeader
    )

    if ([string]::IsNullOrWhiteSpace($AuthorizationHeader)) { return $null }
    if (-not $AuthorizationHeader.StartsWith('Basic ', [System.StringComparison]::OrdinalIgnoreCase)) { return $null }

    $encoded = $AuthorizationHeader.Substring(6).Trim()
    if ([string]::IsNullOrEmpty($encoded)) { return $null }

    try {
        $decodedBytes = [Convert]::FromBase64String($encoded)
    }
    catch {
        return $null
    }

    $decoded = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
    $separatorIndex = $decoded.IndexOf(':')
    if ($separatorIndex -lt 0) { return $null }

    return @{
        Username = $decoded.Substring(0, $separatorIndex)
        Password = $decoded.Substring($separatorIndex + 1)
    }
}

function Test-ServiceCredential {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [hashtable]$Credential,     # output of Read-BasicAuthorization

        [Parameter(Mandatory)]
        [string]$ExpectedUsername,

        [Parameter(Mandatory)]
        [byte[]]$Salt,

        [Parameter(Mandatory)]
        [byte[]]$ExpectedHash,

        [Parameter(Mandatory)]
        [int]$Iterations
    )

    if ($null -eq $Credential) { return $false }

    $usernameMatches = [string]::Equals($Credential.Username, $ExpectedUsername, [System.StringComparison]::Ordinal)
    $derived = Get-Pbkdf2Hash -Password $Credential.Password -Salt $Salt -Iterations $Iterations -Length $ExpectedHash.Length
    $hashMatches = Test-ConstantTimeEqual -Expected $ExpectedHash -Actual $derived

    # Evaluate both before returning so username validity does not short-circuit timing.
    return ($usernameMatches -and $hashMatches)
}

Export-ModuleMember -Function Get-Pbkdf2Hash, Test-ConstantTimeEqual, Read-BasicAuthorization, Test-ServiceCredential
