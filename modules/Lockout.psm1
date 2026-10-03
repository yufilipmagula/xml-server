#requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Thread-safe per-IP brute-force lockout tracker (spec section 3.3).
.DESCRIPTION
    All functions operate on a [hashtable]::Synchronized(@{}) instance created by
    New-FailureTracker and shared across every worker runspace. Each record is
    @{ FailureCount; FirstFailureUtc; LockedUntilUtc }. State is in-memory only
    and resets on service restart, by design.
#>

function New-FailureTracker {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param ()
    return [hashtable]::Synchronized(@{})
}

function Get-LockoutRetryAfterSeconds {
    <#
        Returns the number of whole seconds remaining on an active lockout for
        the given IP, or 0 if the IP is not currently locked.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Tracker,

        [Parameter(Mandatory)]
        [string]$ClientIp
    )

    [System.Threading.Monitor]::Enter($Tracker.SyncRoot)
    try {
        if (-not $Tracker.ContainsKey($ClientIp)) { return 0 }
        $record = $Tracker[$ClientIp]
        if ($null -eq $record.LockedUntilUtc) { return 0 }

        $remaining = $record.LockedUntilUtc - [DateTime]::UtcNow
        if ($remaining.TotalSeconds -le 0) { return 0 }
        return [int][Math]::Ceiling($remaining.TotalSeconds)
    }
    finally {
        [System.Threading.Monitor]::Exit($Tracker.SyncRoot)
    }
}

function Add-AuthFailure {
    <#
        Atomically increments the failure count for an IP and, once it reaches
        MaxAuthFailures, sets a lockout window of LockoutMinutes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Tracker,

        [Parameter(Mandatory)]
        [string]$ClientIp,

        [Parameter(Mandatory)]
        [int]$MaxAuthFailures,

        [Parameter(Mandatory)]
        [int]$LockoutMinutes
    )

    [System.Threading.Monitor]::Enter($Tracker.SyncRoot)
    try {
        $now = [DateTime]::UtcNow
        if (-not $Tracker.ContainsKey($ClientIp)) {
            $Tracker[$ClientIp] = @{
                FailureCount    = 0
                FirstFailureUtc = $now
                LockedUntilUtc  = $null
            }
        }

        $record = $Tracker[$ClientIp]
        $record.FailureCount++
        if ($record.FailureCount -ge $MaxAuthFailures) {
            $record.LockedUntilUtc = $now.AddMinutes($LockoutMinutes)
        }
        $Tracker[$ClientIp] = $record
    }
    finally {
        [System.Threading.Monitor]::Exit($Tracker.SyncRoot)
    }
}

function Clear-AuthFailures {
    <# A successful authentication clears the IP's record. #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Tracker,

        [Parameter(Mandatory)]
        [string]$ClientIp
    )

    [System.Threading.Monitor]::Enter($Tracker.SyncRoot)
    try {
        if ($Tracker.ContainsKey($ClientIp)) {
            [void]$Tracker.Remove($ClientIp)
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($Tracker.SyncRoot)
    }
}

Export-ModuleMember -Function New-FailureTracker, Get-LockoutRetryAfterSeconds, Add-AuthFailure, Clear-AuthFailures
