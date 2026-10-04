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
        if ($remaining.TotalSeconds -le 0) {
            # Lockout expired; reset lock and failure count
            $record.LockedUntilUtc = $null
            $record.FailureCount = 0
            $Tracker[$ClientIp] = $record
            return 0
        }
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

        # Reset count if previous lockout has expired, or if rolling failure window elapsed
        if ($null -ne $record.LockedUntilUtc -and $now -ge $record.LockedUntilUtc) {
            $record.FailureCount = 0
            $record.LockedUntilUtc = $null
            $record.FirstFailureUtc = $now
        }
        elseif ($null -eq $record.LockedUntilUtc -and ($now - $record.FirstFailureUtc).TotalMinutes -ge $LockoutMinutes) {
            $record.FailureCount = 0
            $record.FirstFailureUtc = $now
        }

        $record.FailureCount++
        if ($record.FailureCount -ge $MaxAuthFailures) {
            $record.LockedUntilUtc = $now.AddMinutes($LockoutMinutes)
        }
        $Tracker[$ClientIp] = $record

        # Bound tracker memory if distinct tracking entries accumulate
        if ($Tracker.Count -ge 100) {
            Remove-ExpiredAuthFailures -Tracker $Tracker -MaxAgeMinutes ([Math]::Max(60, $LockoutMinutes * 2))
        }
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

function Remove-ExpiredAuthFailures {
    <#
        Removes expired or stale failure records from the tracker to prevent unbounded memory growth.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Tracker,

        [int]$MaxAgeMinutes = 60
    )

    [System.Threading.Monitor]::Enter($Tracker.SyncRoot)
    try {
        $now = [DateTime]::UtcNow
        $keysToRemove = [System.Collections.ArrayList]::new()
        foreach ($ip in $Tracker.Keys) {
            $record = $Tracker[$ip]
            $isStale = $false
            if ($null -ne $record.LockedUntilUtc) {
                if (($now - $record.LockedUntilUtc).TotalMinutes -ge $MaxAgeMinutes) {
                    $isStale = $true
                }
            }
            elseif (($now - $record.FirstFailureUtc).TotalMinutes -ge $MaxAgeMinutes) {
                $isStale = $true
            }

            if ($isStale) {
                [void]$keysToRemove.Add($ip)
            }
        }

        foreach ($ip in $keysToRemove) {
            [void]$Tracker.Remove($ip)
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($Tracker.SyncRoot)
    }
}

Export-ModuleMember -Function New-FailureTracker, Get-LockoutRetryAfterSeconds, Add-AuthFailure, Clear-AuthFailures, Remove-ExpiredAuthFailures
