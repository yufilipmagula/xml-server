#requires -Version 5.1
#requires -PSEdition Desktop
# Pester 3.4. Brute-force lockout tracker.

Describe 'Lockout tracker' {
    BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\modules\Lockout.psm1') -Force
    }
    BeforeEach {
        $script:Tracker = New-FailureTracker
    }

    It 'reports zero retry-after for an unknown IP' {
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should Be 0
    }

    It 'does not lock before reaching the failure threshold' {
        1..2 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should Be 0
    }

    It 'locks the IP once the threshold is reached' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should BeGreaterThan 0
    }

    It 'tracks IPs independently' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.2' | Should Be 0
    }

    It 'clears an IP on successful auth' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Clear-AuthFailures -Tracker $script:Tracker -ClientIp '10.0.0.1'
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should Be 0
    }

    It 'returns a retry-after no greater than the lockout window' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 1 }
        ((Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1') -le 60) | Should Be $true
    }

    It 'resets failure count after a lockout expires so a single error does not re-lock' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        # Simulate that the lockout period elapsed
        $script:Tracker['10.0.0.1'].LockedUntilUtc = [DateTime]::UtcNow.AddMinutes(-1)
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should Be 0

        # A single new failure should increment to 1, not re-lock
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should Be 0
        $script:Tracker['10.0.0.1'].FailureCount | Should Be 1
    }

    It 'resets failure count after the failure window elapses without lockout' {
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15
        $script:Tracker['10.0.0.1'].FirstFailureUtc = [DateTime]::UtcNow.AddMinutes(-20)

        # New failure after window resets count to 1 instead of 2
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15
        $script:Tracker['10.0.0.1'].FailureCount | Should Be 1
    }

    It 'purges expired entries while retaining active tracking records' {
        # Stale expired lockout (ended 2 hours ago)
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15
        $script:Tracker['10.0.0.1'].LockedUntilUtc = [DateTime]::UtcNow.AddHours(-2)

        # Stale failure without lockout (failed 2 hours ago)
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.2' -MaxAuthFailures 3 -LockoutMinutes 15
        $script:Tracker['10.0.0.2'].FirstFailureUtc = [DateTime]::UtcNow.AddHours(-2)

        # Active locked IP (locked for 15 minutes)
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.3' -MaxAuthFailures 3 -LockoutMinutes 15

        # Active recent failure (5 minutes ago)
        Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.4' -MaxAuthFailures 3 -LockoutMinutes 15
        $script:Tracker['10.0.0.4'].FirstFailureUtc = [DateTime]::UtcNow.AddMinutes(-5)

        Remove-ExpiredAuthFailures -Tracker $script:Tracker -MaxAgeMinutes 60

        $script:Tracker.ContainsKey('10.0.0.1') | Should Be $false
        $script:Tracker.ContainsKey('10.0.0.2') | Should Be $false
        $script:Tracker.ContainsKey('10.0.0.3') | Should Be $true
        $script:Tracker.ContainsKey('10.0.0.4') | Should Be $true
    }
}
