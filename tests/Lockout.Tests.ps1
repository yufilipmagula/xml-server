#requires -Version 5.1
# Pester v5. Brute-force lockout tracker.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'Lockout.psm1') -Force
}

Describe 'Lockout tracker' {
    BeforeEach {
        $script:Tracker = New-FailureTracker
    }

    It 'reports zero retry-after for an unknown IP' {
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should -Be 0
    }

    It 'does not lock before reaching the failure threshold' {
        1..2 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should -Be 0
    }

    It 'locks the IP once the threshold is reached' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should -BeGreaterThan 0
    }

    It 'tracks IPs independently' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.2' | Should -Be 0
    }

    It 'clears an IP on successful auth' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 15 }
        Clear-AuthFailures -Tracker $script:Tracker -ClientIp '10.0.0.1'
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should -Be 0
    }

    It 'returns a retry-after no greater than the lockout window' {
        1..3 | ForEach-Object { Add-AuthFailure -Tracker $script:Tracker -ClientIp '10.0.0.1' -MaxAuthFailures 3 -LockoutMinutes 1 }
        Get-LockoutRetryAfterSeconds -Tracker $script:Tracker -ClientIp '10.0.0.1' | Should -BeLessOrEqual 60
    }
}
