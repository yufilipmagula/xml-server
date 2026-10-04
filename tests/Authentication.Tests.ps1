#requires -Version 5.1
#requires -PSEdition Desktop
# Pester 3.4. PBKDF2 + constant-time compare + Basic auth parsing.

$script:AuthenticationModulePath = Join-Path $PSScriptRoot '..\modules\Authentication.psm1'
Import-Module $script:AuthenticationModulePath -Force

$script:Salt = [byte[]]::new(32)
for ($i = 0; $i -lt 32; $i++) { $script:Salt[$i] = $i }
$script:Iterations = 100000
$script:ExpectedHash = Get-Pbkdf2Hash -Password 'correct horse' -Salt $script:Salt -Iterations $script:Iterations

Describe 'Get-Pbkdf2Hash' {
    It 'is deterministic for the same inputs' {
        $a = Get-Pbkdf2Hash -Password 'pw' -Salt $script:Salt -Iterations 1000
        $b = Get-Pbkdf2Hash -Password 'pw' -Salt $script:Salt -Iterations 1000
        [Convert]::ToBase64String($a) | Should BeExactly ([Convert]::ToBase64String($b))
    }

    It 'produces a 32-byte key by default' {
        (Get-Pbkdf2Hash -Password 'pw' -Salt $script:Salt -Iterations 1000).Length | Should Be 32
    }

    It 'differs when the password differs' {
        $a = Get-Pbkdf2Hash -Password 'pw1' -Salt $script:Salt -Iterations 1000
        $b = Get-Pbkdf2Hash -Password 'pw2' -Salt $script:Salt -Iterations 1000
        [Convert]::ToBase64String($a) | Should Not BeExactly ([Convert]::ToBase64String($b))
    }
}

InModuleScope 'Authentication' {
    Describe 'Test-ConstantTimeEqual' {
        BeforeAll {
            $salt = New-PasswordSalt -Length 32
            $testHash = Get-Pbkdf2Hash -Password 'test-equal' -Salt $salt -Iterations 1000
        }
        It 'returns true for identical arrays' {
            Test-ConstantTimeEqual -Expected $testHash -Actual $testHash | Should Be $true
        }
        It 'returns false for a single-byte difference' {
            $tampered = $testHash.Clone()
            $tampered[0] = $tampered[0] -bxor 0xFF
            Test-ConstantTimeEqual -Expected $testHash -Actual $tampered | Should Be $false
        }
        It 'returns false for a length mismatch' {
            Test-ConstantTimeEqual -Expected $testHash -Actual ([byte[]]::new(16)) | Should Be $false
        }
    }
}

Describe 'Read-BasicAuthorization' {
    It 'parses a well-formed Basic header' {
        $enc = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('alice:p@ss:word'))
        $result = Read-BasicAuthorization -AuthorizationHeader "Basic $enc"
        $result.Username | Should BeExactly 'alice'
        $result.Password | Should BeExactly 'p@ss:word'   # only the first colon splits
    }
    It 'returns null for a missing header' {
        Read-BasicAuthorization -AuthorizationHeader $null | Should BeNullOrEmpty
    }
    It 'returns null for a non-Basic scheme' {
        Read-BasicAuthorization -AuthorizationHeader 'Bearer abc' | Should BeNullOrEmpty
    }
    It 'returns null for malformed Base64' {
        Read-BasicAuthorization -AuthorizationHeader 'Basic !!!not-base64!!!' | Should BeNullOrEmpty
    }
}

Describe 'Test-ServiceCredential' {
    It 'accepts the correct username and password' {
        $cred = @{ Username = 'svc'; Password = 'correct horse' }
        Test-ServiceCredential -Credential $cred -ExpectedUsername 'svc' -Salt $script:Salt -ExpectedHash $script:ExpectedHash -Iterations $script:Iterations | Should Be $true
    }
    It 'rejects a wrong password' {
        $cred = @{ Username = 'svc'; Password = 'wrong' }
        Test-ServiceCredential -Credential $cred -ExpectedUsername 'svc' -Salt $script:Salt -ExpectedHash $script:ExpectedHash -Iterations $script:Iterations | Should Be $false
    }
    It 'rejects a wrong username' {
        $cred = @{ Username = 'mallory'; Password = 'correct horse' }
        Test-ServiceCredential -Credential $cred -ExpectedUsername 'svc' -Salt $script:Salt -ExpectedHash $script:ExpectedHash -Iterations $script:Iterations | Should Be $false
    }
    It 'rejects a null credential' {
        Test-ServiceCredential -Credential $null -ExpectedUsername 'svc' -Salt $script:Salt -ExpectedHash $script:ExpectedHash -Iterations $script:Iterations | Should Be $false
    }
}
