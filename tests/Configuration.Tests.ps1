#requires -Version 5.1
#requires -PSEdition Desktop
# Pester 3.4. config.json schema validation.

Describe 'Import-ServiceConfig' {
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\modules\Configuration.psm1') -Force

    $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("xmlsvc_cfg_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null

    function script:New-ValidConfigObject {
        [ordered]@{
            Server   = [ordered]@{ Port = 8443; MaxThreads = 8; UrlPrefix = 'https://+:8443/api/v1/' }
            Storage  = [ordered]@{ RootDirectory = 'C:\Data\XML_Repository'; FileReadRetryCount = 3; FileReadRetryDelayMs = 50 }
            Security = [ordered]@{
                Username           = 'svc'
                PasswordSaltBase64 = [Convert]::ToBase64String([byte[]]::new(32))
                PasswordHashBase64 = [Convert]::ToBase64String([byte[]]::new(32))
                Pbkdf2Iterations   = 100000
                MaxAuthFailures    = 5
                LockoutMinutes     = 15
            }
            Logging  = [ordered]@{ LogDirectory = 'C:\Logs\XmlDistService'; RetainDays = 14 }
        }
    }

    function script:Write-Config {
        param ($Object)
        $path = Join-Path $script:TmpDir ([Guid]::NewGuid().ToString('N') + '.json')
        ($Object | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }

    function script:Test-ConfigErrorMessage {
        param ($Path, $ExpectedText)
        try {
            Import-ServiceConfig -Path $Path | Out-Null
            return $false
        }
        catch {
            return $_.Exception.Message -like "*$ExpectedText*"
        }
    }
}
AfterAll {
    if (Test-Path -LiteralPath $script:TmpDir) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force }
}
    It 'loads a fully valid config' {
        $path = script:Write-Config (script:New-ValidConfigObject)
        $cfg = Import-ServiceConfig -Path $path
        $cfg.Server.Port | Should Be 8443
    }

    It 'throws when a required section is missing' {
        $obj = script:New-ValidConfigObject
        $obj.Remove('Security')
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'Security') | Should Be $true
    }

    It 'throws when a required key is missing' {
        $obj = script:New-ValidConfigObject
        $obj.Security.Remove('Pbkdf2Iterations')
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'Pbkdf2Iterations') | Should Be $true
    }

    It 'clamps MaxThreads below the minimum up to 4' {
        $obj = script:New-ValidConfigObject
        $obj.Server.MaxThreads = 1
        $path = script:Write-Config $obj
        (Import-ServiceConfig -Path $path).Server.MaxThreads | Should Be 4
    }

    It 'clamps MaxThreads above the maximum down to 16' {
        $obj = script:New-ValidConfigObject
        $obj.Server.MaxThreads = 999
        $path = script:Write-Config $obj
        (Import-ServiceConfig -Path $path).Server.MaxThreads | Should Be 16
    }

    It 'rejects iterations below 100000' {
        $obj = script:New-ValidConfigObject
        $obj.Security.Pbkdf2Iterations = 1000
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'Pbkdf2Iterations') | Should Be $true
    }

    It 'rejects a non-Base64 salt' {
        $obj = script:New-ValidConfigObject
        $obj.Security.PasswordSaltBase64 = 'not base64 !!!'
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'PasswordSaltBase64') | Should Be $true
    }

    It 'throws for a missing file' {
        (Test-ConfigErrorMessage -Path (Join-Path $script:TmpDir 'does-not-exist.json') -ExpectedText 'not found') | Should Be $true
    }

    It 'throws for malformed JSON' {
        $path = Join-Path $script:TmpDir 'bad.json'
        Set-Content -LiteralPath $path -Value '{ this is not json' -Encoding UTF8
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'not valid JSON') | Should Be $true
    }

    It 'rejects a truncated password hash (S1)' {
        $obj = script:New-ValidConfigObject
        $obj.Security.PasswordHashBase64 = [Convert]::ToBase64String([byte[]]::new(4))
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'exactly 32 bytes') | Should Be $true
    }

    It 'rejects a short password salt (S1)' {
        $obj = script:New-ValidConfigObject
        $obj.Security.PasswordSaltBase64 = [Convert]::ToBase64String([byte[]]::new(8))
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'at least 16 bytes') | Should Be $true
    }

    It 'rejects plain http prefix on non-loopback hosts (S2)' {
        $obj = script:New-ValidConfigObject
        $obj.Server.UrlPrefix = 'http://+:8443/api/v1/'
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'must use https://') | Should Be $true
    }

    It 'allows plain http prefix on loopback for local development' {
        $obj = script:New-ValidConfigObject
        $obj.Server.Port = 8080
        $obj.Server.UrlPrefix = 'http://127.0.0.1:8080/api/v1/'
        $path = script:Write-Config $obj
        $cfg = Import-ServiceConfig -Path $path
        $cfg.Server.ApiBasePath | Should Be '/api/v1'
    }

    It 'rejects prefix port mismatch (S2)' {
        $obj = script:New-ValidConfigObject
        $obj.Server.Port = 8443
        $obj.Server.UrlPrefix = 'https://+:9443/api/v1/'
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'does not match Server.Port') | Should Be $true
    }

    It 'rejects negative FileReadRetryDelayMs (B4)' {
        $obj = script:New-ValidConfigObject
        $obj.Storage.FileReadRetryDelayMs = -1
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'FileReadRetryDelayMs must be between') | Should Be $true
    }

    It 'rejects relative RootDirectory or LogDirectory (B5)' {
        $obj = script:New-ValidConfigObject
        $obj.Storage.RootDirectory = 'relative\path'
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'must be an absolute path') | Should Be $true
    }

    It 'rejects a username with colon (B5)' {
        $obj = script:New-ValidConfigObject
        $obj.Security.Username = 'bad:user'
        $path = script:Write-Config $obj
        (Test-ConfigErrorMessage -Path $path -ExpectedText 'must not contain ":"') | Should Be $true
    }
}
