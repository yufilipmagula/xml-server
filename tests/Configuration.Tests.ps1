#requires -Version 5.1
# Pester v5. config.json schema validation.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'Configuration.psm1') -Force

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
}

AfterAll {
    if (Test-Path -LiteralPath $script:TmpDir) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force }
}

Describe 'Import-ServiceConfig' {
    It 'loads a fully valid config' {
        $path = script:Write-Config (script:New-ValidConfigObject)
        $cfg = Import-ServiceConfig -Path $path
        $cfg.Server.Port | Should -Be 8443
    }

    It 'throws when a required section is missing' {
        $obj = script:New-ValidConfigObject
        $obj.Remove('Security')
        $path = script:Write-Config $obj
        { Import-ServiceConfig -Path $path } | Should -Throw -ExpectedMessage '*Security*'
    }

    It 'throws when a required key is missing' {
        $obj = script:New-ValidConfigObject
        $obj.Security.Remove('Pbkdf2Iterations')
        $path = script:Write-Config $obj
        { Import-ServiceConfig -Path $path } | Should -Throw -ExpectedMessage '*Pbkdf2Iterations*'
    }

    It 'clamps MaxThreads below the minimum up to 4' {
        $obj = script:New-ValidConfigObject
        $obj.Server.MaxThreads = 1
        $path = script:Write-Config $obj
        (Import-ServiceConfig -Path $path).Server.MaxThreads | Should -Be 4
    }

    It 'clamps MaxThreads above the maximum down to 16' {
        $obj = script:New-ValidConfigObject
        $obj.Server.MaxThreads = 999
        $path = script:Write-Config $obj
        (Import-ServiceConfig -Path $path).Server.MaxThreads | Should -Be 16
    }

    It 'rejects iterations below 100000' {
        $obj = script:New-ValidConfigObject
        $obj.Security.Pbkdf2Iterations = 1000
        $path = script:Write-Config $obj
        { Import-ServiceConfig -Path $path } | Should -Throw -ExpectedMessage '*Pbkdf2Iterations*'
    }

    It 'rejects a non-Base64 salt' {
        $obj = script:New-ValidConfigObject
        $obj.Security.PasswordSaltBase64 = 'not base64 !!!'
        $path = script:Write-Config $obj
        { Import-ServiceConfig -Path $path } | Should -Throw -ExpectedMessage '*PasswordSaltBase64*'
    }

    It 'throws for a missing file' {
        { Import-ServiceConfig -Path (Join-Path $script:TmpDir 'does-not-exist.json') } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws for malformed JSON' {
        $path = Join-Path $script:TmpDir 'bad.json'
        Set-Content -LiteralPath $path -Value '{ this is not json' -Encoding UTF8
        { Import-ServiceConfig -Path $path } | Should -Throw -ExpectedMessage '*not valid JSON*'
    }
}
