#requires -Version 5.1
# Pester v5. Pure-logic tests for the path-traversal boundary guard.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'PathSecurity.psm1') -Force

    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) ("xmlsvc_pathsec_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:Root 'finance\2026') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $script:Root 'finance\2026\report.xml') -Value '<r/>' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $script:Root 'secret.txt') -Value 'nope' -Encoding UTF8
}

AfterAll {
    if (Test-Path -LiteralPath $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Test-SafePath' {
    It 'resolves a valid nested .xml file to its canonical path' {
        $result = Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'finance/2026/report.xml'
        $result | Should -Not -BeNullOrEmpty
        $result | Should -BeLike '*report.xml'
    }

    It 'rejects a parent-directory traversal attempt' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath '../../../Windows/win.ini' | Should -BeNullOrEmpty
    }

    It 'rejects a dot-dot segment anywhere in the path' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'finance/../../etc/passwd' | Should -BeNullOrEmpty
    }

    It 'rejects a non-.xml file that exists' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'secret.txt' | Should -BeNullOrEmpty
    }

    It 'rejects a directory target' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'finance/2026' | Should -BeNullOrEmpty
    }

    It 'rejects a missing file' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'finance/2026/missing.xml' | Should -BeNullOrEmpty
    }

    It 'rejects a null byte' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath "report.xml`0" | Should -BeNullOrEmpty
    }

    It 'rejects an NTFS alternate data stream / drive colon' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'finance/2026/report.xml::$DATA' | Should -BeNullOrEmpty
    }

    It 'rejects a UNC path marker' {
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath '\\server\share\x.xml' | Should -BeNullOrEmpty
    }

    It 'treats the .xml extension case-insensitively' {
        Set-Content -LiteralPath (Join-Path $script:Root 'upper.XML') -Value '<r/>' -Encoding UTF8
        Test-SafePath -RootDirectory $script:Root -RequestedSubPath 'upper.XML' | Should -Not -BeNullOrEmpty
    }
}
