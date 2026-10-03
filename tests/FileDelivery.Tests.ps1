#requires -Version 5.1
# Pester v5. Shared-read file access with retry.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'FileDelivery.psm1') -Force

    $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("xmlsvc_file_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null
    $script:XmlPath = Join-Path $script:TmpDir 'sample.xml'
    Set-Content -LiteralPath $script:XmlPath -Value '<root><child>value</child></root>' -Encoding UTF8
}

AfterAll {
    if (Test-Path -LiteralPath $script:TmpDir) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force }
}

Describe 'Read-XmlFileBytes' {
    It 'reads the full file contents' {
        $bytes = Read-XmlFileBytes -Path $script:XmlPath -MaxRetries 3 -DelayMs 10
        $text = [System.Text.Encoding]::UTF8.GetString($bytes).Trim([char]0xFEFF, "`r", "`n")
        $text | Should -BeLike '*<child>value</child>*'
    }

    It 'coexists with a concurrent reader holding the file open' {
        # Open the file for read with shared read/write, then confirm we can still read it.
        $other = [System.IO.FileStream]::new($script:XmlPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $bytes = Read-XmlFileBytes -Path $script:XmlPath -MaxRetries 3 -DelayMs 10
            $bytes.Length | Should -BeGreaterThan 0
        }
        finally {
            $other.Dispose()
        }
    }
}
