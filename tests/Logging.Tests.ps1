#requires -Version 5.1
#requires -PSEdition Desktop
# Pester 3.4. Thread-safe audit logging and retention purge tests.

Describe 'Logging Module' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..\modules\Logging.psm1') -Force
        $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("xmlsvc_logtest_" + [Guid]::NewGuid().ToString('N'))
        $script:LogLock = New-LogLock
    }
    AfterAll {
        if (Test-Path -LiteralPath $script:TmpDir) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force }
    }

    Context 'Initialize-LogDirectory' {
        It 'creates a non-existent log directory' {
            $dir = Join-Path $script:TmpDir 'logs1'
            Test-Path -LiteralPath $dir | Should Be $false
            Initialize-LogDirectory -LogDirectory $dir
            Test-Path -LiteralPath $dir -PathType Container | Should Be $true
        }

        It 'is idempotent when directory already exists' {
            $dir = Join-Path $script:TmpDir 'logs1'
            { Initialize-LogDirectory -LogDirectory $dir } | Should Not Throw
        }
    }

    Context 'Write-AuditLog' {
        BeforeAll {
            $script:AuditDir = Join-Path $script:TmpDir 'audit'
            Initialize-LogDirectory -LogDirectory $script:AuditDir
        }

        It 'appends a structured pipe-delimited log entry' {
            Write-AuditLog -LogDirectory $script:AuditDir -LogLock $script:LogLock `
                -ClientIp '192.168.1.100' -RequestedPath '/api/v1/files/sample.xml' `
                -StatusCode 200 -ResponseTimeMs 15 -ExceptionMessage ''

            $datePart = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
            $logFile = Join-Path $script:AuditDir "audit_$datePart.log"
            Test-Path -LiteralPath $logFile | Should Be $true

            $content = Get-Content -LiteralPath $logFile -Raw -Encoding UTF8
            $content | Should BeLike "* | 192.168.1.100 | /api/v1/files/sample.xml | 200 | 15 | *"
        }

        It 'sanitizes delimiter pipes and newline characters from free text fields' {
            Write-AuditLog -LogDirectory $script:AuditDir -LogLock $script:LogLock `
                -ClientIp '10.0.0.1' -RequestedPath "/api/v1/bad`r`npath|inject" `
                -StatusCode 404 -ResponseTimeMs 5 -ExceptionMessage "Error`r`nLine|Message"

            $datePart = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
            $logFile = Join-Path $script:AuditDir "audit_$datePart.log"
            $lines = Get-Content -LiteralPath $logFile -Encoding UTF8
            $lastLine = $lines[-1]

            # Entry must remain on a single line and have exactly 5 pipe delimiters (6 fields)
            $pipeCount = ($lastLine.ToCharArray() | Where-Object { $_ -eq '|' }).Count
            $pipeCount | Should Be 5
            $lastLine | Should BeLike "* /api/v1/bad  path inject *"
            $lastLine | Should BeLike "* Error  Line Message*"
        }
    }

    Context 'Remove-OldLogs' {
        BeforeAll {
            $script:PurgeDir = Join-Path $script:TmpDir 'purge'
            Initialize-LogDirectory -LogDirectory $script:PurgeDir

            # Create an old log (20 days ago) and a recent log (1 day ago)
            $script:OldLog = Join-Path $script:PurgeDir 'audit_2020-01-01.log'
            Set-Content -LiteralPath $script:OldLog -Value 'old' -Encoding UTF8
            (Get-Item -LiteralPath $script:OldLog).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-20)

            $script:NewLog = Join-Path $script:PurgeDir 'audit_2099-01-01.log'
            Set-Content -LiteralPath $script:NewLog -Value 'new' -Encoding UTF8
            (Get-Item -LiteralPath $script:NewLog).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-1)
        }

        It 'purges log files older than the retention window while preserving newer files' {
            Remove-OldLogs -LogDirectory $script:PurgeDir -RetainDays 14
            Test-Path -LiteralPath $script:OldLog | Should Be $false
            Test-Path -LiteralPath $script:NewLog | Should Be $true
        }
    }
}
