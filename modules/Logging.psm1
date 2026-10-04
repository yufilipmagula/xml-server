#requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Thread-safe rotating audit log sink with retention purge (spec sections 7.4, 7.5).
.DESCRIPTION
    A single shared [object] lock serializes appends so concurrent worker lines
    never interleave. Files rotate per UTC calendar day:
    audit_YYYY-MM-DD.log. Retention purge removes files older than RetainDays.
#>

$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function New-LogLock {
    [CmdletBinding()]
    [OutputType([object])]
    param ()
    return [System.Object]::new()
}

function Initialize-LogDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogDirectory
    )
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        [void](New-Item -ItemType Directory -Path $LogDirectory -Force)
    }
}

function Write-AuditLog {
    <#
        Appends one audit record. Fields (spec section 7.4):
        ISO-8601 UTC timestamp | client IP | requested relative path |
        HTTP status | response time (ms) | exception message.
        For 503/500/boundary rejections, log the REAL reason even though the
        client receives a unified 404.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogDirectory,

        [Parameter(Mandatory)]
        [object]$LogLock,

        [Parameter(Mandatory)]
        [string]$ClientIp,

        [AllowEmptyString()]
        [string]$RequestedPath,

        [Parameter(Mandatory)]
        [int]$StatusCode,

        [int]$ResponseTimeMs = 0,

        [AllowEmptyString()]
        [string]$ExceptionMessage = ''
    )

    $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $datePart = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
    $logFile = Join-Path -Path $LogDirectory -ChildPath ("audit_{0}.log" -f $datePart)

    # Pipe-delimited; sanitize field separators and newlines out of free text.
    $safePath = ($RequestedPath -replace '[\r\n|]', ' ')
    $safeException = ($ExceptionMessage -replace '[\r\n|]', ' ')
    $line = '{0} | {1} | {2} | {3} | {4} | {5}' -f $timestamp, $ClientIp, $safePath, $StatusCode, $ResponseTimeMs, $safeException

    [System.Threading.Monitor]::Enter($LogLock)
    try {
        [System.IO.File]::AppendAllText($logFile, $line + [Environment]::NewLine, $script:Utf8NoBom)
    }
    finally {
        [System.Threading.Monitor]::Exit($LogLock)
    }
}

function Remove-OldLogs {
    <# Purge audit_*.log files whose last-write time predates the retention window. #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogDirectory,

        [Parameter(Mandatory)]
        [int]$RetainDays
    )

    if (-not (Test-Path -LiteralPath $LogDirectory)) { return }
    $cutoff = [DateTime]::UtcNow.AddDays(-$RetainDays)
    Get-ChildItem -LiteralPath $LogDirectory -Filter 'audit_*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -lt $cutoff } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
}

Export-ModuleMember -Function New-LogLock, Initialize-LogDirectory, Write-AuditLog, Remove-OldLogs
