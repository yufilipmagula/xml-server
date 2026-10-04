#requires -Version 5.1
#requires -PSEdition Desktop
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

    # Capture UtcNow once to prevent boundary skew across midnight (B10)
    $now = [DateTime]::UtcNow
    $timestamp = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $datePart = $now.ToString('yyyy-MM-dd')
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

function Write-ServiceLog {
    <#
        Writes service-level lifecycle events (startup, shutdown, maintenance, errors)
        with timestamps to console and service_YYYY-MM-DD.log (C13).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Level = 'INFO',

        [string]$LogDirectory = $null,

        [object]$LogLock = $null
    )

    $now = [DateTime]::UtcNow
    $timestamp = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $formatted = "[$timestamp] [$Level] $Message"

    if ($Level -eq 'FATAL' -or $Level -eq 'ERROR') {
        [Console]::Error.WriteLine($formatted)
    }
    else {
        [Console]::Out.WriteLine($formatted)
    }

    if (-not [string]::IsNullOrEmpty($LogDirectory) -and (Test-Path -LiteralPath $LogDirectory)) {
        try {
            $datePart = $now.ToString('yyyy-MM-dd')
            $logFile = Join-Path -Path $LogDirectory -ChildPath ("service_{0}.log" -f $datePart)
            if ($null -ne $LogLock) {
                [System.Threading.Monitor]::Enter($LogLock)
                try {
                    [System.IO.File]::AppendAllText($logFile, $formatted + [Environment]::NewLine, $script:Utf8NoBom)
                }
                finally {
                    [System.Threading.Monitor]::Exit($LogLock)
                }
            }
            else {
                [System.IO.File]::AppendAllText($logFile, $formatted + [Environment]::NewLine, $script:Utf8NoBom)
            }
        }
        catch {
            # Non-terminating fallback to stderr
            [Console]::Error.WriteLine("[$timestamp] [WARN] Could not write to service log file: $($_.Exception.Message)")
        }
    }
}

function Remove-OldLogs {
    <# Purge audit_*.log and service_*.log files whose last-write time predates the retention window. #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogDirectory,

        [Parameter(Mandatory)]
        [int]$RetainDays
    )

    if (-not (Test-Path -LiteralPath $LogDirectory)) { return }
    $cutoff = [DateTime]::UtcNow.AddDays(-$RetainDays)
    Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { ($_.Name -like 'audit_*.log' -or $_.Name -like 'service_*.log') -and $_.LastWriteTimeUtc -lt $cutoff } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
}

Export-ModuleMember -Function New-LogLock, Initialize-LogDirectory, Write-AuditLog, Write-ServiceLog, Remove-OldLogs
