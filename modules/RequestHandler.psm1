#requires -Version 5.1
#requires -PSEdition Desktop
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    HTTP request pipeline and worker execution (spec sections 2, 3, 4, 5).
.DESCRIPTION
    Processes one HttpListenerContext end to end: routing, brute-force lockout,
    Basic authentication, URL decoding, canonical path boundary checks, shared-read
    file delivery, response serialization, and structured audit logging.
#>

function Invoke-RequestHandler {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter(Mandatory)]
        [pscustomobject]$Config,

        [Parameter(Mandatory)]
        [hashtable]$FailureTracker,

        [Parameter(Mandatory)]
        [object]$LogLock,

        [Parameter(Mandatory)]
        [byte[]]$PasswordSalt,

        [Parameter(Mandatory)]
        [byte[]]$PasswordHash
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $request = $Context.Request
    $response = $Context.Response
    $clientIp = if ($request.RemoteEndPoint) { $request.RemoteEndPoint.Address.ToString() } else { 'unknown' }
    $absolutePath = $request.Url.AbsolutePath
    $status = 500
    $realReason = ''

    try {
        $apiBasePath = $Config.Server.ApiBasePath

        # 1. Health endpoint: unauthenticated, no FS access, GET only (spec 2.3).
        if ($absolutePath -eq "$apiBasePath/health") {
            if ($request.HttpMethod -ne 'GET') {
                $status = 405
                Send-HttpResponse -Response $response -Code 405
            }
            else {
                $status = 200
                $body = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                Send-HttpResponse -Response $response -Code 200 -Body $body -ContentType 'application/json; charset=utf-8'
            }
            return
        }

        # 2. File endpoint prefix routing.
        $filesPrefix = "$apiBasePath/files/"
        if (-not $absolutePath.StartsWith($filesPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $status = 404
            $realReason = 'route not matched'
            Send-HttpResponse -Response $response -Code 404
            return
        }

        # 3. HTTP method restriction (spec 2.1).
        if ($request.HttpMethod -ne 'GET') {
            $status = 405
            Send-HttpResponse -Response $response -Code 405
            return
        }

        # 4. Lockout check BEFORE auth/file processing (spec 3.3).
        $retryAfter = Get-LockoutRetryAfterSeconds -Tracker $FailureTracker -ClientIp $clientIp
        if ($retryAfter -gt 0) {
            $status = 429
            Send-HttpResponse -Response $response -Code 429 -Headers @{ 'Retry-After' = $retryAfter }
            return
        }

        # 5. Authentication (spec 3.2).
        $credential = Read-BasicAuthorization -AuthorizationHeader $request.Headers['Authorization']
        $authOk = Test-ServiceCredential -Credential $credential `
            -ExpectedUsername $Config.Security.Username `
            -Salt $PasswordSalt -ExpectedHash $PasswordHash `
            -Iterations ([int]$Config.Security.Pbkdf2Iterations)

        if (-not $authOk) {
            Add-AuthFailure -Tracker $FailureTracker -ClientIp $clientIp `
                -MaxAuthFailures ([int]$Config.Security.MaxAuthFailures) `
                -LockoutMinutes ([int]$Config.Security.LockoutMinutes)
            $status = 401
            Send-HttpResponse -Response $response -Code 401 -Headers @{ 'WWW-Authenticate' = 'Basic realm="XmlDistributionService"' }
            return
        }
        Clear-AuthFailures -Tracker $FailureTracker -ClientIp $clientIp

        # 6. Path boundary guard (spec 3.1). Unescape URL-encoded subpath safely (B1).
        $rawSubPath = $absolutePath.Substring($filesPrefix.Length)
        $subPath = $null
        try {
            $subPath = [System.Uri]::UnescapeDataString($rawSubPath)
        }
        catch {
            $status = 404
            $realReason = "malformed percent-encoding in sub-path '$rawSubPath'"
            Send-HttpResponse -Response $response -Code 404
            return
        }

        $safeTarget = Test-SafePath -RootDirectory $Config.Storage.RootDirectory -RequestedSubPath $subPath
        if ($null -eq $safeTarget) {
            $status = 404
            $realReason = "boundary/extension/existence rejection for sub-path '$subPath'"
            Send-HttpResponse -Response $response -Code 404
            return
        }

        # 7. File delivery with retry (spec 4.3). Atomic read + timestamp (B6, S5).
        try {
            $content = Read-XmlFileContent -Path $safeTarget `
                -MaxRetries ([int]$Config.Storage.FileReadRetryCount) `
                -DelayMs ([int]$Config.Storage.FileReadRetryDelayMs)
        }
        catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            $status = 404
            $realReason = "file missing after retries: $($_.Exception.Message)"
            Send-HttpResponse -Response $response -Code 404
            return
        }
        catch [System.IO.IOException] {
            $status = 503
            $realReason = "sharing violation after retries: $($_.Exception.Message)"
            Send-HttpResponse -Response $response -Code 503
            return
        }
        catch [System.UnauthorizedAccessException] {
            $status = 500
            $realReason = "file access denied by ACL: $($_.Exception.Message)"
            Send-HttpResponse -Response $response -Code 500
            return
        }

        $lastModified = $content.LastWriteTimeUtc.ToString('R')
        $status = 200
        Send-HttpResponse -Response $response -Code 200 -Body $content.Bytes `
            -ContentType 'application/xml; charset=utf-8' `
            -Headers @{ 'Last-Modified' = $lastModified; 'Cache-Control' = 'no-cache' }
    }
    catch {
        $status = 500
        $realReason = "unhandled worker fault: $($_.Exception.Message)"
        try { Send-HttpResponse -Response $response -Code 500 } catch { [void]$_ }
    }
    finally {
        $sw.Stop()
        try {
            Write-AuditLog -LogDirectory $Config.Logging.LogDirectory -LogLock $LogLock `
                -ClientIp $clientIp -RequestedPath $absolutePath -StatusCode $status `
                -ResponseTimeMs ([int]$sw.ElapsedMilliseconds) -ExceptionMessage $realReason
        }
        catch {
            [Console]::Error.WriteLine("[$([DateTime]::UtcNow.ToString('o'))] Audit log write failed: $($_.Exception.Message)")
        }
        try { $response.OutputStream.Close() } catch { [void]$_ }
        try { $response.Close() } catch { [void]$_ }
    }
}

Export-ModuleMember -Function Invoke-RequestHandler
