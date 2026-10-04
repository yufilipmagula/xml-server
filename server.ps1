#requires -Version 5.1
<#
.SYNOPSIS
    PowerShell XML Distribution API - headless read-only REST service.
.DESCRIPTION
    Main entrypoint. Performs startup self-checks (spec 7.5), builds a
    RunspacePool with shared state injected via InitialSessionState, runs the
    HttpListener accept loop, and shuts down gracefully on stop/exception
    (spec 4.4). Targets Windows PowerShell 5.1 on Windows Server 2019.
.NOTES
    HTTPS binding rides on HTTP.sys; it requires a Windows host with a URL ACL
    reservation and an SSL certificate bound to the port (spec 7.1).
#>
[CmdletBinding()]
param (
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'
}

$ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'modules'
$ModulePaths = @(
    (Join-Path $ModuleRoot 'Configuration.psm1'),
    (Join-Path $ModuleRoot 'PathSecurity.psm1'),
    (Join-Path $ModuleRoot 'Authentication.psm1'),
    (Join-Path $ModuleRoot 'Lockout.psm1'),
    (Join-Path $ModuleRoot 'Logging.psm1'),
    (Join-Path $ModuleRoot 'FileDelivery.psm1')
)

foreach ($modulePath in $ModulePaths) {
    Import-Module -Name $modulePath -Force
}

function Write-Fatal {
    param ([string]$Message)
    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    Write-Error "[$stamp] FATAL: $Message"
}

# -------------------------------------------------------------------------
# Startup self-checks (spec 7.5)
# -------------------------------------------------------------------------
try {
    $Config = Import-ServiceConfig -Path $ConfigPath
}
catch {
    Write-Fatal "Configuration load/validation failed: $($_.Exception.Message)"
    exit 1
}

$RootDirectory = $Config.Storage.RootDirectory
if (-not (Test-Path -LiteralPath $RootDirectory -PathType Container)) {
    Write-Fatal "Storage.RootDirectory does not exist or is not a directory: $RootDirectory"
    exit 1
}

$LogDirectory = $Config.Logging.LogDirectory
try {
    Initialize-LogDirectory -LogDirectory $LogDirectory
}
catch {
    Write-Fatal "Could not create Logging.LogDirectory '$LogDirectory': $($_.Exception.Message)"
    exit 1
}

# SSL binding check - warn (do not abort); the listener will fail on first HTTPS request if absent.
$Port = [int]$Config.Server.Port
try {
    $sslInfo = & netsh http show sslcert ipport=0.0.0.0:$Port 2>&1 | Out-String
    if ($sslInfo -notmatch 'Certificate Hash') {
        Write-Warning "No SSL certificate binding found for 0.0.0.0:$Port. HTTPS requests will fail until 'netsh http add sslcert' is run (see deploy/01-provision-httpsys.cmd)."
    }
}
catch {
    Write-Warning "Could not query SSL binding via netsh: $($_.Exception.Message)"
}

Remove-OldLogs -LogDirectory $LogDirectory -RetainDays ([int]$Config.Logging.RetainDays)
$lastPurgeDate = [DateTime]::UtcNow.Date

# -------------------------------------------------------------------------
# Shared state + RunspacePool (spec 4.1, 4.2)
# -------------------------------------------------------------------------
$FailureTracker = New-FailureTracker
$LogLock = New-LogLock
$PasswordSalt = [Convert]::FromBase64String($Config.Security.PasswordSaltBase64)
$PasswordHash = [Convert]::FromBase64String($Config.Security.PasswordHashBase64)

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$iss.ImportPSModule($ModulePaths)
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('ServiceConfig', $Config, ''))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('FailureTracker', $FailureTracker, ''))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('LogLock', $LogLock, ''))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('PasswordSalt', $PasswordSalt, ''))
$iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('PasswordHash', $PasswordHash, ''))

$MaxThreads = [int]$Config.Server.MaxThreads
$Pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $iss, $Host)
$Pool.Open()

# -------------------------------------------------------------------------
# Worker: processes one HttpListenerContext end to end (spec 4.1)
# Runs inside a pool runspace; module functions and shared variables are
# supplied by the InitialSessionState above.
# -------------------------------------------------------------------------
$WorkerScript = {
    param ($Context)

    Set-StrictMode -Version Latest
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $request = $Context.Request
    $response = $Context.Response
    $clientIp = if ($request.RemoteEndPoint) { $request.RemoteEndPoint.Address.ToString() } else { 'unknown' }
    $absolutePath = $request.Url.AbsolutePath
    $status = 500
    $realReason = ''

    try {
        $prefix = '/api/v1'

        # Health endpoint: unauthenticated, no FS access, GET only (spec 2.3).
        if ($absolutePath -eq "$prefix/health") {
            if ($request.HttpMethod -ne 'GET') {
                $status = 405
                Send-Status -Response $response -Code 405
            }
            else {
                $status = 200
                $body = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                Send-Status -Response $response -Code 200 -Body $body -ContentType 'application/json; charset=utf-8'
            }
            return
        }

        # File endpoint.
        if (-not $absolutePath.StartsWith("$prefix/files/", [System.StringComparison]::OrdinalIgnoreCase)) {
            $status = 404
            $realReason = 'route not matched'
            Send-Status -Response $response -Code 404
            return
        }

        if ($request.HttpMethod -ne 'GET') {
            $status = 405
            Send-Status -Response $response -Code 405
            return
        }

        # Lockout check BEFORE auth/file processing (spec 3.3).
        $retryAfter = Get-LockoutRetryAfterSeconds -Tracker $FailureTracker -ClientIp $clientIp
        if ($retryAfter -gt 0) {
            $status = 429
            Send-Status -Response $response -Code 429 -Headers @{ 'Retry-After' = $retryAfter }
            return
        }

        # Authentication (spec 3.2).
        $credential = Read-BasicAuthorization -AuthorizationHeader $request.Headers['Authorization']
        $authOk = Test-ServiceCredential -Credential $credential `
            -ExpectedUsername $ServiceConfig.Security.Username `
            -Salt $PasswordSalt -ExpectedHash $PasswordHash `
            -Iterations ([int]$ServiceConfig.Security.Pbkdf2Iterations)

        if (-not $authOk) {
            Add-AuthFailure -Tracker $FailureTracker -ClientIp $clientIp `
                -MaxAuthFailures ([int]$ServiceConfig.Security.MaxAuthFailures) `
                -LockoutMinutes ([int]$ServiceConfig.Security.LockoutMinutes)
            $status = 401
            Send-Status -Response $response -Code 401 -Headers @{ 'WWW-Authenticate' = 'Basic realm="XmlDistributionService"' }
            return
        }
        Clear-AuthFailures -Tracker $FailureTracker -ClientIp $clientIp

        # Path boundary guard (spec 3.1). Sub-path is already decoded exactly once.
        $subPath = $absolutePath.Substring("$prefix/files/".Length)
        $safeTarget = Test-SafePath -RootDirectory $ServiceConfig.Storage.RootDirectory -RequestedSubPath $subPath
        if ($null -eq $safeTarget) {
            $status = 404
            $realReason = "boundary/extension/existence rejection for sub-path '$subPath'"
            Send-Status -Response $response -Code 404
            return
        }

        # File delivery with retry (spec 4.3).
        try {
            $bytes = Read-XmlFileBytes -Path $safeTarget `
                -MaxRetries ([int]$ServiceConfig.Storage.FileReadRetryCount) `
                -DelayMs ([int]$ServiceConfig.Storage.FileReadRetryDelayMs)
        }
        catch [System.IO.IOException] {
            $status = 503
            $realReason = "sharing violation after retries: $($_.Exception.Message)"
            Send-Status -Response $response -Code 503
            return
        }

        $lastModified = ([System.IO.File]::GetLastWriteTimeUtc($safeTarget)).ToString('R')
        $status = 200
        Send-Status -Response $response -Code 200 -Body $bytes `
            -ContentType 'application/xml; charset=utf-8' `
            -Headers @{ 'Last-Modified' = $lastModified; 'Cache-Control' = 'no-cache' }
    }
    catch {
        $status = 500
        $realReason = "unhandled worker fault: $($_.Exception.Message)"
        try { Send-Status -Response $response -Code 500 } catch { [void]$_ }
    }
    finally {
        $sw.Stop()
        try {
            Write-AuditLog -LogDirectory $ServiceConfig.Logging.LogDirectory -LogLock $LogLock `
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

# -------------------------------------------------------------------------
# HttpListener accept loop + graceful shutdown (spec 4.1, 4.4)
# -------------------------------------------------------------------------
$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add($Config.Server.UrlPrefix)
$Jobs = [System.Collections.ArrayList]::new()

try {
    $Listener.Start()
    Write-Host "XmlDistributionService listening on $($Config.Server.UrlPrefix) (MaxThreads=$MaxThreads)"

    function script:Invoke-JobReaping {
        for ($i = $Jobs.Count - 1; $i -ge 0; $i--) {
            if ($Jobs[$i].Handle.IsCompleted) {
                try { [void]$Jobs[$i].PowerShell.EndInvoke($Jobs[$i].Handle) } catch { [void]$_ }
                $Jobs[$i].PowerShell.Dispose()
                $Jobs.RemoveAt($i)
            }
        }
    }

    $asyncContext = $null
    while ($Listener.IsListening) {
        if ($null -eq $asyncContext) {
            try {
                $asyncContext = $Listener.BeginGetContext($null, $null)
            }
            catch [System.Net.HttpListenerException] {
                break
            }
            catch [System.ObjectDisposedException] {
                break
            }
        }

        # Non-blocking wait with 500ms timeout: allows idle worker reaping, daily log purge, and responsive shutdown.
        if (-not $asyncContext.AsyncWaitHandle.WaitOne(500)) {
            Invoke-JobReaping

            $todayUtc = [DateTime]::UtcNow.Date
            if ($todayUtc -gt $lastPurgeDate) {
                try {
                    Remove-OldLogs -LogDirectory $LogDirectory -RetainDays ([int]$Config.Logging.RetainDays)
                    Remove-ExpiredAuthFailures -Tracker $FailureTracker
                    $lastPurgeDate = $todayUtc
                }
                catch {
                    Write-Warning "Daily log retention/tracker purge failed: $($_.Exception.Message)"
                }
            }
            continue
        }

        try {
            $context = $Listener.EndGetContext($asyncContext)
        }
        catch [System.Net.HttpListenerException] {
            break
        }
        catch [System.ObjectDisposedException] {
            break
        }
        finally {
            $asyncContext = $null
        }

        $ps = [powershell]::Create()
        $ps.RunspacePool = $Pool
        [void]$ps.AddScript($WorkerScript.ToString()).AddArgument($context)
        $handle = $ps.BeginInvoke()
        [void]$Jobs.Add([pscustomobject]@{ PowerShell = $ps; Handle = $handle })

        Invoke-JobReaping

        # Once-per-day log retention and tracker purge (spec 7.5).
        $todayUtc = [DateTime]::UtcNow.Date
        if ($todayUtc -gt $lastPurgeDate) {
            try {
                Remove-OldLogs -LogDirectory $LogDirectory -RetainDays ([int]$Config.Logging.RetainDays)
                Remove-ExpiredAuthFailures -Tracker $FailureTracker
                $lastPurgeDate = $todayUtc
            }
            catch {
                Write-Warning "Daily log retention/tracker purge failed: $($_.Exception.Message)"
            }
        }
    }
}
finally {
    Write-Host 'Shutting down XmlDistributionService...'
    try { if ($Listener.IsListening) { $Listener.Stop() } } catch { [void]$_ }
    try { $Listener.Close() } catch { [void]$_ }

    foreach ($job in $Jobs) {
        try { [void]$job.PowerShell.EndInvoke($job.Handle) } catch { [void]$_ }
        try { $job.PowerShell.Dispose() } catch { [void]$_ }
    }
    try { $Pool.Close() } catch { [void]$_ }
    try { $Pool.Dispose() } catch { [void]$_ }
    Write-Host 'Shutdown complete.'
}
