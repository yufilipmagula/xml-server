#requires -Version 5.1
#requires -PSEdition Desktop
<#
.SYNOPSIS
    PowerShell XML Distribution API - headless read-only REST service.
.DESCRIPTION
    Main entrypoint. Performs startup self-checks (spec 7.5), builds a
    RunspacePool with shared state, runs the HttpListener accept loop,
    and shuts down gracefully on stop/exception (spec 4.4).
    Targets Windows PowerShell 5.1 on Windows Server 2019.
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
    (Join-Path $ModuleRoot 'FileDelivery.psm1'),
    (Join-Path $ModuleRoot 'RequestHandler.psm1')
)

foreach ($modulePath in $ModulePaths) {
    Import-Module -Name $modulePath -Force
}

function Write-Fatal {
    param (
        [string]$Message,
        [string]$LogDir = $null
    )
    Write-ServiceLog -Message "FATAL: $Message" -Level 'FATAL' -LogDirectory $LogDir
}

# -------------------------------------------------------------------------
# Startup self-checks (spec 7.5)
# -------------------------------------------------------------------------
try {
    $Config = Import-ServiceConfig -Path $ConfigPath
}
catch {
    Write-Fatal -Message "Configuration load/validation failed: $($_.Exception.Message)"
    exit 1
}

$RootDirectory = $Config.Storage.RootDirectory
if (-not (Test-Path -LiteralPath $RootDirectory -PathType Container)) {
    Write-Fatal -Message "Storage.RootDirectory does not exist or is not a directory: $RootDirectory" -LogDir $Config.Logging.LogDirectory
    exit 1
}

$LogDirectory = $Config.Logging.LogDirectory
try {
    Initialize-LogDirectory -LogDirectory $LogDirectory
}
catch {
    Write-Fatal -Message "Could not create Logging.LogDirectory '$LogDirectory': $($_.Exception.Message)"
    exit 1
}

$LogLock = New-LogLock
$Port = [int]$Config.Server.Port

# SSL binding check (B9) - warn (do not abort); the listener will fail on first HTTPS request if absent.
$isHttps = $Config.Server.UrlPrefix.StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)
if ($isHttps) {
    try {
        $sslInfo = & netsh http show sslcert ipport=0.0.0.0:$Port 2>&1 | Out-String
        if ($sslInfo -notmatch 'Certificate Hash') {
            $sslAll = & netsh http show sslcert 2>&1 | Out-String
            if ($sslAll -notmatch ":$Port\b") {
                Write-ServiceLog -Message "No SSL certificate binding found for port $Port. HTTPS requests will fail until 'netsh http add sslcert' is run (see deploy/01-provision-httpsys.cmd)." -Level 'WARN' -LogDirectory $LogDirectory -LogLock $LogLock
            }
        }
    }
    catch {
        Write-ServiceLog -Message "Could not query SSL binding via netsh: $($_.Exception.Message)" -Level 'WARN' -LogDirectory $LogDirectory -LogLock $LogLock
    }
}

Remove-OldLogs -LogDirectory $LogDirectory -RetainDays ([int]$Config.Logging.RetainDays)
$lastPurgeDate = [DateTime]::UtcNow.Date

# -------------------------------------------------------------------------
# Shared state + RunspacePool (spec 4.1, 4.2)
# -------------------------------------------------------------------------
$FailureTracker = New-FailureTracker
$PasswordSalt = [Convert]::FromBase64String($Config.Security.PasswordSaltBase64)
$PasswordHash = [Convert]::FromBase64String($Config.Security.PasswordHashBase64)

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$iss.ImportPSModule($ModulePaths)

$MaxThreads = [int]$Config.Server.MaxThreads
$MaxBacklog = $MaxThreads * 4
$Pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $iss, $Host)
$Pool.Open()

# -------------------------------------------------------------------------
# Helper functions for accept loop (C1, C11)
# -------------------------------------------------------------------------
function Invoke-JobReaping {
    param ([System.Collections.ArrayList]$JobList)
    for ($i = $JobList.Count - 1; $i -ge 0; $i--) {
        if ($JobList[$i].Handle.IsCompleted) {
            try { [void]$JobList[$i].PowerShell.EndInvoke($JobList[$i].Handle) } catch { [void]$_ }
            $JobList[$i].PowerShell.Dispose()
            $JobList.RemoveAt($i)
        }
    }
}

function Invoke-DailyMaintenance {
    param (
        [string]$LogDir,
        [int]$RetainDays,
        [hashtable]$Tracker,
        [ref]$LastPurgeDateRef,
        [object]$LockObj
    )
    $todayUtc = [DateTime]::UtcNow.Date
    if ($todayUtc -gt $LastPurgeDateRef.Value) {
        try {
            Remove-OldLogs -LogDirectory $LogDir -RetainDays $RetainDays
            Remove-ExpiredAuthFailures -Tracker $Tracker
            $LastPurgeDateRef.Value = $todayUtc
        }
        catch {
            Write-ServiceLog -Message "Daily log retention/tracker purge failed: $($_.Exception.Message)" -Level 'WARN' -LogDirectory $LogDir -LogLock $LockObj
        }
    }
}

# -------------------------------------------------------------------------
# HttpListener accept loop + graceful shutdown (spec 4.1, 4.4, S7, B7)
# -------------------------------------------------------------------------
$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add($Config.Server.UrlPrefix)

# HTTP.sys connection timeout protection (S7)
try {
    $Listener.TimeoutManager.IdleConnection = [TimeSpan]::FromSeconds(120)
    $Listener.TimeoutManager.HeaderWait = [TimeSpan]::FromSeconds(30)
}
catch {
    # Non-fatal if platform does not permit setting TimeoutManager
    [void]$_
}

$Jobs = [System.Collections.ArrayList]::new()

try {
    $Listener.Start()
    Write-ServiceLog -Message "XmlDistributionService listening on $($Config.Server.UrlPrefix) (MaxThreads=$MaxThreads, MaxBacklog=$MaxBacklog)" -Level 'INFO' -LogDirectory $LogDirectory -LogLock $LogLock

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
            Invoke-JobReaping -JobList $Jobs
            Invoke-DailyMaintenance -LogDir $LogDirectory -RetainDays ([int]$Config.Logging.RetainDays) -Tracker $FailureTracker -LastPurgeDateRef ([ref]$lastPurgeDate) -LockObj $LogLock
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

        Invoke-JobReaping -JobList $Jobs

        # DoS overload protection (S7): shed load with 503 if worker backlog exceeds threshold
        if ($Jobs.Count -ge $MaxBacklog) {
            try {
                $context.Response.StatusCode = 503
                $context.Response.Headers.Add('Retry-After', '5')
                $context.Response.Close()
            }
            catch { [void]$_ }
            continue
        }

        # Dispatch request to runspace pool using RequestHandler (C2, C12)
        $ps = [powershell]::Create()
        $ps.RunspacePool = $Pool
        [void]$ps.AddCommand('Invoke-RequestHandler')
        [void]$ps.AddParameter('Context', $context)
        [void]$ps.AddParameter('Config', $Config)
        [void]$ps.AddParameter('FailureTracker', $FailureTracker)
        [void]$ps.AddParameter('LogLock', $LogLock)
        [void]$ps.AddParameter('PasswordSalt', $PasswordSalt)
        [void]$ps.AddParameter('PasswordHash', $PasswordHash)

        $handle = $ps.BeginInvoke()
        [void]$Jobs.Add([pscustomobject]@{ PowerShell = $ps; Handle = $handle })

        Invoke-DailyMaintenance -LogDir $LogDirectory -RetainDays ([int]$Config.Logging.RetainDays) -Tracker $FailureTracker -LastPurgeDateRef ([ref]$lastPurgeDate) -LockObj $LogLock
    }
}
finally {
    Write-ServiceLog -Message 'Shutting down XmlDistributionService...' -Level 'INFO' -LogDirectory $LogDirectory -LogLock $LogLock
    try { if ($Listener.IsListening) { $Listener.Stop() } } catch { [void]$_ }
    try { $Listener.Close() } catch { [void]$_ }

    # Bounded wait for in-flight requests (B7)
    foreach ($job in $Jobs) {
        try {
            if (-not $job.Handle.IsCompleted) {
                [void]$job.Handle.AsyncWaitHandle.WaitOne(3000)
            }
            if ($job.Handle.IsCompleted) {
                try { [void]$job.PowerShell.EndInvoke($job.Handle) } catch { [void]$_ }
            }
            else {
                $job.PowerShell.Stop()
            }
            $job.PowerShell.Dispose()
        }
        catch { [void]$_ }
    }
    try { $Pool.Close() } catch { [void]$_ }
    try { $Pool.Dispose() } catch { [void]$_ }
    Write-ServiceLog -Message 'Shutdown complete.' -Level 'INFO' -LogDirectory $LogDirectory -LogLock $LogLock
}
