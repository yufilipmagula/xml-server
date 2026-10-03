#requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    config.json loading and schema validation (spec sections 6, 7.5).
.DESCRIPTION
    ConvertFrom-Json on Windows PowerShell 5.1 returns PSCustomObject (no
    -AsHashtable), so validation walks the object graph by property name.
    The service must fail fast with a clear message on any missing or malformed
    key. MaxThreads is clamped to 4-16.
#>

$script:RequiredSchema = @{
    Server   = @('Port', 'MaxThreads', 'UrlPrefix')
    Storage  = @('RootDirectory', 'FileReadRetryCount', 'FileReadRetryDelayMs')
    Security = @('Username', 'PasswordSaltBase64', 'PasswordHashBase64', 'Pbkdf2Iterations', 'MaxAuthFailures', 'LockoutMinutes')
    Logging  = @('LogDirectory', 'RetainDays')
}

function Test-Base64 {
    [OutputType([bool])]
    param ([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    try {
        [void][Convert]::FromBase64String($Value)
        return $true
    }
    catch {
        return $false
    }
}

function Import-ServiceConfig {
    <#
        Reads and validates config.json. Throws a descriptive terminating error
        on any schema violation so startup self-checks (spec 7.5) can abort with
        a clear fatal log entry. Returns the validated PSCustomObject on success.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Configuration file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    try {
        $config = $raw | ConvertFrom-Json
    }
    catch {
        throw "config.json is not valid JSON: $($_.Exception.Message)"
    }

    # Required sections and keys.
    foreach ($section in $script:RequiredSchema.Keys) {
        if (-not ($config.PSObject.Properties.Name -contains $section)) {
            throw "config.json is missing required section '$section'."
        }
        foreach ($key in $script:RequiredSchema[$section]) {
            if (-not ($config.$section.PSObject.Properties.Name -contains $key)) {
                throw "config.json is missing required key '$section.$key'."
            }
        }
    }

    # Type / range checks.
    $maxThreads = [int]$config.Server.MaxThreads
    if ($maxThreads -lt 4) { $maxThreads = 4 }
    if ($maxThreads -gt 16) { $maxThreads = 16 }
    $config.Server.MaxThreads = $maxThreads

    if ([int]$config.Server.Port -le 0 -or [int]$config.Server.Port -gt 65535) {
        throw "config.json Server.Port must be between 1 and 65535."
    }
    if ([string]::IsNullOrWhiteSpace($config.Server.UrlPrefix)) {
        throw "config.json Server.UrlPrefix must be a non-empty URL ACL prefix."
    }
    if ([int]$config.Security.Pbkdf2Iterations -lt 100000) {
        throw "config.json Security.Pbkdf2Iterations must be at least 100000."
    }
    if (-not (Test-Base64 $config.Security.PasswordSaltBase64)) {
        throw "config.json Security.PasswordSaltBase64 is not valid Base64."
    }
    if (-not (Test-Base64 $config.Security.PasswordHashBase64)) {
        throw "config.json Security.PasswordHashBase64 is not valid Base64."
    }
    if ([int]$config.Security.MaxAuthFailures -lt 1) {
        throw "config.json Security.MaxAuthFailures must be at least 1."
    }
    if ([int]$config.Security.LockoutMinutes -lt 1) {
        throw "config.json Security.LockoutMinutes must be at least 1."
    }
    if ([int]$config.Storage.FileReadRetryCount -lt 1) {
        throw "config.json Storage.FileReadRetryCount must be at least 1."
    }
    if ([int]$config.Logging.RetainDays -lt 1) {
        throw "config.json Logging.RetainDays must be at least 1."
    }

    return $config
}

Export-ModuleMember -Function Import-ServiceConfig, Test-Base64
