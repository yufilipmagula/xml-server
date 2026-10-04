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

    Beyond the spec minimum, validation also enforces:
      - integer types and sane upper bounds for every numeric setting
        (e.g. FileReadRetryDelayMs = -1 would make Thread.Sleep block forever);
      - exact PBKDF2 hash length (a truncated hash would make guessing trivial);
      - HTTPS-only UrlPrefix, except on loopback hosts where Basic credentials
        never cross the network (local development);
      - UrlPrefix port matching Server.Port;
      - absolute (rooted) storage and log paths.
    On success a derived Server.ApiBasePath (UrlPrefix path without the trailing
    slash, e.g. '/api/v1') is attached so routing never hard-codes the prefix.
#>

$script:RequiredSchema = @{
    Server   = @('Port', 'MaxThreads', 'UrlPrefix')
    Storage  = @('RootDirectory', 'FileReadRetryCount', 'FileReadRetryDelayMs')
    Security = @('Username', 'PasswordSaltBase64', 'PasswordHashBase64', 'Pbkdf2Iterations', 'MaxAuthFailures', 'LockoutMinutes')
    Logging  = @('LogDirectory', 'RetainDays')
}

# Inclusive integer ranges. MaxThreads is clamped (spec 6); all others are rejected when out of range.
$script:IntegerRanges = @{
    'Server.Port'                  = @(1, 65535)
    'Server.MaxThreads'            = @(4, 16)
    'Storage.FileReadRetryCount'   = @(1, 10)
    'Storage.FileReadRetryDelayMs' = @(0, 5000)
    'Security.Pbkdf2Iterations'    = @(100000, 10000000)
    'Security.MaxAuthFailures'     = @(1, 100)
    'Security.LockoutMinutes'      = @(1, 1440)
    'Logging.RetainDays'           = @(1, 3650)
}

$script:RequiredHashBytes = 32   # spec 3.2: 32-byte PBKDF2 derived key
$script:MinSaltBytes = 16        # NIST SP 800-132 minimum; New-PasswordHash.ps1 emits 32
$script:LoopbackHosts = @('localhost', '127.0.0.1', '[::1]')

function ConvertFrom-Base64OrNull {
    [OutputType([byte[]])]
    param ([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        return , [Convert]::FromBase64String($Value)
    }
    catch {
        return $null
    }
}

function Get-ValidatedInteger {
    param ($Config, [string]$Section, [string]$Key, [switch]$Clamp)

    $name = "$Section.$Key"
    $value = $Config.$Section.$Key
    if (-not ($value -is [int] -or $value -is [long])) {
        throw "config.json $name must be an integer (got '$value')."
    }
    $min, $max = $script:IntegerRanges[$name]
    if ($value -lt $min -or $value -gt $max) {
        if (-not $Clamp) {
            throw "config.json $name must be between $min and $max (got $value)."
        }
        $clamped = [Math]::Min([Math]::Max([long]$value, $min), $max)
        Write-Warning "config.json $name=$value is outside $min-$max; clamped to $clamped."
        $value = $clamped
    }
    return [int]$value
}

function Assert-NonEmptyString {
    param ($Config, [string]$Section, [string]$Key)
    $value = $Config.$Section.$Key
    if (-not ($value -is [string]) -or [string]::IsNullOrWhiteSpace($value)) {
        throw "config.json $Section.$Key must be a non-empty string."
    }
    return $value
}

function Assert-AbsolutePath {
    param ($Config, [string]$Section, [string]$Key)
    $value = Assert-NonEmptyString -Config $Config -Section $Section -Key $Key
    # Drive-absolute (C:\...) or UNC (\\server\share). Rejects relative and drive-relative ('C:foo') paths,
    # which would silently resolve against the service's working directory.
    if ($value -notmatch '^[A-Za-z]:\\' -and -not $value.StartsWith('\\')) {
        throw "config.json $Section.$Key must be an absolute path (got '$value')."
    }
}

function Get-ValidatedApiBasePath {
    param ([string]$UrlPrefix, [int]$Port)

    if (-not $UrlPrefix.EndsWith('/')) {
        throw "config.json Server.UrlPrefix must end with '/' (got '$UrlPrefix')."
    }

    # HttpListener wildcards '+' and '*' are not valid URI hosts; substitute one for parsing only.
    $match = [regex]::Match($UrlPrefix, '^(?<scheme>[A-Za-z]+)://(?<host>\[[^\]]+\]|[^:/]+)(:(?<port>\d+))?(?<path>/.*)$')
    if (-not $match.Success) {
        throw "config.json Server.UrlPrefix is not a valid HttpListener prefix (got '$UrlPrefix')."
    }
    $scheme = $match.Groups['scheme'].Value.ToLowerInvariant()
    $hostName = $match.Groups['host'].Value.ToLowerInvariant()
    $prefixPort = if ($match.Groups['port'].Success) { [int]$match.Groups['port'].Value } elseif ($scheme -eq 'https') { 443 } else { 80 }

    if ($scheme -ne 'https' -and -not ($scheme -eq 'http' -and $script:LoopbackHosts -contains $hostName)) {
        throw "config.json Server.UrlPrefix must use https:// (plain http is only allowed for loopback hosts); got '$UrlPrefix'."
    }
    if ($prefixPort -ne $Port) {
        throw "config.json Server.UrlPrefix port ($prefixPort) does not match Server.Port ($Port)."
    }

    $basePath = $match.Groups['path'].Value.TrimEnd('/')
    if ([string]::IsNullOrEmpty($basePath)) {
        throw "config.json Server.UrlPrefix must include a path segment such as '/api/v1/' (got '$UrlPrefix')."
    }
    return $basePath
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

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Configuration file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    try {
        $config = $raw | ConvertFrom-Json
    }
    catch {
        throw "config.json is not valid JSON: $($_.Exception.Message)"
    }
    if ($config -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'config.json must contain a JSON object at the top level.'
    }

    # Required sections and keys.
    foreach ($section in $script:RequiredSchema.Keys) {
        if (-not ($config.PSObject.Properties.Name -contains $section) -or
            $config.$section -isnot [System.Management.Automation.PSCustomObject]) {
            throw "config.json is missing required section '$section'."
        }
        foreach ($key in $script:RequiredSchema[$section]) {
            if (-not ($config.$section.PSObject.Properties.Name -contains $key)) {
                throw "config.json is missing required key '$section.$key'."
            }
        }
    }

    # Integers: type + range.
    $config.Server.MaxThreads = Get-ValidatedInteger -Config $config -Section 'Server' -Key 'MaxThreads' -Clamp
    foreach ($name in $script:IntegerRanges.Keys) {
        if ($name -eq 'Server.MaxThreads') { continue }
        $section, $key = $name.Split('.')
        $config.$section.$key = Get-ValidatedInteger -Config $config -Section $section -Key $key
    }

    # Server.
    $urlPrefix = Assert-NonEmptyString -Config $config -Section 'Server' -Key 'UrlPrefix'
    $apiBasePath = Get-ValidatedApiBasePath -UrlPrefix $urlPrefix -Port $config.Server.Port
    $config.Server | Add-Member -NotePropertyName 'ApiBasePath' -NotePropertyValue $apiBasePath -Force

    # Paths.
    Assert-AbsolutePath -Config $config -Section 'Storage' -Key 'RootDirectory'
    Assert-AbsolutePath -Config $config -Section 'Logging' -Key 'LogDirectory'

    # Security.
    $username = Assert-NonEmptyString -Config $config -Section 'Security' -Key 'Username'
    if ($username.Contains(':') -or $username -match '[\x00-\x1F\x7F]') {
        throw 'config.json Security.Username must not contain ":" or control characters (Basic auth constraint).'
    }

    $salt = ConvertFrom-Base64OrNull $config.Security.PasswordSaltBase64
    if ($null -eq $salt) {
        throw 'config.json Security.PasswordSaltBase64 is not valid Base64.'
    }
    if ($salt.Length -lt $script:MinSaltBytes) {
        throw "config.json Security.PasswordSaltBase64 must decode to at least $($script:MinSaltBytes) bytes (got $($salt.Length)). Regenerate with New-PasswordHash.ps1."
    }

    $hash = ConvertFrom-Base64OrNull $config.Security.PasswordHashBase64
    if ($null -eq $hash) {
        throw 'config.json Security.PasswordHashBase64 is not valid Base64.'
    }
    if ($hash.Length -ne $script:RequiredHashBytes) {
        throw "config.json Security.PasswordHashBase64 must decode to exactly $($script:RequiredHashBytes) bytes (got $($hash.Length)). Regenerate with New-PasswordHash.ps1."
    }

    return $config
}

Export-ModuleMember -Function Import-ServiceConfig
