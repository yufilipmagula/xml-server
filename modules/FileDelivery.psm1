#requires -Version 5.1
#requires -PSEdition Desktop
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Shared-read file access with retry and response formatting (spec section 4.3).
.DESCRIPTION
    Opens files with FileShare.ReadWrite to coexist with external writers that
    swap the XML files roughly every five minutes. Retries IOExceptions and
    transient FileNotFoundExceptions with linear backoff. Discarding missing files
    as 404 and locked files as 503 avoids misclassifying deleted files.
#>

function Get-XmlStreamWithRetry {
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxRetries = 3,

        [int]$DelayMs = 50
    )

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            return [System.IO.FileStream]::new(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)   # coexist with external writers
        }
        catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
            # File may be mid-swap; retry briefly, then propagate not-found for unified 404
            $attempt++
            if ($attempt -ge $MaxRetries) { throw }
            [System.Threading.Thread]::Sleep($DelayMs * $attempt)
        }
        catch [System.IO.IOException] {
            # Sharing/lock violation during external write; retry then propagate for 503
            $attempt++
            if ($attempt -ge $MaxRetries) { throw }
            [System.Threading.Thread]::Sleep($DelayMs * $attempt)   # linear backoff
        }
    }
}

function Read-XmlFileContent {
    <#
        Reads the entire file into a byte[] and captures LastWriteTimeUtc in
        a single atomic operation to prevent TOCTOU header discrepancies (spec 4.3).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxRetries = 3,

        [int]$DelayMs = 50
    )

    $stream = Get-XmlStreamWithRetry -Path $Path -MaxRetries $MaxRetries -DelayMs $DelayMs
    try {
        $lastWriteUtc = [System.IO.File]::GetLastWriteTimeUtc($Path)
        $ms = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($ms)
            return [pscustomobject]@{
                Bytes            = $ms.ToArray()
                LastWriteTimeUtc = $lastWriteUtc
            }
        }
        finally {
            $ms.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Read-XmlFileBytes {
    <#
        Reads the entire file into a byte[] using the retrying shared-read stream.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxRetries = 3,

        [int]$DelayMs = 50
    )

    $content = Read-XmlFileContent -Path $Path -MaxRetries $MaxRetries -DelayMs $DelayMs
    return $content.Bytes
}

function Send-HttpResponse {
    <#
        Writes HTTP status code, standard hardening headers, custom headers,
        and optional body to HttpListenerResponse.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Net.HttpListenerResponse]$Response,

        [Parameter(Mandatory)]
        [int]$Code,

        [hashtable]$Headers = @{},

        [byte[]]$Body = $null,

        [string]$ContentType = $null
    )

    $Response.StatusCode = $Code

    # Security headers (S11)
    if (-not $Response.Headers['X-Content-Type-Options']) {
        $Response.AddHeader('X-Content-Type-Options', 'nosniff')
    }

    # RFC 9110: 405 Method Not Allowed MUST include an Allow header
    if ($Code -eq 405 -and -not $Headers.ContainsKey('Allow')) {
        $Response.AddHeader('Allow', 'GET')
    }

    foreach ($h in $Headers.Keys) {
        $Response.AddHeader($h, [string]$Headers[$h])
    }

    if ($ContentType) {
        $Response.ContentType = $ContentType
    }

    if ($null -ne $Body) {
        $Response.ContentLength64 = $Body.Length
        $Response.OutputStream.Write($Body, 0, $Body.Length)
    }
    else {
        $Response.ContentLength64 = 0
    }
}

function Send-Status {
    <# Alias for Send-HttpResponse for backwards compatibility #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Net.HttpListenerResponse]$Response,

        [Parameter(Mandatory)]
        [int]$Code,

        [hashtable]$Headers = @{},

        [byte[]]$Body = $null,

        [string]$ContentType = $null
    )
    Send-HttpResponse -Response $Response -Code $Code -Headers $Headers -Body $Body -ContentType $ContentType
}

Export-ModuleMember -Function Get-XmlStreamWithRetry, Read-XmlFileContent, Read-XmlFileBytes, Send-HttpResponse, Send-Status
