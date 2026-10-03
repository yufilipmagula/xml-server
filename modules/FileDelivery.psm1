#requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Shared-read file access with retry (spec section 4.3).
.DESCRIPTION
    Opens files with FileShare.ReadWrite to coexist with external writers that
    swap the XML files roughly every five minutes. Retries IOExceptions with
    linear backoff; the caller returns 503 on exhaustion.
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
        catch [System.IO.IOException] {
            $attempt++
            if ($attempt -ge $MaxRetries) { throw }
            [System.Threading.Thread]::Sleep($DelayMs * $attempt)   # linear backoff
        }
    }
}

function Read-XmlFileBytes {
    <#
        Reads the entire file into a byte[] using the retrying shared-read
        stream. For the low-scale / small-file profile the worker reads fully
        then writes with Content-Length set (spec section 4.3).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxRetries = 3,

        [int]$DelayMs = 50
    )

    $stream = Get-XmlStreamWithRetry -Path $Path -MaxRetries $MaxRetries -DelayMs $DelayMs
    try {
        $buffer = [byte[]]::new($stream.Length)
        $totalRead = 0
        while ($totalRead -lt $buffer.Length) {
            $read = $stream.Read($buffer, $totalRead, $buffer.Length - $totalRead)
            if ($read -le 0) { break }
            $totalRead += $read
        }
        return $buffer
    }
    finally {
        $stream.Dispose()
    }
}

Export-ModuleMember -Function Get-XmlStreamWithRetry, Read-XmlFileBytes
