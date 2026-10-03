#requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Canonical path-traversal verification for the XML Distribution API.
.DESCRIPTION
    Implements the boundary guard from spec section 3.1. The requested sub-path
    is assumed to have been URL-decoded exactly once by HttpListener. Extension
    and directory rejections live inside this function so they are
    indistinguishable from traversal rejections (unified 404, spec section 2.4).
#>

function Test-SafePath {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$RootDirectory,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RequestedSubPath   # already decoded exactly once
    )

    # 1. Reject null bytes, NTFS alternate streams / drive-colons, literal
    #    back-references, and UNC / absolute path markers.
    if ($RequestedSubPath -match '[\0:]' -or
        $RequestedSubPath.Contains('..') -or
        $RequestedSubPath.StartsWith('\\') -or
        $RequestedSubPath.StartsWith('//')) {
        return $null
    }

    # 2. Normalize and resolve.
    $canonicalRoot = [System.IO.Path]::GetFullPath($RootDirectory).TrimEnd('\', '/')
    $combinedPath = [System.IO.Path]::Combine($canonicalRoot, $RequestedSubPath.TrimStart('\', '/'))
    $canonicalTarget = [System.IO.Path]::GetFullPath($combinedPath)

    # 3. Boundary guard: target must strictly reside within root, be an existing
    #    FILE, and carry the .xml extension.
    $expectedPrefix = $canonicalRoot + [System.IO.Path]::DirectorySeparatorChar
    if ($canonicalTarget.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.File]::Exists($canonicalTarget) -and
        [System.IO.Path]::GetExtension($canonicalTarget).Equals('.xml', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $canonicalTarget
    }

    return $null
}

Export-ModuleMember -Function Test-SafePath
