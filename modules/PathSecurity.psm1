#requires -Version 5.1
#requires -PSEdition Desktop
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Canonical path-traversal verification for the XML Distribution API.
.DESCRIPTION
    Implements the boundary guard from spec section 3.1. The requested sub-path
    is assumed to have been URL-decoded exactly once by HttpListener / request
    handler. Extension, directory, and reparse-point (symlink/junction) rejections
    live inside this function so they are indistinguishable from traversal
    rejections (unified 404, spec section 2.4).
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

    # 1. Reject null bytes, NTFS alternate streams / drive-colons, illegal path characters,
    #    literal back-references, UNC / absolute path markers, and trailing dots/spaces.
    if ($RequestedSubPath -match '[\0:<>|*?"]' -or
        $RequestedSubPath.Contains('..') -or
        $RequestedSubPath.StartsWith('\\') -or
        $RequestedSubPath.StartsWith('//') -or
        $RequestedSubPath -match '(?:\.|\s)(?:/|\\|$)') {
        return $null
    }

    # 2. Normalize and resolve under try/catch to ensure invalid paths map to unified 404 (spec 2.4).
    try {
        $canonicalRoot = [System.IO.Path]::GetFullPath($RootDirectory).TrimEnd('\', '/')
        $combinedPath = [System.IO.Path]::Combine($canonicalRoot, $RequestedSubPath.TrimStart('\', '/'))
        $canonicalTarget = [System.IO.Path]::GetFullPath($combinedPath)

        # 3. Boundary guard: target must strictly reside within root, be an existing
        #    FILE, and carry the .xml extension.
        $expectedPrefix = $canonicalRoot + [System.IO.Path]::DirectorySeparatorChar
        if (-not $canonicalTarget.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not [System.IO.File]::Exists($canonicalTarget) -or
            -not [System.IO.Path]::GetExtension($canonicalTarget).Equals('.xml', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $null
        }

        # 4. Reparse point guard (spec hardening S6): reject symlinks, junctions,
        #    and mounted volumes to prevent escaping the root directory tree.
        $fileInfo = [System.IO.FileInfo]::new($canonicalTarget)
        if ($fileInfo.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            return $null
        }

        $rootDirInfo = [System.IO.DirectoryInfo]::new($canonicalRoot)
        $currentDir = $fileInfo.Directory
        while ($null -ne $currentDir -and $currentDir.FullName.Length -gt $rootDirInfo.FullName.Length) {
            if ($currentDir.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
                return $null
            }
            $currentDir = $currentDir.Parent
        }

        return $canonicalTarget
    }
    catch {
        return $null
    }
}

Export-ModuleMember -Function Test-SafePath
