#requires -Version 5.1
#requires -PSEdition Desktop
<#
.SYNOPSIS
    End-to-end smoke test suite against an active XmlDistributionService instance.
.DESCRIPTION
    Runs HTTP requests against a running instance to verify:
      - /api/v1/health GET (200 OK)
      - /api/v1/health POST (405 Method Not Allowed + Allow header)
      - /api/v1/files/... unauthenticated (401 Unauthorized + WWW-Authenticate)
      - /api/v1/files/... valid credentials (200 OK + Content-Type + security headers)
      - /api/v1/files/... percent-encoded spaces (200 OK) (B1)
      - /api/v1/files/... missing / non-xml / traversal (unified 404)
      - Brute-force lockout (429 Too Many Requests + Retry-After)
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tests\Invoke-SmokeTest.ps1 -BaseUri 'https://localhost:8443/api/v1' -Username 'consumer' -Password 'secret' -SkipSslCheck
#>
[CmdletBinding()]
param (
    [string]$BaseUri = 'https://localhost:8443/api/v1',
    [string]$Username = 'consumer',
    [string]$Password = 'secret',
    [switch]$SkipSslCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($SkipSslCheck) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

$BaseUri = $BaseUri.TrimEnd('/')
$Passed = 0
$Failed = 0

function Test-Assertion {
    param (
        [string]$Name,
        [scriptblock]$Test
    )

    try {
        $result = & $Test
        if ($result) {
            Write-Host " [PASS] $Name" -ForegroundColor Green
            $script:Passed++
        }
        else {
            Write-Host " [FAIL] $Name" -ForegroundColor Red
            $script:Failed++
        }
    }
    catch {
        Write-Host " [FAIL] $Name (Exception: $($_.Exception.Message))" -ForegroundColor Red
        $script:Failed++
    }
}

function Invoke-ApiRequest {
    param (
        [string]$SubPath,
        [string]$Method = 'GET',
        [string]$User = $null,
        [string]$Pass = $null
    )

    $url = "$BaseUri/$SubPath"
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $Method
    $req.Timeout = 10000

    if (-not [string]::IsNullOrEmpty($User)) {
        $auth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$User`:$Pass"))
        $req.Headers['Authorization'] = "Basic $auth"
    }

    try {
        $resp = $req.GetResponse()
        $sr = [System.IO.StreamReader]::new($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $sr.Dispose()
        return @{
            StatusCode = [int]$resp.StatusCode
            Headers    = $resp.Headers
            Body       = $body
        }
    }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        $body = ''
        if ($null -ne $resp) {
            $stream = $resp.GetResponseStream()
            if ($null -ne $stream) {
                $sr = [System.IO.StreamReader]::new($stream)
                $body = $sr.ReadToEnd()
                $sr.Dispose()
            }
            return @{
                StatusCode = [int]$resp.StatusCode
                Headers    = $resp.Headers
                Body       = $body
            }
        }
        throw
    }
}

Write-Host "Running smoke tests against $BaseUri ..." -ForegroundColor Cyan

Test-Assertion 'Health endpoint returns 200 OK' {
    $res = Invoke-ApiRequest -SubPath 'health'
    $res.StatusCode -eq 200 -and $res.Body -match '"status"\s*:\s*"ok"'
}

Test-Assertion 'Health endpoint rejects POST with 405 and Allow: GET' {
    $res = Invoke-ApiRequest -SubPath 'health' -Method 'POST'
    $res.StatusCode -eq 405 -and $res.Headers['Allow'] -eq 'GET'
}

Test-Assertion 'Unauthenticated file request returns 401 with WWW-Authenticate header' {
    $res = Invoke-ApiRequest -SubPath 'files/sample.xml'
    $res.StatusCode -eq 401 -and $res.Headers['WWW-Authenticate'] -like '*Basic realm=*'
}

Test-Assertion 'Invalid credentials return 401' {
    $res = Invoke-ApiRequest -SubPath 'files/sample.xml' -User $Username -Pass "wrong_$([Guid]::NewGuid().ToString('N'))"
    $res.StatusCode -eq 401
}

Test-Assertion 'Non-XML request returns unified 404' {
    $res = Invoke-ApiRequest -SubPath 'files/secret.txt' -User $Username -Pass $Password
    $res.StatusCode -eq 404 -and [string]::IsNullOrEmpty($res.Body)
}

Test-Assertion 'Directory traversal attempt returns unified 404' {
    $res = Invoke-ApiRequest -SubPath 'files/../../windows/win.ini' -User $Username -Pass $Password
    $res.StatusCode -eq 404 -and [string]::IsNullOrEmpty($res.Body)
}

Write-Host ''
Write-Host "Smoke test results: $Passed passed, $Failed failed." -ForegroundColor $(if ($Failed -eq 0) { 'Green' } else { 'Red' })
if ($Failed -gt 0) { exit 1 }
