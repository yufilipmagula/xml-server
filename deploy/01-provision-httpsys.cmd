@echo off
setlocal enabledelayedexpansion

REM =====================================================================
REM One-time HTTP.sys provisioning (spec 7.1). Run as Administrator.
REM Adjust PORT, SERVICE_ACCOUNT, and CERT_THUMBPRINT before running.
REM =====================================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    exit /b 1
)

set PORT=8443
set SERVICE_ACCOUNT=NT SERVICE\XmlDistributionService
set CERT_THUMBPRINT=YOUR_THUMBPRINT_HERE
set APP_ID={7c8b41e2-563b-4179-8802-1262d086f68c}

if "%CERT_THUMBPRINT%"=="YOUR_THUMBPRINT_HERE" (
    echo [ERROR] Please edit this script and set CERT_THUMBPRINT to your installed certificate thumbprint.
    exit /b 1
)

echo [1/2] Reserving URL ACL for https://+:%PORT%/api/v1/ to %SERVICE_ACCOUNT% ...
netsh http add urlacl url=https://+:%PORT%/api/v1/ user="%SERVICE_ACCOUNT%"
if %errorLevel% neq 0 (
    echo [WARNING] urlacl add returned error %errorLevel% (may already exist). Continuing...
)

echo [2/2] Binding customer-provided TLS certificate to 0.0.0.0:%PORT% ...
REM The certificate WITH its private key must already be installed in LocalMachine\My.
REM NOTE: short-lived certs (e.g. Let's Encrypt) change thumbprint on renewal; re-run this bind each renewal.
netsh http delete sslcert ipport=0.0.0.0:%PORT% >nul 2>&1
netsh http add sslcert ipport=0.0.0.0:%PORT% certhash=%CERT_THUMBPRINT% appid=%APP_ID%
if %errorLevel% neq 0 (
    echo [ERROR] Failed to bind SSL certificate to 0.0.0.0:%PORT%.
    exit /b %errorLevel%
)

echo.
echo Done. Verify binding with:
echo   netsh http show sslcert ipport=0.0.0.0:%PORT%
echo   netsh http show urlacl url=https://+:%PORT%/api/v1/
