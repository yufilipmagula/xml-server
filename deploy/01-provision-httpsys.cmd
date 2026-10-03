@echo off
REM =====================================================================
REM One-time HTTP.sys provisioning (spec 7.1). Run as Administrator.
REM Adjust PORT, SERVICE_ACCOUNT, and CERT_THUMBPRINT before running.
REM =====================================================================

set PORT=8443
set SERVICE_ACCOUNT=NT AUTHORITY\SYSTEM
set CERT_THUMBPRINT=YOUR_THUMBPRINT_HERE
set APP_ID={a1b2c3d4-e5f6-7890-abcd-1234567890ab}

echo [1/2] Reserving URL ACL for https://+:%PORT%/api/v1/ ...
netsh http add urlacl url=https://+:%PORT%/api/v1/ user="%SERVICE_ACCOUNT%"

echo [2/2] Binding customer-provided TLS certificate to 0.0.0.0:%PORT% ...
REM The certificate WITH its private key must already be installed in LocalMachine\My.
REM NOTE: short-lived certs (e.g. Let's Encrypt) change thumbprint on renewal; re-run this bind each renewal.
netsh http add sslcert ipport=0.0.0.0:%PORT% certhash=%CERT_THUMBPRINT% appid=%APP_ID%

echo Done. Verify with: netsh http show sslcert ipport=0.0.0.0:%PORT%
