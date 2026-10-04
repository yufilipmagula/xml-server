@echo off
setlocal enabledelayedexpansion

REM =====================================================================
REM Install the service via NSSM (spec 7.3). Run as Administrator.
REM nssm.exe must be on PATH or in this folder. Adjust INSTALL_DIR.
REM The service account must match the urlacl reservation (01-provision-httpsys.cmd)
REM and have read access to RootDirectory and write access to LogDirectory.
REM =====================================================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    exit /b 1
)

set SERVICE_NAME=XmlDistributionService
set SERVICE_ACCOUNT=NT SERVICE\XmlDistributionService
set INSTALL_DIR=C:\Services\XmlFileService
set PS_EXE=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

where nssm.exe >nul 2>&1
if %errorLevel% neq 0 (
    if not exist "%~dp0nssm.exe" (
        echo [ERROR] nssm.exe not found on PATH or in script directory.
        exit /b 1
    )
    set NSSM_CMD="%~dp0nssm.exe"
) else (
    set NSSM_CMD=nssm.exe
)

echo [1/4] Installing %SERVICE_NAME% service...
%NSSM_CMD% install %SERVICE_NAME% "%PS_EXE%"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install %SERVICE_NAME% with NSSM.
    exit /b %errorLevel%
)

echo [2/4] Configuring service parameters and crash recovery...
%NSSM_CMD% set %SERVICE_NAME% AppParameters "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""%INSTALL_DIR%\server.ps1"""
%NSSM_CMD% set %SERVICE_NAME% AppDirectory "%INSTALL_DIR%"
%NSSM_CMD% set %SERVICE_NAME% Start SERVICE_AUTO_START

REM Service account isolation (S3)
if not "%SERVICE_ACCOUNT%"=="" (
    %NSSM_CMD% set %SERVICE_NAME% ObjectName "%SERVICE_ACCOUNT%"
)

REM Process recovery and throttle (B3)
%NSSM_CMD% set %SERVICE_NAME% AppExit Default Restart
%NSSM_CMD% set %SERVICE_NAME% AppRestartDelay 5000
%NSSM_CMD% set %SERVICE_NAME% AppThrottle 5000
%NSSM_CMD% set %SERVICE_NAME% AppStopMethodConsole 3000

REM Stdout and stderr logging under NSSM (B3)
if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"
%NSSM_CMD% set %SERVICE_NAME% AppStdout "%INSTALL_DIR%\logs\service_stdout.log"
%NSSM_CMD% set %SERVICE_NAME% AppStderr "%INSTALL_DIR%\logs\service_stderr.log"
%NSSM_CMD% set %SERVICE_NAME% AppRotateFiles 1
%NSSM_CMD% set %SERVICE_NAME% AppRotateBytes 10485760

echo [3/4] Hardening NTFS ACLs (S4)...
REM Lock down installation directory to Administrators, SYSTEM, and the service account
icacls "%INSTALL_DIR%" /inheritance:r /grant:r "Administrators:(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F" /grant:r "%SERVICE_ACCOUNT%:(OI)(CI)RX" >nul 2>&1
if exist "%INSTALL_DIR%\config.json" (
    icacls "%INSTALL_DIR%\config.json" /inheritance:r /grant:r "Administrators:F" /grant:r "SYSTEM:F" /grant:r "%SERVICE_ACCOUNT%:R" >nul 2>&1
)
if exist "%INSTALL_DIR%\logs" (
    icacls "%INSTALL_DIR%\logs" /grant:r "%SERVICE_ACCOUNT%:(OI)(CI)M" >nul 2>&1
)

echo [4/4] Starting %SERVICE_NAME%...
%NSSM_CMD% start %SERVICE_NAME%
echo.
echo Service %SERVICE_NAME% installed, hardened, and started.
