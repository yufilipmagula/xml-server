@echo off
REM =====================================================================
REM Install the service via NSSM (spec 7.3). Run as Administrator.
REM nssm.exe must be on PATH or in this folder. Adjust INSTALL_DIR.
REM The service account must match the urlacl reservation (01-provision-httpsys.cmd)
REM and have read access to RootDirectory and write access to LogDirectory.
REM =====================================================================

set SERVICE_NAME=XmlDistributionService
set INSTALL_DIR=C:\Services\XmlFileService
set PS_EXE=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

nssm.exe install %SERVICE_NAME% "%PS_EXE%"
nssm.exe set %SERVICE_NAME% AppParameters "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File %INSTALL_DIR%\server.ps1"
nssm.exe set %SERVICE_NAME% AppDirectory "%INSTALL_DIR%"
nssm.exe set %SERVICE_NAME% Start SERVICE_AUTO_START

REM Process recovery
nssm.exe set %SERVICE_NAME% AppExit Default Restart
nssm.exe set %SERVICE_NAME% AppRestartDelay 5000

nssm.exe start %SERVICE_NAME%
echo Service %SERVICE_NAME% installed and started.
