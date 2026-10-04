# PowerShell XML Distribution API

Headless, read-only REST service that serves `.xml` files from a local directory tree over HTTPS with Basic auth, built on Windows PowerShell 5.1 and `.NET` (`System.Net.HttpListener` / HTTP.sys). See [final-spec.md](final-spec.md) for the authoritative requirements.

## Project layout

```
xml-server/
├── server.ps1                 # Entrypoint: self-checks, RunspacePool listener, graceful shutdown
├── New-PasswordHash.ps1       # CLI: generate PBKDF2 salt+hash for config.json (interactive or param)
├── config.example.json        # Config template — copy to config.json and fill in
├── PSScriptAnalyzerSettings.psd1  # Static analysis pinned to PS 5.1 Desktop (Server 2019)
├── modules/
│   ├── Configuration.psm1     # config.json load + schema validation
│   ├── PathSecurity.psm1      # Test-SafePath traversal/boundary/reparse-point guard
│   ├── Authentication.psm1    # PBKDF2-SHA256 + constant-time verify + Basic parse
│   ├── Lockout.psm1           # Thread-safe per-IP brute-force tracker + rate-limited purge
│   ├── Logging.psm1           # Thread-safe rotating audit log + service lifecycle log + purge
│   ├── FileDelivery.psm1      # Shared-read file access with retry + HTTP response headers
│   └── RequestHandler.psm1    # End-to-end request pipeline + routing + audit dispatch
├── tests/                     # Pester 3.4.0 unit suite (in-box on Windows PowerShell 5.1)
│   ├── Invoke-Tests.ps1       # Unit test runner
│   └── Invoke-SmokeTest.ps1   # Live endpoint smoke test runner
└── deploy/
    ├── 01-provision-httpsys.cmd  # One-time netsh urlacl + sslcert (prod)
    ├── 02-install-service.cmd    # NSSM service install with virtual account + ACL hardening (prod)
    └── Setup-LocalTest.ps1       # Self-signed cert + bindings for local Win11 testing
```

## Development workflow

Target runtime is **Windows PowerShell 5.1 Desktop Edition** (in-box on Windows 11 and Windows Server 2019). All development and testing happens on Windows.

### 1. Static analysis

```powershell
# One-time
powershell -Command "Install-Module PSScriptAnalyzer -Scope CurrentUser -Force"

# Scope to app code: Pester's Should/Invoke-Pester aren't in the in-box
# command catalog, so they surface as harmless false positives in tests/.
powershell -ExecutionPolicy Bypass -Command "& { Import-Module PSScriptAnalyzer; @('.\modules','.\server.ps1','.\New-PasswordHash.ps1') | ForEach-Object { Invoke-ScriptAnalyzer -Path `$_ -Recurse -Settings .\PSScriptAnalyzerSettings.psd1 } }"
```

### 2. Unit tests

```powershell
# Uses the Pester 3.4.0 module included with Windows PowerShell 5.1
powershell -ExecutionPolicy Bypass -File .\tests\Invoke-Tests.ps1
```

### 3. Integration test on local Windows 11

Windows 11 ships Windows PowerShell 5.1 and HTTP.sys in-box, making it a faithful test target for the full stack.

#### 3.1 One-time local HTTPS setup (Elevated PowerShell)
Open PowerShell as Administrator to create a self-signed certificate and bind HTTP.sys URL ACL and SSL port:
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\Setup-LocalTest.ps1 -Port 8443
```

#### 3.2 Prepare local test data and configuration
In a normal PowerShell prompt:
```powershell
# 1. Create local repository directory and a test XML file
New-Item -ItemType Directory -Path 'C:\Data\XML_Repository' -Force
Set-Content -Path 'C:\Data\XML_Repository\sample.xml' -Value '<?xml version="1.0" encoding="utf-8"?><data><item>test</item></data>'

# 2. Copy the example configuration template
Copy-Item .\config.example.json .\config.json

# 3. Generate salt and hash for test credentials (e.g., password 'local-test-pw')
.\New-PasswordHash.ps1 -PlainPassword 'local-test-pw'
# Or run without parameters to securely prompt without saving password in terminal history:
# .\New-PasswordHash.ps1

# 4. Open config.json and replace the placeholders:
#    - Set "PasswordSaltBase64" to the generated salt
#    - Set "PasswordHashBase64" to the generated hash
#    - Verify "RootDirectory" points to your test folder ('C:\Data\XML_Repository')
```

> **Note:** The server verifies on startup that `PasswordSaltBase64` and `PasswordHashBase64` are valid Base64 strings and rejects placeholder values, preventing deployment with unconfigured credentials.

#### 3.3 Run the service
```powershell
powershell -ExecutionPolicy Bypass -File .\server.ps1
```

#### 3.4 Verify endpoints
From another shell:
```powershell
# Liveness health check (unauthenticated):
curl.exe -k https://localhost:8443/api/v1/health

# Authenticated XML file delivery:
curl.exe -k -u service_consumer:local-test-pw https://localhost:8443/api/v1/files/sample.xml

# Or run the automated smoke test suite:
powershell -ExecutionPolicy Bypass -File .\tests\Invoke-SmokeTest.ps1 -BaseUri 'https://localhost:8443/api/v1' -Username 'service_consumer' -Password 'local-test-pw' -SkipSslCheck
```

---

### 4. Deploy to Windows Server 2019

#### 4.1 Production Prerequisites
1. **Operating System:** Windows Server 2019 with Windows PowerShell 5.1 and .NET Framework 4.7.2+ (included in-box).
2. **Customer-Provided TLS Certificate:**
   - Must be installed with its private key in `Cert:\LocalMachine\My` (Local Computer Personal store).
   - Record the certificate **Thumbprint** for HTTP.sys binding.
   - *Note on Certificate Renewal:* HTTP.sys binds by thumbprint. If using short-lived certificates (such as Let's Encrypt / win-acme), automate re-running `netsh http add sslcert` with the new thumbprint upon renewal.
3. **Firewall Allowlisting:**
   - Configure Windows Defender Firewall to allow inbound TCP on your chosen port (default `8443`).
   - Per spec §1.1 and §8, network-level IP allowlisting is enforced at the Windows Firewall layer. Restrict the inbound firewall rule to authorized client IP ranges.
4. **Service Account:**
   - The deployment scripts default to `NT SERVICE\XmlDistributionService`, a virtual service account requiring no password management or interactive login rights.
   - Ensure the account is granted **Read** access on `RootDirectory` and **Modify/Write** access on `LogDirectory`.
5. **NSSM (Non-Sucking Service Manager):**
   - Download `nssm.exe` and place it either on the system `PATH` or directly inside the `deploy\` folder.

#### 4.2 Step-by-Step Deployment

1. **Deploy application files:**
   Copy the repository contents to the target service directory (default: `C:\Services\XmlFileService`).

2. **Configure HTTP.sys kernel driver (Elevated Command Prompt / Admin):**
   Edit `deploy\01-provision-httpsys.cmd`:
   - Set `PORT` (e.g., `8443`).
   - Set `SERVICE_ACCOUNT` (default: `NT SERVICE\XmlDistributionService`).
   - Set `CERT_THUMBPRINT` to the customer certificate thumbprint.
   Execute:
   ```cmd
   deploy\01-provision-httpsys.cmd
   ```

3. **Configure production storage, logging, and credentials:**
   - Copy `config.example.json` to `C:\Services\XmlFileService\config.json`.
   - Run `New-PasswordHash.ps1` to generate a secure PBKDF2-SHA256 salt and hash for the production consumer password:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\New-PasswordHash.ps1
     ```
   - In `config.json`:
     - Set `Storage.RootDirectory` to the authoritative XML storage path (e.g., `D:\Data\XML_Repository`).
     - Set `Logging.LogDirectory` to the target log path (e.g., `D:\Logs\XmlDistService`).
     - Paste `PasswordSaltBase64` and `PasswordHashBase64`.
     - Confirm `Server.Port` and `Server.UrlPrefix` match the HTTP.sys provisioning.

4. **Install service and harden NTFS permissions (Elevated Command Prompt / Admin):**
   Edit `deploy\02-install-service.cmd` if your installation directory or service name differs from defaults, then run:
   ```cmd
   deploy\02-install-service.cmd
   ```
   This script:
   - Registers `XmlDistributionService` under NSSM pointing to `server.ps1`.
   - Sets process recovery (restart on failure, 5-second restart delay).
   - Configures stdout/stderr log rotation under `C:\Services\XmlFileService\logs\`.
   - Configures the virtual service account `NT SERVICE\XmlDistributionService`.
   - **Hardens NTFS ACLs:** Strips inherited permissions; restricts the installation folder to Administrators, SYSTEM, and Read/Execute for the service account; restricts `config.json` to Read-only for the service account; and grants Modify rights to `logs\`.
   - Starts the Windows service.

5. **Post-Deployment Verification:**
   - Check service status: `sc query XmlDistributionService`
   - Review startup logs: `type C:\Services\XmlFileService\logs\service_stdout.log`
   - Run smoke tests against the production endpoint:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\tests\Invoke-SmokeTest.ps1 -BaseUri 'https://<server-fqdn>:8443/api/v1' -Username '<consumer-user>' -Password '<consumer-password>'
     ```

---

## Notes & Security Best Practices

- **Never use PowerShell 7+ features** — 5.1 Desktop is the sole supported runtime (spec §1.2). Pinned via `#requires -PSEdition Desktop` and analyzer settings.
- **Service Account Isolation:** Production deployment defaults to `NT SERVICE\XmlDistributionService` rather than LocalSystem, adhering to the principle of least privilege.
- **TLS Hardening on Windows Server 2019:** HTTP.sys uses the Windows Schannel security package. Ensure legacy protocols (SSL 2.0/3.0, TLS 1.0/1.1) and weak ciphers are disabled via registry / IIS Crypto on the host OS.
- **Secrets Protection:** `config.json` holds only the PBKDF2 salt+hash (not reversible to plaintext) and is ACL-restricted by `02-install-service.cmd` so that only the service account and administrators have read access (spec §8).
- **Brute-Force Rate Limiting:** State is maintained in-memory and resets on restart by design (spec §3.3). Persistent blocklisting is handled at the network firewall layer.
