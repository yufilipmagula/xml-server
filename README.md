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

Windows 11 ships Windows PowerShell 5.1 and HTTP.sys in-box, so it is a faithful test target for the full stack.

```powershell
# Prepare local HTTPS (self-signed cert — LOCAL TESTING ONLY), elevated prompt
powershell -ExecutionPolicy Bypass -File .\deploy\Setup-LocalTest.ps1 -Port 8443

# Create config.json, generate credentials, point RootDirectory at a test folder
Copy-Item .\config.example.json .\config.json
.\New-PasswordHash.ps1   # Prompts securely without saving password to terminal history

# Run the service
powershell -ExecutionPolicy Bypass -File .\server.ps1

# From another shell:
curl.exe -k https://localhost:8443/api/v1/health
curl.exe -k -u service_consumer:local-test-pw https://localhost:8443/api/v1/files/sample.xml

# Or run the automated smoke test suite:
powershell -ExecutionPolicy Bypass -File .\tests\Invoke-SmokeTest.ps1 -BaseUri 'https://localhost:8443/api/v1' -Username 'service_consumer' -Password 'local-test-pw' -SkipSslCheck
```

### 4. Deploy to Windows Server 2019

1. Copy the project to `C:\Services\XmlFileService`.
2. Install the **customer-provided** certificate (with private key) into `LocalMachine\My`.
3. Edit and run `deploy\01-provision-httpsys.cmd` as Administrator (sets port, service account, cert thumbprint). Default service account is `NT SERVICE\XmlDistributionService`.
4. Create and fill `config.json` (use `New-PasswordHash.ps1` for credentials).
5. Edit and run `deploy\02-install-service.cmd` as Administrator (requires `nssm.exe`). Configures log rotation and ACL hardening automatically.

## Notes & Security Best Practices

- **Never use PowerShell 7+ features** — 5.1 Desktop is the sole supported runtime (spec 1.2). Pinned via `#requires -PSEdition Desktop` and analyzer settings.
- **Service Account Isolation:** Production deployment defaults to `NT SERVICE\XmlDistributionService` rather than LocalSystem, following the principle of least privilege.
- **TLS Hardening on Windows Server 2019:** HTTP.sys uses the Windows Schannel security package. Ensure legacy protocols (SSL 2.0/3.0, TLS 1.0/1.1) and weak ciphers are disabled via registry / IIS Crypto on the host OS.
- `config.json` holds only the PBKDF2 salt+hash (not reversible to plaintext) but is ACL-restricted to the service account and administrators by `02-install-service.cmd` (spec 8).
- Brute-force state is in-memory and resets on restart, by design (spec 3.3).
