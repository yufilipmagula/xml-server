# PowerShell XML Distribution API

Headless, read-only REST service that serves `.xml` files from a local directory tree over HTTPS with Basic auth, built on Windows PowerShell 5.1 and `.NET` (`System.Net.HttpListener` / HTTP.sys). See [final-spec.md](final-spec.md) for the authoritative requirements.

## Project layout

```
cz-ps-app/
├── server.ps1                 # Entrypoint: self-checks, RunspacePool listener, graceful shutdown
├── New-PasswordHash.ps1       # CLI: generate PBKDF2 salt+hash for config.json
├── config.example.json        # Config template — copy to config.json and fill in
├── PSScriptAnalyzerSettings.psd1  # Static analysis pinned to PS 5.1 (Server 2019)
├── modules/
│   ├── Configuration.psm1     # config.json load + schema validation
│   ├── PathSecurity.psm1      # Test-SafePath traversal/boundary guard
│   ├── Authentication.psm1    # PBKDF2-SHA256 + constant-time verify + Basic parse
│   ├── Lockout.psm1           # Thread-safe per-IP brute-force tracker
│   ├── Logging.psm1           # Thread-safe rotating audit log + retention purge
│   └── FileDelivery.psm1      # Shared-read file access with retry
├── tests/                     # Pester v5 unit suite (runs on PS7/Mac and PS5.1/Windows)
│   └── Invoke-Tests.ps1       # Test runner
└── deploy/
    ├── 01-provision-httpsys.cmd  # One-time netsh urlacl + sslcert (prod)
    ├── 02-install-service.cmd    # NSSM service install (prod)
    └── Setup-LocalTest.ps1       # Self-signed cert + bindings for local Win11 testing
```

## Cross-platform development workflow

The code splits into two layers with very different portability:

| Layer | Modules | Testable on Mac/PS7? |
| --- | --- | --- |
| Pure logic | PathSecurity, Authentication, Lockout, Configuration, FileDelivery | **Yes** — plain `.NET` calls present in both PS 5.1 and PS 7 |
| Hosting | `server.ps1` HttpListener + HTTPS, netsh, NSSM | **No** — HTTPS rides on the Windows-only HTTP.sys kernel driver |

### 1. Author + static-check on macOS (PowerShell 7)

```bash
# One-time
pwsh -c "Install-Module PSScriptAnalyzer -Scope CurrentUser -Force"

# Catch any PS7-only syntax/commands/types before they reach Windows.
# Scope to app code: Pester's Should/Invoke-Pester aren't in the in-box
# command catalog, so they surface as harmless false positives in tests/.
pwsh -c '@("./modules","./server.ps1","./New-PasswordHash.ps1") | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Recurse -Settings ./PSScriptAnalyzerSettings.psd1 }'
```

### 2. Unit-test the logic on macOS (fast loop)

```bash
pwsh -c "Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force"   # one-time
pwsh ./tests/Invoke-Tests.ps1
```

### 3. Parity + integration test on local Windows 11

Windows 11 ships Windows PowerShell 5.1 and HTTP.sys in-box, so it is a faithful test target for the full stack.

```powershell
# Re-run the same unit suite under 5.1 to confirm parity
powershell -ExecutionPolicy Bypass -File .\tests\Invoke-Tests.ps1

# Prepare local HTTPS (self-signed cert — LOCAL TESTING ONLY), elevated prompt
powershell -ExecutionPolicy Bypass -File .\deploy\Setup-LocalTest.ps1 -Port 8443

# Create config.json, generate credentials, point RootDirectory at a test folder
Copy-Item .\config.example.json .\config.json
.\New-PasswordHash.ps1 -PlainPassword 'local-test-pw'   # paste salt+hash into config.json

# Run the service
powershell -ExecutionPolicy Bypass -File .\server.ps1

# From another shell:
curl.exe -k https://localhost:8443/api/v1/health
curl.exe -k -u service_consumer:local-test-pw https://localhost:8443/api/v1/files/sample.xml
```

### 4. Deploy to Windows Server 2019

1. Copy the project to `C:\Services\XmlFileService`.
2. Install the **customer-provided** certificate (with private key) into `LocalMachine\My`.
3. Edit and run `deploy\01-provision-httpsys.cmd` (set port, service account, cert thumbprint).
4. Create and fill `config.json` (use `New-PasswordHash.ps1` for credentials).
5. Edit and run `deploy\02-install-service.cmd` (requires `nssm.exe`).

## Notes

- **Never use PowerShell 7+ features** — 5.1 is the sole supported runtime (spec 1.2). The analyzer settings enforce this; keep the build clean.
- `config.json` holds only the PBKDF2 salt+hash (not reversible to plaintext) but should still be ACL-restricted to the service account and administrators (spec 8).
- Brute-force state is in-memory and resets on restart, by design (spec 3.3).
```
