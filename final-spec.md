# Software Requirements & Technical Specification: PowerShell XML Distribution API

**Status:** Final · **Date:** 2026-10-01 · **Target platform:** Windows Server 2019, Windows PowerShell 5.1

---

## 1. System Overview

The system is a headless, script-based Windows service implemented in Windows PowerShell 5.1 that exposes a local directory structure of XML files over a secure, read-only REST API. It builds directly on the Windows `.NET` runtime (`System.Net.HttpListener`, `System.IO`, `System.Security.Cryptography`), so it deploys without compilation, maps the file system dynamically, authenticates every request, and tolerates concurrent third-party writes to the served files.

```
[ External Client ]
        │  (HTTPS / Basic Auth)
        ▼
[ Windows Firewall ] ─── (IP Whitelist Filter - External, operator-managed)
        │
        ▼
[ HTTP.sys Kernel Driver ] ─── (TLS Termination & Port Binding)
        │
        ▼
[ PowerShell Host Process (server.ps1) ]
        ├── Auth Module (PBKDF2-SHA256, constant-time verify)
        ├── Path Normalizer & Boundary Guard (.xml only)
        ├── Runspace Pool (4–16 concurrent workers)
        ├── Shared State (synchronized failure tracker + log lock)
        └── File Delivery Engine ([System.IO.FileShare]::ReadWrite, retry)
                │
                ▼
        [ Local Storage: C:\Data\XML_Repository\... ]
```

### 1.1 Scope & Non-Goals

**In scope:** read-only `GET` of `.xml` files, single-service-account Basic Auth over HTTPS, path-traversal prevention, concurrency-safe shared reads, brute-force lockout, audit logging, NSSM-based service deployment.

**Out of scope (non-goals):** write/upload operations; multi-user or role-based auth; multi-factor auth; data-at-rest encryption; in-process IP filtering (delegated to Windows Firewall); PKI/certificate issuance and renewal (the certificate is customer-provided); directory listing.

### 1.2 Runtime & Platform Constraints

- **Windows PowerShell 5.1** is the sole supported runtime (the in-box version on Windows Server 2019). All APIs in this spec are chosen to work there; no PowerShell 7+ features may be used.
- `.NET Framework` 4.7.2+ (in-box on Server 2019) is assumed, which is required for the `Rfc2898DeriveBytes` constructor that takes an explicit `HashAlgorithmName`. **The implementation must use that explicit-SHA256 constructor** — the legacy `Rfc2898DeriveBytes(password, salt, iterations)` overload silently defaults to SHA1 and must not be used.

---

## 2. Functional Requirements

### 2.1 File Retrieval & Path Resolution

- **Recursive path mapping.** Request URIs map directly onto the folder hierarchy beneath the configured root.
  - Example: `GET /api/v1/files/finance/2026/report.xml` → `C:\Data\XML_Repository\finance\2026\report.xml`.
- **`.xml` only.** Only files whose extension is `.xml` (case-insensitive) are served. A request for any other extension is treated as not found (see §2.4), even when the file exists. This hides non-XML artifacts that may sit in the tree.
- **Zero-latency / live disk access.** The application must not cache file payloads in memory. Every request reads directly from disk, so that:
  - Updates to XML files (which occur roughly every 5 minutes) are served immediately.
  - Daily/weekly additions or removals of subfolders and files take effect with no script restart.
- **HTTP verb restriction.** Only `GET` is permitted on file and health endpoints. Any `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, or `OPTIONS` request is rejected with `405 Method Not Allowed`.
- **MIME configuration.** XML files are delivered with `Content-Type: application/xml; charset=utf-8`.

### 2.2 Directory Enumeration

- Requests that resolve to a directory rather than a file (e.g., `GET /api/v1/files/finance/`) return `404 Not Found` with no body, to prevent attackers from mapping the folder structure.

### 2.3 Health Check

- `GET /api/v1/health` is **unauthenticated**, performs **no file-system access**, and returns `200 OK` with body `{"status":"ok"}` and `Content-Type: application/json; charset=utf-8`. It exists solely so NSSM, load balancers, and monitoring can confirm the listener is alive. It reveals nothing about configuration, credentials, or the served directory.

### 2.4 Unified "Not Found" Behavior

To avoid leaking *why* a request failed, the following all return an **identical** `404 Not Found` with an empty body and no distinguishing headers:

- The file does not exist.
- The target is a directory.
- The target extension is not `.xml`.
- The path failed the traversal/boundary assertion (§3.1).

---

## 3. Security & Integrity Specification

Given operational constraints (no MFA, no data-at-rest encryption), defensive controls focus on transport security, traversal prevention, credential derivation, brute-force resistance, and memory-safe shared reads.

| Threat Category | Attack Vector | Mitigation Strategy |
| --- | --- | --- |
| **Directory Traversal** | `../`, encoded characters (`%2e%2e`), null bytes (`%00`), NTFS streams (`::$DATA`), UNC/absolute paths. | Decode the request path exactly once, then sanitize; resolve the fully qualified path via `[System.IO.Path]::GetFullPath()`; assert a case-insensitive prefix match against the canonical root (§3.1). |
| **Credential Interception** | Network eavesdropping on HTTP Basic Auth. | Mandatory HTTPS. Bind a customer-provided SSL/TLS certificate to the endpoint via `HTTP.sys` (`netsh http add sslcert`). |
| **Credential Theft from Disk** | Plaintext password extraction from config. | Store a salted **PBKDF2-SHA256** derived key via `Rfc2898DeriveBytes` (explicit SHA256). Plaintext never appears in config. |
| **Brute Force** | Continuous dictionary attempts on Basic Auth. | Thread-safe (`[hashtable]::Synchronized`) failure tracker per client IP, enforcing temporary lockout → `429` with `Retry-After`. |
| **Credential Timing Side-Channel** | Measuring auth response time to infer hash correctness. | Fixed-time byte comparison of the derived key (§3.2). |
| **Sharing Violations (`IOException`, `0x80070020`)** | Third-party processes writing/swapping XML every ~5 min. | Open with `[System.IO.FileShare]::ReadWrite`; retry up to `FileReadRetryCount` with linear-backoff delay; `503` on exhaustion. |

### 3.1 Path Traversal Verification

The requested sub-path is derived from `HttpListenerRequest.Url.AbsolutePath` with the API prefix stripped. It is URL-decoded **exactly once** (HttpListener provides a decoded `AbsolutePath`; the implementation must not decode a second time, which would re-introduce `%2e%2e`-style attacks). The decoded sub-path then passes the following pipeline before any file-system access:

```powershell
function Test-SafePath {
    param (
        [string]$RootDirectory,
        [string]$RequestedSubPath   # already decoded exactly once
    )

    # 1. Reject null bytes, NTFS alternate streams / drive-colons, literal back-references,
    #    and UNC/absolute path markers.
    if ($RequestedSubPath -match '[\0:]' -or
        $RequestedSubPath.Contains("..") -or
        $RequestedSubPath.StartsWith("\\") -or
        $RequestedSubPath.StartsWith("//")) {
        return $null
    }

    # 2. Normalize and resolve.
    $canonicalRoot = [System.IO.Path]::GetFullPath($RootDirectory).TrimEnd('\','/')
    $combinedPath  = [System.IO.Path]::Combine($canonicalRoot, $RequestedSubPath.TrimStart('\','/'))
    $canonicalTarget = [System.IO.Path]::GetFullPath($combinedPath)

    # 3. Boundary guard: target must strictly reside within root, be an existing FILE, and be .xml.
    $expectedPrefix = $canonicalRoot + [System.IO.Path]::DirectorySeparatorChar
    if ($canonicalTarget.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.File]::Exists($canonicalTarget) -and
        [System.IO.Path]::GetExtension($canonicalTarget).Equals(".xml", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $canonicalTarget
    }

    return $null
}
```

A `$null` return maps to the unified `404` (§2.4). The `.xml` and `File::Exists` checks live inside this function so that extension and directory rejections are indistinguishable from traversal rejections.

### 3.2 Authentication & Cryptographic Standards

- **Scheme:** HTTP Basic Authentication (`Authorization: Basic <base64(user:pass)>`).
- **Credential verification steps:**
  1. Parse and Base64-decode the `Authorization` header; malformed/missing header → `401`.
  2. Compare the supplied username to the configured `Username`.
  3. Derive the key from the supplied password using the stored salt and iteration count (`Rfc2898DeriveBytes`, explicit `HashAlgorithmName.SHA256`, 32-byte output).
  4. Compare the derived key to the stored hash using a **constant-time** byte comparison (iterate all bytes, accumulate differences with `-bxor`, never short-circuit).
  5. Any failure → `401` with header `WWW-Authenticate: Basic realm="XmlDistributionService"`, and the client IP's failure counter is incremented (§3.3).
- **Password storage:** `config.json` stores a 32-byte salt (Base64) and a 32-byte PBKDF2 derived key (Base64), computed with ≥ 100,000 iterations of HMAC-SHA256. Plaintext passwords never appear in configuration.

### 3.3 Brute-Force Lockout

- A process-wide `[hashtable]::Synchronized(@{})` keyed by client IP tracks `{ FailureCount, FirstFailureUtc, LockedUntilUtc }`.
- After `MaxAuthFailures` failures, the IP is locked for `LockoutMinutes`. While locked, requests from that IP return `429 Too Many Requests` with a `Retry-After` header (seconds remaining) **before** any auth or file processing.
- A successful authentication clears that IP's counter.
- The tracker is **in-memory only** and resets on service restart. This is acceptable for the low-scale, trusted-network deployment and is documented as such.

---

## 4. Concurrency & Non-Blocking Architecture

A single PowerShell thread would let one slow download block all other requests. The server uses a **PowerShell RunspacePool** for request processing.

### 4.1 Worker Processing Flow

1. The main thread initializes a `[System.Net.HttpListener]` on the configured URI prefix.
2. An asynchronous RunspacePool (`MaxThreads`, configurable 4–16) is created once at startup. Shared objects — the synchronized failure tracker and a log-writer lock object — are injected into each runspace via the pool's `InitialSessionState`/shared variables.
3. Each accepted `HttpListenerContext` (obtained via `GetContext()` in a loop, or `GetContextAsync()`) is dispatched to an available worker runspace.
4. The worker: reads headers → applies lockout check → validates auth → validates path boundary → reads the file with retry → writes the response → closes the context in a `finally`. Any unhandled worker exception is logged and results in `500` (never a stack trace in the response body).

### 4.2 Shared-State Thread Safety

Because workers run concurrently, all shared mutable state must be synchronized:

- **Failure tracker:** `[hashtable]::Synchronized(@{})`; reads/writes of a given IP's record are guarded so increment-and-check is atomic.
- **Log sink:** a single shared `[object]` lock; every log write takes the lock around the file append so lines from different workers never interleave or race (§7.4).

### 4.3 Shared File Access Implementation

To coexist with background writers without `IOException`:

```powershell
function Get-XmlStreamWithRetry {
    param (
        [string]$Path,
        [int]$MaxRetries = 3,
        [int]$DelayMs = 50
    )

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            return [System.IO.FileStream]::new(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)   # coexist with external writers
        }
        catch [System.IO.IOException] {
            $attempt++
            if ($attempt -ge $MaxRetries) { throw $_ }
            [System.Threading.Thread]::Sleep($DelayMs * $attempt)   # linear backoff
        }
    }
}
```

On exhausting retries the worker returns `503 Service Unavailable`. For the low-scale / small-file profile, the worker reads the stream fully and writes it to the response output with `Content-Length` set; no chunked-transfer machinery is required.

### 4.4 Graceful Shutdown

NSSM signals process stop. The main loop must run under a `try/finally` that, on stop/exception, calls `HttpListener.Stop()` then `HttpListener.Close()`, closes the RunspacePool (allowing in-flight workers to complete), and flushes/closes the log. This ensures the SSL binding and port are released cleanly and no partial responses are left open.

---

## 5. API Interface Specification

### Base URI

`https://<hostname>:<port>/api/v1`

### 5.1 `GET /api/v1/files/{*filepath}`

Streams the raw XML document at the requested path.

- **Request headers:** `Authorization: Basic <credentials>` (required).
- **Response headers (200):** `Content-Type: application/xml; charset=utf-8`, `Last-Modified: <RFC 1123>`, `Cache-Control: no-cache`, `Content-Length`.
- **Response status codes:**

| Status | Meaning | Condition |
| --- | --- | --- |
| `200 OK` | Resource found | The `.xml` file was safely opened and streamed. |
| `401 Unauthorized` | Auth failure | Missing/malformed/invalid credentials. Includes `WWW-Authenticate`. |
| `404 Not Found` | Not found | File missing, is a directory, non-`.xml`, or failed traversal assertion (indistinguishable; empty body). |
| `405 Method Not Allowed` | Invalid verb | Verb other than `GET`. |
| `429 Too Many Requests` | Rate limited | IP temporarily locked after excessive failed logins. Includes `Retry-After`. |
| `503 Service Unavailable` | File lock timeout | External process locked the file beyond all retries. |
| `500 Internal Server Error` | Unexpected fault | Unhandled worker error (logged; empty body, no stack trace). |

### 5.2 `GET /api/v1/health`

Unauthenticated liveness probe. Always `200 OK`, body `{"status":"ok"}`, `Content-Type: application/json; charset=utf-8`. No file-system access.

---

## 6. Configuration Specification

Settings live in `config.json` alongside the script root. On startup the schema is validated and the service fails fast with a clear log message if required keys are missing or malformed (§7.5).

```json
{
  "Server": {
    "Port": 8443,
    "MaxThreads": 8,
    "UrlPrefix": "https://+:8443/api/v1/"
  },
  "Storage": {
    "RootDirectory": "C:\\Data\\XML_Repository",
    "FileReadRetryCount": 3,
    "FileReadRetryDelayMs": 50
  },
  "Security": {
    "Username": "service_consumer",
    "PasswordSaltBase64": "vF8xQz9zVw...==",
    "PasswordHashBase64": "hK9pLm7xYz...==",
    "Pbkdf2Iterations": 100000,
    "MaxAuthFailures": 5,
    "LockoutMinutes": 15
  },
  "Logging": {
    "LogDirectory": "C:\\Logs\\XmlDistService",
    "RetainDays": 14
  }
}
```

- `MaxThreads` is clamped to the range 4–16.
- `UrlPrefix` must match the `netsh` URL reservation and SSL binding (§7.1). It covers both `/files/` and `/health` under `/api/v1/`.

---

## 7. Operational & Deployment Architecture

```
C:\Services\XmlFileService\
├── config.json              # Runtime configuration
├── server.ps1               # Main entrypoint, config validation, Runspace listener, shutdown
├── New-PasswordHash.ps1     # CLI utility to generate salt+hash for a new password
├── modules\
│   ├── Authentication.psm1  # PBKDF2 derivation + constant-time verification
│   ├── PathSecurity.psm1     # Canonical traversal verification (Test-SafePath)
│   └── Logging.psm1          # Thread-safe rotating log sink + retention purge
└── logs\                     # Daily rotating log files
```

### 7.1 Windows OS Prerequisites (one-time provisioning, admin)

Because `HttpListener` runs on the `HTTP.sys` kernel driver, two one-time steps are required.

1. **URL reservation** — delegate to the service account:
   ```cmd
   netsh http add urlacl url=https://+:8443/api/v1/ user="NT AUTHORITY\SYSTEM"
   ```
2. **TLS certificate binding** — bind the **customer-provided** certificate's thumbprint to the port:
   ```cmd
   netsh http add sslcert ipport=0.0.0.0:8443 certhash=YOUR_THUMBPRINT_HERE appid={a1b2c3d4-e5f6-7890-abcd-1234567890ab}
   ```

**Certificate notes.** Any certificate works with HTTP.sys regardless of issuer (including Let's Encrypt), provided the certificate **with its private key** is installed in the `LocalMachine\My` store and bound by thumbprint. The certificate is **customer-provided and customer-managed**; issuance/renewal/PKI is out of scope for this application. If the customer uses a short-lived certificate (e.g., Let's Encrypt, 90-day), note that **renewal changes the thumbprint, so the `netsh http add sslcert` binding must be re-applied on each renewal** — typically automated by the customer's ACME client (win-acme/Certify). The application only requires that a valid binding exists on its port at startup.

### 7.2 CLI Utility: Credential Management

`New-PasswordHash.ps1` generates a salt + PBKDF2 hash for operators to paste into `config.json`; plaintext is never persisted. It must use the explicit-SHA256 constructor:

```powershell
param([Parameter(Mandatory)][string]$PlainPassword, [int]$Iterations = 100000)

$saltBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltBytes)

$pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
    $PlainPassword,
    $saltBytes,
    $Iterations,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256)   # explicit SHA256 — do NOT use the legacy overload
$hashBytes = $pbkdf2.GetBytes(32)

Write-Host "PasswordSaltBase64:" ([Convert]::ToBase64String($saltBytes))
Write-Host "PasswordHashBase64:" ([Convert]::ToBase64String($hashBytes))
Write-Host "Pbkdf2Iterations:  " $Iterations
```

### 7.3 Windows Service Installation (NSSM)

PowerShell cannot act directly as a managed Windows Service without a host to handle SCM signals. Deploy via **NSSM**:

```cmd
nssm.exe install XmlDistributionService "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
nssm.exe set XmlDistributionService AppParameters "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Services\XmlFileService\server.ps1"
nssm.exe set XmlDistributionService AppDirectory "C:\Services\XmlFileService"
nssm.exe set XmlDistributionService Start SERVICE_AUTO_START

:: Process recovery
nssm.exe set XmlDistributionService AppExit Default Restart
nssm.exe set XmlDistributionService AppRestartDelay 5000

nssm.exe start XmlDistributionService
```

The service account must match the `urlacl` reservation (§7.1) and have read access to `RootDirectory` and write access to `LogDirectory`.

### 7.4 Logging & Audit Trail

- Logs append to `C:\Logs\XmlDistService\audit_YYYY-MM-DD.log`; a new file is used per calendar day (UTC).
- Every write is guarded by the shared log lock (§4.2) so concurrent workers do not interleave lines.
- Each access record captures: ISO-8601 UTC timestamp · client IP · requested relative path · HTTP status code · response time (ms) · exception message (for `503` sharing violations, `500` faults, or boundary rejections, logged with the *real* reason even though the client receives a unified `404`).

### 7.5 Startup Self-Checks

On launch, `server.ps1` must, in order, and abort with a clear fatal log entry on failure:

1. Load and schema-validate `config.json` (required keys present, types correct, `MaxThreads` in range, Base64 fields decodable).
2. Confirm `RootDirectory` exists and is a directory.
3. Confirm `LogDirectory` exists or can be created.
4. Verify an SSL certificate binding exists for the configured port (`netsh http show sslcert ipport=0.0.0.0:<port>`); if absent, log a prominent warning — the listener will otherwise fail on first HTTPS request.
5. On each startup (and once per day thereafter), purge log files older than `RetainDays`.

---

## 8. Open Items / Operator Responsibilities

- **Certificate lifecycle** (issuance, renewal, re-binding) is owned by the customer/operator (§7.1).
- **Network-level IP allowlisting** is enforced in Windows Firewall; the application does not duplicate it.
- **Brute-force state** is in-memory and resets on restart by design.
- **Secrets in `config.json`** are limited to the PBKDF2 salt+hash (not reversible to plaintext); the file should still be ACL-restricted to the service account and administrators.
