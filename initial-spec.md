# Software Requirements & Technical Specification: PowerShell XML Distribution API

## 1. System Overview

The system is a headless, script-based Windows service implemented in PowerShell that exposes a local directory structure containing XML files over a secure, read-only REST API. Leveraging the underlying Windows `.NET` runtime (`System.Net.HttpListener` and `System.IO`), the application provides instant deployment without compilation, dynamic file-system mapping, authenticated access, and concurrency safeguards against active disk writes.

```
[ External Client ]
        │  (HTTPS / Basic Auth)
        ▼
[ Windows Firewall ] ─── (IP Whitelist Filter - External)
        │
        ▼
[ HTTP.sys Kernel Driver ] ─── (TLS Termination & Port Binding)
        │
        ▼
[ PowerShell Host Process ]
        ├── Auth Module (PBKDF2-SHA256 Verification)
        ├── Path Normalizer & Boundary Guard
        ├── Runspace Pool (Concurrent Worker Threads)
        └── File Delivery Engine ([System.IO.FileShare]::ReadWrite)
                │
                ▼
        [ Local Storage: C:\Data\XML_Root\... ]

```

---

## 2. Functional Requirements

### 2.1 File Retrieval & Path Resolution

* **Recursive Path Mapping:** Incoming request URIs map directly to the folder hierarchy relative to the configured root folder.
* Example: `GET /api/v1/files/finance/2026/report.xml` $\rightarrow$ `C:\Data\XML_Root\finance\2026\report.xml`.


* **Zero-Latency Invalidation (Live Disk Access):** The application must not cache file payloads in memory. Every incoming request reads directly from disk to guarantee:
* Updates made to XML files every 5 minutes are served immediately.
* Daily or weekly additions or removals of subfolders and files take effect without restarting the script.


* **HTTP Verb Restriction:** Only the `GET` verb is permitted. Any request using `POST`, `PUT`, `DELETE`, `PATCH`, or `OPTIONS` must be rejected immediately with `405 Method Not Allowed`.
* **MIME Configuration:** Valid XML files must be delivered with `Content-Type: application/xml; charset=utf-8`.

### 2.2 Directory Enumeration

* Requests targeting directories rather than files (e.g., `GET /api/v1/files/finance/`) must return `404 Not Found` by default to prevent attackers from mapping the folder structure.

---

## 3. Security & Integrity Specification

Given operational constraints (no multi-factor authentication, no data-at-rest encryption), defensive controls focus on transport security, traversal prevention, credential derivation, and memory-safe shared reads.

| Threat Category | Attack Vector | PowerShell / Windows Mitigation Strategy |
| --- | --- | --- |
| **Directory Traversal** | `../`, encoded characters (`%2e%2e`), null bytes (`%00`), NTFS streams (`::$DATA`). | Sanitize input strings, then resolve fully qualified paths via `[System.IO.Path]::GetFullPath()`. Assert string prefix match against the canonical root directory. |
| **Credential Interception** | Network eavesdropping on HTTP Basic Auth credentials. | Mandatory HTTPS. Bind an SSL/TLS certificate to the endpoint via `HTTP.sys` (`netsh http add sslcert`). |
| **Credential Theft from Disk** | Plaintext password extraction from configuration files. | Store passwords using a salted **PBKDF2-SHA256** cryptographic hash via `System.Security.Cryptography.Rfc2898DeriveBytes`. |
| **Brute Force Attacks** | Continuous dictionary attempts on Basic Auth. | In-memory hashtable tracking failed attempts per IP address, enforcing temporary lockouts. |
| **Sharing Violations (`IOException`)** | Third-party background processes writing or swapping XML files every 5 minutes. | Open files using `[System.IO.FileShare]::ReadWrite` and execute up to 3 retries with exponential backoff before failing. |

### 3.1 Path Traversal Verification Algorithm

All requested subpaths must pass the following verification pipeline before touching the file system:

```powershell
function Test-SafePath {
    param (
        [string]$RootDirectory,
        [string]$RequestedSubPath
    )

    # 1. Deny null bytes, NTFS alternative streams, or literal back-references
    if ($RequestedSubPath -match '[\0:]' -or $RequestedSubPath.Contains("..")) {
        return $null
    }

    # 2. Normalize and resolve paths
    $canonicalRoot = [System.IO.Path]::GetFullPath($RootDirectory).TrimEnd('\', '/')
    $combinedPath  = [System.IO.Path]::Combine($canonicalRoot, $RequestedSubPath.TrimStart('\', '/'))
    $canonicalTarget = [System.IO.Path]::GetFullPath($combinedPath)

    # 3. Boundary guard: target must strictly reside within root directory
    $expectedPrefix = $canonicalRoot + [System.IO.Path]::DirectorySeparatorChar
    if ($canonicalTarget.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and 
        [System.IO.File]::Exists($canonicalTarget)) {
        return $canonicalTarget
    }

    return $null
}

```

### 3.2 Authentication & Cryptographic Standards

* **Scheme:** HTTP Basic Authentication (`Authorization: Basic <base64-encoded-user:pass>`).
* **Password Storage:** The configuration file stores a 32-byte salt (Base64) and a 32-byte PBKDF2 derived key (Base64) calculated with $\ge 100,000$ iterations of HMAC-SHA256. Plaintext passwords must never appear in configuration files.

---

## 4. Concurrency & Non-Blocking Architecture

PowerShell execution in a single thread creates a bottleneck where one long-running download blocks all other requests. The server architecture must implement a multi-threaded request processing loop using a **PowerShell RunspacePool**.

### 4.1 Worker Processing Flow

1. The main listener thread initializes a `[System.Net.HttpListener]` listening on the designated URI prefix.
2. An asynchronous RunspacePool (configurable from 4 to 16 threads) is established.
3. Upon receiving an HTTP connection via `GetContextAsync()`, the context is dispatched into an available worker Runspace.
4. The worker extracts headers, validates authentication, checks the path boundary, reads the file stream, flushes the output, and closes the context cleanly.

### 4.2 Shared File Access Implementation

To handle background updates occurring every 5 minutes without throwing file-in-use exceptions (`HRESULT 0x80070020`):

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
            # Open with ReadWrite sharing to coexist with external writers
            $stream = [System.IO.FileStream]::new(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )
            return $stream
        }
        catch [System.IO.IOException] {
            $attempt++
            if ($attempt -ge $MaxRetries) { throw $_ }
            [System.Threading.Thread]::Sleep($DelayMs * $attempt)
        }
    }
}

```

---

## 5. API Interface Specification

### Base URI

`https://<hostname>:<port>/api/v1`

### Endpoints

#### `GET /api/v1/files/{*filepath}`

Streams the raw XML document located at the requested path.

* **Headers:**
* `Authorization: Basic <credentials>` (Required)


* **Response Headers:**
* `Content-Type: application/xml; charset=utf-8`
* `Last-Modified: <RFC 1123 Date>`
* `Cache-Control: no-cache`


* **Response Status Codes:**

| Status Code | Meaning | Condition |
| --- | --- | --- |
| `200 OK` | Resource found | The XML file was safely opened and streamed. |
| `401 Unauthorized` | Authentication failure | Missing, malformed, or invalid username/password. |
| `404 Not Found` | Target not found | File does not exist, is a directory, or failed traversal assertion. |
| `405 Method Not Allowed` | Invalid verb | Request used `POST`, `PUT`, `DELETE`, etc. |
| `429 Too Many Requests` | Rate limit enforced | IP temporarily blocked due to excessive failed logins. |
| `503 Service Unavailable` | File lock timeout | External process locked the file beyond all retry thresholds. |

---

## 6. Configuration Specification

Configuration settings must be maintained in a JSON format (`config.json`) alongside the script root.

```json
{
  "Server": {
    "Port": 8443,
    "MaxThreads": 8,
    "UrlPrefix": "https://+:8443/api/v1/files/"
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

---

## 7. Operational & Deployment Architecture

```
C:\Services\XmlFileService\
├── config.json              # Runtime configuration
├── server.ps1               # Main entrypoint and Runspace listener
├── New-PasswordHash.ps1     # CLI utility to generate new password credentials
├── modules\
│   ├── Authentication.psm1  # PBKDF2 password derivation and validation
│   ├── PathSecurity.psm1    # Canonical traversal verification
│   └── Logging.psm1         # Rotating log sink
└── logs\                    # Daily rotating log files

```

### 7.1 Windows OS Prerequisites

Because `[System.Net.HttpListener]` runs on top of the Windows kernel driver `HTTP.sys`, administrative setup is required once during provisioning:

1. **Port Reservation:** Delegate URL reservation to the running user account:
```cmd
netsh http add urlacl url=https://+:8443/api/v1/files/ user="NT AUTHORITY\SYSTEM"

```


2. **TLS Certificate Binding:** Bind an SSL certificate thumbprint to the application port:
```cmd
netsh http add sslcert ipport=0.0.0.0:8443 certhash=YOUR_THUMBPRINT_HERE appid={a1b2c3d4-e5f6-7890-abcd-1234567890ab}

```



### 7.2 CLI Utility: Credential Management

A dedicated CLI tool (`New-PasswordHash.ps1`) updates credentials without storing plaintext:

```powershell
param([string]$PlainPassword)

$saltBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltBytes)

$pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
    $PlainPassword,
    $saltBytes,
    100000,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256
)
$hashBytes = $pbkdf2.GetBytes(32)

Write-Host "Salt (Base64):" ([Convert]::ToBase64String($saltBytes))
Write-Host "Hash (Base64):" ([Convert]::ToBase64String($hashBytes))

```

### 7.3 Windows Service Installation (Using NSSM)

PowerShell cannot run directly as a managed Windows Service without a host process to handle Service Control Manager (SCM) stop/pause signals. Deploy using **NSSM** (Non-Sucking Service Manager):

```cmd
:: Install the service
nssm.exe install XmlDistributionService "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
nssm.exe set XmlDistributionService AppParameters "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Services\XmlFileService\server.ps1"
nssm.exe set XmlDistributionService AppDirectory "C:\Services\XmlFileService"
nssm.exe set XmlDistributionService Start SERVICE_AUTO_START

:: Configure process recovery
nssm.exe set XmlDistributionService AppExit Default Restart
nssm.exe set XmlDistributionService AppRestartDelay 5000

:: Start service
nssm.exe start XmlDistributionService

```

### 7.4 Logging & Audit Trail

* Logs are appended to `C:\Logs\XmlDistService\audit_YYYY-MM-DD.log`.
* Every access record captures:
* Timestamp (ISO 8601 UTC)
* Client IP Address
* Requested relative path
* HTTP Status Code
* Response time (ms)
* Exception message (for `503` sharing violations or `404` boundary rejections)