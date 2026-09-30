# Threat Model — World Monitor Security Assessment

## Assets Under Assessment

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| User Authentication Sessions | Bearer tokens, cookies, OAuth grants | Critical |
| User Credentials | Password hashes, salts, MFA recovery codes | Critical |
| Classified Intelligence Reports | TOP_SECRET orbital/surveillance data | Critical |
| Satellite Uplink API Keys | Keys for satellite data ingestion | Critical |
| Internal Network Topology | Gateway URLs, internal IP addresses | High |
| Telemetry Data | Ground station coordinates, satellite signals | High |
| System Logs | Debug logs containing tokens | High |
| User Profiles | PII, emails, roles | Medium |
| Application Config | Version info, feature flags | Low |

## Threat Actors

### 1. Unauthenticated Internet Attacker
- **Capability**: Can issue HTTP requests to public endpoints
- **Motivation**: Obtain credentials, API keys, or intelligence data
- **Attack Surface**: Login endpoint, config endpoint, telemetry endpoint

### 2. Low-Privilege Authenticated User (Viewer/Analyst)
- **Capability**: Valid session token, access to viewer-level features
- **Motivation**: Escalate privilege, access classified reports
- **Attack Surface**: Report endpoints, admin export, profile API

### 3. Malicious Data/Feed Provider
- **Capability**: Controls RSS/news content ingested by the system
- **Motivation**: Inject XSS payloads, content injection
- **Attack Surface**: Feed rendering, report notes field

### 4. Insider Threat / Rogue Employee
- **Capability**: Valid admin credentials or direct DB access
- **Motivation**: Steal classified intelligence, sell credentials
- **Attack Surface**: Logs, database, export functions

### 5. Attacker with Network Interception
- **Capability**: Man-in-the-middle capability on a network segment
- **Motivation**: Intercept tokens, downgrade TLS
- **Attack Surface**: Missing HSTS, missing security headers

## STRIDE Threat Analysis

| Component | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|-----------|----------|-----------|-------------|-----------------|-----|-----------|
| Auth Middleware | ⚠️ HIGH (forged tokens) | - | - | - | - | ⚠️ HIGH |
| Reports API | - | ⚠️ MED (XSS in notes) | - | ⚠️ HIGH (IDOR) | - | ⚠️ HIGH (BFLA) |
| User Profile API | - | - | - | ⚠️ HIGH (hash leak) | - | - |
| Login Endpoint | - | - | - | - | ⚠️ MED (brute force) | - |
| Config Endpoint | - | - | - | ⚠️ HIGH (key leak) | - | - |
| System Logs | - | - | ⚠️ MED | ⚠️ MED (tokens) | - | - |
| HTTP Transport | - | ⚠️ MED (MITM) | - | - | - | - |

## Security Goals Assessment

| Goal | Status | Notes |
|------|--------|-------|
| Confidentiality | ❌ FAILED | SQLi, IDOR, key leak, excessive data exposure |
| Integrity | ❌ FAILED | Stored XSS, SQLi allows data manipulation |
| Availability | ⚠️ DEGRADED | No rate limiting on login (brute force risk) |
| Authentication | ❌ FAILED | Forged token bypass allows unauthenticated admin access |
| Authorization | ❌ FAILED | BOLA and BFLA confirmed |
| Accountability | ⚠️ DEGRADED | Logs exist but contain cleartext tokens |
| Privacy | ❌ FAILED | Password hashes, recovery codes, and IPs leaked |

## Attack Trees

### Attack Tree 1: Unauthorized Access to Classified Reports
```
Root: Read RESTRICTED_TOP_SECRET report
├── Path A: Auth bypass via forged token (FINDING-AUTH-001)
│   └── GET /api/reports/3 with forged admin token
├── Path B: IDOR as viewer (FINDING-AUTHZ-001)
│   └── GET /api/reports/3 with viewer token
└── Path C: SQL injection to dump all reports (FINDING-INP-001)
    └── GET /api/reports?search=' UNION SELECT ...
```

### Attack Tree 2: Account Credential Compromise
```
Root: Obtain valid admin credentials
├── Path A: Brute force login (FINDING-API-002)
│   └── No rate limit → dictionary attack against /api/auth/login
├── Path B: Harvest password hash from profile API (FINDING-API-001)
│   └── GET /api/users/profile → offline crack SHA-256 hash
└── Path C: Read cleartext token from logs (FINDING-DATA-001)
    └── GET /api/admin/system-logs → token in plaintext
```
