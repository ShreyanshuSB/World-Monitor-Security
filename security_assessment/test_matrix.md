# Security Test Matrix — World Monitor Assessment
## Assessment ID: ASM-C2DE5856 | Date: 2026-09-28

| ID | Category | Test Description | Expected | Actual | Result | Finding ID | Evidence |
|----|----------|-----------------|----------|--------|--------|------------|----------|
| T-001 | AUTH | Forged admin token acceptance test | HTTP 401/403 | HTTP 200 (admin profile returned) | ❌ FAIL | FINDING-AUTH-001 | evidence/auth_bypass.json |
| T-002 | AUTH | Valid token authentication | HTTP 200 | HTTP 200 | ✅ PASS | - | - |
| T-003 | AUTH | Expired/invalid token rejection | HTTP 401 | HTTP 401 | ✅ PASS | - | - |
| T-004 | SESSION | Session fixation test | New session on login | N/A (static tokens) | ⚠️ INFO | - | - |
| T-005 | AUTHZ | Viewer accesses TOP_SECRET report (IDOR) | HTTP 403 | HTTP 200 (classified data returned) | ❌ FAIL | FINDING-AUTHZ-001 | evidence/idor_report.json |
| T-006 | AUTHZ | Viewer invokes admin export function (BFLA) | HTTP 403 | HTTP 200 (full telemetry dump) | ❌ FAIL | FINDING-AUTHZ-002 | evidence/bfla_export.json |
| T-007 | AUTHZ | Admin accesses admin functions | HTTP 200 | HTTP 200 | ✅ PASS | - | - |
| T-008 | API | Profile endpoint returns minimal fields only | Only public fields | password_hash, salt, recovery_codes, internal_ip leaked | ❌ FAIL | FINDING-API-001 | evidence/excessive_data.json |
| T-009 | API | Rate limiting on login endpoint | HTTP 429 after 5 fails | Never returned 429 across 6 attempts | ❌ FAIL | FINDING-API-002 | evidence/no_rate_limit.json |
| T-010 | INPUT | SQL injection via search parameter | Parameterized query / sanitized | UNION SELECT returns unauthorized data | ❌ FAIL | FINDING-INP-001 | evidence/sqli.json |
| T-011 | INPUT | Stored XSS via report notes | HTML-encoded output | Raw HTML/JS payload stored and returned | ❌ FAIL | FINDING-INP-002 | evidence/stored_xss.json |
| T-012 | INPUT | Normal report search (safe input) | Correct results | Correct results | ✅ PASS | - | - |
| T-013 | CLIENT | Client config exposes secrets | Only public config | SATELLITE_UPLINK_KEY, INTERNAL_GATEWAY_URL, DEBUG_SECRET_TOKEN returned | ❌ FAIL | FINDING-CLI-001 | evidence/key_leak.json |
| T-014 | SECRET | Secrets in Git history | No secrets | N/A (lab env, not scanned) | ⚠️ INFO | - | - |
| T-015 | CSP | Content-Security-Policy header present | CSP header present | Missing | ❌ FAIL | FINDING-COMM-001 | evidence/headers.json |
| T-016 | CSP | X-Frame-Options header present | Present | Missing | ❌ FAIL | FINDING-COMM-001 | evidence/headers.json |
| T-017 | CSP | X-Content-Type-Options present | nosniff | Missing | ❌ FAIL | FINDING-COMM-001 | evidence/headers.json |
| T-018 | CSP | HSTS header present | Present | Missing | ❌ FAIL | FINDING-COMM-001 | evidence/headers.json |
| T-019 | STORAGE | Tokens stored in cleartext in DB logs | Tokens redacted/masked | Active token wm_sec_token_adm_9941 in plaintext | ❌ FAIL | FINDING-DATA-001 | evidence/cleartext_logs.json |
| T-020 | PRIVACY | PII stored securely | Encrypted/hashed | Salted SHA-256 (acceptable) but leaked in API | ❌ FAIL | FINDING-API-001 | evidence/excessive_data.json |
| T-021 | CORS | CORS policy restricted | Specific origins | allow_origins=["*"] | ⚠️ INFO | - | - |
| T-022 | SSRF | Server-side proxy URL validation | Strict allowlist | N/A (Scope Guard handles this in platform) | ✅ PASS | - | - |

## Summary

| Category | Tests | Pass | Fail | Info |
|----------|-------|------|------|------|
| AUTH | 3 | 2 | 1 | 0 |
| SESSION | 1 | 0 | 0 | 1 |
| AUTHZ | 3 | 1 | 2 | 0 |
| API | 2 | 0 | 2 | 0 |
| INPUT | 3 | 1 | 2 | 0 |
| CLIENT | 1 | 0 | 1 | 0 |
| SECRET | 1 | 0 | 0 | 1 |
| CSP | 4 | 0 | 4 | 0 |
| STORAGE | 1 | 0 | 1 | 0 |
| PRIVACY | 1 | 0 | 1 | 0 |
| CORS | 1 | 0 | 0 | 1 |
| SSRF | 1 | 1 | 0 | 0 |
| **TOTAL** | **22** | **5** | **14** | **3** |
