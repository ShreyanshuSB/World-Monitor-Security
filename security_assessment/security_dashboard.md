# Security Dashboard — World Monitor Assessment
## Assessment ID: ASM-C2DE5856 | Date: 2026-09-28

---

## Overall Security Posture

```
RISK SCORE: 98 / 100   [CRITICAL]
████████████████████████████████████████ 98%
```

> Assessment determined the application's current security posture to be **CRITICAL**.
> Fundamental security controls across authentication, authorization, and input validation are absent or bypassed.

---

## Assessment Statistics

| Metric | Value |
|--------|-------|
| Total Tests Executed | 22 |
| Tests Passed | 5 |
| Tests Failed | 14 |
| Informational | 3 |
| Total Confirmed Vulnerabilities | 9 |
| Assessment Run Duration | ~15 seconds |
| Modules Scanned | 7 |
| Lab Target | http://127.0.0.1:8001 |

---

## Vulnerability Summary

| ID | Finding | Severity | CVSS | Affected Component | Exploitable | Fixed |
|----|---------|----------|------|-------------------|-------------|-------|
| F-001 | Weak Token Auth Bypass | **CRITICAL** | 9.1 | Auth Middleware | ✅ Yes | ❌ No |
| F-002 | SQL Injection — Search | **CRITICAL** | 9.8 | /api/reports?search | ✅ Yes | ❌ No |
| F-003 | Hardcoded API Secrets | **HIGH** | 8.2 | /api/config/client | ✅ Yes | ❌ No |
| F-004 | IDOR — Classified Reports | **MEDIUM** | 6.5 | /api/reports/{id} | ✅ Yes | ❌ No |
| F-005 | BFLA — Admin Export | **MEDIUM** | 6.5 | /api/admin/telemetry-export | ✅ Yes | ❌ No |
| F-006 | Stored XSS — Report Notes | **MEDIUM** | 5.4 | /api/reports/{id}/notes | ✅ Yes | ❌ No |
| F-007 | Excessive Data Exposure | **MEDIUM** | 6.5 | /api/users/profile | ✅ Yes | ❌ No |
| F-008 | No Rate Limiting on Login | **MEDIUM** | 5.3 | /api/auth/login | ✅ Yes | ❌ No |
| F-009 | Missing Security Headers | **MEDIUM** | 5.4 | Global Middleware | ✅ Yes | ❌ No |
| F-010 | Cleartext Tokens in Logs | **MEDIUM** | 4.9 | Logging Pipeline | ✅ Yes | ❌ No |

---

## Severity Distribution

```
CRITICAL  ██████  2 findings  (22%)
HIGH      ███     1 finding   (11%)
MEDIUM    ████████████████  7 findings  (78%)
LOW       0
INFO      0
```

---

## OWASP Top 10 Coverage

| OWASP Category | Findings | Status |
|----------------|----------|--------|
| A01:2021 – Broken Access Control | F-004, F-005 | ❌ FAIL |
| A03:2021 – Injection | F-002, F-006 | ❌ FAIL |
| A04:2021 – Insecure Design | F-003, F-007 | ❌ FAIL |
| A05:2021 – Security Misconfiguration | F-009 | ❌ FAIL |
| A07:2021 – Auth Failures | F-001, F-008 | ❌ FAIL |
| A09:2021 – Logging Failures | F-010 | ❌ FAIL |
| A02, A06, A08, A10 | — | ✅ PASS (not confirmed) |

---

## Security Domain Coverage

| Domain | Status | Max CVSS | Findings |
|--------|--------|----------|----------|
| Authentication & Session Management | ❌ CRITICAL | 9.1 | F-001 |
| Authorization & Access Control | ❌ CRITICAL | 6.5 | F-004, F-005 |
| Input Validation & Data Handling | ❌ CRITICAL | 9.8 | F-002, F-006 |
| API Security | ❌ HIGH | 6.5 | F-007, F-008 |
| Client-Side Controls | ❌ HIGH | 8.2 | F-003 |
| Secure Communication | ❌ MEDIUM | 5.4 | F-009 |
| Data Storage & Privacy | ❌ MEDIUM | 4.9 | F-010 |

---

## Scope Guard Compliance

- ✅ All probes restricted to `http://127.0.0.1:8001`
- ✅ No external traffic generated
- ✅ Authorization gate acknowledged before probes
- ✅ All 7 audit log entries confirm authorized operation
- ✅ No production data modified or extracted

---

## Quick Links

- [Architecture](architecture.md)
- [Threat Model](threat_model.md)
- [Test Matrix](test_matrix.md)
- [F-001 Auth Bypass](findings/F-001/README.md)
- [F-002 SQL Injection](findings/F-002/README.md)
- [F-003 Secret Leak](findings/F-003/README.md)
- [Executive Summary](executive_summary.md)
- [Full Report](final_report.md)
