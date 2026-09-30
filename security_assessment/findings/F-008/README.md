# F-008 — Absence of Rate Limiting on Authentication Endpoint (Brute-Force Exposure)

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 5.3
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Status
**Confirmed**

## Finding ID
`FINDING-API-002`

## Affected Component
`/api/auth/login` — `lab/app.py` lines 121–152

## Description

The primary login endpoint accepts unlimited authentication attempts without any rate limiting, IP throttling, or account lockout. Six rapid consecutive failed login attempts were submitted and all received HTTP 401 — no HTTP 429 was returned at any point.

**Evidence:**
```
Sent 6 rapid requests. Status codes: [401, 401, 401, 401, 401, 401]
No HTTP 429 received → brute force unrestricted
```

## Remediation

```python
# Token-bucket sliding window rate limiter
from collections import defaultdict
import time

login_attempts = defaultdict(list)

@app.post("/api/auth/login")
def login(creds: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host
    now = time.time()
    # Sliding window: max 5 attempts per 60 seconds
    attempts = [t for t in login_attempts[ip] if now - t < 60]
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in 60 seconds.")
    ...
    login_attempts[ip].append(now)
```

## References
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

# F-009 — Absence of Essential HTTP Security Headers

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 5.4
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

## Status
**Confirmed**

## Finding ID
`FINDING-COMM-001`

## Affected Component
Global HTTP Response Pipeline & Middleware — `lab/app.py` lines 44–62

## Missing Headers Confirmed

| Header | Purpose | Status |
|--------|---------|--------|
| `Strict-Transport-Security` | Prevents TLS downgrade attacks | ❌ MISSING |
| `X-Content-Type-Options` | Prevents MIME-sniffing | ❌ MISSING |
| `X-Frame-Options` | Prevents clickjacking | ❌ MISSING |
| `Content-Security-Policy` | Restricts resource loading, mitigates XSS | ❌ MISSING |

## Remediation

```python
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

---

# F-009b — Cleartext Authentication Tokens in Persistent System Logs

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 4.9
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`

## Status
**Confirmed**

## Finding ID
`FINDING-DATA-001`

## Affected Component
`/api/admin/system-logs` & Logging Pipeline — `lab/seed.py` lines 110–128

## Description

The system debug log contains the active administrator bearer token `wm_sec_token_adm_9941` in plaintext in the `message` and `context` fields. Any person with access to logs (log aggregation tools, SIEM, CI/CD build logs, S3 buckets) can extract a valid live session token.

**Evidence from live endpoint:**
```json
{
  "level": "DEBUG",
  "message": "User authentication successful for admin. Assigned session token wm_sec_token_adm_9941.",
  "context": "auth_token=wm_sec_token_adm_9941; cleartext_token=wm_sec_token_adm_9941"
}
```

## Remediation

```python
import re

def redact_tokens(text: str) -> str:
    """Redact bearer tokens and sensitive patterns from log strings."""
    return re.sub(r'wm_sec_token_\w+', 'wm_sec_token_[REDACTED]', text)

# Apply to all log writes and log export endpoints
```

## References
- [CWE-532: Sensitive Information in Log Files](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
