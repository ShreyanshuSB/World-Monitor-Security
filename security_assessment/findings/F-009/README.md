# F-009 — Cleartext Authentication Tokens in Persistent System Logs

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
`/api/admin/system-logs` & Logging Pipeline — `lab/seed.py`

## Description

The system diagnostic log contains the active administrator bearer token `wm_sec_token_adm_9941` stored verbatim in the `message` and `context` fields of the `system_logs` table. Any party with read access to this endpoint (admin users, log aggregation systems, SIEM exporters, cloud storage buckets, or CI/CD log collectors) can extract a live, valid authentication token.

**Live Evidence from `/api/admin/system-logs`:**
```json
{
  "level": "DEBUG",
  "message": "User authentication successful for admin. Assigned session token wm_sec_token_adm_9941.",
  "context": "auth_token=wm_sec_token_adm_9941; cleartext_token=wm_sec_token_adm_9941",
  "timestamp": "2026-09-28T09:45:54"
}
```

## Root Cause

The logging statement in the authentication handler uses Python's default string formatting, embedding the token value directly into the log message. No scrubbing or redaction is applied before writing to the database.

## Impact

| Dimension | Detail |
|-----------|--------|
| Confidentiality | HIGH — Live admin token extracted from logs → full admin session hijack |
| Integrity | None |
| Availability | None |

## Remediation

```python
import re

TOKEN_PATTERN = re.compile(r'wm_sec_token_\w+')

def redact_sensitive(text: str) -> str:
    return TOKEN_PATTERN.sub('[TOKEN_REDACTED]', text)

# Apply before every log write
db_log = SystemLog(
    message=redact_sensitive(message),
    context=redact_sensitive(context)
)
```

## Regression Test

```python
def test_tokens_not_in_logs():
    resp = httpx.get("http://127.0.0.1:8001/api/admin/system-logs",
                     headers={"Authorization": "Bearer wm_sec_token_adm_9941"})
    log_text = resp.text
    assert "wm_sec_token_" not in log_text, "Active token found in log output"
```

## References
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
