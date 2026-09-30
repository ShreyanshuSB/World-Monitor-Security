# F-007 — Excessive Data Exposure in User Profile API

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 6.5
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

## Status
**Confirmed**

## Finding ID
`FINDING-API-001`

## Affected Component
`/api/users/profile` — `lab/app.py` lines 155–182

## Description

The user profile endpoint serializes the complete database ORM entity into the HTTP response, exposing fields that were never intended for client consumption: `password_hash`, `salt`, `recovery_codes`, and `internal_ip`.

**Vulnerable code:**
```python
# Lines 171–182 (VULNERABLE)
return {
    "password_hash": user.password_hash,   # SENSITIVE
    "salt": user.salt,                     # SENSITIVE
    "recovery_codes": user.recovery_codes, # SENSITIVE (MFA bypass)
    "internal_ip": user.internal_ip        # SENSITIVE (network recon)
}
```

## Impact

A viewer-tier user can:
1. Obtain their own password hash → offline brute-force attack
2. Extract MFA recovery codes → bypass two-factor authentication
3. Discover internal network addresses → facilitate lateral movement

## Remediation

Use strict Pydantic output schemas (Data Transfer Objects):
```python
class UserProfileResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

@app.get("/api/users/profile", response_model=UserProfileResponse)
def get_user_profile(user: User = Depends(require_auth)):
    return user  # Pydantic schema strips all unlisted fields
```

## References
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP API3:2023 – Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
