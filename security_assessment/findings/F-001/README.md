# F-001 — Cryptographically Weak Token Verification Permitting Authentication Bypass

## Severity
**CRITICAL**

## CVSS v3.1
- **Score:** 9.1
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **Metric Reasoning:**
  - **AV:N** — Exploitable over the network (no physical access required)
  - **AC:L** — No special preconditions, trivially reproducible
  - **PR:N** — No privileges required; unauthenticated attacker can exploit
  - **UI:N** — No user interaction needed
  - **S:U** — Scope unchanged (impact confined to the vulnerable component)
  - **C:H** — Complete confidentiality loss (admin profile, hashes, tokens)
  - **I:H** — Complete integrity loss (attacker gains admin write capability)
  - **A:N** — No availability impact directly from this vector

## Status
**Confirmed — Independently Reproduced**

## Finding ID
`FINDING-AUTH-001`  
Assessment: `ASM-C2DE5856`

## Affected Component
- **File:** `lab/app.py` — `get_current_user()` function (lines 73–86)
- **Endpoint:** `GET /api/users/profile` (and all authenticated endpoints)

---

## Description

The authentication middleware in the World Monitor API accepts tokens matching a hardcoded prefix pattern (`wm_forged_admin_`) as valid administrative credentials without any cryptographic signature verification. This design constitutes a backdoor that permits any unauthenticated attacker who knows the token prefix to gain complete administrative access to the system.

The vulnerability exists in the token validation fallback path:

```python
# lab/app.py — Lines 82–85 (VULNERABLE)
if not vuln_config.is_fixed("AUTH_WEAK_SECRET"):
    # Accepts ANY token prefixed "wm_forged_admin_" as admin
    if token.startswith("wm_forged_admin_"):
        return db.query(User).filter(User.role == "admin").first()
```

## Root Cause

The authentication service was implemented with a hardcoded "backdoor" fallback token pattern. Instead of validating tokens against a cryptographic signature (e.g., HMAC-SHA256 or EdDSA/RS256 JWT), it performs a simple string prefix check. Any value starting with `wm_forged_admin_` — regardless of cryptographic origin — is unconditionally accepted as a valid admin session.

Secondary cause: Session tokens are stored as static strings in the database rather than being generated as short-lived signed JWTs.

## Attack Preconditions

- **Network access** to the World Monitor API (HTTP/HTTPS)
- **Knowledge of the prefix pattern** `wm_forged_admin_` (discoverable via source code review, API error messages, or decompilation of bundled assets)
- No valid credentials, no OAuth, no MFA — zero authentication requirements

## Attack Flow

```
Attacker
  │
  ▼ HTTP GET /api/users/profile
  │   Authorization: Bearer wm_forged_admin_anyvalue
  ▼
Authentication Middleware (get_current_user)
  │  Token not found in DB → falls through to prefix check
  ▼
Backdoor Check: token.startswith("wm_forged_admin_")
  │  TRUE → Returns admin User object
  ▼
Security Boundary Crossed: Authentication
  │
  ▼ HTTP 200 OK — Full admin profile returned
    (password_hash, salt, recovery_codes, internal_ip, role: admin)
```

## Steps to Reproduce

1. Start the World Monitor Lab API at `http://127.0.0.1:8001`.
2. Issue the following HTTP request using any HTTP client:
   ```bash
   curl -s -H "Authorization: Bearer wm_forged_admin_test_signature" \
        http://127.0.0.1:8001/api/users/profile
   ```
3. Observe that the server returns **HTTP 200 OK** with the full administrative profile.

## Proof of Concept

```bash
# Safe PoC — Localhost only
curl -s -H "Authorization: Bearer wm_forged_admin_test_signature" \
     http://127.0.0.1:8001/api/users/profile
```

**Observed Response (redacted):**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@worldmonitor.local",
  "role": "admin",
  "password_hash": "<REDACTED_HASH>",
  "salt": "<REDACTED_SALT>",
  "recovery_codes": "<REDACTED_RECOVERY_CODES>",
  "internal_ip": "<REDACTED_IP>"
}
```

## Evidence

- **HTTP Evidence:** `evidence/auth_bypass.json`
- **Source Code Location:** `lab/app.py` lines 73–86
- **Assessment Finding:** `FINDING-AUTH-001` (status: VERIFIED)
- **CVSS Score Confirmed by Engine:** 9.1

## Security Impact

| Dimension | Impact |
|-----------|--------|
| Confidentiality | **COMPLETE** — Admin profile, password hashes, recovery codes, internal IPs disclosed |
| Integrity | **COMPLETE** — Attacker gains admin session; can modify all data |
| Availability | **None** — This vector alone does not impact availability |
| Authentication | **FAILED** — Core authentication mechanism is defeated |
| Authorization | **FAILED** — Attacker inherits highest privilege level |

## Business Impact

An unauthenticated attacker who discovers the token prefix pattern (trivial via source code or source map) can:

1. **Forge administrative sessions** indefinitely without requiring credentials
2. **Access classified intelligence reports** including TOP_SECRET orbital surveillance data
3. **Initiate bulk telemetry exports** of satellite ground station coordinates
4. **Modify or destroy intelligence data** using admin-level write access
5. **Extract password hashes** for offline cracking attacks against other systems

For a national-security intelligence platform (NTRO context), this constitutes a complete and unrecoverable authentication bypass.

## Remediation

### Immediate Fix

Replace the backdoor prefix check with proper HMAC-SHA256 JWT validation:

```python
# lab/app.py — REMEDIATED get_current_user()
import jwt, os

def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    try:
        payload = jwt.decode(
            token,
            os.environ["JWT_SECRET_KEY"],   # From secrets manager — never hardcoded
            algorithms=["HS256"]
        )
        user_id = payload.get("sub")
        return db.query(User).filter(User.id == int(user_id)).first()
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
```

### Long-term Architectural Fix

1. Migrate to short-lived JWTs (15-minute expiry) with refresh token rotation
2. Store `JWT_SECRET_KEY` in a Hardware Security Module or AWS Secrets Manager
3. Add token revocation list (Redis-backed) for immediate session invalidation
4. Remove all hardcoded/backdoor token patterns from codebase and history (`git-secrets` scan)

### Monitoring

- Alert on any authentication attempt using tokens not found in the database
- Log all admin session creations with source IP and geographic anomaly detection

## Regression Test

```python
def test_forged_token_rejected():
    """Verify that forged tokens are rejected after remediation."""
    resp = httpx.get(
        "http://127.0.0.1:8001/api/users/profile",
        headers={"Authorization": "Bearer wm_forged_admin_test_signature"}
    )
    assert resp.status_code == 401, "Forged admin token must be rejected"
```

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [RFC 7519 — JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc7519)
