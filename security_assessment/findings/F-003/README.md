# F-003 — Hardcoded Production API Secrets in Client Configuration Endpoint

## Severity
**HIGH**

## CVSS v3.1
- **Score:** 8.2
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Metric Reasoning:**
  - **AV:N** — Network exploitable
  - **AC:L** — No special conditions; trivially exploitable
  - **PR:N** — No authentication required
  - **UI:N** — No user interaction required
  - **S:U** — Scope unchanged
  - **C:H** — Full secret key material exposed to any visitor
  - **I:L** — Low integrity impact (attacker can use keys to modify data externally)
  - **A:N** — No direct availability impact

## Status
**Confirmed — Independently Reproduced**

## Finding ID
`FINDING-CLI-001`  
Assessment: `ASM-C2DE5856`

## Affected Component
- **File:** `lab/app.py` — `get_client_config()` function (lines 332–351)
- **Endpoint:** `GET /api/config/client` (no authentication required)

---

## Description

The client configuration bootstrap endpoint (`/api/config/client`) is accessible by unauthenticated HTTP clients and returns hardcoded production-level sensitive credentials in plaintext JSON. The exposed secrets include:

- `SATELLITE_UPLINK_KEY` — A high-privilege API key for the satellite uplink ingestion gateway
- `INTERNAL_GATEWAY_URL` — The internal network URL of the uplink gateway, revealing internal network topology
- `DEBUG_SECRET_TOKEN` — A master bypass debug token

**Vulnerable code:**
```python
# lab/app.py — Lines 342–351 (VULNERABLE)
return {
    "appName": "World Monitor System",
    "SATELLITE_UPLINK_KEY": "sk_live_ntro_9921_classified",    # SECRET
    "INTERNAL_GATEWAY_URL": "http://gateway.internal.ntro.local:9000/uplink",  # SECRET
    "DEBUG_SECRET_TOKEN": "wm_debug_master_bypass_9812"        # SECRET
}
```

## Root Cause

The developer embedded production secrets directly in application code and returned them in the client bootstrap API response — presumably for frontend convenience. This is a violation of the principle of secret separation. Secrets must never be embedded in source code or served via public API endpoints.

## Attack Preconditions

- Network access to the API (no credentials needed)
- A single HTTP GET request

## Attack Flow

```
Attacker
  │
  ▼ GET /api/config/client (no auth header)
  │
get_client_config handler
  │  Returns full config including hardcoded secrets
  ▼
Security Boundary Crossed: Secret Storage / Client-Side Isolation
  │
  ▼ HTTP 200 OK — SATELLITE_UPLINK_KEY, INTERNAL_GATEWAY_URL,
                   DEBUG_SECRET_TOKEN returned in plaintext JSON
```

## Steps to Reproduce

```bash
curl -s http://127.0.0.1:8001/api/config/client
```

**Observed Response (redacted):**
```json
{
  "appName": "World Monitor System",
  "environment": "staging-restricted",
  "SATELLITE_UPLINK_KEY": "<REDACTED_API_KEY>",
  "INTERNAL_GATEWAY_URL": "<REDACTED_INTERNAL_URL>",
  "DEBUG_SECRET_TOKEN": "<REDACTED_DEBUG_TOKEN>"
}
```

## Evidence

- **Assessment Finding:** `FINDING-CLI-001` (status: VERIFIED, CVSS: 8.2)
- **Source Code:** `lab/app.py` lines 332–351
- **Live Response:** HTTP 200 with all three secrets confirmed present

## Security Impact

| Dimension | Impact |
|-----------|--------|
| Confidentiality | **COMPLETE** — Production API credentials exposed to any visitor |
| Integrity | **LOW** — Keys could be used to push malicious satellite data |
| Availability | **None** | 

## Business Impact

- **Satellite uplink compromise** — An attacker can forge satellite telemetry feeds by using the leaked uplink key, potentially injecting false intelligence data into the monitoring platform
- **Internal network discovery** — The gateway URL reveals internal network topology, facilitating further lateral movement attacks
- **Debug bypass exploitation** — The `DEBUG_SECRET_TOKEN` may allow bypassing other security controls if used elsewhere in the application

## Remediation

### Immediate Fix

```python
# lab/app.py — REMEDIATED get_client_config()
@app.get("/api/config/client")
def get_client_config():
    # ONLY return non-sensitive public configuration
    return {
        "appName": "World Monitor System",
        "environment": "production",
        "telemetryRefreshMs": 5000,
        "version": "2.4.1"
        # NO secrets, NO internal URLs, NO debug tokens
    }
```

### Long-term

1. Store all secrets in environment variables or secrets managers (AWS SSM, HashiCorp Vault)
2. Never pass secret keys to the frontend — proxy all authenticated API calls server-side
3. Implement secret scanning in CI/CD pipeline (`git-secrets`, `truffleHog`, `detect-secrets`)
4. Rotate all currently exposed credentials immediately

## Regression Test

```python
def test_client_config_no_secrets():
    resp = httpx.get("http://127.0.0.1:8001/api/config/client")
    data = resp.json()
    for key in ["SATELLITE_UPLINK_KEY", "INTERNAL_GATEWAY_URL", "DEBUG_SECRET_TOKEN"]:
        assert key not in data, f"Secret {key} must not be returned in client config"
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP API Security – Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
