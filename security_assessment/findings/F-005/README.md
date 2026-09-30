# F-005 — Broken Function Level Authorization (BFLA) on Admin Telemetry Export

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 6.5
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

## Status
**Confirmed**

## Finding ID
`FINDING-AUTHZ-002`

## Affected Component
`/api/admin/telemetry-export` — `lab/app.py` lines 300–329

## Description

The `/api/admin/telemetry-export` endpoint performs authentication (confirms the user has a valid token) but omits role-based authorization. A viewer-role user can invoke this admin-only bulk export function, extracting all satellite ground station coordinates.

**Vulnerable code:**
```python
# VULNERABLE (lines 310–312)
else:
    # No role check — any authenticated user can invoke admin export
    pass
```

## Steps to Reproduce

```bash
curl -s -H "Authorization: Bearer wm_sec_token_viw_1038" \
     http://127.0.0.1:8001/api/admin/telemetry-export
```

**Observed:** HTTP 200 with full telemetry export containing all 4 ground station coordinates and satellite IDs.

## Remediation

```python
@app.get("/api/admin/telemetry-export")
def export_bulk_telemetry(user: User = Depends(require_role("admin")), ...):
    # require_role dependency raises 403 if user.role != "admin"
    ...
```

## Regression Test

```python
def test_bfla_blocked():
    resp = httpx.get("http://127.0.0.1:8001/api/admin/telemetry-export",
                     headers={"Authorization": "Bearer wm_sec_token_viw_1038"})
    assert resp.status_code == 403
```

## References

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP API5:2023 – Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
