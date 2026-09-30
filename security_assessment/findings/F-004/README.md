# F-004 — Broken Object Level Authorization (BOLA/IDOR) on Classified Reports

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 6.5
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Metric Reasoning:**
  - **AV:N** — Network exploitable
  - **AC:L** — No special conditions required
  - **PR:L** — Low privileges (any valid user session)
  - **UI:N** — No user interaction needed
  - **S:U** — Scope unchanged
  - **C:H** — Complete confidentiality loss — classified TOP_SECRET intelligence exposed
  - **I:N** — No integrity impact
  - **A:N** — No availability impact

## Status
**Confirmed — Independently Reproduced**

## Finding ID
`FINDING-AUTHZ-001`  
Assessment: `ASM-C2DE5856`

## Affected Component
- **File:** `lab/app.py` — `get_report_detail()` function (lines 229–257)
- **Endpoint:** `GET /api/reports/{report_id}`

---

## Description

The report detail endpoint accepts an integer `report_id` path parameter and returns the report data to any authenticated user, regardless of whether that user holds the security clearance level required to access the report's classification. A low-privilege "viewer" user can directly request report ID 3 or 4 (classified `RESTRICTED_TOP_SECRET`) and receive the full classified content.

**Vulnerable code:**
```python
# lab/app.py — Lines 239–247 (VULNERABLE)
if vuln_config.is_fixed("AUTHZ_IDOR_REPORT"):
    # Safe version (not active)
    if report.classification == "RESTRICTED_TOP_SECRET" and user.role not in ["admin"]:
        raise HTTPException(status_code=403, ...)
else:
    # VULNERABLE: No clearance check — any authenticated user passes through
    pass
```

## Root Cause

The authorization check is completely absent in the default (vulnerable) state. The endpoint verifies that the user is authenticated (logged in) but performs no ownership check, no clearance level check, and no role comparison against the report's classification field. The report ID is an incrementing integer, making enumeration trivial.

## Steps to Reproduce

1. Obtain a valid viewer-level token (lowest privilege): `wm_sec_token_viw_1038`
2. Execute:
   ```bash
   curl -s -H "Authorization: Bearer wm_sec_token_viw_1038" \
        http://127.0.0.1:8001/api/reports/3
   ```
3. Observe HTTP 200 with the full `RESTRICTED_TOP_SECRET` report content returned.

## Proof of Concept

```bash
# Viewer accessing RESTRICTED_TOP_SECRET report
curl -s -H "Authorization: Bearer wm_sec_token_viw_1038" \
     http://127.0.0.1:8001/api/reports/3

# Expected: HTTP 403 Forbidden
# Actual:   HTTP 200 with classified orbital analysis content
```

## Evidence

- **FINDING-AUTHZ-001** status: VERIFIED | CVSS: 6.5
- Evidence URL: `http://127.0.0.1:8001/api/reports/3`
- Response status: **HTTP 200 OK**
- Response body confirms: `"classification": "RESTRICTED_TOP_SECRET"`

## Security Impact

| Dimension | Impact |
|-----------|--------|
| Confidentiality | **COMPLETE** — Classified intelligence disclosed to unauthorized personnel |
| Integrity | None |
| Availability | None |

## Remediation

```python
# REMEDIATED get_report_detail()
@app.get("/api/reports/{report_id}")
def get_report_detail(report_id: int, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Not found")

    # Clearance-based ABAC enforcement
    clearance_map = {
        "RESTRICTED_TOP_SECRET": ["admin"],
        "INTERNAL": ["admin", "analyst"],
        "PUBLIC": ["admin", "analyst", "viewer"]
    }
    allowed_roles = clearance_map.get(report.classification, ["admin"])
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient clearance level")

    return report
```

## Regression Test

```python
def test_idor_blocked_after_fix():
    resp = httpx.get("http://127.0.0.1:8001/api/reports/3",
                     headers={"Authorization": "Bearer wm_sec_token_viw_1038"})
    assert resp.status_code == 403
```

## References

- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP API1:2023 – Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
