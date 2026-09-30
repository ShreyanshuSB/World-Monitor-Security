# Assessment Environment Baseline

## Test Environment Specification

| Parameter | Value |
|-----------|-------|
| Assessment Date | 2026-09-28 |
| Assessment Time | 17:07 IST (UTC+05:30) |
| Operating System | Windows 11 |
| Python Version | 3.13.7 |
| pytest Version | 9.1.1 |
| Repository | koala73/worldmonitor (SIH26163 Lab Platform) |
| Assessment ID | ASM-C2DE5856 |
| Branch | main |
| Lab Platform Version | 1.0.0-lab |
| Assessment Platform Version | 1.0.0 |

## Service URLs (Localhost Only)

| Service | URL | Port | Status |
|---------|-----|------|--------|
| World Monitor Lab Target | http://127.0.0.1:8001 | 8001 | HEALTHY |
| Security Assessment API | http://127.0.0.1:8000 | 8000 | OPERATIONAL |
| Security Operator Console | http://127.0.0.1:5173 | 5173 | (Dashboard — optional) |

## Python Dependencies

- fastapi, uvicorn — ASGI web framework
- httpx — HTTP client for probes
- sqlalchemy — ORM
- pydantic — Data validation
- reportlab — PDF generation

## Baseline Test Results

```
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.1.1
tests/test_cvss.py::test_cvss_critical_vector        PASSED
tests/test_cvss.py::test_cvss_high_idor_vector       PASSED
tests/test_cvss.py::test_cvss_scope_changed_xss      PASSED
tests/test_cvss.py::test_cvss_roundup                PASSED
tests/test_scope_guard.py::test_scope_guard_permits_localhost        PASSED
tests/test_scope_guard.py::test_scope_guard_blocks_external_domains  PASSED
tests/test_scope_guard.py::test_scope_guard_blocks_malformed_and_empty PASSED
============================== 7 passed in 0.11s ==============================
```

## Scope Guard Policy

- Policy: **FAIL_CLOSED_LOCALHOST_ONLY**
- Allowed Hosts: `localhost`, `127.0.0.1`, `::1`
- External IPs and domains: **BLOCKED**

## Authorization Compliance

- Authorization gate acknowledged: ✅
- No actions performed on production infrastructure: ✅
- All probes restricted to `http://127.0.0.1:8001`: ✅
- No real user data accessed or modified: ✅
- No high-volume traffic generated: ✅
