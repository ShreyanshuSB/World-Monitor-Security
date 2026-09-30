# World Monitor Security Assessment
## Smart India Hackathon 2026 | Problem Statement SIH26163 (NTRO)
### Assessment ID: ASM-C2DE5856 | Date: 2026-09-28

---

## Quick Navigation

| Document | Purpose |
|----------|---------|
| [final_report.md](final_report.md) | **Complete security assessment report (start here)** |
| [executive_summary.md](executive_summary.md) | Non-technical summary for judges/management |
| [security_dashboard.md](security_dashboard.md) | Metrics dashboard — risk scores and finding table |
| [sih_demo.md](sih_demo.md) | **Live demo script for SIH presentation** |
| [test_matrix.md](test_matrix.md) | All 22 security tests with pass/fail status |
| [threat_model.md](threat_model.md) | STRIDE threat model and attack trees |
| [architecture.md](architecture.md) | System architecture and API surface map |
| [environment.md](environment.md) | Test environment baseline and unit test results |

---

## Individual Finding Reports

| Folder | Severity | CVSS | Title |
|--------|----------|------|-------|
| [findings/F-001](findings/F-001/README.md) | **CRITICAL** | 9.1 | Auth Bypass via Forged Token |
| [findings/F-002](findings/F-002/README.md) | **CRITICAL** | 9.8 | SQL Injection — Report Search |
| [findings/F-003](findings/F-003/README.md) | **HIGH** | 8.2 | Hardcoded API Secrets in Client Config |
| [findings/F-004](findings/F-004/README.md) | MEDIUM | 6.5 | IDOR — Classified Report Access |
| [findings/F-005](findings/F-005/README.md) | MEDIUM | 6.5 | BFLA — Admin Telemetry Export |
| [findings/F-006](findings/F-006/README.md) | MEDIUM | 5.4 | Stored XSS — Report Notes |
| [findings/F-007](findings/F-007/README.md) | MEDIUM | 6.5 | Excessive Data Exposure |
| [findings/F-008](findings/F-008/README.md) | MEDIUM | 5.3 | No Rate Limiting on Login |
| [findings/F-009](findings/F-009/README.md) | MEDIUM | 4.9 | Cleartext Tokens in System Logs |

---

## PoC Scripts (Safe — Localhost Only)

| Script | Finding | Description |
|--------|---------|-------------|
| [poc/poc_f001_auth_bypass.py](poc/poc_f001_auth_bypass.py) | F-001 | Demonstrates auth bypass with forged token |
| [poc/poc_f002_sqli.py](poc/poc_f002_sqli.py) | F-002 | Demonstrates SQL injection with UNION SELECT |

---

## Overall Risk Posture

```
RISK SCORE: CRITICAL (98/100)

Findings:    2 CRITICAL  |  1 HIGH  |  7 MEDIUM
OWASP:      6/10 categories impacted
Unit Tests: 7/7 PASSED (CVSS engine + scope guard verified)
```

---

## Running the Assessment Platform

### Prerequisites
```bash
pip install fastapi uvicorn httpx sqlalchemy pydantic reportlab
```

### Start Services
```bash
# Terminal 1: Lab target (intentionally vulnerable)
python -m uvicorn lab.app:app --host 127.0.0.1 --port 8001

# Terminal 2: Assessment API
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000

# Terminal 3 (optional): Dashboard UI
cd dashboard && npm run dev
```

### Run Assessment
```bash
python -c "
import httpx, json
resp = httpx.post('http://127.0.0.1:8000/api/assessments/run',
    json={'target_url': 'http://127.0.0.1:8001', 'authorized_acknowledged': True})
print(resp.json())
"
```

### Run Unit Tests
```bash
python -m pytest tests/ -v
```

### Run PoC Scripts
```bash
python security_assessment/poc/poc_f001_auth_bypass.py
python security_assessment/poc/poc_f002_sqli.py
```
