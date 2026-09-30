# SIH Demo Script — World Monitor Security Assessment
## Problem Statement SIH26163 (NTRO) | Assessment ID: ASM-C2DE5856

**Duration: 5–10 minutes | Format: Live technical demonstration**

---

## Pre-Demo Setup Checklist

- [ ] Lab server running: `python -m uvicorn lab.app:app --host 127.0.0.1 --port 8001`
- [ ] Assessment API running: `python -m uvicorn api.main:app --host 127.0.0.1 --port 8000`
- [ ] Dashboard (optional): `cd dashboard && npm run dev`
- [ ] Browser at: `http://127.0.0.1:5173` (or 5174)
- [ ] Terminal ready with PoC scripts

---

## Demo 1 — Application Overview (60 seconds)

**Narration:**
> "World Monitor is a real-time global intelligence monitoring platform used for national-security situational awareness. It handles classified satellite data, telemetry feeds, and intelligence reports across three user tiers — Admin, Analyst, and Viewer — with a REST API backend."

**Show:**
- Open `http://www.worldmonitor.app` briefly (or screenshots)
- Point to key features: globe visualization, report management, role-based access

---

## Demo 2 — Architecture & Attack Surface (60 seconds)

**Narration:**
> "Our assessment mapped the complete API surface. We identified 9 endpoint groups, 3 authentication levels, and classified data at multiple security levels. The most sensitive assets are: classified intelligence reports, satellite uplink API keys, and user session tokens."

**Show:**
- [Architecture diagram](architecture.md) — API endpoint table
- [Threat model](threat_model.md) — attack tree diagram

---

## Demo 3 — Vulnerability Demonstration (3–4 minutes)

### 3A: Critical — SQL Injection (F-002, CVSS 9.8)

**Narration:**
> "Our first and most severe finding is a SQL Injection vulnerability. The search endpoint directly interpolates user input into a SQL query without parameterization. Watch what happens."

**Run:**
```bash
python security_assessment/poc/poc_f002_sqli.py
```

**Expected output:**
```
[CONFIRMED] SQL Injection returned 4 rows
  [!] TOP SECRET RECORD LEAKED: id=3, title=CLASSIFIED: Strategic Satellite...
  [!] TOP SECRET RECORD LEAKED: id=4, title=Critical Border Surveillance...
```

**Point to source code:** `lab/app.py` lines 193–196 — show the `f"...{search}..."` interpolation

---

### 3B: Critical — Authentication Bypass (F-001, CVSS 9.1)

**Narration:**
> "Our second critical finding is even more alarming — the authentication layer can be completely bypassed using a forged token. No credentials needed."

**Run:**
```bash
python security_assessment/poc/poc_f001_auth_bypass.py
```

**Expected output:**
```
HTTP Status: 200
[CONFIRMED] Authentication bypassed!
  → Username: admin
  → Role: admin
```

**Point to source code:** `lab/app.py` lines 82–85 — show the `if token.startswith("wm_forged_admin_")` backdoor

---

### 3C: High — Hardcoded Secrets (F-003, CVSS 8.2)

**Narration:**
> "The client configuration endpoint is publicly accessible and returns production API keys in plaintext. Any visitor to the site can steal the satellite uplink credential."

**Run in terminal:**
```bash
curl -s http://127.0.0.1:8001/api/config/client
```

**Expected:** JSON with `SATELLITE_UPLINK_KEY`, `INTERNAL_GATEWAY_URL`, `DEBUG_SECRET_TOKEN` visible

---

## Demo 4 — Evidence & Assessment Platform (90 seconds)

**Narration:**
> "Every finding was captured with live HTTP evidence — real request and response headers, status codes, and response bodies. This is not scanner output — every finding was dynamically triggered against the live lab target."

**Show:**
- Security operator console at `http://127.0.0.1:5173`
- Click on `FINDING-INP-001` (SQL Injection)
- Show the HTTP Evidence tab — actual captured request/response
- Show the CVSS v3.1 metric breakdown

---

## Demo 5 — Impact Explanation (60 seconds)

**Narration:**
> "What does this mean in practice?"

**Walk through attack chain:**
```
Unauthenticated attacker
    ↓ (F-003) Reads SATELLITE_UPLINK_KEY from /api/config/client
    ↓ (F-001) Forges admin token → gains admin session
    ↓ (F-002) SQL Injection → dumps all classified reports
    ↓ (F-004) IDOR → directly reads TOP_SECRET orbital data
    Result: Complete intelligence compromise
```

---

## Demo 6 — Remediation (90 seconds)

**Narration:**
> "For each vulnerability, we provide a specific code-level fix. Let's patch the SQL injection and retest."

**In the dashboard:**
1. Navigate to Remediation & Retest
2. Click "Apply Fix to Lab" on `FINDING-INP-001`
3. Click "Re-run Verification Check"

**Or via API:**
```bash
# Apply patch
curl -s -X POST http://127.0.0.1:8000/api/findings/FINDING-INP-001/apply-fix

# Retest
curl -s -X POST http://127.0.0.1:8000/api/findings/FINDING-INP-001/retest
```

**Expected:** Status transitions to `RETESTED_PASS`

**Show the unified diff:**
```diff
- raw_query = f"SELECT ... WHERE title LIKE '%{search}%'"
+ results = db.query(Report).filter(Report.title.ilike(f"%{search}%")).all()
```

---

## Demo 7 — Regression Test (30 seconds)

**Narration:**
> "After patching, the automated regression test confirms the vulnerability is eliminated — the SQL injection payload now returns an empty list instead of classified data."

**Run:**
```bash
python -c "
import httpx
payload = \"' UNION SELECT 1,2,3,4,5,6,7 FROM users WHERE '1'='1\"
resp = httpx.get('http://127.0.0.1:8001/api/reports', params={'search': payload})
print('After fix:', resp.status_code, 'rows:', len(resp.json()))
"
```

**Expected:** Empty list returned — exploit no longer works.

---

## Key Talking Points for Judges

1. **This is active testing, not scanner output** — every finding was triggered by live HTTP probes
2. **CVSS scores are calculated by a FIRST-compliant engine** — not assigned arbitrarily
3. **Scope Guard enforces fail-closed localhost boundary** — no production systems at risk
4. **Dynamic patch-and-retest** demonstrates the full security lifecycle: discover → fix → verify
5. **9 confirmed vulnerabilities across all 7 OWASP-mapped domains** — comprehensive coverage
