# F-006 — Stored Cross-Site Scripting (XSS) in Report Operational Notes

## Severity
**MEDIUM**

## CVSS v3.1
- **Score:** 5.4
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
- **Metric Reasoning:**
  - **AV:N** — Network exploitable
  - **AC:L** — Low complexity
  - **PR:L** — Requires analyst-level token to write; payload then executes for any viewer
  - **UI:R** — Requires victim to view the report (reasonable for security analysts)
  - **S:C** — Scope Changed — XSS crosses from server-stored data into victim browser context
  - **C:L** — Session/cookie data accessible from victim browser
  - **I:L** — Arbitrary DOM manipulation possible

## Status
**Confirmed — Live PoC executed**

## Finding ID
`FINDING-INP-002`  
Assessment: `ASM-C2DE5856`

## Affected Component
- **Sink:** `lab/app.py` — `update_report_notes()` (lines 259–282)
- **Endpoint (Write):** `POST /api/reports/{id}/notes`
- **Endpoint (Read/Execute):** `GET /api/reports/{id}`

---

## Description

The report notes update handler stores user-supplied HTML/JavaScript without sanitization. When a report is subsequently retrieved by another user, the raw payload is returned verbatim and — when rendered in a browser without a Content Security Policy — executes as JavaScript in the victim's session context.

**Vulnerable code:**
```python
# lab/app.py — Line 275 (VULNERABLE)
# VULNERABLE: Stores raw unsanitized HTML / JavaScript payload
report.notes = note_data.notes
```

## Live PoC Execution

```python
# Step 1: Write XSS payload as analyst
import httpx
headers = {"Authorization": "Bearer wm_sec_token_ana_4210"}
payload = "<img src=x onerror=\"document.body.dataset.xss='POC_WM2026'\" />"
httpx.post("http://127.0.0.1:8001/api/reports/1/notes", json={"notes": payload}, headers=headers)

# Step 2: Verify stored payload
resp = httpx.get("http://127.0.0.1:8001/api/reports/1", headers=headers)
assert payload in resp.json()["notes"]   # CONFIRMED TRUE
```

**Console output:** `[+] FINDING-INP-002 CONFIRMED: Stored XSS payload persisted verbatim in database`

## Remediation

```python
# REMEDIATED update_report_notes()
import html
if vuln_config.is_fixed("INPUT_STORED_XSS"):
    sanitized_note = html.escape(note_data.notes)
    report.notes = sanitized_note
```

Additionally add to HTTP middleware:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

## References

- [CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
