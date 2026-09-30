"""
Module 3: Input Validation & Data Handling — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Checks: SQL Injection (read-only impact demonstrated), HTML Injection / Potential XSS.

XSS Classification:
  - CONFIRMED XSS requires: attacker-controlled → storage → browser rendering → script execution
  - This probe only confirms storage of HTML. Without browser execution evidence, we classify
    as "HTML Injection / Potential XSS" (not "Confirmed XSS").
  - Severity is scored accordingly (no scope change, UI interaction required).

SQLi CVSS:
  - Read access to reports demonstrated (C:H).
  - No write/destructive capability demonstrated in this probe (I:N, A:N).
  - If write impact is separately demonstrated, CVSS would be updated.
"""

import time
import uuid
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "Input Validation & Data Handling"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []
    analyst_token = "wm_sec_token_ana_4210"
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # ---------------------------------------------------------------
    # Check 1: SQL Injection — read access demonstrated
    # ---------------------------------------------------------------
    sqli_payload = "' UNION SELECT id, title, classification, summary, content, notes, author_id FROM reports WHERE '1'='1"
    sqli_url = f"{base_url}/api/reports"

    start_time = time.time()
    try:
        response = client.get(sqli_url, params={"search": sqli_payload}, headers=headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            try:
                rows = response.json()
            except Exception:
                rows = []

            if isinstance(rows, list) and len(rows) >= 3:
                # CVSS: Only claiming demonstrated read impact (C:H, I:N, A:N)
                # NOT claiming I:H/A:H which would require demonstrated write/destructive capability
                cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                calc = CVSS31Calculator.calculate(cvss_vec)

                metric_reasoning = (
                    "AV:N — Exploitable over network via search parameter. "
                    "AC:L — No special conditions; simple SQL metacharacter injection. "
                    "PR:L — Requires valid analyst token (authentication needed for /api/reports). "
                    "UI:N — Automated. "
                    "S:U — Impact contained within application database. "
                    "C:H — UNION query returned full report records including classified content. "
                    "I:N — This probe demonstrated READ access only; write/destructive capability not demonstrated. "
                    "A:N — No availability impact demonstrated. "
                    "NOTE: Theoretical maximum with write capability would be C:H/I:H/A:H, "
                    "but CVSS is scored on demonstrated impact only."
                )

                diff = (
                    "--- a/lab/app.py\n"
                    "+++ b/lab/app.py\n"
                    "@@ -188,4 +188,4 @@\n"
                    "-    raw_query = f\"SELECT ... WHERE title LIKE '%{search}%'\"\n"
                    "-    cursor = db.execute(text(raw_query))\n"
                    "+    # Use parameterized ORM filter — no string interpolation\n"
                    "+    results = db.query(Report).filter(Report.title.ilike(f'%{search}%')).all()\n"
                )

                evidence = EvidenceModel(
                    request_method="GET",
                    request_url=f"{sqli_url}?search={sqli_payload}",
                    request_headers=headers,
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=response.text[:1000],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                    note="LAB SYNTHETIC: UNION query returned all report records — read access demonstrated"
                )

                record_id = str(uuid.uuid4())
                finding = FindingModel(
                    finding_record_id=record_id,
                    id=record_id,
                    finding_key="INPUT_SQLI_SEARCH",
                    vuln_key="INPUT_SQLI_SEARCH",
                    origin=MODULE_ORIGIN,
                    environment_type=MODULE_ENV,
                    verification_status="CONFIRMED",
                    title="SQL Injection via Search Parameter — Read Access Demonstrated [Lab Synthetic]",
                    description=(
                        "[LAB SYNTHETIC] The /api/reports?search parameter executes raw SQL "
                        "via string interpolation. A UNION SELECT payload returned all report "
                        "records. READ access (C:H) is demonstrated. Write/destructive capability "
                        "(I:H/A:H) is NOT claimed in this probe — separate validation required."
                    ),
                    affected_component="/api/reports?search={query}",
                    scope_area=MODULE_NAME,
                    cwe_id="CWE-89: SQL Injection",
                    owasp_category="A03:2021-Injection",
                    cvss_vector=cvss_vec,
                    cvss_score=calc["base_score"],
                    severity=calc["severity"],
                    metric_reasoning=metric_reasoning,
                    steps_to_reproduce=[
                        "Authenticate as analyst.",
                        f"GET {sqli_url}?search=' UNION SELECT id,title,classification,summary,content,notes,author_id FROM reports WHERE '1'='1",
                        "Observe all report records returned via UNION injection — SQL structure manipulated.",
                        "Note: CVSS reflects demonstrated read access only."
                    ],
                    proof_of_concept=f"curl -s -H \"Authorization: Bearer {analyst_token}\" \"{sqli_url}?search=%27%20UNION%20SELECT%20id%2Ctitle%2Cclassification%2Csummary%2Ccontent%2Cnotes%2Cauthor_id%20FROM%20reports%20WHERE%20%271%27%3D%271\"",
                    business_impact="Read access to all report records demonstrated. Full write/destructive capability possible with additional payloads (not demonstrated here).",
                    remediation="Replace raw SQL string interpolation with parameterized ORM queries.",
                    code_diff=diff,
                    status="CONFIRMED",
                    evidence=evidence,
                )
                findings.append(finding)
    except Exception as e:
        print(f"[{MODULE_NAME}] SQLi check error: {e}")

    # ---------------------------------------------------------------
    # Check 2: HTML Injection / Potential XSS (stored HTML confirmed; browser execution NOT confirmed)
    # ---------------------------------------------------------------
    xss_target_id = 1
    xss_url = f"{base_url}/api/reports/{xss_target_id}/notes"
    # Use a harmless HTML payload (no active script) for the storage check
    html_payload = "<b>HTML_INJECTION_PROBE</b>"

    start_time = time.time()
    try:
        post_resp = client.post(xss_url, json={"notes": html_payload}, headers=headers, timeout=5.0)
        verify_resp = client.get(f"{base_url}/api/reports/{xss_target_id}", headers=headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if verify_resp.status_code == 200 and html_payload in verify_resp.text:
            # HTML is stored verbatim — this is HTML Injection / Potential XSS
            # NOT "Confirmed XSS" without browser rendering evidence + controlled script execution
            cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
            calc = CVSS31Calculator.calculate(cvss_vec)

            metric_reasoning = (
                "AV:N — Injected via network. "
                "AC:L — Simple injection, no special conditions. "
                "PR:L — Requires analyst account to post notes. "
                "UI:R — Requires another user to view the affected report (browser rendering). "
                "S:C — If browser executes script: scope changes to victim's browser session. "
                "C:L — Potential session cookie/data access if XSS executes. "
                "I:L — Potential form/DOM manipulation if XSS executes. "
                "A:N — No availability impact. "
                "CLASSIFICATION: HTML Injection / Potential XSS — "
                "browser execution not confirmed in this probe. "
                "Confirmed XSS requires: attacker-controlled payload → storage → browser rendering → script execution."
            )

            diff = (
                "--- a/lab/app.py\n"
                "+++ b/lab/app.py\n"
                "@@ -274,2 +274,3 @@\n"
                "-    report.notes = note_data.notes  # raw storage\n"
                "+    import html\n"
                "+    report.notes = html.escape(note_data.notes)  # HTML entity encode\n"
            )

            evidence = EvidenceModel(
                request_method="POST",
                request_url=xss_url,
                request_headers=headers,
                request_body=f'{{"notes": "{html_payload}"}}',
                response_status=post_resp.status_code,
                response_headers=dict(post_resp.headers),
                response_body=verify_resp.text[:1000],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: HTML stored verbatim — HTML Injection confirmed. Browser XSS execution not confirmed in this automated probe."
            )

            record_id = str(uuid.uuid4())
            finding = FindingModel(
                finding_record_id=record_id,
                id=record_id,
                finding_key="INPUT_STORED_HTML_INJECTION",
                vuln_key="INPUT_STORED_XSS",
                origin=MODULE_ORIGIN,
                environment_type=MODULE_ENV,
                verification_status="VALIDATED",  # HTML injection confirmed; XSS pending browser test
                title="HTML Injection / Potential Stored XSS in Report Notes [Lab Synthetic]",
                description=(
                    "[LAB SYNTHETIC] The report notes endpoint stores raw unescaped HTML without "
                    "sanitization. This probe confirms HTML Injection (stored verbatim). "
                    "Potential Stored XSS exists — browser rendering confirmation pending. "
                    "Classification: HTML Injection / Potential XSS (not Confirmed XSS without "
                    "controlled script execution evidence)."
                ),
                affected_component="/api/reports/{report_id}/notes",
                scope_area=MODULE_NAME,
                cwe_id="CWE-79: Cross-site Scripting (Stored)",
                owasp_category="A03:2021-Injection",
                cvss_vector=cvss_vec,
                cvss_score=calc["base_score"],
                severity=calc["severity"],
                metric_reasoning=metric_reasoning,
                steps_to_reproduce=[
                    f"POST {xss_url} with body: {{\"notes\": \"<b>HTML_INJECTION_PROBE</b>\"}}",
                    "GET /api/reports/1 — verify notes field contains raw HTML verbatim.",
                    "HTML is stored unescaped. A script payload would require browser rendering to confirm XSS execution."
                ],
                proof_of_concept=f"curl -s -X POST -H \"Authorization: Bearer {analyst_token}\" -H \"Content-Type: application/json\" -d '{{\"notes\":\"<b>PROBE</b>\"}}' {xss_url}",
                business_impact="HTML injection confirmed. If a victim views the notes in a browser context without output encoding, script execution (XSS) would occur.",
                remediation="Apply html.escape() before storage. Deploy a strict Content-Security-Policy header.",
                code_diff=diff,
                status="VALIDATED",
                evidence=evidence,
            )
            findings.append(finding)
    except Exception as e:
        print(f"[{MODULE_NAME}] HTML injection check error: {e}")

    return findings
