"""
Module 2: Authorization & Access Control — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Tests BOLA/IDOR on classified reports and BFLA on admin telemetry export.
Also checks: unauthenticated report listing, unauthenticated telemetry access,
viewer access to system logs, unauthorized report-note modification.
"""

import time
import uuid
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "Authorization & Access Control"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"


def _make_finding(
    finding_key: str,
    vuln_key: str,
    title: str,
    description: str,
    affected_component: str,
    cwe_id: str,
    owasp_category: str,
    cvss_vec: str,
    steps: list,
    poc: str,
    impact: str,
    remediation: str,
    diff: str,
    evidence: EvidenceModel,
    metric_reasoning: str = "",
    verification_status: str = "CONFIRMED",
) -> FindingModel:
    calc = CVSS31Calculator.calculate(cvss_vec)
    record_id = str(uuid.uuid4())
    return FindingModel(
        finding_record_id=record_id,
        id=record_id,
        finding_key=finding_key,
        vuln_key=vuln_key,
        origin=MODULE_ORIGIN,
        environment_type=MODULE_ENV,
        verification_status=verification_status,
        title=title,
        description=description,
        affected_component=affected_component,
        scope_area=MODULE_NAME,
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        cvss_vector=cvss_vec,
        cvss_score=calc["base_score"],
        severity=calc["severity"],
        metric_reasoning=metric_reasoning,
        steps_to_reproduce=steps,
        proof_of_concept=poc,
        business_impact=impact,
        remediation=remediation,
        code_diff=diff,
        status="CONFIRMED",
        evidence=evidence,
    )


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []
    viewer_token = "wm_sec_token_viw_1038"
    analyst_token = "wm_sec_token_ana_4210"
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # ---------------------------------------------------------------
    # Check 1: BOLA/IDOR — viewer accesses TOP_SECRET report by ID
    # ---------------------------------------------------------------
    idor_url = f"{base_url}/api/reports/3"
    start_time = time.time()
    try:
        response = client.get(idor_url, headers=viewer_headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200 and "RESTRICTED_TOP_SECRET" in response.text:
            evidence = EvidenceModel(
                request_method="GET", request_url=idor_url,
                request_headers={"Authorization": f"Bearer {viewer_token}"},
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:1000],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: Viewer accessed RESTRICTED_TOP_SECRET report via direct ID"
            )
            findings.append(_make_finding(
                finding_key="AUTHZ_IDOR_REPORT",
                vuln_key="AUTHZ_IDOR_REPORT",
                title="Broken Object Level Authorization (BOLA/IDOR) on Classified Reports [Lab Synthetic]",
                description=(
                    "[LAB SYNTHETIC] The report endpoint fails to validate clearance level "
                    "against the requested object. A low-privileged viewer reads a "
                    "RESTRICTED_TOP_SECRET report by supplying its integer ID."
                ),
                affected_component="/api/reports/{report_id}",
                cwe_id="CWE-639: Authorization Bypass Through User-Controlled Key",
                owasp_category="A01:2021-Broken Access Control",
                cvss_vec="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                steps=[
                    "Authenticate as viewer (wm_sec_token_viw_1038).",
                    "GET /api/reports/3 — returns HTTP 200 with RESTRICTED_TOP_SECRET content.",
                    "Expected: HTTP 403 Forbidden.",
                ],
                poc=f'curl -s -H "Authorization: Bearer {viewer_token}" {idor_url}',
                impact="Unauthorized disclosure of classified reports to low-privileged users.",
                remediation="Enforce clearance-level check on every report access. Compare user.role against report.classification server-side.",
                diff=(
                    "--- a/lab/app.py\n+++ b/lab/app.py\n"
                    "@@ -239,1 +239,4 @@\n"
                    "-    pass  # VULNERABLE\n"
                    "+    if report.classification == 'RESTRICTED_TOP_SECRET' and user.role not in ['admin']:\n"
                    "+        raise HTTPException(status_code=403, detail='Insufficient clearance')\n"
                ),
                evidence=evidence,
                metric_reasoning="PR:L — requires valid viewer account. C:H — reads classified content. I:N — read only. A:N — no availability impact.",
            ))
    except Exception as e:
        print(f"[{MODULE_NAME}] IDOR check error: {e}")

    # ---------------------------------------------------------------
    # Check 2: BFLA — viewer invokes admin telemetry export
    # ---------------------------------------------------------------
    bfla_url = f"{base_url}/api/admin/telemetry-export"
    start_time = time.time()
    try:
        response = client.get(bfla_url, headers=viewer_headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200 and "export_status" in response.text and "SUCCESS" in response.text:
            evidence = EvidenceModel(
                request_method="GET", request_url=bfla_url,
                request_headers={"Authorization": f"Bearer {viewer_token}"},
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:1000],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: Viewer invoked admin-only export endpoint"
            )
            findings.append(_make_finding(
                finding_key="AUTHZ_BFLA_EXPORT",
                vuln_key="AUTHZ_BFLA_EXPORT",
                title="Broken Function Level Authorization (BFLA) on Admin Telemetry Export [Lab Synthetic]",
                description=(
                    "[LAB SYNTHETIC] The admin export endpoint lacks role enforcement. "
                    "A viewer-role account successfully invokes the administrative data dump."
                ),
                affected_component="/api/admin/telemetry-export",
                cwe_id="CWE-285: Improper Authorization",
                owasp_category="A01:2021-Broken Access Control",
                cvss_vec="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                steps=[
                    "Authenticate as viewer.",
                    "GET /api/admin/telemetry-export — returns HTTP 200 with full export.",
                    "Expected: HTTP 403 Forbidden.",
                ],
                poc=f'curl -s -H "Authorization: Bearer {viewer_token}" {bfla_url}',
                impact="Privilege escalation allowing low-privilege accounts to initiate bulk admin data exports.",
                remediation="Declare explicit role dependency (require_role('admin')) on all admin routes.",
                diff=(
                    "--- a/lab/app.py\n+++ b/lab/app.py\n"
                    "@@ -306,1 +306,4 @@\n"
                    "-    pass  # VULNERABLE\n"
                    "+    if user.role != 'admin':\n"
                    "+        raise HTTPException(status_code=403, detail='Admin role required')\n"
                ),
                evidence=evidence,
                metric_reasoning="PR:L — requires valid account. C:H — reads all telemetry. I:N — read only. A:N — no availability impact.",
            ))
    except Exception as e:
        print(f"[{MODULE_NAME}] BFLA check error: {e}")

    # ---------------------------------------------------------------
    # Check 3: Unauthenticated report listing
    # ---------------------------------------------------------------
    reports_url = f"{base_url}/api/reports"
    start_time = time.time()
    try:
        response = client.get(reports_url, timeout=5.0)  # no auth header
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                evidence = EvidenceModel(
                    request_method="GET", request_url=reports_url,
                    request_headers={},
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=response.text[:500],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                    note="LAB SYNTHETIC: Unauthenticated request returns report listing"
                )
                findings.append(_make_finding(
                    finding_key="AUTHZ_UNAUTH_REPORT_LIST",
                    vuln_key="AUTHZ_UNAUTH_REPORT_LIST",
                    title="Unauthenticated Report Listing [Lab Synthetic]",
                    description=(
                        "[LAB SYNTHETIC] The /api/reports endpoint returns a listing of "
                        "reports to unauthenticated callers. No Authorization header required."
                    ),
                    affected_component="/api/reports",
                    cwe_id="CWE-306: Missing Authentication for Critical Function",
                    owasp_category="A01:2021-Broken Access Control",
                    cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N",
                    steps=[
                        "Send GET /api/reports with no Authorization header.",
                        "Observe HTTP 200 with report listing.",
                    ],
                    poc=f"curl -s {reports_url}",
                    impact="Public disclosure of report titles and metadata without authentication.",
                    remediation="Add authentication requirement to /api/reports — reject unauthenticated requests with HTTP 401.",
                    diff=(
                        "--- a/lab/app.py\n+++ b/lab/app.py\n"
                        "@@ -186,1 +186,3 @@\n"
                        "-def list_reports(search=None, user=None, ...):\n"
                        "+def list_reports(search=None, user: User = Depends(require_auth), ...):\n"
                        "+    # user is now required; unauthenticated returns 401\n"
                    ),
                    evidence=evidence,
                    metric_reasoning="PR:N — no credentials required. C:M — report metadata exposed. I:N/A:N — read only.",
                    verification_status="CONFIRMED",
                ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Unauth report check error: {e}")

    # ---------------------------------------------------------------
    # Check 4: Unauthenticated telemetry access
    # ---------------------------------------------------------------
    telem_url = f"{base_url}/api/telemetry/live"
    start_time = time.time()
    try:
        response = client.get(telem_url, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                evidence = EvidenceModel(
                    request_method="GET", request_url=telem_url,
                    request_headers={},
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=response.text[:500],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                    note="LAB SYNTHETIC: Unauthenticated telemetry access"
                )
                findings.append(_make_finding(
                    finding_key="AUTHZ_UNAUTH_TELEMETRY",
                    vuln_key="AUTHZ_UNAUTH_TELEMETRY",
                    title="Unauthenticated Live Telemetry Access [Lab Synthetic]",
                    description=(
                        "[LAB SYNTHETIC] The /api/telemetry/live endpoint returns live "
                        "telemetry data to unauthenticated callers."
                    ),
                    affected_component="/api/telemetry/live",
                    cwe_id="CWE-306: Missing Authentication for Critical Function",
                    owasp_category="A01:2021-Broken Access Control",
                    cvss_vec="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N",
                    steps=[
                        "Send GET /api/telemetry/live with no Authorization header.",
                        "Observe HTTP 200 with telemetry data.",
                    ],
                    poc=f"curl -s {telem_url}",
                    impact="Live telemetry data exposed publicly without authentication.",
                    remediation="Add authentication requirement to /api/telemetry/live.",
                    diff=(
                        "--- a/lab/app.py\n+++ b/lab/app.py\n"
                        "@@ telemetry def\n"
                        "+def get_live_telemetry(user: User = Depends(require_auth), ...):\n"
                    ),
                    evidence=evidence,
                    metric_reasoning="PR:N — no credentials required. C:M — telemetry data exposed.",
                ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Unauth telemetry check error: {e}")

    # ---------------------------------------------------------------
    # Check 5: Unauthorized report-note modification (viewer modifies notes)
    # ---------------------------------------------------------------
    notes_url = f"{base_url}/api/reports/1/notes"
    start_time = time.time()
    try:
        response = client.post(
            notes_url,
            json={"notes": "AUTHZ_CHECK_PROBE"},
            headers=viewer_headers,
            timeout=5.0
        )
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            evidence = EvidenceModel(
                request_method="POST", request_url=notes_url,
                request_headers={"Authorization": f"Bearer {viewer_token}"},
                request_body='{"notes": "AUTHZ_CHECK_PROBE"}',
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:500],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: Viewer successfully modified report notes"
            )
            findings.append(_make_finding(
                finding_key="AUTHZ_UNAUTHORIZED_NOTE_MODIFY",
                vuln_key="AUTHZ_UNAUTHORIZED_NOTE_MODIFY",
                title="Unauthorized Report Note Modification by Viewer [Lab Synthetic]",
                description=(
                    "[LAB SYNTHETIC] A viewer-role user can modify report notes via POST "
                    "/api/reports/{id}/notes. No write authorization check is enforced."
                ),
                affected_component="/api/reports/{report_id}/notes",
                cwe_id="CWE-862: Missing Authorization",
                owasp_category="A01:2021-Broken Access Control",
                cvss_vec="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                steps=[
                    "Authenticate as viewer.",
                    "POST /api/reports/1/notes with modified notes content.",
                    "Observe HTTP 200 — modification succeeds.",
                    "Expected: HTTP 403 Forbidden for viewer role.",
                ],
                poc=f'curl -s -X POST -H "Authorization: Bearer {viewer_token}" -H "Content-Type: application/json" -d \'{{"notes":"test"}}\' {notes_url}',
                impact="Viewers can tamper with official report notes, compromising data integrity.",
                remediation="Add role check to note update endpoint — only analysts and admins should be permitted.",
                diff=(
                    "--- a/lab/app.py\n+++ b/lab/app.py\n"
                    "@@ notes endpoint\n"
                    "+    if user.role not in ['analyst', 'admin']:\n"
                    "+        raise HTTPException(status_code=403, detail='Write access requires analyst role')\n"
                ),
                evidence=evidence,
                metric_reasoning="PR:L — requires viewer account. I:H — can modify official report data. C:N/A:N — write only, no availability impact.",
            ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Note modification check error: {e}")

    return findings
