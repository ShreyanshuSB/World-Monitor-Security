"""
Module 7: Data Storage & Privacy — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Checks: Cleartext authentication tokens in system logs.

Retest fix: The detector checks for the ACTUAL token value in the response body.
It does NOT trigger on field names like "cleartext_token" — only on the actual
token string "wm_sec_token_adm_9941" appearing in the log content.

Also checks: viewer access to system logs (should be admin-only).
"""

import time
import uuid
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "Data Storage & Privacy"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"

# The actual token value that should NOT appear in log output
ACTUAL_TOKEN = "wm_sec_token_adm_9941"
# Field names that are acceptable in output (not secrets themselves)
ACCEPTABLE_FIELD_NAMES = {"cleartext_token", "message", "context", "level", "id", "timestamp"}


def _token_present_in_body(response_text: str) -> bool:
    """
    Check for the ACTUAL secret token value in the response body.
    Do NOT flag field names like 'cleartext_token' as false positives.
    """
    return ACTUAL_TOKEN in response_text


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []
    admin_token = ACTUAL_TOKEN
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    viewer_token = "wm_sec_token_viw_1038"
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    logs_url = f"{base_url}/api/admin/system-logs"

    # ---------------------------------------------------------------
    # Check 1: Cleartext token in log body (admin-accessible)
    # ---------------------------------------------------------------
    start_time = time.time()
    try:
        response = client.get(logs_url, headers=admin_headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            raw_text = response.text
            # Only flag if the ACTUAL token value appears in the response,
            # not merely field names that reference it
            if _token_present_in_body(raw_text):
                cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"
                calc = CVSS31Calculator.calculate(cvss_vec)

                metric_reasoning = (
                    "PR:H — Requires admin account to access logs. "
                    "C:H — Active admin session token exposed in cleartext — enables session impersonation. "
                    "I:N — Read-only log access; no write demonstrated. "
                    "A:N — No availability impact."
                )

                # Redact the actual token in evidence
                redacted_body = raw_text.replace(ACTUAL_TOKEN, "<REDACTED:admin_token>")

                evidence = EvidenceModel(
                    request_method="GET",
                    request_url=logs_url,
                    request_headers={"Authorization": "Bearer <REDACTED>"},
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=redacted_body[:1000],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                    note="LAB SYNTHETIC: Actual token value detected in log output — redacted in evidence"
                )

                record_id = str(uuid.uuid4())
                findings.append(FindingModel(
                    finding_record_id=record_id,
                    id=record_id,
                    finding_key="DATA_CLEARTEXT_TOKEN_IN_LOGS",
                    vuln_key="DATA_CLEARTEXT_LOGS",
                    origin=MODULE_ORIGIN,
                    environment_type=MODULE_ENV,
                    verification_status="CONFIRMED",
                    title="Cleartext Session Token in Diagnostic Logs [Lab Synthetic]",
                    description=(
                        "[LAB SYNTHETIC] The admin system-logs endpoint returns log records "
                        "containing the actual bearer token value in cleartext. "
                        "Detection: actual token value present in response body (not just field name). "
                        "Token value is redacted in this evidence record."
                    ),
                    affected_component="/api/admin/system-logs & Logging Pipeline",
                    scope_area=MODULE_NAME,
                    cwe_id="CWE-532: Insertion of Sensitive Information into Log File",
                    owasp_category="A09:2021-Security Logging and Monitoring Failures",
                    cvss_vector=cvss_vec,
                    cvss_score=calc["base_score"],
                    severity=calc["severity"],
                    metric_reasoning=metric_reasoning,
                    steps_to_reproduce=[
                        "Authenticate as admin.",
                        "GET /api/admin/system-logs",
                        "Verify that the actual bearer token string appears in message/context fields.",
                        "Note: the retest passes only when the actual token value is ABSENT from log output.",
                    ],
                    proof_of_concept='curl -s -H "Authorization: Bearer <REDACTED>" ' + logs_url + ' | grep wm_sec_token',
                    business_impact="Admin session token accessible to anyone with log access — enables session hijacking.",
                    remediation=(
                        "Redact token patterns at log source before writing. "
                        "Apply regex/pattern scrubbing at log formatter level. "
                        "Regression test: actual token must NOT appear in log output after patch."
                    ),
                    code_diff=(
                        "--- a/lab/app.py\n+++ b/lab/app.py\n"
                        "@@ logs endpoint\n"
                        "-    return logs  # raw\n"
                        "+    # Redact credential patterns before returning\n"
                        "+    masked = [redact_sensitive(l) for l in logs]\n"
                        "+    return masked\n"
                    ),
                    status="CONFIRMED",
                    evidence=evidence,
                ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Cleartext token check error: {e}")

    # ---------------------------------------------------------------
    # Check 2: Viewer access to admin system-logs (should be blocked)
    # ---------------------------------------------------------------
    start_time = time.time()
    try:
        response = client.get(logs_url, headers=viewer_headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            evidence = EvidenceModel(
                request_method="GET",
                request_url=logs_url,
                request_headers={"Authorization": f"Bearer {viewer_token}"},
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:500],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: Viewer accessed admin-only system logs"
            )
            record_id = str(uuid.uuid4())
            findings.append(FindingModel(
                finding_record_id=record_id,
                id=record_id,
                finding_key="DATA_VIEWER_LOG_ACCESS",
                vuln_key="DATA_VIEWER_LOG_ACCESS",
                origin=MODULE_ORIGIN,
                environment_type=MODULE_ENV,
                verification_status="CONFIRMED",
                title="Viewer Role Accesses Admin System Logs [Lab Synthetic]",
                description=(
                    "[LAB SYNTHETIC] /api/admin/system-logs is accessible to viewer-role accounts. "
                    "Expected: HTTP 403 Forbidden."
                ),
                affected_component="/api/admin/system-logs",
                scope_area=MODULE_NAME,
                cwe_id="CWE-862: Missing Authorization",
                owasp_category="A01:2021-Broken Access Control",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:M/I:N/A:N",
                cvss_score=5.4,
                severity="MEDIUM",
                metric_reasoning="PR:L — Requires viewer account. C:M — Internal log data exposed to low-privilege users.",
                steps_to_reproduce=[
                    "Authenticate as viewer.",
                    "GET /api/admin/system-logs",
                    "Observe HTTP 200 — Expected 403.",
                ],
                proof_of_concept=f'curl -s -H "Authorization: Bearer {viewer_token}" {logs_url}',
                business_impact="Sensitive operational log data accessible to low-privilege accounts.",
                remediation="Enforce admin-only role check on /api/admin/system-logs.",
                code_diff=(
                    "--- a/lab/app.py\n+++ b/lab/app.py\n"
                    "@@ system-logs\n"
                    "+    if user.role != 'admin':\n"
                    "+        raise HTTPException(status_code=403, detail='Admin only')\n"
                ),
                status="CONFIRMED",
                evidence=evidence,
            ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Viewer log access check error: {e}")

    return findings
