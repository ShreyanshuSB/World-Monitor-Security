"""
Module 1: Authentication & Session Management — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Checks authentication bypass via hardcoded token pattern in the controlled lab.
Correctly identifies the flaw as "Hardcoded Token Pattern" — NOT "Weak JWT Secret"
because the lab uses a string prefix check, not JWT.
"""

import time
import uuid
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "Authentication & Session Management"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []

    # Probe: Attempt access using forged token matching the hardcoded prefix pattern
    probe_url = f"{base_url}/api/users/profile"
    forged_token = "wm_forged_admin_test_signature"
    headers = {"Authorization": f"Bearer {forged_token}"}

    start_time = time.time()
    try:
        response = client.get(probe_url, headers=headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Vulnerable if server accepts the forged token and returns admin profile
        if response.status_code == 200 and "admin" in response.text:
            # CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
            # Justification: Network attack vector, no privileges required,
            # grants admin-level read+write (C:H/I:H), no availability impact demonstrated
            cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            calc = CVSS31Calculator.calculate(cvss_vec)

            metric_reasoning = (
                "AV:N — Exploitable over network. "
                "AC:L — No special conditions; simple token string. "
                "PR:N — No prior credentials required to forge the token. "
                "UI:N — No user interaction. "
                "S:U — No scope change; impact contained to application. "
                "C:H — Admin profile data including all user fields exposed. "
                "I:H — Authenticated as admin allows data modification. "
                "A:N — No availability impact demonstrated in this probe."
            )

            diff = (
                "--- a/lab/app.py\n"
                "+++ b/lab/app.py\n"
                "@@ -82,5 +82,5 @@ def get_current_user(...):\n"
                "-    if token.startswith('wm_forged_admin_'):\n"
                "-        return db.query(User).filter(User.role == 'admin').first()\n"
                "+    # Remove hardcoded token pattern bypass entirely\n"
                "+    # All tokens must be validated against the database token store\n"
                "+    return None  # unauthenticated if token not found in DB\n"
            )

            evidence = EvidenceModel(
                request_method="GET",
                request_url=probe_url,
                request_headers={"Authorization": f"Bearer {forged_token}"},
                request_body=None,
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text[:1000],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: Forged token accepted by hardcoded prefix bypass"
            )

            finding_key = "AUTH_HARDCODED_TOKEN_BYPASS"
            record_id = str(uuid.uuid4())

            finding = FindingModel(
                finding_record_id=record_id,
                id=record_id,
                assessment_id="UNASSIGNED",
                finding_key=finding_key,
                vuln_key="AUTH_WEAK_SECRET",
                origin=MODULE_ORIGIN,
                environment_type=MODULE_ENV,
                verification_status="CONFIRMED",
                title="Authentication Bypass via Hardcoded Token Pattern (Lab Synthetic)",
                description=(
                    "[LAB SYNTHETIC — Controlled Vulnerability Validation Lab] "
                    "The authentication middleware validates session tokens using a hardcoded "
                    "string prefix check ('wm_forged_admin_'). Any token matching this prefix "
                    "is unconditionally granted admin privileges without database lookup or "
                    "cryptographic verification. This is NOT a JWT vulnerability — the lab "
                    "does not use JWT; it uses a simple string.startswith() check."
                ),
                affected_component="Authentication Middleware (lab/app.py → get_current_user)",
                scope_area="Authentication & Session Management",
                cwe_id="CWE-798: Use of Hard-coded Credentials",
                owasp_category="A07:2021-Identification and Authentication Failures",
                cvss_vector=cvss_vec,
                cvss_score=calc["base_score"],
                severity=calc["severity"],
                metric_reasoning=metric_reasoning,
                steps_to_reproduce=[
                    "Send GET /api/users/profile with Authorization: Bearer wm_forged_admin_test_signature",
                    "Observe HTTP 200 with admin role in response — no valid credentials required.",
                    "Note: this works because the middleware uses token.startswith('wm_forged_admin_'), not JWT validation."
                ],
                proof_of_concept=f'curl -s -H "Authorization: Bearer wm_forged_admin_test_signature" {probe_url}',
                business_impact=(
                    "Any party aware of the prefix pattern can forge administrative sessions. "
                    "In a real system this would allow complete account takeover and data access."
                ),
                remediation=(
                    "Remove the hardcoded prefix bypass entirely. "
                    "Validate all tokens strictly against the database token store or implement "
                    "proper cryptographic token signing (e.g. HMAC-SHA256 or RS256)."
                ),
                code_diff=diff,
                status="CONFIRMED",
                evidence=evidence,
            )
            findings.append(finding)
    except Exception as e:
        print(f"[{MODULE_NAME}] Probe error: {e}")

    return findings
