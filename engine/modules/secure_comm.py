"""
Module 6: Secure Communication — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Checks for missing HTTP security headers. Tests against the lab root, not just /api/health.
Does NOT score missing HSTS on plain HTTP localhost as a production-level vulnerability.
"""

import time
import uuid
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "Secure Communication"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []

    # Test against multiple paths to get a broader view of header coverage
    test_paths = ["/api/health", "/"]
    combined_headers = {}
    best_response = None
    best_url = None
    best_duration = 0.0

    for path in test_paths:
        target_url = f"{base_url}{path}"
        start_time = time.time()
        try:
            response = client.get(target_url, timeout=5.0)
            duration_ms = round((time.time() - start_time) * 1000, 2)
            combined_headers.update({k.lower(): v for k, v in response.headers.items()})
            if best_response is None:
                best_response = response
                best_url = target_url
                best_duration = duration_ms
        except Exception:
            pass

    if best_response is None:
        return findings

    # Check headers (exclude HSTS from scoring on plain HTTP localhost)
    is_plain_http = base_url.startswith("http://")

    required_headers = [
        ("X-Content-Type-Options", "Prevents MIME-sniffing exploits"),
        ("X-Frame-Options", "Prevents Clickjacking"),
        ("Content-Security-Policy", "Restricts resource loading and mitigates XSS"),
    ]
    # Only include HSTS if we're on HTTPS
    if not is_plain_http:
        required_headers.append(("Strict-Transport-Security", "Enforces TLS and blocks downgrade attacks"))

    missing_headers = []
    for h, purpose in required_headers:
        if h.lower() not in combined_headers:
            missing_headers.append(f"{h} ({purpose})")

    if missing_headers:
        # Adjusted CVSS: HSTS not applicable on plain HTTP localhost
        # Score reflects actual missing non-transport headers
        cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        calc = CVSS31Calculator.calculate(cvss_vec)

        metric_reasoning = (
            "AV:N — Missing headers exploitable by network adversary or malicious page. "
            "AC:L — No special conditions to exploit missing headers. "
            "PR:N — No authentication needed to observe missing headers. "
            "UI:R — Browser user interaction required (clickjacking, XSS execution). "
            "S:U — No scope change. "
            "C:L / I:L — Missing CSP enables XSS content injection; missing X-Frame-Options enables Clickjacking. "
            "A:N — No availability impact. "
            "NOTE: HSTS is not scored on plain HTTP localhost — HSTS is only meaningful on HTTPS endpoints."
        )

        evidence = EvidenceModel(
            request_method="GET",
            request_url=best_url,
            request_headers={},
            response_status=best_response.status_code,
            response_headers=dict(best_response.headers),
            response_body=f"Missing headers checked across {test_paths}:\n" + "\n".join(f"- {m}" for m in missing_headers),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_ms=best_duration,
            note="LAB SYNTHETIC: Headers tested across multiple paths"
        )

        record_id = str(uuid.uuid4())
        findings.append(FindingModel(
            finding_record_id=record_id,
            id=record_id,
            finding_key="COMM_MISSING_SECURITY_HEADERS",
            vuln_key="COMM_MISSING_HEADERS",
            origin=MODULE_ORIGIN,
            environment_type=MODULE_ENV,
            verification_status="CONFIRMED",
            title="Missing HTTP Security Headers [Lab Synthetic]",
            description=(
                f"[LAB SYNTHETIC] The lab server omits key defense-in-depth HTTP headers. "
                f"Missing: {', '.join(missing_headers)}. "
                "Note: HSTS is not applicable to plain HTTP localhost deployments."
            ),
            affected_component="Global HTTP Response Pipeline",
            scope_area=MODULE_NAME,
            cwe_id="CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
            owasp_category="A05:2021-Security Misconfiguration",
            cvss_vector=cvss_vec,
            cvss_score=calc["base_score"],
            severity=calc["severity"],
            metric_reasoning=metric_reasoning,
            steps_to_reproduce=[
                f"GET {best_url}",
                "Inspect response headers.",
                f"Verify absence of: {', '.join(missing_headers)}"
            ],
            proof_of_concept=f"curl -sI {best_url}",
            business_impact="Increased exposure to Clickjacking, MIME confusion, and XSS content injection attacks.",
            remediation="Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy in middleware for all responses.",
            code_diff=(
                "--- a/lab/app.py\n+++ b/lab/app.py\n"
                "@@ middleware\n"
                "+    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                "+    response.headers['X-Frame-Options'] = 'DENY'\n"
                "+    response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
            ),
            status="CONFIRMED",
            evidence=evidence,
        ))

    return findings
