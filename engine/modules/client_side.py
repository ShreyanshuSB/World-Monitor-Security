"""
Module 5: Client-Side Controls — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Checks: API key/secret leakage in client config endpoint.
Secrets are redacted in evidence output (SHA-256 fingerprint stored instead of full value).
"""

import time
import uuid
import hashlib
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "Client-Side Controls"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"


def _redact_secret(value: str) -> str:
    """Return <REDACTED:sha256=xxxx> instead of the raw secret."""
    fingerprint = hashlib.sha256(value.encode()).hexdigest()[:16]
    return f"<REDACTED:sha256={fingerprint}>"


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []
    config_url = f"{base_url}/api/config/client"

    start_time = time.time()
    try:
        response = client.get(config_url, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            data = response.json()
            secret_keys = ["SATELLITE_UPLINK_KEY", "INTERNAL_GATEWAY_URL", "DEBUG_SECRET_TOKEN"]
            leaked_keys = [k for k in secret_keys if k in data]

            if leaked_keys:
                cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
                calc = CVSS31Calculator.calculate(cvss_vec)

                # Build redacted evidence — never print full secrets in reports
                redacted_body = response.text
                for k in leaked_keys:
                    val = data.get(k, "")
                    if val:
                        redacted_body = redacted_body.replace(val, _redact_secret(val))

                evidence = EvidenceModel(
                    request_method="GET",
                    request_url=config_url,
                    request_headers={},
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=redacted_body[:1000],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                    note=f"LAB SYNTHETIC: Secrets redacted in evidence. Leaked keys: {', '.join(leaked_keys)}"
                )

                record_id = str(uuid.uuid4())
                findings.append(FindingModel(
                    finding_record_id=record_id,
                    id=record_id,
                    finding_key="CLIENT_SECRET_LEAK_CONFIG",
                    vuln_key="CLIENT_KEY_LEAK",
                    origin=MODULE_ORIGIN,
                    environment_type=MODULE_ENV,
                    verification_status="CONFIRMED",
                    title="Synthetic API Secret & Internal Gateway Exposed in Client Config [Lab Synthetic]",
                    description=(
                        f"[LAB SYNTHETIC] /api/config/client exposes synthetic credential-like values "
                        f"to unauthenticated clients. Detected keys: {', '.join(leaked_keys)}. "
                        "Values are SYNTHETIC LAB DATA — not real production secrets. "
                        "Secret values are redacted in evidence output."
                    ),
                    affected_component="/api/config/client",
                    scope_area=MODULE_NAME,
                    cwe_id="CWE-798: Use of Hard-coded Credentials",
                    owasp_category="A04:2021-Insecure Design",
                    cvss_vector=cvss_vec,
                    cvss_score=calc["base_score"],
                    severity=calc["severity"],
                    metric_reasoning="PR:N — Unauthenticated access. C:H — Credential-class values exposed. I:L — Gateway URL could enable further access if real. A:N — No availability impact.",
                    steps_to_reproduce=[
                        "GET /api/config/client (no authentication).",
                        f"Observe keys in response: {', '.join(leaked_keys)}.",
                        "Note: values shown in evidence are redacted."
                    ],
                    proof_of_concept=f"curl -s {config_url}",
                    business_impact=(
                        "In a real system: compromise of service account keys and internal endpoint discovery. "
                        "In this lab: synthetic data only — classified as lab validation finding."
                    ),
                    remediation="Remove all credential-class values from client-facing configuration endpoints. Authenticate uplink requests server-side with short-lived tokens.",
                    code_diff=(
                        "--- a/lab/app.py\n+++ b/lab/app.py\n"
                        "@@ config endpoint\n"
                        "-    'SATELLITE_UPLINK_KEY': 'sk_live_...',\n"
                        "-    'INTERNAL_GATEWAY_URL': 'http://...',\n"
                        "+    # No secrets in client config\n"
                    ),
                    status="CONFIRMED",
                    evidence=evidence,
                ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Module error: {e}")

    return findings
