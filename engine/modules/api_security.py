"""
Module 4: API Security — Dynamic Lab Validation
Origin: LAB_SYNTHETIC | Environment: LAB_SYNTHETIC

Checks: Excessive Data Exposure, Missing Rate Limiting.
"""

import time
import uuid
import httpx
from typing import List
from engine.models import FindingModel, EvidenceModel
from engine.cvss import CVSS31Calculator

MODULE_NAME = "API Security"
MODULE_ORIGIN = "LAB_SYNTHETIC"
MODULE_ENV = "LAB_SYNTHETIC"


def run_module(base_url: str, client: httpx.Client) -> List[FindingModel]:
    findings = []
    viewer_token = "wm_sec_token_viw_1038"
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # Check 1: Excessive Data Exposure on /api/users/profile
    profile_url = f"{base_url}/api/users/profile"
    start_time = time.time()
    try:
        response = client.get(profile_url, headers=headers, timeout=5.0)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        if response.status_code == 200:
            data = response.json()
            leaked_keys = [k for k in ["password_hash", "salt", "recovery_codes", "internal_ip"] if k in data]
            if leaked_keys:
                cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                calc = CVSS31Calculator.calculate(cvss_vec)

                metric_reasoning = (
                    "PR:L — Requires valid account. C:H — Password hash, salt, recovery codes, internal IP disclosed. "
                    "I:N — Read-only exposure. A:N — No availability impact."
                )

                evidence = EvidenceModel(
                    request_method="GET",
                    request_url=profile_url,
                    request_headers=headers,
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=response.text[:1000],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                    note=f"LAB SYNTHETIC: Leaked keys: {', '.join(leaked_keys)}"
                )

                record_id = str(uuid.uuid4())
                findings.append(FindingModel(
                    finding_record_id=record_id,
                    id=record_id,
                    finding_key="API_EXCESSIVE_DATA_EXPOSURE",
                    vuln_key="API_EXCESSIVE_DATA",
                    origin=MODULE_ORIGIN,
                    environment_type=MODULE_ENV,
                    verification_status="CONFIRMED",
                    title="Excessive Data Exposure in User Profile API [Lab Synthetic]",
                    description=(
                        f"[LAB SYNTHETIC] /api/users/profile serializes raw DB model fields. "
                        f"Detected leaked attributes: {', '.join(leaked_keys)}. "
                        "Includes password hash, salt, recovery codes, and internal IP."
                    ),
                    affected_component="/api/users/profile",
                    scope_area=MODULE_NAME,
                    cwe_id="CWE-200: Exposure of Sensitive Information",
                    owasp_category="A04:2021-Insecure Design",
                    cvss_vector=cvss_vec,
                    cvss_score=calc["base_score"],
                    severity=calc["severity"],
                    metric_reasoning=metric_reasoning,
                    steps_to_reproduce=[
                        "Authenticate as viewer.",
                        "GET /api/users/profile",
                        f"Observe sensitive fields: {', '.join(leaked_keys)}.",
                    ],
                    proof_of_concept=f'curl -s -H "Authorization: Bearer {viewer_token}" {profile_url}',
                    business_impact="Offline brute-force of leaked password hashes, account takeover via recovery codes, internal network mapping.",
                    remediation="Use strict DTO/Pydantic output schema that allowlists only non-sensitive fields.",
                    code_diff=(
                        "--- a/lab/app.py\n+++ b/lab/app.py\n"
                        "@@ profile endpoint\n"
                        "-    return user.__dict__\n"
                        "+    return {'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}\n"
                    ),
                    status="CONFIRMED",
                    evidence=evidence,
                ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Check 1 error: {e}")

    # Check 2: Missing Rate Limiting on Login
    login_url = f"{base_url}/api/auth/login"
    start_time = time.time()
    try:
        rapid_responses = []
        for i in range(6):
            r = client.post(login_url, json={"username": "admin", "password": f"wrong_{i}"}, timeout=5.0)
            rapid_responses.append(r.status_code)

        duration_ms = round((time.time() - start_time) * 1000, 2)

        if 429 not in rapid_responses:
            cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            calc = CVSS31Calculator.calculate(cvss_vec)

            evidence = EvidenceModel(
                request_method="POST",
                request_url=login_url,
                request_headers={"Content-Type": "application/json"},
                request_body='{"username": "admin", "password": "[REDACTED]"}',
                response_status=rapid_responses[-1],
                response_headers={"X-Probe-Count": "6"},
                response_body=f"6 rapid requests. Status codes: {rapid_responses}. No HTTP 429 received.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=duration_ms,
                note="LAB SYNTHETIC: No rate limiting on login endpoint"
            )

            record_id = str(uuid.uuid4())
            findings.append(FindingModel(
                finding_record_id=record_id,
                id=record_id,
                finding_key="API_NO_RATE_LIMIT_LOGIN",
                vuln_key="API_NO_RATE_LIMIT",
                origin=MODULE_ORIGIN,
                environment_type=MODULE_ENV,
                verification_status="CONFIRMED",
                title="Missing Rate Limiting on Authentication Endpoint [Lab Synthetic]",
                description=(
                    "[LAB SYNTHETIC] /api/auth/login does not throttle repeated failed attempts. "
                    "6 rapid invalid requests received no HTTP 429 response."
                ),
                affected_component="/api/auth/login",
                scope_area=MODULE_NAME,
                cwe_id="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                owasp_category="A07:2021-Identification and Authentication Failures",
                cvss_vector=cvss_vec,
                cvss_score=calc["base_score"],
                severity=calc["severity"],
                metric_reasoning="PR:N — No credentials required to attempt. C:L — Enables credential guessing attacks. I:N/A:N — No direct impact demonstrated beyond brute-force enablement.",
                steps_to_reproduce=[
                    "Issue 6 consecutive failed login requests to /api/auth/login.",
                    "Observe no HTTP 429 rate limit response.",
                ],
                proof_of_concept=f"for i in $(seq 1 6); do curl -s -o /dev/null -w 'HTTP %{{http_code}}\\n' -X POST {login_url} -H 'Content-Type: application/json' -d '{{\"username\":\"admin\",\"password\":\"x\"}}'; done",
                business_impact="Automated brute-force and credential stuffing attacks without throttling or lockout.",
                remediation="Implement IP-based sliding window rate limits (5 attempts/60s) with HTTP 429 and progressive lockout.",
                code_diff=(
                    "--- a/lab/app.py\n+++ b/lab/app.py\n"
                    "@@ login\n"
                    "+    if rate_limiter.is_rate_limited(request.client.host):\n"
                    "+        raise HTTPException(status_code=429, detail='Rate limit exceeded')\n"
                ),
                status="CONFIRMED",
                evidence=evidence,
            ))
    except Exception as e:
        print(f"[{MODULE_NAME}] Check 2 error: {e}")

    return findings
