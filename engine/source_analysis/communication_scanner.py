"""Communication Security Scanner — Checks transport security in source code."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class CommunicationScanner(BaseScanner):
    SCANNER_NAME = "CommunicationScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".mjs", ".py", ".json", ".yaml", ".yml", ".toml"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # HTTP hardcoded in non-localhost URLs
                if re.search(r"http://(?!localhost|127\.0\.0\.1|::1)", line):
                    # Skip comments
                    stripped = line.strip()
                    if not stripped.startswith("//") and not stripped.startswith("#") and not stripped.startswith("*"):
                        findings.append(SourceFinding(
                            finding_key="COMM_PLAINTEXT_HTTP_URL",
                            category="Transport Security",
                            title="Hardcoded Plain HTTP URL to Non-Localhost Host",
                            description=(
                                f"Plain HTTP URL (non-localhost) at '{rel}:{line_no}'. "
                                "Communications over HTTP are unencrypted and vulnerable to MITM attacks."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="http://", snippet=line.strip()[:200]),
                            confidence="MEDIUM",
                            cwe_id="CWE-319: Cleartext Transmission of Sensitive Information",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=5.9, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Use HTTPS for all external communications. Configure HSTS.",
                            metric_reasoning="CANDIDATE — may be a development-only URL or comment. Verify production usage.",
                        ))

                # TLS verification disabled
                if re.search(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl_verify\s*=\s*False", line, re.IGNORECASE):
                    findings.append(SourceFinding(
                        finding_key="COMM_TLS_VERIFICATION_DISABLED",
                        category="Transport Security",
                        title="TLS Certificate Verification Disabled",
                        description=(
                            f"TLS verification disabled at '{rel}:{line_no}'. "
                            "This allows MITM attacks by accepting any certificate."
                        ),
                        location=SourceLocation(file_path=rel, line_number=line_no, symbol="verify=False", snippet=line.strip()[:200]),
                        confidence="HIGH",
                        cwe_id="CWE-295: Improper Certificate Validation",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cvss_score=8.1, severity="HIGH",
                        verification_status="CANDIDATE",
                        remediation="Enable TLS verification. Use proper certificates in production. Never set verify=False in production code.",
                        metric_reasoning="High confidence candidate. If in production code path, HIGH severity confirmed.",
                    ))

                # WebSocket without origin check
                if re.search(r"new\s+WebSocket\s*\(|WebSocketServer|ws\.on\s*\(['\"]connection", line):
                    ctx = "\n".join(lines[max(0,line_no):min(len(lines),line_no+10)])
                    if not re.search(r"origin|allowedOrigins|verifyClient", ctx, re.IGNORECASE):
                        findings.append(SourceFinding(
                            finding_key="COMM_WEBSOCKET_NO_ORIGIN",
                            category="Transport Security",
                            title="WebSocket Without Apparent Origin Validation",
                            description=(
                                f"WebSocket at '{rel}:{line_no}' has no apparent origin validation. "
                                "Browsers send Origin header on WebSocket upgrades — servers should validate it."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="WebSocket", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-346: Origin Validation Error",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            cvss_score=5.4, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Implement verifyClient callback to validate the Origin header against an allowlist.",
                            metric_reasoning="Low confidence — origin validation may be in server config or middleware.",
                        ))
        return findings
