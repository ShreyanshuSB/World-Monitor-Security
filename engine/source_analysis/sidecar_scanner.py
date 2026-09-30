"""Sidecar Security Scanner — Analyzes Node.js sidecar authentication and IPC patterns."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class SidecarScanner(BaseScanner):
    SCANNER_NAME = "SidecarScanner"
    RELEVANT_EXTENSIONS = [".ts", ".js", ".mjs", ".rs"]

    SIDECAR_INDICATORS = ["sidecar", "node-sidecar", "ipc", "child_process", "spawn", "fork"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lower = content.lower()

            if not any(ind in lower for ind in self.SIDECAR_INDICATORS):
                continue

            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                # Sidecar with no token authentication
                if re.search(r"spawn|fork|child_process", line) and not re.search(r"auth|token|secret|verify", line):
                    ctx = "\n".join(lines[max(0,line_no-5):min(len(lines),line_no+15)])
                    if not re.search(r"auth|token|secret|verify|sign", ctx, re.IGNORECASE):
                        findings.append(SourceFinding(
                            finding_key="SIDECAR_NO_AUTH",
                            category="Sidecar Security",
                            title="Sidecar Process Launch Without Apparent Authentication Token",
                            description=(
                                f"Process spawn/fork at '{rel}:{line_no}' lacks apparent auth token setup. "
                                "Sidecars without mutual authentication can be hijacked by other processes."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="spawn/fork", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-287: Improper Authentication",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            cvss_score=6.3, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Implement mutual authentication between Tauri app and Node sidecar. Use short-lived tokens generated at startup.",
                            metric_reasoning="CANDIDATE. Low confidence — auth may be set up elsewhere. AV:L — local access required.",
                        ))

                # Short-lived token check
                if re.search(r"token|secret", line, re.IGNORECASE) and re.search(r"sidecar|ipc", line, re.IGNORECASE):
                    if not re.search(r"expir|ttl|lifetime|maxAge", line, re.IGNORECASE):
                        findings.append(SourceFinding(
                            finding_key="SIDECAR_NO_TOKEN_EXPIRY",
                            category="Sidecar Security",
                            title="Sidecar Token Without Apparent Expiry/Lifetime",
                            description=(
                                f"Sidecar token at '{rel}:{line_no}' has no apparent expiry. "
                                "Long-lived or permanent tokens enable replay attacks if intercepted."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="token", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-613: Insufficient Session Expiration",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:M/I:N/A:N",
                            cvss_score=2.5, severity="LOW",
                            verification_status="CANDIDATE",
                            remediation="Use short-lived (session-scoped) tokens for sidecar IPC. Regenerate on each app launch.",
                            metric_reasoning="CANDIDATE. Low confidence CANDIDATE — expiry may exist outside this context.",
                        ))
        return findings
