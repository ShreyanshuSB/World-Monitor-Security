"""Cache Security Scanner — Checks for cache-related security misconfigurations."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class CacheScanner(BaseScanner):
    SCANNER_NAME = "CacheScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".mjs", ".py", ".json", ".yaml", ".yml"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # Cache-Control: public on sensitive endpoint responses
                if re.search(r"Cache-Control.*public|cache.*public", line, re.IGNORECASE):
                    ctx = "\n".join(lines[max(0,line_no-5):min(len(lines),line_no+5)])
                    if any(s in ctx.lower() for s in ["auth", "user", "profile", "token", "session", "admin"]):
                        findings.append(SourceFinding(
                            finding_key="CACHE_PUBLIC_SENSITIVE_ENDPOINT",
                            category="Cache Security",
                            title="Public Cache-Control on Potentially Sensitive Endpoint",
                            description=(
                                f"'Cache-Control: public' near auth/user/admin context at '{rel}:{line_no}'. "
                                "Public caching of authenticated responses can expose user data to other users via shared CDN caches."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="Cache-Control", snippet=line.strip()[:200]),
                            confidence="MEDIUM",
                            cwe_id="CWE-524: Use of Cache Containing Sensitive Information",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=5.9, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Use 'Cache-Control: private, no-store' for authenticated or user-specific responses.",
                            metric_reasoning="CANDIDATE — AC:H because requires shared cache infrastructure. Verify actual caching behavior.",
                        ))

                # Missing Vary header on content-negotiated responses
                if re.search(r"Authorization.*header|user.*header", line, re.IGNORECASE):
                    ctx = "\n".join(lines[max(0,line_no):min(len(lines),line_no+10)])
                    if "Vary" not in ctx and "cache" in ctx.lower():
                        findings.append(SourceFinding(
                            finding_key="CACHE_MISSING_VARY_AUTHORIZATION",
                            category="Cache Security",
                            title="Potential Cache Key Missing Authorization Header (Vary)",
                            description=(
                                f"Cache usage near Authorization header at '{rel}:{line_no}' without Vary: Authorization. "
                                "Caches may serve one user's authenticated response to another user."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="Vary", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-524: Use of Cache Containing Sensitive Information",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=5.9, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Add 'Vary: Authorization' header when caching responses that differ by auth token.",
                            metric_reasoning="Low confidence CANDIDATE — cache behavior depends on infrastructure.",
                        ))
        return findings
