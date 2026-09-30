"""API Route Scanner — Maps API endpoints and checks for missing input validation."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class ApiRouteScanner(BaseScanner):
    SCANNER_NAME = "ApiRouteScanner"
    RELEVANT_EXTENSIONS = [".ts", ".js", ".mjs", ".py"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # Check for raw SQL string interpolation
                if re.search(r"['\"]SELECT.*\+|f['\"].*SELECT.*{", line, re.IGNORECASE):
                    ctx = "\n".join(lines[max(0,line_no-2):min(len(lines),line_no+3)])
                    findings.append(SourceFinding(
                        finding_key="API_RAW_SQL_CONCAT",
                        category="Injection",
                        title="Potential SQL Injection — Raw SQL String Concatenation",
                        description=(
                            f"Raw SQL string concatenation at '{rel}:{line_no}'. "
                            "User-controlled input concatenated into SQL query without parameterization."
                        ),
                        location=SourceLocation(file_path=rel, line_number=line_no, symbol="raw SQL", snippet=line.strip()[:200]),
                        confidence="MEDIUM",
                        cwe_id="CWE-89: SQL Injection",
                        owasp_category="A03:2021-Injection",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=6.5, severity="HIGH",
                        verification_status="CANDIDATE",
                        remediation="Use parameterized queries or ORM query builders exclusively.",
                        metric_reasoning="CANDIDATE — must verify input source is user-controlled.",
                    ))

                # Check for missing rate limiting on auth endpoints
                if re.search(r"(?i)login|signin|authenticate", line) and re.search(r"def |function |async ", line):
                    ctx = "\n".join(lines[max(0,line_no):min(len(lines),line_no+20)])
                    if not re.search(r"rate|throttle|limit|ratelimit", ctx, re.IGNORECASE):
                        findings.append(SourceFinding(
                            finding_key="API_LOGIN_NO_RATE_LIMIT",
                            category="API Security",
                            title="Authentication Endpoint Potentially Missing Rate Limiting",
                            description=(
                                f"Auth handler at '{rel}:{line_no}' has no apparent rate limiting in surrounding code. "
                                "CANDIDATE — rate limiting may be applied at middleware/infrastructure level."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="auth handler", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cvss_score=5.3, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Add per-IP rate limiting at the route handler or reverse proxy level.",
                            metric_reasoning="Low confidence — infra-level rate limiting not visible in source.",
                        ))
        return findings
