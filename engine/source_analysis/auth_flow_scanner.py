"""Auth Flow Scanner — Identifies authentication implementation patterns."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class AuthFlowScanner(BaseScanner):
    SCANNER_NAME = "AuthFlowScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".mjs", ".py", ".rs"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # Check for JWT verify without algorithm specification
                if re.search(r"jwt\.verify\s*\(", line) or re.search(r"jwt\.decode\s*\(", line):
                    ctx = "\n".join(lines[max(0,line_no-3):min(len(lines),line_no+5)])
                    if "algorithms" not in ctx and "algorithm" not in ctx:
                        findings.append(SourceFinding(
                            finding_key="AUTH_JWT_NO_ALGORITHM_SPEC",
                            category="Authentication",
                            title="JWT Verification Without Explicit Algorithm Specification",
                            description=(
                                f"jwt.verify/decode at '{rel}:{line_no}' does not specify 'algorithms' parameter. "
                                "Without explicit algorithm specification, libraries may accept 'none' algorithm or "
                                "algorithm confusion attacks (e.g. RS256 public key used as HS256 secret)."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="jwt.verify", snippet=line.strip()[:200]),
                            confidence="MEDIUM",
                            cwe_id="CWE-327: Use of Broken Algorithm",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            cvss_score=8.1, severity="HIGH",
                            verification_status="CANDIDATE",
                            remediation="Always specify algorithms: ['HS256'] or ['RS256'] in jwt.verify(). Never allow 'none'.",
                            metric_reasoning="CANDIDATE — AC:H because algorithm confusion requires specific conditions. Confirm library behavior.",
                        ))

                # Check for hardcoded fallback secret
                if re.search(r"(?i)(secret|key)\s*\|\|\s*['\"][^'\"]{6,}['\"]", line):
                    findings.append(SourceFinding(
                        finding_key="AUTH_HARDCODED_SECRET_FALLBACK",
                        category="Authentication",
                        title="Potential Hardcoded Fallback Secret in Authentication Code",
                        description=(
                            f"Pattern suggests hardcoded fallback secret at '{rel}:{line_no}'. "
                            "e.g. process.env.JWT_SECRET || 'hardcoded_secret'. "
                            "If the environment variable is unset, the hardcoded value is used."
                        ),
                        location=SourceLocation(file_path=rel, line_number=line_no, snippet=line.strip()[:200]),
                        confidence="MEDIUM",
                        cwe_id="CWE-798: Use of Hard-coded Credentials",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cvss_score=9.8, severity="CRITICAL",
                        verification_status="CANDIDATE",
                        remediation="Remove hardcoded fallback. Fail closed if secret is missing (throw error instead of fallback).",
                        metric_reasoning="CANDIDATE — verify the fallback is actually reachable in production. High score if confirmed.",
                    ))
        return findings
