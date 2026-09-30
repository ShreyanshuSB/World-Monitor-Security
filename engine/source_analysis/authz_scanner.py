"""Authorization Scanner — Checks for missing server-side authorization in API routes."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class AuthzScanner(BaseScanner):
    SCANNER_NAME = "AuthzScanner"
    RELEVANT_EXTENSIONS = [".ts", ".js", ".mjs", ".py"]

    ROUTE_PATTERNS = [
        r"app\.(get|post|put|patch|delete)\s*\(['\"][^'\"]+['\"]",
        r"router\.(get|post|put|patch|delete)\s*\(",
        r"@app\.(get|post|put|patch|delete)\s*\(",
    ]
    AUTH_INDICATORS = ["auth", "session", "token", "user", "permission", "role", "middleware", "guard", "require"]
    ADMIN_INDICATORS = ["admin", "internal", "management", "export", "delete", "purge"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                is_route = any(re.search(p, line) for p in self.ROUTE_PATTERNS)
                if not is_route:
                    continue

                is_admin_route = any(ind in line.lower() for ind in self.ADMIN_INDICATORS)
                if not is_admin_route:
                    continue

                # Check surrounding context for auth
                ctx = "\n".join(lines[max(0,line_no-5):min(len(lines),line_no+15)])
                has_auth = any(ind in ctx.lower() for ind in self.AUTH_INDICATORS)

                if not has_auth:
                    findings.append(SourceFinding(
                        finding_key="AUTHZ_ADMIN_ROUTE_NO_AUTH",
                        category="Authorization",
                        title=f"Potential Admin Route Without Authorization Check",
                        description=(
                            f"Admin/privileged route at '{rel}:{line_no}' has no apparent "
                            "authentication or authorization check in surrounding context. "
                            "CANDIDATE — auth may exist in middleware chain (not visible in static analysis)."
                        ),
                        location=SourceLocation(file_path=rel, line_number=line_no, symbol="route", snippet=line.strip()[:200]),
                        confidence="LOW",
                        cwe_id="CWE-862: Missing Authorization",
                        owasp_category="A01:2021-Broken Access Control",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cvss_score=9.8, severity="CRITICAL",
                        verification_status="CANDIDATE",
                        remediation="Add explicit authorization middleware to all admin routes. Verify auth is applied at route level, not just globally.",
                        metric_reasoning="CANDIDATE. Low confidence — middleware may handle auth. Verify with dynamic test.",
                    ))
        return findings
