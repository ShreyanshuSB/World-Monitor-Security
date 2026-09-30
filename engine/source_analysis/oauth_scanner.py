"""OAuth / Session Scanner — Checks OAuth flow implementation for security issues."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class OAuthScanner(BaseScanner):
    SCANNER_NAME = "OAuthScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".mjs", ".py"]

    OAUTH_INDICATORS = ["oauth", "openid", "oidc", "clerk", "auth0", "nextauth", "lucia"]
    REQUIRED_CHECKS = {
        "state": "state parameter (CSRF protection)",
        "nonce": "nonce (replay protection)",
        "redirect_uri": "redirect_uri validation",
        "code_verifier": "PKCE code_verifier",
    }

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lower = content.lower()

            if not any(ind in lower for ind in self.OAUTH_INDICATORS):
                continue

            # Check for state parameter usage
            if "oauth" in lower or "authorization_code" in lower:
                if "state" not in lower:
                    findings.append(SourceFinding(
                        finding_key="OAUTH_MISSING_STATE",
                        category="OAuth/Session",
                        title="OAuth Flow Without State Parameter (CSRF Risk)",
                        description=(
                            f"OAuth-related code in '{rel}' does not appear to use a 'state' parameter. "
                            "Missing state enables CSRF attacks against the OAuth callback endpoint."
                        ),
                        location=SourceLocation(file_path=rel, line_number=1, symbol="OAuth state"),
                        confidence="MEDIUM",
                        cwe_id="CWE-352: Cross-Site Request Forgery (CSRF)",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        cvss_score=8.0, severity="HIGH",
                        verification_status="CANDIDATE",
                        remediation="Generate a cryptographically random 'state' parameter for each OAuth request. Validate on callback.",
                        metric_reasoning="CANDIDATE — state may be handled by auth library internally. Verify library docs.",
                    ))

            # Check for redirect URI validation
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                if re.search(r"redirect_uri|redirectUri|callbackUrl", line, re.IGNORECASE):
                    ctx = "\n".join(lines[max(0,line_no-3):min(len(lines),line_no+5)])
                    if not re.search(r"validate|allowlist|startsWith|match|===", ctx):
                        findings.append(SourceFinding(
                            finding_key="OAUTH_REDIRECT_URI_UNVALIDATED",
                            category="OAuth/Session",
                            title="OAuth Redirect URI Without Apparent Validation",
                            description=(
                                f"Redirect URI at '{rel}:{line_no}' used without apparent validation. "
                                "Open redirect via redirect_uri enables token interception."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="redirect_uri", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-601: URL Redirection to Untrusted Site",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            cvss_score=5.9, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Validate redirect_uri against a strict allowlist of registered URIs.",
                            metric_reasoning="CANDIDATE. Low confidence — validation may exist in library/framework.",
                        ))
                        break
        return findings
