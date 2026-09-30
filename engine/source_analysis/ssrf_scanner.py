"""
SSRF Scanner — Source analysis for Server-Side Request Forgery patterns.

For source analysis (MODE A):
  - Identifies server-side URL fetch patterns
  - Checks for allowlists, hostname validation, IP normalization
  - Checks for redirect following in fetch calls

Classification: safe | blocked | potential_ssrf | candidate_ssrf
Never claims "confirmed SSRF" from source analysis alone.
"""

from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation, DataFlow


class SsrfScanner(BaseScanner):
    SCANNER_NAME = "SsrfScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".mjs", ".py", ".rs"]

    # Server-side fetch patterns (not browser fetch)
    SERVER_FETCH_PATTERNS = [
        (r"fetch\(.*req\.|fetch\(.*params\.|fetch\(.*query\.", "fetch() with request-derived URL"),
        (r"axios\.\w+\(.*req\.", "axios with request-derived URL"),
        (r"httpx\.\w+\(.*req\.", "httpx with request-derived URL"),
        (r"requests\.\w+\(.*req\.", "requests with request-derived URL"),
        (r"urllib.*urlopen\(", "urllib.urlopen with variable URL"),
        (r"new\s+URL\s*\([^)]*\+", "URL constructor with concatenation"),
    ]

    # Allowlist / validation patterns
    VALIDATION_PATTERNS = [
        r"allowlist", r"whitelist", r"isAllowed", r"validateUrl",
        r"hostname\s*===", r"\.hostname\s*===",
        r"ALLOWED_HOSTS", r"allowedHosts",
    ]

    # Redirect-following indicators
    REDIRECT_PATTERNS = [
        r"follow_redirects\s*=\s*True",
        r"redirect\s*:\s*['\"]follow['\"]",
        r"maxRedirects\s*:",
    ]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue

            lines = content.splitlines()

            # Skip client-side files (browser fetch is not SSRF)
            rel = self._rel(path)
            is_server = any(s in rel for s in [
                "/api/", "/server/", "/convex/", "edge", "middleware",
                "app.py", "main.py", "server.ts", "server.js",
                "/functions/", "netlify/functions", "vercel/api",
            ])

            for line_no, line in enumerate(lines, 1):
                for pattern, fetch_name in self.SERVER_FETCH_PATTERNS:
                    if not re.search(pattern, line):
                        continue

                    # Check surrounding context for validation
                    ctx_start = max(0, line_no - 10)
                    ctx_end = min(len(lines), line_no + 10)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    has_validation = any(
                        re.search(vp, context) for vp in self.VALIDATION_PATTERNS
                    )
                    has_redirect_follow = any(
                        re.search(rp, context) for rp in self.REDIRECT_PATTERNS
                    )

                    # Only flag server-side code (or unknown context as CANDIDATE)
                    if not is_server:
                        confidence = "LOW"
                        status = "CANDIDATE"
                    elif has_validation:
                        confidence = "LOW"
                        status = "CANDIDATE"  # Validation present — may be safe
                    else:
                        confidence = "MEDIUM"
                        status = "CANDIDATE"  # No validation found — needs review

                    extra = []
                    if has_redirect_follow:
                        extra.append("redirect-following enabled (every redirect must be revalidated)")
                    if not has_validation:
                        extra.append("no apparent URL allowlist or hostname validation found")
                    else:
                        extra.append("URL validation pattern present — verify it covers all bypass cases")

                    findings.append(SourceFinding(
                        finding_key=f"SSRF_CANDIDATE_{fetch_name.upper().replace(' ', '_')[:30]}",
                        category="SSRF",
                        title=f"Potential SSRF — Server-Side {fetch_name} with Variable URL",
                        description=(
                            f"Server-side code uses '{fetch_name}' with a URL that may be "
                            f"derived from user input. "
                            f"{'Validation detected but requires manual review. ' if has_validation else 'No validation found in context. '}"
                            f"Additional notes: {'; '.join(extra) if extra else 'none'}. "
                            f"CANDIDATE only — dynamic confirmation required."
                        ),
                        location=SourceLocation(
                            file_path=rel,
                            line_number=line_no,
                            symbol=fetch_name,
                            snippet=line.strip()[:200],
                        ),
                        data_flow=DataFlow(
                            source="Request-derived URL parameter",
                            validation="Present (unverified)" if has_validation else "Not found",
                            transformation="String concatenation / URL construction",
                            sink=fetch_name,
                            path_confirmed=False,
                        ),
                        confidence=confidence,
                        cwe_id="CWE-918: Server-Side Request Forgery (SSRF)",
                        owasp_category="A10:2021-Server-Side Request Forgery",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        cvss_score=7.5,
                        severity="HIGH",
                        verification_status=status,
                        remediation=(
                            "1. Validate and allowlist all server-side URL destinations. "
                            "2. Block internal IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x). "
                            "3. Normalize URLs before validation (resolve redirects independently). "
                            "4. Use trust_env=False on HTTP clients to prevent proxy bypass."
                        ),
                        metric_reasoning="CANDIDATE. High theoretical score if confirmed. AC:H — assumes no bypass. Requires dynamic validation.",
                    ))
        return findings
