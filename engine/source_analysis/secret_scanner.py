"""
Secret Scanner — Scans source files, configs, and build output for exposed secrets.

Classification tiers:
  - PUBLIC_CONFIG: non-sensitive (app names, public URLs)
  - NON_SENSITIVE_ID: public identifiers (project IDs, client IDs for public OAuth)
  - CREDENTIAL_LIKE: looks like a credential but requires confirmation
  - HIGH_CONFIDENCE_SECRET: strong pattern match (API keys, private tokens)

Never prints full secrets. Stores SHA-256 fingerprint for correlation.
"""

from __future__ import annotations
import re
import hashlib
from pathlib import Path
from typing import List, Tuple, Optional
from .base import BaseScanner, SourceFinding, SourceLocation


class SecretScanner(BaseScanner):
    SCANNER_NAME = "SecretScanner"
    RELEVANT_EXTENSIONS = [
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".env",
        ".yaml", ".yml", ".toml", ".sh", ".py", ".md"
    ]

    # Patterns: (name, regex, tier, cwe, confidence)
    SECRET_PATTERNS: List[Tuple[str, str, str, str, str]] = [
        # High confidence — specific token formats
        ("GitHub PAT", r"ghp_[A-Za-z0-9]{36}", "HIGH_CONFIDENCE_SECRET", "CWE-798", "HIGH"),
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "HIGH_CONFIDENCE_SECRET", "CWE-798", "HIGH"),
        ("Stripe Secret", r"sk_live_[A-Za-z0-9]{24,}", "HIGH_CONFIDENCE_SECRET", "CWE-798", "HIGH"),
        ("Stripe Test", r"sk_test_[A-Za-z0-9]{24,}", "CREDENTIAL_LIKE", "CWE-798", "MEDIUM"),
        ("Generic API Key", r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9/+_\-]{20,})['\"]", "CREDENTIAL_LIKE", "CWE-798", "MEDIUM"),
        ("Private Key Header", r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----", "HIGH_CONFIDENCE_SECRET", "CWE-312", "HIGH"),
        ("JWT Secret Assignment", r"(?i)jwt[_-]?secret\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "CREDENTIAL_LIKE", "CWE-798", "MEDIUM"),
        ("Hardcoded Password", r"(?i)password\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "CREDENTIAL_LIKE", "CWE-798", "MEDIUM"),
        ("Bearer Token Hardcode", r"[Bb]earer\s+([A-Za-z0-9\-_\.]{20,})", "CREDENTIAL_LIKE", "CWE-798", "LOW"),
        ("Convex Deploy Key", r"(?i)convex[_-]?deploy[_-]?key\s*[:=]\s*['\"]([^'\"]{10,})['\"]", "CREDENTIAL_LIKE", "CWE-798", "MEDIUM"),
    ]

    # Paths to skip (known safe locations)
    SKIP_PATTERNS = [
        ".env.example", "*.test.*", "*.spec.*", "*.md",
        "node_modules", "dist", "build",
    ]

    def scan(self) -> List[SourceFinding]:
        findings = []
        seen: set = set()  # deduplicate by (file, line, pattern)

        for path in self._iter_files():
            rel = self._rel(path)
            # Skip test files, examples, and build output
            if any(skip in rel for skip in ["node_modules", "dist/", "build/", ".git/"]):
                continue
            if any(path.name.endswith(s.replace("*", "")) for s in [".example", ".test.ts", ".spec.ts"]):
                continue

            content = self._read(path)
            if not content:
                continue

            for name, pattern, tier, cwe, confidence in self.SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    line_no = content[:match.start()].count("\n") + 1
                    key = (rel, line_no, name)
                    if key in seen:
                        continue
                    seen.add(key)

                    # Extract matched value (handle both group 0 and group 1)
                    value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    fingerprint = hashlib.sha256(value.encode()).hexdigest()[:16]

                    # Skip obvious placeholders
                    if re.match(r'^(your[-_]|<|{|\$|%|placeholder|example|test123|changeme)', value.lower()):
                        continue

                    severity = "HIGH" if tier == "HIGH_CONFIDENCE_SECRET" else "MEDIUM" if tier == "CREDENTIAL_LIKE" else "LOW"
                    cvss = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" if severity == "HIGH" else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:M/I:N/A:N"
                    cvss_score = 6.5 if severity == "HIGH" else 4.3

                    snippet = self._extract_snippet(content, line_no)
                    # Redact the secret value in the snippet
                    redacted_snippet = snippet.replace(value, f"<REDACTED:sha256={fingerprint}>")

                    findings.append(SourceFinding(
                        finding_key=f"SECRET_{name.upper().replace(' ', '_')}",
                        category="Secret Exposure",
                        title=f"Potential {name} Exposure in Source [{tier}]",
                        description=(
                            f"Pattern '{name}' matched in '{rel}' at line {line_no}. "
                            f"Classification: {tier}. "
                            f"Secret fingerprint (SHA-256 prefix): {fingerprint}. "
                            f"Full value REDACTED — not stored in findings. "
                            f"Requires manual confirmation that this is a real credential, "
                            f"not a placeholder or test value."
                        ),
                        location=SourceLocation(
                            file_path=rel,
                            line_number=line_no,
                            symbol=name,
                            snippet=redacted_snippet,
                        ),
                        confidence=confidence,
                        cwe_id=cwe,
                        owasp_category="A02:2021-Cryptographic Failures",
                        cvss_vector=cvss,
                        cvss_score=cvss_score,
                        severity=severity,
                        verification_status="CANDIDATE",
                        remediation=(
                            "1. Confirm this is a real credential (not placeholder). "
                            "2. If real: rotate the credential immediately. "
                            "3. Store secrets in environment variables or secrets manager. "
                            "4. Add to .gitignore if in env file."
                        ),
                        metric_reasoning=f"Candidate only — tier {tier}. Confidence: {confidence}. Must verify value is not placeholder.",
                    ))
        return findings

    @staticmethod
    def _extract_snippet(content: str, line_no: int, context: int = 1) -> str:
        lines = content.splitlines()
        start = max(0, line_no - 1 - context)
        end = min(len(lines), line_no + context)
        return "\n".join(f"{start+i+1}: {line}" for i, line in enumerate(lines[start:end]))
