"""Storage Scanner — Analyzes client-side and server-side storage of sensitive data."""
from __future__ import annotations
import re
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation

class StorageScanner(BaseScanner):
    SCANNER_NAME = "StorageScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs"]

    SENSITIVE_KEYS = ["token", "secret", "password", "credential", "auth", "session", "key", "apikey"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # localStorage with sensitive values
                if re.search(r"localStorage\.setItem", line):
                    key_match = re.search(r"localStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]", line)
                    stored_key = key_match.group(1).lower() if key_match else ""
                    if any(s in stored_key for s in self.SENSITIVE_KEYS):
                        findings.append(SourceFinding(
                            finding_key="STORAGE_SENSITIVE_LOCALSTORAGE",
                            category="Data Storage",
                            title=f"Sensitive Data Stored in localStorage ('{stored_key}')",
                            description=(
                                f"localStorage.setItem with key '{stored_key}' at '{rel}:{line_no}'. "
                                "localStorage is accessible to all same-origin JavaScript — "
                                "XSS attacks can exfiltrate tokens stored here."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="localStorage.setItem", snippet=line.strip()[:200]),
                            confidence="MEDIUM",
                            cwe_id="CWE-312: Cleartext Storage of Sensitive Information",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            cvss_score=5.9, severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation="Store authentication tokens in httpOnly cookies (inaccessible to JS). Avoid localStorage for credentials.",
                            metric_reasoning="CANDIDATE — impact depends on whether value stored is actually a credential.",
                        ))

                # Logging sensitive values
                if re.search(r"console\.(log|debug|info|warn|error)\s*\(", line):
                    ctx_lower = line.lower()
                    if any(s in ctx_lower for s in self.SENSITIVE_KEYS):
                        findings.append(SourceFinding(
                            finding_key="STORAGE_SENSITIVE_CONSOLE_LOG",
                            category="Data Storage",
                            title="Potential Sensitive Data in console.log",
                            description=(
                                f"console.log/debug near sensitive keyword at '{rel}:{line_no}'. "
                                "Browser DevTools and log aggregators capture console output. "
                                "Credentials logged here are exposed to DevTools users and log sinks."
                            ),
                            location=SourceLocation(file_path=rel, line_number=line_no, symbol="console.log", snippet=line.strip()[:200]),
                            confidence="LOW",
                            cwe_id="CWE-532: Insertion of Sensitive Information into Log File",
                            owasp_category="A09:2021-Security Logging and Monitoring Failures",
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:M/I:N/A:N",
                            cvss_score=3.3, severity="LOW",
                            verification_status="CANDIDATE",
                            remediation="Remove debug logging of credentials. Use structured logging with field-level redaction.",
                            metric_reasoning="Low confidence — may be logging metadata, not credential values.",
                        ))
        return findings
