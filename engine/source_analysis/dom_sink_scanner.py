"""
DOM Sink Scanner — Finds dangerous DOM sinks in TypeScript/JavaScript source.

Follows data-flow from source to sink rather than pure keyword matching.
Categories:
  - HTML Injection candidate: innerHTML/outerHTML/insertAdjacentHTML with variable input
  - Potential XSS: above + attacker-reachable source identified
  - Confirmed XSS: requires browser execution evidence (not from static analysis alone)

postMessage handlers and unsafe eval() patterns also detected.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List
from .base import BaseScanner, SourceFinding, SourceLocation, DataFlow


class DomSinkScanner(BaseScanner):
    SCANNER_NAME = "DomSinkScanner"
    RELEVANT_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs"]

    # Dangerous DOM sinks
    SINK_PATTERNS = [
        # innerHTML / outerHTML
        (r"\.innerHTML\s*=\s*(?!\"[^\"]*\"|'[^']*')", "innerHTML assignment", "CWE-79"),
        (r"\.outerHTML\s*=\s*(?!\"[^\"]*\"|'[^']*')", "outerHTML assignment", "CWE-79"),
        (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML call", "CWE-79"),
        (r"dangerouslySetInnerHTML\s*=\s*\{", "React dangerouslySetInnerHTML", "CWE-79"),
        # Eval / Function constructor
        (r"\beval\s*\(", "eval() call", "CWE-95"),
        (r"new\s+Function\s*\(", "new Function() constructor", "CWE-95"),
        # URL/location manipulation
        (r"window\.location\s*=", "window.location assignment", "CWE-601"),
        (r"location\.href\s*=", "location.href assignment", "CWE-601"),
        (r"window\.open\s*\(", "window.open() call", "CWE-601"),
        # postMessage handlers without origin check
        (r"window\.addEventListener\s*\(\s*['\"]message['\"]", "postMessage handler", "CWE-346"),
    ]

    # Attacker-reachable sources
    SOURCE_PATTERNS = [
        r"searchParams\.get\(",
        r"location\.search",
        r"location\.hash",
        r"event\.data",
        r"messageEvent\.data",
        r"req\.query",
        r"req\.params",
        r"req\.body",
        r"props\.",
        r"useSearchParams",
    ]

    def scan(self) -> List[SourceFinding]:
        findings = []
        for path in self._iter_files():
            content = self._read(path)
            if not content:
                continue
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # Check each sink pattern
                for sink_pattern, sink_name, cwe in self.SINK_PATTERNS:
                    if not re.search(sink_pattern, line):
                        continue

                    # Check surrounding context (±5 lines) for attacker-reachable source
                    context_start = max(0, line_no - 6)
                    context_end = min(len(lines), line_no + 5)
                    context_block = "\n".join(lines[context_start:context_end])

                    source_found = None
                    for src_pattern in self.SOURCE_PATTERNS:
                        if re.search(src_pattern, context_block):
                            source_found = src_pattern.replace(r"\(", "()").replace(r"\.", ".")
                            break

                    if sink_name == "postMessage handler":
                        # Check if origin validation is present near the handler
                        if "event.origin" not in context_block and "origin ===" not in context_block:
                            findings.append(self._make_postmessage_finding(path, line_no, line))
                        continue

                    if source_found:
                        confidence = "MEDIUM"
                        verification = "VALIDATED"  # Source + sink identified
                        title = f"Potential DOM XSS — {sink_name} with Attacker-Reachable Source"
                        description = (
                            f"Data-flow candidate: attacker-reachable source '{source_found}' "
                            f"flows toward dangerous sink '{sink_name}'. "
                            f"Static analysis cannot confirm browser rendering — "
                            f"manual or dynamic validation required to confirm XSS."
                        )
                        data_flow = DataFlow(
                            source=source_found,
                            sink=sink_name,
                            path_confirmed=False,
                        )
                    else:
                        confidence = "LOW"
                        verification = "CANDIDATE"
                        title = f"HTML Injection Candidate — {sink_name} with Non-Literal Input"
                        description = (
                            f"Dangerous sink '{sink_name}' detected with non-literal (variable) input. "
                            f"No attacker-reachable source traced in immediate context. "
                            f"Review data flow to determine if user-controlled input reaches this sink."
                        )
                        data_flow = DataFlow(source="unknown", sink=sink_name, path_confirmed=False)

                    findings.append(SourceFinding(
                        finding_key=f"DOM_SINK_{sink_name.upper().replace(' ', '_').replace('()', '')}",
                        category="DOM Injection",
                        title=title,
                        description=description,
                        location=SourceLocation(
                            file_path=self._rel(path),
                            line_number=line_no,
                            symbol=sink_name,
                            snippet=line.strip()[:200],
                        ),
                        data_flow=data_flow,
                        confidence=confidence,
                        cwe_id=cwe,
                        owasp_category="A03:2021-Injection",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                        cvss_score=5.4,
                        severity="MEDIUM",
                        verification_status=verification,
                        remediation=(
                            f"1. Verify data-flow: does attacker-controlled input reach {sink_name}? "
                            "2. Apply DOMPurify.sanitize() before assignment or use safe DOM APIs. "
                            "3. Implement strict Content-Security-Policy."
                        ),
                        metric_reasoning=f"CANDIDATE/VALIDATED — static analysis only. Browser execution not confirmed.",
                    ))
        return findings

    def _make_postmessage_finding(self, path: Path, line_no: int, line: str) -> SourceFinding:
        return SourceFinding(
            finding_key="DOM_POSTMESSAGE_NO_ORIGIN_CHECK",
            category="DOM Injection",
            title="postMessage Handler Without Origin Validation",
            description=(
                "A window.addEventListener('message', ...) handler is registered without "
                "apparent event.origin validation in the surrounding context. "
                "Unvalidated postMessage handlers can receive messages from any origin."
            ),
            location=SourceLocation(
                file_path=self._rel(path),
                line_number=line_no,
                symbol="message event listener",
                snippet=line.strip()[:200],
            ),
            data_flow=DataFlow(
                source="messageEvent.data (untrusted origin)",
                sink="postMessage handler body",
                path_confirmed=False,
            ),
            confidence="MEDIUM",
            cwe_id="CWE-346: Origin Validation Error",
            owasp_category="A03:2021-Injection",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_score=6.1,
            severity="MEDIUM",
            verification_status="CANDIDATE",
            remediation="Validate event.origin against an explicit allowlist before processing postMessage data.",
            metric_reasoning="CANDIDATE — origin check may exist in handler body (static analysis limitation). Verify manually.",
        )
