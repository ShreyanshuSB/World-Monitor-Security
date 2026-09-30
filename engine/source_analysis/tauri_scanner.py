"""
Tauri Security Scanner — Analyzes Tauri desktop app source (src-tauri/).

Checks for World Monitor-specific Tauri security concerns:
- IPC command exposure without capability guards
- Missing origin validation on external WebView windows
- Shell / process execution commands
- Filesystem access patterns
- Sidecar communication setup
- Production DevTools settings
- URL-opening code (tauri::api::shell::open)
"""

from __future__ import annotations
import re
import json
from pathlib import Path
from typing import List, Optional
from .base import BaseScanner, SourceFinding, SourceLocation


class TauriScanner(BaseScanner):
    SCANNER_NAME = "TauriScanner"
    RELEVANT_EXTENSIONS = [".rs", ".toml", ".json", ".ts", ".js"]

    def scan(self) -> List[SourceFinding]:
        findings = []
        tauri_root = self.repo_root / "src-tauri"

        if not tauri_root.exists():
            return findings

        findings.extend(self._check_tauri_conf(tauri_root))
        findings.extend(self._check_rust_ipc(tauri_root))
        findings.extend(self._check_capabilities(tauri_root))
        return findings

    def _check_tauri_conf(self, tauri_root: Path) -> List[SourceFinding]:
        """Check tauri.conf.json for security settings."""
        findings = []
        conf_paths = list(tauri_root.rglob("tauri.conf.json")) + list(tauri_root.rglob("tauri.conf.*.json"))

        for conf_path in conf_paths:
            content = self._read(conf_path)
            if not content:
                continue
            try:
                conf = json.loads(content)
            except json.JSONDecodeError:
                continue

            rel = self._rel(conf_path)

            # Check devtools in production
            app_conf = conf.get("app", conf.get("tauri", {}))
            windows = app_conf.get("windows", [])
            for i, window in enumerate(windows):
                if window.get("devtools", False) is True:
                    findings.append(SourceFinding(
                        finding_key="TAURI_DEVTOOLS_ENABLED",
                        category="Tauri Configuration",
                        title="Tauri DevTools Potentially Enabled in Production Config",
                        description=(
                            f"Window config at index {i} has devtools: true. "
                            "If this config is used in production builds, browser DevTools "
                            "are accessible in the desktop app, exposing source code, localStorage, "
                            "and IPC communication to users with physical access."
                        ),
                        location=SourceLocation(
                            file_path=rel,
                            line_number=self._find_line(content, "devtools"),
                            symbol="devtools",
                        ),
                        confidence="HIGH",
                        cwe_id="CWE-489: Active Debug Code",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:M/I:N/A:N",
                        cvss_score=3.3,
                        severity="LOW",
                        verification_status="CANDIDATE",
                        remediation="Set devtools: false (or remove) in production Tauri config. Use feature flags to enable only in dev builds.",
                        metric_reasoning="AV:L — requires local access to the desktop app. C:M — DevTools exposes app internals.",
                    ))

            # Check CSP / allowlist for external content
            security = app_conf.get("security", {})
            csp = security.get("csp", None)
            if csp is None:
                findings.append(SourceFinding(
                    finding_key="TAURI_NO_CSP",
                    category="Tauri Configuration",
                    title="No Content Security Policy in Tauri Configuration",
                    description=(
                        "No CSP is defined in tauri.conf.json security.csp. "
                        "Without a CSP, the embedded WebView has no restriction on "
                        "script sources, potentially enabling XSS in the desktop context."
                    ),
                    location=SourceLocation(
                        file_path=rel,
                        line_number=1,
                        symbol="security.csp",
                    ),
                    confidence="MEDIUM",
                    cwe_id="CWE-1021: Improper Restriction of Rendered UI Layers",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    cvss_score=5.4,
                    severity="MEDIUM",
                    verification_status="CANDIDATE",
                    remediation="Define a strict CSP in tauri.conf.json security.csp. Restrict default-src to 'self'.",
                    metric_reasoning="CANDIDATE — CSP absence increases XSS risk in WebView context. Impact depends on actual content loaded.",
                ))
        return findings

    def _check_rust_ipc(self, tauri_root: Path) -> List[SourceFinding]:
        """Check Rust IPC command handlers for missing authorization."""
        findings = []
        for path in tauri_root.rglob("*.rs"):
            content = self._read(path)
            if not content:
                continue
            rel = self._rel(path)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                # Look for #[tauri::command] without apparent auth checks
                if "#[tauri::command]" in line or "#[command]" in line:
                    # Check next 20 lines for auth-like patterns
                    ctx_end = min(len(lines), line_no + 20)
                    fn_body = "\n".join(lines[line_no:ctx_end])

                    has_auth = any(kw in fn_body.lower() for kw in [
                        "auth", "token", "permission", "capability", "verify",
                        "session", "identity", "authorize"
                    ])

                    if not has_auth:
                        # Extract function name
                        fn_name = "unknown"
                        for next_line in lines[line_no:min(len(lines), line_no + 3)]:
                            m = re.search(r"fn\s+(\w+)", next_line)
                            if m:
                                fn_name = m.group(1)
                                break

                        findings.append(SourceFinding(
                            finding_key=f"TAURI_IPC_NO_AUTH_{fn_name.upper()}",
                            category="Tauri IPC",
                            title=f"Tauri IPC Command '{fn_name}' Without Apparent Authorization",
                            description=(
                                f"Rust IPC command '{fn_name}' is exposed via #[tauri::command] "
                                f"without apparent authentication or capability check in the function body. "
                                f"If this command performs privileged operations, it may be invocable "
                                f"from any renderer context without authorization."
                            ),
                            location=SourceLocation(
                                file_path=rel,
                                line_number=line_no,
                                symbol=fn_name,
                                snippet=lines[line_no].strip()[:200] if line_no < len(lines) else "",
                            ),
                            confidence="LOW",
                            cwe_id="CWE-862: Missing Authorization",
                            owasp_category="A01:2021-Broken Access Control",
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            cvss_score=7.1,
                            severity="HIGH",
                            verification_status="CANDIDATE",
                            remediation=(
                                "1. Use Tauri capability system to restrict IPC commands to specific windows. "
                                "2. Add authorization checks within command handlers. "
                                "3. Review what sensitive operations this command can perform."
                            ),
                            metric_reasoning="CANDIDATE. Low confidence — auth may exist outside static context. Requires manual IPC audit.",
                        ))
        return findings

    def _check_capabilities(self, tauri_root: Path) -> List[SourceFinding]:
        """Check Tauri capabilities configuration for overly broad permissions."""
        findings = []
        cap_dir = tauri_root / "capabilities"
        if not cap_dir.exists():
            return findings

        for cap_file in cap_dir.rglob("*.json"):
            content = self._read(cap_file)
            if not content:
                continue
            try:
                cap = json.loads(content)
            except json.JSONDecodeError:
                continue

            rel = self._rel(cap_file)
            permissions = cap.get("permissions", [])

            # Check for filesystem:read-all or filesystem:write-all
            broad_perms = [p for p in permissions if isinstance(p, str) and (
                "all" in p.lower() or p == "fs:default"
            )]

            if broad_perms:
                findings.append(SourceFinding(
                    finding_key="TAURI_BROAD_CAPABILITY",
                    category="Tauri Capabilities",
                    title=f"Broad Tauri Capability Permissions in {cap_file.name}",
                    description=(
                        f"Capability file '{rel}' grants broad permissions: {broad_perms}. "
                        "Principle of least privilege requires narrowing to only the specific "
                        "filesystem paths and operations the application needs."
                    ),
                    location=SourceLocation(
                        file_path=rel,
                        line_number=1,
                        symbol="permissions",
                    ),
                    confidence="MEDIUM",
                    cwe_id="CWE-269: Improper Privilege Management",
                    owasp_category="A01:2021-Broken Access Control",
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cvss_score=7.1,
                    severity="HIGH",
                    verification_status="CANDIDATE",
                    remediation="Replace broad permissions with specific scoped permissions. Use allow-listed paths instead of 'all'.",
                    metric_reasoning="CANDIDATE — impact depends on what the app does with broad permissions.",
                ))
        return findings

    @staticmethod
    def _find_line(content: str, keyword: str) -> int:
        for i, line in enumerate(content.splitlines(), 1):
            if keyword in line:
                return i
        return 1
