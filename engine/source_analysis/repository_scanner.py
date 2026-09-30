"""
Repository Scanner — Discovers and catalogs the World Monitor source tree.

Identifies:
- Technology stack
- Security-sensitive directories
- Configuration files
- Authentication entry points
- API route definitions
- Dependency manifests
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, SourceFinding, SourceLocation


class RepositoryScanner(BaseScanner):
    SCANNER_NAME = "RepositoryScanner"

    # World Monitor-specific security-sensitive paths
    SECURITY_SENSITIVE_PATHS = [
        "src-tauri",           # Tauri IPC, capabilities, permissions
        "convex",              # Convex backend functions / access control
        "src/lib/auth",        # Authentication logic
        "src/lib/session",     # Session handling
        "src/api",             # API routes
        "src/middleware",      # Middleware
        ".github/workflows",   # CI/CD — check for secret exposure
        "*.env*",              # Environment files
        "vite.config*",        # Build config — source maps, defines
    ]

    TECH_MARKERS = {
        "TypeScript": [".ts", ".tsx"],
        "JavaScript": [".js", ".jsx", ".mjs"],
        "Rust": [".rs"],
        "Python": [".py"],
        "Tauri": ["tauri.conf.json", "Cargo.toml"],
        "Convex": ["convex.json", "_generated"],
        "Vite": ["vite.config.ts", "vite.config.js"],
    }

    def scan(self) -> List[SourceFinding]:
        findings = []
        catalog = self._build_catalog()
        findings.extend(self._check_source_maps(catalog))
        findings.extend(self._check_env_files(catalog))
        findings.extend(self._check_ci_secrets(catalog))
        return findings

    def _build_catalog(self) -> Dict[str, Any]:
        """Build a map of discovered technologies and sensitive paths."""
        catalog: Dict[str, Any] = {
            "tech_stack": [],
            "sensitive_dirs": [],
            "config_files": [],
            "total_files": 0,
        }
        for path in self._iter_files():
            catalog["total_files"] += 1
            for tech, extensions in self.TECH_MARKERS.items():
                if path.suffix in extensions or path.name in extensions:
                    if tech not in catalog["tech_stack"]:
                        catalog["tech_stack"].append(tech)
            rel = self._rel(path)
            for sensitive in self.SECURITY_SENSITIVE_PATHS:
                if sensitive.startswith("*"):
                    pattern = sensitive.replace("*.", ".")
                    if rel.endswith(pattern) or f"/{pattern.lstrip('/')}" in f"/{rel}":
                        catalog["sensitive_dirs"].append(rel)
                elif sensitive in rel:
                    if sensitive not in catalog["sensitive_dirs"]:
                        catalog["sensitive_dirs"].append(sensitive)
        return catalog

    def _check_source_maps(self, catalog: Dict) -> List[SourceFinding]:
        """Check if source maps are enabled in production Vite config."""
        findings = []
        for path in self._iter_files([".ts", ".js"]):
            if "vite.config" not in path.name:
                continue
            content = self._read(path)
            if not content:
                continue
            # sourcemap: true in build config is a potential source disclosure
            if re.search(r"sourcemap\s*:\s*true", content):
                findings.append(SourceFinding(
                    finding_key="SOURCE_MAP_IN_PRODUCTION",
                    category="Configuration",
                    title="Source Maps Potentially Enabled in Production Build",
                    description=(
                        "Vite configuration contains 'sourcemap: true' which may include "
                        "TypeScript/JavaScript source maps in production builds. "
                        "This exposes original source code to anyone with DevTools access."
                    ),
                    location=SourceLocation(
                        file_path=self._rel(path),
                        line_number=self._find_line(content, "sourcemap"),
                        symbol="sourcemap",
                        snippet=self._extract_snippet(content, "sourcemap"),
                    ),
                    confidence="MEDIUM",
                    cwe_id="CWE-540: Inclusion of Sensitive Information in Source Code",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cvss_score=5.3,
                    severity="MEDIUM",
                    verification_status="CANDIDATE",
                    remediation="Set sourcemap: false (or remove) for production builds. Use separate source-map service for internal debugging.",
                    metric_reasoning="C:L — source disclosure narrows attacker knowledge. Needs verification that build output actually includes maps.",
                ))
        return findings

    def _check_env_files(self, catalog: Dict) -> List[SourceFinding]:
        """Check for committed .env files (not .env.example)."""
        findings = []
        env_patterns = [".env", ".env.local", ".env.production", ".env.staging"]
        for path in self._iter_files():
            if path.name in env_patterns and ".example" not in path.name:
                content = self._read(path)
                if not content:
                    continue
                # Check if file has real values (not just placeholders)
                has_values = bool(re.search(r'^[A-Z_]+=\S+', content, re.MULTILINE))
                if has_values:
                    findings.append(SourceFinding(
                        finding_key="COMMITTED_ENV_FILE",
                        category="Secret Storage",
                        title="Environment File with Potential Secrets in Repository",
                        description=(
                            f"File '{path.name}' found in repository with key=value pairs. "
                            "If committed to version control, secrets in this file are exposed "
                            "to all repository readers."
                        ),
                        location=SourceLocation(
                            file_path=self._rel(path),
                            line_number=1,
                            symbol=path.name,
                        ),
                        confidence="HIGH",
                        cwe_id="CWE-312: Cleartext Storage of Sensitive Information",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=6.5,
                        severity="HIGH",
                        verification_status="CANDIDATE",
                        remediation="Add .env to .gitignore immediately. Rotate any secrets that may have been committed. Use .env.example for documentation.",
                        metric_reasoning="PR:L — requires repo read access. C:H — all secrets in file potentially exposed.",
                    ))
        return findings

    def _check_ci_secrets(self, catalog: Dict) -> List[SourceFinding]:
        """Check CI/CD workflow files for hardcoded secrets."""
        findings = []
        ci_dirs = [".github/workflows", ".gitlab-ci.yml", "Jenkinsfile"]
        for path in self._iter_files([".yml", ".yaml", ".json"]):
            rel = self._rel(path)
            if not any(ci in rel for ci in [".github/workflows", "gitlab-ci", "Jenkins"]):
                continue
            content = self._read(path)
            if not content:
                continue
            # Look for suspicious hardcoded strings (not ${{ secrets.X }} references)
            for line_no, line in enumerate(content.splitlines(), 1):
                if re.search(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\'][^$][^"\']{8,}["\']', line):
                    findings.append(SourceFinding(
                        finding_key="CI_HARDCODED_SECRET",
                        category="Secret Storage",
                        title="Potential Hardcoded Secret in CI/CD Configuration",
                        description=(
                            f"CI/CD file '{rel}' line {line_no} contains a pattern matching "
                            "hardcoded credential. GitHub Actions secrets (${{{{ secrets.X }}}}) "
                            "are the correct pattern; hardcoded values are not."
                        ),
                        location=SourceLocation(
                            file_path=rel,
                            line_number=line_no,
                            snippet=line.strip()[:120],
                        ),
                        confidence="MEDIUM",
                        cwe_id="CWE-798: Use of Hard-coded Credentials",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=6.5,
                        severity="HIGH",
                        verification_status="CANDIDATE",
                        remediation="Use repository secret variables (${{ secrets.VAR_NAME }}) exclusively. Never hardcode credentials in YAML.",
                        metric_reasoning="Candidate only — must verify value is not a placeholder before confirming.",
                    ))
        return findings

    @staticmethod
    def _find_line(content: str, keyword: str) -> int:
        for i, line in enumerate(content.splitlines(), 1):
            if keyword in line:
                return i
        return 1

    @staticmethod
    def _extract_snippet(content: str, keyword: str, context: int = 2) -> str:
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if keyword in line:
                start = max(0, i - context)
                end = min(len(lines), i + context + 1)
                return "\n".join(lines[start:end])
        return ""
