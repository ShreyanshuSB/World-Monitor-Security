"""Dependency Scanner — Checks package.json for known vulnerable dependencies."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, SourceFinding, SourceLocation


# Known vulnerable version ranges for common packages (illustrative, not exhaustive)
# Format: package -> [(vulnerable_semver_pattern, fixed_version, cve, description)]
KNOWN_ADVISORIES: Dict[str, List[tuple]] = {
    "axios": [
        (r"^0\.[0-9]+\.", "1.6.0", "CVE-2023-45857", "CSRF via cross-site request in axios < 1.6.0"),
    ],
    "next": [
        (r"^1[0-2]\.", "13.5.1", "CVE-2023-46298", "Next.js DoS via infinite loop in dev server"),
    ],
    "vite": [
        (r"^[1-3]\.", "4.5.2", "CVE-2024-23331", "Vite dev server bypasses for source code exposure"),
    ],
    "semver": [
        (r"^[5-6]\.", "7.5.2", "CVE-2022-25883", "ReDoS via semver.satisfies"),
    ],
    "tough-cookie": [
        (r"^[0-3]\.", "4.1.3", "CVE-2023-26136", "Prototype pollution in tough-cookie"),
    ],
}


class DependencyScanner(BaseScanner):
    SCANNER_NAME = "DependencyScanner"

    def scan(self) -> List[SourceFinding]:
        findings = []
        for pkg_file in self.repo_root.rglob("package.json"):
            rel = self._rel(pkg_file)
            # Skip node_modules
            if "node_modules" in rel:
                continue
            content = self._read(pkg_file)
            if not content:
                continue
            try:
                pkg = json.loads(content)
            except json.JSONDecodeError:
                continue

            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))

            for pkg_name, version_spec in all_deps.items():
                if pkg_name not in KNOWN_ADVISORIES:
                    continue
                # Strip semver operators
                version = re.sub(r"[^0-9.]", "", version_spec)
                for vuln_pattern, fixed_version, cve, description in KNOWN_ADVISORIES[pkg_name]:
                    if re.match(vuln_pattern, version):
                        findings.append(SourceFinding(
                            finding_key=f"DEP_VULN_{pkg_name.upper().replace('-','_')}",
                            category="Dependency Advisory",
                            title=f"Vulnerable Dependency: {pkg_name}@{version_spec} ({cve})",
                            description=(
                                f"Advisory {cve}: {description}. "
                                f"Current version: {version_spec}. Fixed in: >= {fixed_version}. "
                                f"Reachability must be verified — this is a DEPENDENCY ADVISORY, "
                                f"not a confirmed application vulnerability."
                            ),
                            location=SourceLocation(
                                file_path=rel,
                                line_number=self._find_line(content, pkg_name),
                                symbol=f"{pkg_name}@{version_spec}",
                            ),
                            confidence="MEDIUM",
                            cwe_id="CWE-1035: Vulnerable Third-Party Component",
                            owasp_category="A06:2021-Vulnerable and Outdated Components",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cvss_score=5.3,
                            severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation=f"Upgrade {pkg_name} to >= {fixed_version}. Verify reachability of vulnerable code path.",
                            metric_reasoning=(
                                f"DEPENDENCY ADVISORY — not a confirmed application vulnerability. "
                                f"CVE CVSS may differ from application CVSS (depends on reachability). "
                                f"Verify whether vulnerable code path is reachable in this application."
                            ),
                            references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                        ))

        # Also check lockfile for pinned vulnerable versions
        for lock_file in self.repo_root.rglob("package-lock.json"):
            rel = self._rel(lock_file)
            if "node_modules" in rel:
                continue
            content = self._read(lock_file)
            if not content or len(content) > 2_000_000:  # Skip very large lockfiles
                continue
            try:
                lock = json.loads(content)
            except json.JSONDecodeError:
                continue

            packages = lock.get("packages", lock.get("dependencies", {}))
            for pkg_path, pkg_info in packages.items():
                pkg_name = pkg_path.split("node_modules/")[-1].split("/")[0]
                if pkg_name not in KNOWN_ADVISORIES:
                    continue
                version = pkg_info.get("version", "")
                for vuln_pattern, fixed_version, cve, description in KNOWN_ADVISORIES[pkg_name]:
                    if re.match(vuln_pattern, version):
                        findings.append(SourceFinding(
                            finding_key=f"DEP_LOCK_VULN_{pkg_name.upper().replace('-','_')}",
                            category="Dependency Advisory",
                            title=f"Vulnerable Locked Dependency: {pkg_name}@{version} ({cve})",
                            description=(
                                f"Lockfile pins {pkg_name}@{version} which matches vulnerability pattern for {cve}. "
                                f"Fixed in: >= {fixed_version}. "
                                "DEPENDENCY ADVISORY — verify reachability before confirming."
                            ),
                            location=SourceLocation(file_path=rel, line_number=1, symbol=f"{pkg_name}@{version}"),
                            confidence="MEDIUM",
                            cwe_id="CWE-1035: Vulnerable Third-Party Component",
                            owasp_category="A06:2021-Vulnerable and Outdated Components",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cvss_score=5.3,
                            severity="MEDIUM",
                            verification_status="CANDIDATE",
                            remediation=f"Run npm audit and upgrade {pkg_name} to >= {fixed_version}.",
                            metric_reasoning="CANDIDATE dependency advisory. Reachability not assessed.",
                            references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                        ))
        return findings

    @staticmethod
    def _find_line(content: str, keyword: str) -> int:
        for i, line in enumerate(content.splitlines(), 1):
            if f'"{keyword}"' in line:
                return i
        return 1
