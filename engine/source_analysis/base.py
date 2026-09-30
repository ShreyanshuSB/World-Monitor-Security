"""
Source Analysis Engine — Base classes and data models for static analysis findings.

All source analysis findings:
  - origin: SOURCE_STATIC
  - environment_type: WORLD_MONITOR_SOURCE
  - verification_status: CANDIDATE (pending dynamic validation)

Candidate findings are NEVER auto-elevated to CONFIRMED just because a keyword exists.
They require data-flow validation or dynamic confirmation.
"""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Optional, List
from pathlib import Path


@dataclass
class SourceLocation:
    """Identifies a specific location within the source repository."""
    file_path: str        # relative to repo root
    line_number: int
    column: Optional[int] = None
    symbol: Optional[str] = None
    snippet: Optional[str] = None


@dataclass
class DataFlow:
    """Models a data-flow path from source to sink."""
    source: str           # e.g. "URL query parameter", "messageEvent.data"
    validation: Optional[str] = None   # e.g. "hostname check", "allowlist"
    transformation: Optional[str] = None  # e.g. "string concatenation"
    sink: str = ""        # e.g. "fetch()", "innerHTML", "eval()"
    path_confirmed: bool = False  # True only when full path is traced


@dataclass
class SourceFinding:
    """
    A candidate finding from static source analysis.
    NOT automatically a vulnerability — requires validation.
    """
    finding_record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_key: str = ""
    category: str = ""        # e.g. "POTENTIAL_SSRF", "SECRET_EXPOSURE"
    title: str = ""
    description: str = ""
    location: Optional[SourceLocation] = None
    data_flow: Optional[DataFlow] = None
    confidence: str = "LOW"   # HIGH | MEDIUM | LOW
    cwe_id: str = ""
    owasp_category: str = ""
    cvss_vector: str = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    cvss_score: float = 3.7
    severity: str = "LOW"
    verification_status: str = "CANDIDATE"
    origin: str = "SOURCE_STATIC"
    environment_type: str = "WORLD_MONITOR_SOURCE"
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metric_reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_record_id": self.finding_record_id,
            "finding_key": self.finding_key,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "origin": self.origin,
            "environment_type": self.environment_type,
            "verification_status": self.verification_status,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "remediation": self.remediation,
            "metric_reasoning": self.metric_reasoning,
            "source_file": self.location.file_path if self.location else None,
            "line_number": self.location.line_number if self.location else None,
            "symbol": self.location.symbol if self.location else None,
            "source_snippet": self.location.snippet if self.location else None,
            "data_flow_source": self.data_flow.source if self.data_flow else None,
            "data_flow_sink": self.data_flow.sink if self.data_flow else None,
            "references": self.references,
        }


class BaseScanner:
    """
    Abstract base for all source analysis scanners.

    Each scanner:
      1. Walks the repository tree looking for relevant files
      2. Applies pattern matching and optional AST-aware parsing
      3. Returns SourceFinding candidates (NOT confirmed vulnerabilities)
      4. Never elevates a candidate based on keyword alone
    """

    SCANNER_NAME = "BaseScanner"
    RELEVANT_EXTENSIONS: List[str] = []

    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)

    def scan(self) -> List[SourceFinding]:
        raise NotImplementedError

    def _iter_files(self, extensions: Optional[List[str]] = None) -> List[Path]:
        """Walk repo and yield files matching extensions."""
        exts = extensions or self.RELEVANT_EXTENSIONS
        result = []
        skip_dirs = {
            "node_modules", ".git", "dist", "build", ".next",
            "__pycache__", ".venv", "venv", "env", "target", ".gradle"
        }
        for path in self.repo_root.rglob("*"):
            # Skip hidden/build directories
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.is_file() and (not exts or path.suffix in exts):
                result.append(path)
        return result

    def _rel(self, path: Path) -> str:
        """Return path relative to repo root as string."""
        try:
            return str(path.relative_to(self.repo_root))
        except ValueError:
            return str(path)

    def _read(self, path: Path) -> Optional[str]:
        """Safe file read — returns None on binary/decode error."""
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
