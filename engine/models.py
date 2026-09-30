"""
Security Assessment Platform - Core Data Schemas (Pydantic)
v2: adds origin, verification_status, environment_type, finding_key, source analysis fields.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class EvidenceModel(BaseModel):
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str] = None
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    timestamp: str
    duration_ms: float
    note: Optional[str] = None


class FindingModel(BaseModel):
    # Primary identifiers
    finding_record_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID — unique per finding record per assessment run"
    )
    assessment_id: str = Field("UNASSIGNED", description="FK to assessment run")
    finding_key: str = Field(..., description="Stable logical key e.g. AUTHZ_IDOR_REPORT")

    # Legacy field kept for backward-compat with existing frontend code
    id: Optional[str] = Field(None, description="Legacy ID alias; populated from finding_key+assessment prefix")
    vuln_key: str = Field(..., description="Lab patch toggle key (same as finding_key for lab findings)")

    # Classification trinity — MANDATORY on every finding
    origin: str = Field(
        "LAB_SYNTHETIC",
        description="SOURCE_STATIC | DYNAMIC_LOCAL | LAB_SYNTHETIC"
    )
    environment_type: str = Field(
        "LAB_SYNTHETIC",
        description="WORLD_MONITOR_SOURCE | WORLD_MONITOR_LOCAL | LAB_SYNTHETIC"
    )
    verification_status: str = Field(
        "CANDIDATE",
        description="CANDIDATE | VALIDATED | CONFIRMED | FALSE_POSITIVE | REMEDIATED"
    )

    # Content
    title: str
    description: str
    affected_component: str
    scope_area: str
    cwe_id: str
    owasp_category: str
    cvss_vector: str
    cvss_score: float
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    metric_reasoning: Optional[str] = None  # CVSS manual justification

    steps_to_reproduce: List[str]
    proof_of_concept: str
    business_impact: str
    remediation: str
    code_diff: str

    # Legacy status for UI compatibility
    status: str = "CANDIDATE"

    evidence: EvidenceModel

    # Source-analysis fields (for SOURCE_STATIC findings)
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    symbol: Optional[str] = None
    source_snippet: Optional[str] = None
    data_flow_source: Optional[str] = None
    data_flow_sink: Optional[str] = None
    confidence: Optional[str] = None  # HIGH | MEDIUM | LOW

    # Advisory
    public_advisory_status: Optional[str] = None
    known_issue: bool = False
    newly_discovered: bool = True

    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    def model_post_init(self, __context: Any) -> None:
        """Auto-populate the legacy id field from finding_key if not set."""
        if not self.id:
            object.__setattr__(self, 'id', self.finding_record_id)


class AssessmentRunModel(BaseModel):
    id: str
    target_url: str
    assessment_mode: str = "LAB"   # SOURCE | DYNAMIC | LAB
    source_repo_path: Optional[str] = None
    status: str  # INITIALIZED | RUNNING | COMPLETED | FAILED
    authorized: bool
    operator_identifier: str = "sec_engineer"
    authorization_scope: Optional[str] = None
    started_at: str
    completed_at: Optional[str] = None
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = {}
    modules_scanned: List[str] = []


class AuditLogModel(BaseModel):
    id: Optional[int] = None
    timestamp: str
    action: str
    target: str
    operator: str = "security_auditor"
    status: str
    details: Dict[str, Any] = {}
    prev_hash: Optional[str] = None
    row_hash: Optional[str] = None


class RetestResultModel(BaseModel):
    finding_id: str
    finding_key: Optional[str] = None
    passed: bool
    previous_status: str
    new_status: str
    before_evidence: Dict[str, Any]
    after_evidence: Dict[str, Any]
    changed_behavior: Optional[str] = None
