"""
Security Assessment Platform - Platform Database (SQLite)
Persists assessment runs, findings, audit trails, and retest evidence.

Schema v2 — adds:
  - UUID-based finding_record_id (PK) + finding_key (stable logical key)
  - origin: SOURCE_STATIC | DYNAMIC_LOCAL | LAB_SYNTHETIC
  - verification_status: CANDIDATE | VALIDATED | CONFIRMED | FALSE_POSITIVE | REMEDIATED
  - environment_type: WORLD_MONITOR_SOURCE | WORLD_MONITOR_LOCAL | LAB_SYNTHETIC
  - assessment_mode: SOURCE | DYNAMIC | LAB
  - Audit-chain hash for append-only integrity
"""

import os
import json
import hashlib
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

PLATFORM_DB_PATH = os.path.join(os.path.dirname(__file__), "assessment.db")
DATABASE_URL = f"sqlite:///{PLATFORM_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AssessmentRunEntity(Base):
    __tablename__ = "assessment_runs"

    id = Column(String(50), primary_key=True)          # ASM-<hex>
    target_url = Column(String(200), nullable=False)
    assessment_mode = Column(String(20), default="LAB") # SOURCE | DYNAMIC | LAB
    source_repo_path = Column(String(500), nullable=True)
    status = Column(String(30), default="INITIALIZED")  # INITIALIZED|RUNNING|COMPLETED|FAILED
    authorized = Column(Boolean, default=False)
    authorization_timestamp = Column(DateTime, nullable=True)
    operator_identifier = Column(String(100), default="sec_engineer")
    authorization_scope = Column(String(200), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_findings = Column(Integer, default=0)
    findings_by_severity_json = Column(Text, default="{}")
    modules_scanned_json = Column(Text, default="[]")


class FindingEntity(Base):
    """
    One row per finding PER assessment run.
    finding_record_id  — UUID (PK, unique per row)
    assessment_id      — FK to assessment_runs
    finding_key        — stable logical identifier (e.g. AUTHZ_IDOR_REPORT)
    Multiple assessment runs may share the same finding_key.
    """
    __tablename__ = "findings"

    finding_record_id = Column(String(50), primary_key=True)  # UUID
    assessment_id = Column(String(50), nullable=False)
    finding_key = Column(String(100), nullable=False)          # stable logical key
    # Legacy 'id' alias for backwards-compat with older API callers
    id = Column(String(100), nullable=True)
    vuln_key = Column(String(100), nullable=False)

    # Origin / environment classification
    origin = Column(String(20), default="LAB_SYNTHETIC")
    # SOURCE_STATIC | DYNAMIC_LOCAL | LAB_SYNTHETIC
    environment_type = Column(String(30), default="LAB_SYNTHETIC")
    # WORLD_MONITOR_SOURCE | WORLD_MONITOR_LOCAL | LAB_SYNTHETIC
    verification_status = Column(String(20), default="CANDIDATE")
    # CANDIDATE | VALIDATED | CONFIRMED | FALSE_POSITIVE | REMEDIATED

    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    affected_component = Column(String(300), nullable=False)
    scope_area = Column(String(100), nullable=False)
    cwe_id = Column(String(100), nullable=False)
    owasp_category = Column(String(100), nullable=False)
    cvss_vector = Column(String(200), nullable=False)
    cvss_score = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    metric_reasoning = Column(Text, nullable=True)         # CVSS manual justification
    steps_to_reproduce_json = Column(Text, nullable=False)
    proof_of_concept = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    code_diff = Column(Text, nullable=False)

    # Status uses legacy VERIFIED/FIXED/RETESTED_PASS/RETESTED_FAIL for UI compat
    status = Column(String(30), default="CANDIDATE")

    evidence_json = Column(Text, nullable=False)

    # Source analysis fields (populated for SOURCE_STATIC findings)
    source_file = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    symbol = Column(String(200), nullable=True)
    source_snippet = Column(Text, nullable=True)
    data_flow_source = Column(String(200), nullable=True)
    data_flow_sink = Column(String(200), nullable=True)
    confidence = Column(String(20), nullable=True)  # HIGH|MEDIUM|LOW

    # Advisory fields
    public_advisory_status = Column(String(50), nullable=True)
    known_issue = Column(Boolean, default=False)
    newly_discovered = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class AuditLogEntity(Base):
    """
    Append-only audit log with SHA-256 hash chain for integrity.
    Each entry contains the hash of the previous entry, forming a chain.
    Chain can be verified via GET /api/audit-log/verify.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(100), nullable=False)
    target = Column(String(200), nullable=False)
    operator = Column(String(50), default="sec_engineer")
    status = Column(String(30), nullable=False)
    details_json = Column(Text, default="{}")
    prev_hash = Column(String(64), nullable=True)   # SHA-256 of previous row
    row_hash = Column(String(64), nullable=True)    # SHA-256 of this row's content


class RetestRecordEntity(Base):
    __tablename__ = "retest_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(50), nullable=False)      # finding_record_id
    finding_key = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    previous_status = Column(String(30), nullable=False)
    new_status = Column(String(30), nullable=False)
    passed = Column(Boolean, nullable=False)
    before_evidence_json = Column(Text, nullable=False)
    after_evidence_json = Column(Text, nullable=False)
    changed_behavior = Column(Text, nullable=True)


def compute_row_hash(row: AuditLogEntity, prev_hash: str) -> str:
    """Compute deterministic SHA-256 for an audit log row."""
    content = (
        f"{row.id}|{row.timestamp}|{row.action}|{row.target}"
        f"|{row.operator}|{row.status}|{row.details_json}|{prev_hash}"
    )
    return hashlib.sha256(content.encode()).hexdigest()


def get_last_audit_hash(db) -> str:
    last = db.query(AuditLogEntity).order_by(AuditLogEntity.id.desc()).first()
    return last.row_hash if last and last.row_hash else "GENESIS"


def _schema_is_current(connection) -> bool:
    """Return True if the DB already has the v2 schema (finding_record_id column exists)."""
    try:
        result = connection.execute(
            __import__("sqlalchemy").text(
                "SELECT COUNT(*) FROM pragma_table_info('findings') WHERE name='finding_record_id'"
            )
        )
        return result.scalar() > 0
    except Exception:
        return False


def init_platform_db():
    """
    Initialize the platform database.
    If an existing DB has the old v1 schema (missing finding_record_id column),
    it is automatically dropped and recreated with the v2 schema.
    """
    import logging
    log = logging.getLogger("platform_db")

    with engine.connect() as conn:
        current = _schema_is_current(conn)

    if not current:
        log.warning(
            "Schema mismatch detected (v1 DB or new DB). "
            "Dropping all tables and recreating with v2 schema."
        )
        Base.metadata.drop_all(bind=engine)

    Base.metadata.create_all(bind=engine)
    log.info("Platform DB schema v2 ready.")


def get_platform_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
