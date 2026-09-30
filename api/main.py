"""
Security Assessment Platform - Main FastAPI Application v2

Key fixes:
- POST /api/assessments/run: stores mode, source_repo_path, selected modules correctly
- GET /api/assessments/{id}/events: no longer accepts target_url/authorized query params;
  loads everything from stored assessment (prevents parameter injection)
- POST /api/findings/{id}/apply-fix: looks up by finding_record_id, scope-guarded to lab
- POST /api/findings/{id}/retest: no longer accepts target_url param
- GET /api/coverage: fixed coverage status logic (FAIL takes precedence over REMEDIATED)
- GET /api/stats/overview: risk score formula [0,100], never negative, per-mode breakdown
- GET /api/audit-log/verify: returns audit chain integrity verification result
- GET /api/assessments: returns paginated assessment history
- GET /api/assessments/{id}/findings: returns findings for specific assessment
- POST /api/source/analyze: triggers source analysis on stored repo path
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
import httpx

from engine.database import (
    get_platform_db, init_platform_db,
    AssessmentRunEntity, FindingEntity, AuditLogEntity, RetestRecordEntity,
    compute_row_hash, get_last_audit_hash
)
from engine.runner import run_assessment_stream, retest_finding_sync, log_audit, MODULE_REGISTRY
from engine.scope_guard import ScopeGuard, ScopeViolationException
from reports.generator import generate_markdown_report, generate_pdf_report

app = FastAPI(
    title="World Monitor Security Assessment Platform API",
    description="Backend API for SIH26163 (NTRO) Authorized Security Assessment Platform v2",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_platform_db()


# ==================== REQUEST SCHEMAS ====================
class RunAssessmentRequest(BaseModel):
    target_url: str = "http://127.0.0.1:8001"
    authorized_acknowledged: bool = False
    assessment_mode: str = "LAB"         # SOURCE | DYNAMIC | LAB
    source_repo_path: Optional[str] = None
    operator_identifier: str = "sec_engineer"
    authorization_scope: Optional[str] = None
    modules: Optional[List[str]] = None   # If None, all modules run


class RetestRequest(BaseModel):
    pass  # No parameters — target loaded from stored assessment


class SourceAnalysisRequest(BaseModel):
    assessment_id: str
    repo_path: str
    scanners: Optional[List[str]] = None  # None = all scanners


# ==================== SYSTEM STATUS ====================
@app.get("/api/system/status")
def system_status():
    return {
        "status": "OPERATIONAL",
        "version": "2.0.0",
        "service": "World Monitor Security Assessment Platform",
        "scope_guard": {
            "policy": "FAIL_CLOSED_LOCALHOST_ONLY",
            "allowed_hosts": list(ScopeGuard.ALLOWED_HOSTS),
            "trust_env": False,
            "redirect_revalidation": True,
        },
        "assessment_modes": ["SOURCE", "DYNAMIC", "LAB"],
        "available_modules": [
            {"id": mod_id, "name": mod_name}
            for (mod_id, mod_name, _) in MODULE_REGISTRY
        ],
        "compliance": "SIH26163 (NTRO)",
        "environment_types": ["WORLD_MONITOR_SOURCE", "WORLD_MONITOR_LOCAL", "LAB_SYNTHETIC"],
        "origin_types": ["SOURCE_STATIC", "DYNAMIC_LOCAL", "LAB_SYNTHETIC"],
        "verification_states": ["CANDIDATE", "VALIDATED", "CONFIRMED", "FALSE_POSITIVE", "REMEDIATED"],
    }


# ==================== LAUNCH ASSESSMENT ====================
@app.post("/api/assessments/run")
def start_assessment(req: RunAssessmentRequest, db: Session = Depends(get_platform_db)):
    """
    Initializes an assessment run record and returns the assessment_id.
    SECURITY: All parameters (target, modules, authorization) are STORED in the DB.
    The SSE stream endpoint loads from DB — it never trusts query parameters.
    """
    if not req.authorized_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Authorization acknowledgment is required before initiating active probes."
        )

    # Validate mode
    if req.assessment_mode not in ("SOURCE", "DYNAMIC", "LAB"):
        raise HTTPException(status_code=400, detail="assessment_mode must be SOURCE, DYNAMIC, or LAB")

    # Scope guard for dynamic/lab modes (source mode uses local file path)
    if req.assessment_mode in ("DYNAMIC", "LAB"):
        if not ScopeGuard.is_allowed(req.target_url):
            log_audit("ASSESSMENT_REJECTED", req.target_url, "BLOCKED", {"reason": "Scope guard blocked target"})
            raise HTTPException(
                status_code=403,
                detail=f"Target '{req.target_url}' violates Scope Guard policy."
            )

    # Validate source path for SOURCE mode
    if req.assessment_mode == "SOURCE" and req.source_repo_path:
        if not os.path.isdir(req.source_repo_path):
            raise HTTPException(status_code=400, detail=f"Source repo path not found: {req.source_repo_path}")

    # Resolve final module list
    if req.modules:
        valid_ids = {m[0] for m in MODULE_REGISTRY}
        selected = [m for m in req.modules if m in valid_ids]
        if not selected:
            selected = [m[0] for m in MODULE_REGISTRY]
    else:
        selected = [m[0] for m in MODULE_REGISTRY]

    assessment_id = f"ASM-{uuid.uuid4().hex[:8].upper()}"

    run_record = AssessmentRunEntity(
        id=assessment_id,
        target_url=req.target_url,
        assessment_mode=req.assessment_mode,
        source_repo_path=req.source_repo_path,
        status="INITIALIZED",
        authorized=req.authorized_acknowledged,
        authorization_timestamp=datetime.utcnow(),
        operator_identifier=req.operator_identifier,
        authorization_scope=req.authorization_scope,
        started_at=datetime.utcnow(),
        modules_scanned_json=json.dumps(selected),
    )
    db.add(run_record)
    db.commit()

    log_audit("ASSESSMENT_INITIALIZED", req.target_url, "SUCCESS", {
        "assessment_id": assessment_id,
        "mode": req.assessment_mode,
        "modules": selected,
        "operator": req.operator_identifier,
    })

    return {
        "assessment_id": assessment_id,
        "target_url": req.target_url,
        "assessment_mode": req.assessment_mode,
        "status": "INITIALIZED",
        "modules_selected": selected,
        "stream_url": f"/api/assessments/{assessment_id}/events"
    }


# ==================== SSE STREAM ====================
@app.get("/api/assessments/{assessment_id}/events")
async def stream_assessment_events(assessment_id: str):
    """
    Server-Sent Events endpoint.
    SECURITY: Loads target_url, authorized flag, and module list from stored DB record.
    Does NOT accept target_url or authorized as query parameters.
    """
    return StreamingResponse(
        run_assessment_stream(assessment_id=assessment_id),
        media_type="text/event-stream"
    )


# ==================== ASSESSMENT HISTORY ====================
@app.get("/api/assessments")
def list_assessments(
    limit: int = 20,
    mode: Optional[str] = None,
    db: Session = Depends(get_platform_db)
):
    """Returns paginated assessment history."""
    query = db.query(AssessmentRunEntity).order_by(AssessmentRunEntity.started_at.desc())
    if mode:
        query = query.filter(AssessmentRunEntity.assessment_mode == mode.upper())
    records = query.limit(limit).all()
    return [
        {
            "id": r.id,
            "target_url": r.target_url,
            "assessment_mode": r.assessment_mode,
            "status": r.status,
            "authorized": r.authorized,
            "operator_identifier": r.operator_identifier,
            "started_at": r.started_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "total_findings": r.total_findings,
            "findings_by_severity": json.loads(r.findings_by_severity_json or "{}"),
            "modules_scanned": json.loads(r.modules_scanned_json or "[]"),
        }
        for r in records
    ]


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str, db: Session = Depends(get_platform_db)):
    r = db.query(AssessmentRunEntity).filter(AssessmentRunEntity.id == assessment_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Assessment {assessment_id} not found")
    return {
        "id": r.id,
        "target_url": r.target_url,
        "assessment_mode": r.assessment_mode,
        "source_repo_path": r.source_repo_path,
        "status": r.status,
        "authorized": r.authorized,
        "operator_identifier": r.operator_identifier,
        "authorization_scope": r.authorization_scope,
        "started_at": r.started_at.isoformat(),
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "total_findings": r.total_findings,
        "findings_by_severity": json.loads(r.findings_by_severity_json or "{}"),
        "modules_scanned": json.loads(r.modules_scanned_json or "[]"),
    }


@app.get("/api/assessments/{assessment_id}/findings")
def list_assessment_findings(assessment_id: str, db: Session = Depends(get_platform_db)):
    """Returns all findings for a specific assessment run (historical isolation)."""
    findings = (
        db.query(FindingEntity)
        .filter(FindingEntity.assessment_id == assessment_id)
        .order_by(FindingEntity.cvss_score.desc())
        .all()
    )
    return [_serialize_finding(f) for f in findings]


# ==================== FINDINGS EXPLORATION ====================
@app.get("/api/findings")
def list_findings(
    severity: Optional[str] = None,
    domain: Optional[str] = None,
    status: Optional[str] = None,
    origin: Optional[str] = None,
    environment_type: Optional[str] = None,
    verification_status: Optional[str] = None,
    assessment_id: Optional[str] = None,
    component: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_platform_db)
):
    query = db.query(FindingEntity)

    if severity and severity.upper() != "ALL":
        query = query.filter(FindingEntity.severity == severity.upper())
    if domain and domain.upper() != "ALL":
        query = query.filter(FindingEntity.scope_area.ilike(f"%{domain}%"))
    if status and status.upper() != "ALL":
        query = query.filter(FindingEntity.status == status.upper())
    if origin and origin.upper() != "ALL":
        query = query.filter(FindingEntity.origin == origin.upper())
    if environment_type and environment_type.upper() != "ALL":
        query = query.filter(FindingEntity.environment_type == environment_type.upper())
    if verification_status and verification_status.upper() != "ALL":
        query = query.filter(FindingEntity.verification_status == verification_status.upper())
    if assessment_id:
        query = query.filter(FindingEntity.assessment_id == assessment_id)
    if component:
        query = query.filter(FindingEntity.affected_component.ilike(f"%{component}%"))
    if search:
        sf = f"%{search}%"
        query = query.filter(
            (FindingEntity.title.ilike(sf)) |
            (FindingEntity.description.ilike(sf)) |
            (FindingEntity.finding_key.ilike(sf)) |
            (FindingEntity.cwe_id.ilike(sf))
        )

    records = query.order_by(FindingEntity.cvss_score.desc()).all()
    return [_serialize_finding(r) for r in records]


@app.get("/api/findings/{finding_id}")
def get_finding_detail(finding_id: str, db: Session = Depends(get_platform_db)):
    # Try finding_record_id first, then legacy id
    r = db.query(FindingEntity).filter(FindingEntity.finding_record_id == finding_id).first()
    if not r:
        r = db.query(FindingEntity).filter(FindingEntity.id == finding_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")

    retests = (
        db.query(RetestRecordEntity)
        .filter(RetestRecordEntity.finding_id == r.finding_record_id)
        .order_by(RetestRecordEntity.timestamp.desc())
        .all()
    )
    retest_history = [
        {
            "id": rt.id,
            "timestamp": rt.timestamp.isoformat(),
            "previous_status": rt.previous_status,
            "new_status": rt.new_status,
            "passed": rt.passed,
            "before_evidence": json.loads(rt.before_evidence_json),
            "after_evidence": json.loads(rt.after_evidence_json),
            "changed_behavior": rt.changed_behavior,
        }
        for rt in retests
    ]

    result = _serialize_finding(r)
    result["retest_history"] = retest_history
    return result


def _serialize_finding(r: FindingEntity) -> dict:
    return {
        "finding_record_id": r.finding_record_id,
        "id": r.id or r.finding_record_id,
        "assessment_id": r.assessment_id,
        "finding_key": r.finding_key,
        "vuln_key": r.vuln_key,
        "origin": r.origin,
        "environment_type": r.environment_type,
        "verification_status": r.verification_status,
        "title": r.title,
        "description": r.description,
        "affected_component": r.affected_component,
        "scope_area": r.scope_area,
        "cwe_id": r.cwe_id,
        "owasp_category": r.owasp_category,
        "cvss_vector": r.cvss_vector,
        "cvss_score": r.cvss_score,
        "severity": r.severity,
        "metric_reasoning": r.metric_reasoning,
        "steps_to_reproduce": json.loads(r.steps_to_reproduce_json or "[]"),
        "proof_of_concept": r.proof_of_concept,
        "business_impact": r.business_impact,
        "remediation": r.remediation,
        "code_diff": r.code_diff,
        "status": r.status,
        "evidence": json.loads(r.evidence_json or "{}"),
        "source_file": r.source_file,
        "line_number": r.line_number,
        "symbol": r.symbol,
        "source_snippet": r.source_snippet,
        "data_flow_source": r.data_flow_source,
        "data_flow_sink": r.data_flow_sink,
        "confidence": r.confidence,
        "known_issue": r.known_issue,
        "newly_discovered": r.newly_discovered,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


# ==================== REMEDIATION & RETEST ====================
@app.post("/api/findings/{finding_id}/apply-fix")
def apply_fix_to_lab(finding_id: str, db: Session = Depends(get_platform_db)):
    """
    Applies a lab remediation patch toggle.
    Only works on LAB_SYNTHETIC findings — refuses to patch SOURCE/DYNAMIC findings.
    Scope-guarded: only contacts localhost lab.
    """
    f = db.query(FindingEntity).filter(FindingEntity.finding_record_id == finding_id).first()
    if not f:
        f = db.query(FindingEntity).filter(FindingEntity.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    if f.environment_type != "LAB_SYNTHETIC":
        raise HTTPException(
            status_code=400,
            detail=f"Apply-fix only works on LAB_SYNTHETIC findings. This finding is {f.environment_type}."
        )

    lab_patch_url = f"http://127.0.0.1:8001/api/lab/patch/{f.vuln_key}?enable=true"
    try:
        ScopeGuard.enforce("http://127.0.0.1:8001")
        scoped_kwargs = ScopeGuard.make_scoped_client_kwargs()
        ck = {k: v for k, v in scoped_kwargs.items() if k != "follow_redirects"}
        r = httpx.post(lab_patch_url, **ck, timeout=4.0)
        if r.status_code == 200:
            f.status = "FIXED"
            f.verification_status = "REMEDIATED"
            f.updated_at = datetime.utcnow()
            db.commit()
            log_audit("APPLIED_LAB_PATCH", f.affected_component, "SUCCESS", {
                "finding_record_id": f.finding_record_id,
                "finding_key": f.finding_key,
                "vuln_key": f.vuln_key,
                "environment_type": f.environment_type,
            })
            return {
                "success": True,
                "message": f"Lab patch applied for {f.vuln_key}.",
                "finding_record_id": f.finding_record_id,
                "finding_key": f.finding_key,
                "status": f.status,
                "verification_status": f.verification_status,
            }
        else:
            raise HTTPException(status_code=500, detail="Lab target rejected patch request")
    except ScopeViolationException as sve:
        raise HTTPException(status_code=403, detail=str(sve))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lab communication error: {str(e)}")


@app.post("/api/findings/{finding_id}/retest")
def retest_finding(finding_id: str):
    """
    Retests a finding by re-running the associated probe.
    SECURITY: target_url is loaded from stored assessment — not accepted as parameter.
    """
    result = retest_finding_sync(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ==================== SOURCE ANALYSIS ====================
@app.post("/api/source/analyze")
def run_source_analysis(req: SourceAnalysisRequest, db: Session = Depends(get_platform_db)):
    """
    Runs static source analysis on the stored repo path.
    Returns candidate findings (WORLD_MONITOR_SOURCE, SOURCE_STATIC).
    """
    # Load assessment
    run_record = db.query(AssessmentRunEntity).filter(
        AssessmentRunEntity.id == req.assessment_id
    ).first()
    if not run_record:
        raise HTTPException(status_code=404, detail=f"Assessment {req.assessment_id} not found")

    if not os.path.isdir(req.repo_path):
        raise HTTPException(status_code=400, detail=f"Repo path not found: {req.repo_path}")

    # Import dynamically to avoid circular imports
    from engine.source_analysis import (
        RepositoryScanner, SecretScanner, DependencyScanner, DomSinkScanner,
        AuthFlowScanner, AuthzScanner, ApiRouteScanner, SsrfScanner,
        OAuthScanner, CacheScanner, TauriScanner, SidecarScanner,
        CommunicationScanner, StorageScanner,
    )

    ALL_SCANNERS = {
        "repository": RepositoryScanner,
        "secret": SecretScanner,
        "dependency": DependencyScanner,
        "dom_sink": DomSinkScanner,
        "auth_flow": AuthFlowScanner,
        "authz": AuthzScanner,
        "api_route": ApiRouteScanner,
        "ssrf": SsrfScanner,
        "oauth": OAuthScanner,
        "cache": CacheScanner,
        "tauri": TauriScanner,
        "sidecar": SidecarScanner,
        "communication": CommunicationScanner,
        "storage": StorageScanner,
    }

    active_scanners = req.scanners or list(ALL_SCANNERS.keys())
    all_findings = []

    for scanner_key in active_scanners:
        if scanner_key not in ALL_SCANNERS:
            continue
        scanner = ALL_SCANNERS[scanner_key](req.repo_path)
        try:
            findings = scanner.scan()
            all_findings.extend(findings)

            # Persist each source finding
            for sf in findings:
                record_id = sf.finding_record_id
                evidence_data = {
                    "request_method": "STATIC_ANALYSIS",
                    "request_url": f"file://{req.repo_path}",
                    "request_headers": {},
                    "response_status": 0,
                    "response_headers": {},
                    "response_body": sf.location.snippet if sf.location else "",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "duration_ms": 0.0,
                    "note": f"Static analysis by {scanner.SCANNER_NAME}",
                }
                entity = FindingEntity(
                    finding_record_id=record_id,
                    assessment_id=req.assessment_id,
                    finding_key=sf.finding_key,
                    id=record_id,
                    vuln_key=sf.finding_key,
                    origin="SOURCE_STATIC",
                    environment_type="WORLD_MONITOR_SOURCE",
                    verification_status=sf.verification_status,
                    title=sf.title,
                    description=sf.description,
                    affected_component=sf.location.file_path if sf.location else "unknown",
                    scope_area=sf.category,
                    cwe_id=sf.cwe_id,
                    owasp_category=sf.owasp_category,
                    cvss_vector=sf.cvss_vector,
                    cvss_score=sf.cvss_score,
                    severity=sf.severity,
                    metric_reasoning=sf.metric_reasoning,
                    steps_to_reproduce_json=json.dumps([
                        "Review the source code location identified.",
                        "Trace data flow from source to sink (if applicable).",
                        "Validate with dynamic testing before confirming.",
                    ]),
                    proof_of_concept=f"Static analysis: {sf.location.file_path}:{sf.location.line_number}" if sf.location else "See source_file field",
                    business_impact="To be determined after dynamic validation.",
                    remediation=sf.remediation,
                    code_diff="",
                    status=sf.verification_status,
                    evidence_json=json.dumps(evidence_data),
                    source_file=sf.location.file_path if sf.location else None,
                    line_number=sf.location.line_number if sf.location else None,
                    symbol=sf.location.symbol if sf.location else None,
                    source_snippet=sf.location.snippet if sf.location else None,
                    data_flow_source=sf.data_flow.source if sf.data_flow else None,
                    data_flow_sink=sf.data_flow.sink if sf.data_flow else None,
                    confidence=sf.confidence,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                db.add(entity)
        except Exception as e:
            print(f"[Source Analysis] Scanner {scanner_key} error: {e}")

    db.commit()

    log_audit("SOURCE_ANALYSIS_COMPLETED", req.repo_path, "SUCCESS", {
        "assessment_id": req.assessment_id,
        "scanners_run": active_scanners,
        "findings_count": len(all_findings),
    })

    return {
        "assessment_id": req.assessment_id,
        "repo_path": req.repo_path,
        "scanners_run": active_scanners,
        "findings_count": len(all_findings),
        "findings": [sf.to_dict() for sf in all_findings],
        "note": "All findings are CANDIDATE (SOURCE_STATIC). Dynamic validation required before confirming.",
    }


# ==================== COVERAGE & METRICS ====================
@app.get("/api/coverage")
def get_coverage(
    assessment_id: Optional[str] = None,
    db: Session = Depends(get_platform_db)
):
    query = db.query(FindingEntity)
    if assessment_id:
        query = query.filter(FindingEntity.assessment_id == assessment_id)
    findings = query.all()

    domains = [
        "Authentication & Session Management",
        "Authorization & Access Control",
        "Input Validation & Data Handling",
        "API Security",
        "Client-Side Controls",
        "Secure Communication",
        "Data Storage & Privacy",
        "Secret Exposure",
        "DOM Injection",
        "Transport Security",
        "SSRF",
        "Tauri Security",
        "Dependency Advisory",
    ]

    domain_data = {}
    for d in domains:
        domain_data[d] = {
            "name": d,
            "findings_count": 0,
            "max_cvss": 0.0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "confirmed": 0, "remediated": 0, "candidate": 0,
            "status": "PASS"
        }

    for f in findings:
        for d in domains:
            if d.lower() in (f.scope_area or "").lower() or d.lower() in (f.owasp_category or "").lower():
                dd = domain_data[d]
                dd["findings_count"] += 1
                dd["max_cvss"] = max(dd["max_cvss"], f.cvss_score)
                sev_key = f.severity.lower()
                if sev_key in dd:
                    dd[sev_key] += 1

                vs = f.verification_status or ""
                if vs in ("CONFIRMED",):
                    dd["confirmed"] += 1
                    # FAIL takes precedence over REMEDIATED (never overwrite FAIL with REMEDIATED)
                    dd["status"] = "FAIL"
                elif vs == "REMEDIATED" and dd["status"] == "PASS":
                    dd["status"] = "REMEDIATED"
                elif vs == "CANDIDATE":
                    dd["candidate"] += 1
                    if dd["status"] == "PASS":
                        dd["status"] = "CANDIDATE"

    owasp_mapping = {
        "A01:2021-Broken Access Control": {"category": "A01", "name": "Broken Access Control", "count": 0, "findings": []},
        "A02:2021-Cryptographic Failures": {"category": "A02", "name": "Cryptographic Failures", "count": 0, "findings": []},
        "A03:2021-Injection": {"category": "A03", "name": "Injection", "count": 0, "findings": []},
        "A04:2021-Insecure Design": {"category": "A04", "name": "Insecure Design", "count": 0, "findings": []},
        "A05:2021-Security Misconfiguration": {"category": "A05", "name": "Security Misconfiguration", "count": 0, "findings": []},
        "A06:2021-Vulnerable and Outdated Components": {"category": "A06", "name": "Vulnerable Components", "count": 0, "findings": []},
        "A07:2021-Identification and Authentication Failures": {"category": "A07", "name": "Auth Failures", "count": 0, "findings": []},
        "A08:2021-Software and Data Integrity Failures": {"category": "A08", "name": "Integrity Failures", "count": 0, "findings": []},
        "A09:2021-Security Logging and Monitoring Failures": {"category": "A09", "name": "Logging Failures", "count": 0, "findings": []},
        "A10:2021-Server-Side Request Forgery": {"category": "A10", "name": "SSRF", "count": 0, "findings": []},
    }

    for f in findings:
        for k in owasp_mapping:
            if k.split("-")[0] in (f.owasp_category or ""):
                owasp_mapping[k]["count"] += 1
                owasp_mapping[k]["findings"].append(f.finding_record_id)

    return {
        "scope_domains": list(domain_data.values()),
        "owasp_coverage": list(owasp_mapping.values()),
        "total_active_checks": len(MODULE_REGISTRY),
        "total_findings": len(findings),
        "assessment_id_filter": assessment_id,
    }


# ==================== DASHBOARD OVERVIEW ====================
@app.get("/api/stats/overview")
def get_dashboard_overview(
    assessment_id: Optional[str] = None,
    db: Session = Depends(get_platform_db)
):
    query = db.query(FindingEntity)
    if assessment_id:
        query = query.filter(FindingEntity.assessment_id == assessment_id)
    findings = query.all()

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    status_counts = {"CANDIDATE": 0, "VALIDATED": 0, "CONFIRMED": 0, "REMEDIATED": 0, "FALSE_POSITIVE": 0}
    origin_counts = {"SOURCE_STATIC": 0, "DYNAMIC_LOCAL": 0, "LAB_SYNTHETIC": 0}
    env_counts = {"WORLD_MONITOR_SOURCE": 0, "WORLD_MONITOR_LOCAL": 0, "LAB_SYNTHETIC": 0}
    component_counts: Dict[str, int] = {}

    total_cvss = 0.0
    active_count = 0
    remediated_count = 0

    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        vs = f.verification_status or "CANDIDATE"
        status_counts[vs] = status_counts.get(vs, 0) + 1
        origin_counts[f.origin or "LAB_SYNTHETIC"] = origin_counts.get(f.origin, 0) + 1
        env_counts[f.environment_type or "LAB_SYNTHETIC"] = env_counts.get(f.environment_type, 0) + 1

        comp = (f.affected_component or "Unknown").split(" ")[0]
        component_counts[comp] = component_counts.get(comp, 0) + 1
        total_cvss += f.cvss_score or 0.0

        if vs in ("CONFIRMED", "VALIDATED") or f.status in ("CONFIRMED", "RETESTED_FAIL"):
            active_count += 1
        elif vs == "REMEDIATED" or f.status in ("FIXED", "RETESTED_PASS"):
            remediated_count += 1

    # Risk score formula: weighted sum clamped to [0, 100], never negative
    # Active (non-remediated) findings drive the score; remediated findings reduce it
    raw_risk = (
        sev_counts["CRITICAL"] * 25 +
        sev_counts["HIGH"] * 15 +
        sev_counts["MEDIUM"] * 8 +
        sev_counts["LOW"] * 3
    )
    # Remediated findings reduce the score (capped at 40% reduction)
    total = len(findings) if findings else 1
    remediated_ratio = min(remediated_count / total, 0.4)
    risk_score = max(0.0, min(100.0, round(raw_risk * (1.0 - remediated_ratio), 1)))

    if risk_score > 75:
        risk_rating = "CRITICAL"
    elif risk_score > 50:
        risk_rating = "HIGH"
    elif risk_score > 25:
        risk_rating = "MEDIUM"
    elif risk_score > 0:
        risk_rating = "LOW"
    else:
        risk_rating = "CLEAR"

    top_components = sorted(
        [{"component": k, "count": v} for k, v in component_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:5]

    return {
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "total_findings": len(findings),
        "active_vulnerabilities": active_count,
        "remediated_count": remediated_count,
        "severity_breakdown": sev_counts,
        "verification_status_breakdown": status_counts,
        "origin_breakdown": origin_counts,
        "environment_type_breakdown": env_counts,
        "top_affected_components": top_components,
        "compliance_score_percent": max(0.0, min(100.0, round(100.0 - risk_score, 1))),
        "assessment_id_filter": assessment_id,
    }


# ==================== AUDIT LOG ====================
@app.get("/api/audit-log")
def get_audit_logs(limit: int = 100, db: Session = Depends(get_platform_db)):
    entries = db.query(AuditLogEntity).order_by(AuditLogEntity.id.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "action": e.action,
            "target": e.target,
            "operator": e.operator,
            "status": e.status,
            "details": json.loads(e.details_json or "{}"),
            "prev_hash": e.prev_hash,
            "row_hash": e.row_hash,
        }
        for e in entries
    ]


@app.get("/api/audit-log/verify")
def verify_audit_chain(db: Session = Depends(get_platform_db)):
    """
    Verifies the integrity of the audit log hash chain.
    Returns: verified=True if all rows match their computed hash, False if tampered.
    """
    entries = db.query(AuditLogEntity).order_by(AuditLogEntity.id.asc()).all()
    prev_hash = "GENESIS"
    broken_at = None

    for entry in entries:
        expected_hash = compute_row_hash(entry, prev_hash)
        if entry.row_hash != expected_hash:
            broken_at = entry.id
            break
        prev_hash = entry.row_hash

    return {
        "verified": broken_at is None,
        "total_entries": len(entries),
        "broken_at_id": broken_at,
        "note": (
            "Audit chain integrity verified — no tampering detected."
            if broken_at is None
            else f"Chain broken at entry ID {broken_at}. Possible tampering."
        ),
    }


# ==================== LAB CONTROL (Mode C only) ====================
@app.get("/api/lab/vulnerabilities")
def get_lab_vulnerabilities():
    """Returns current state of lab vulnerability toggles."""
    lab_url = "http://127.0.0.1:8001/api/lab/vulnerabilities"
    try:
        ScopeGuard.enforce(lab_url)
        scoped_kwargs = ScopeGuard.make_scoped_client_kwargs()
        ck = {k: v for k, v in scoped_kwargs.items() if k != "follow_redirects"}
        r = httpx.get(lab_url, **ck, timeout=3.0)
        data = r.json()
        # Label response clearly as lab synthetic state
        return {
            "environment": "LAB_SYNTHETIC",
            "note": "These are synthetic vulnerability toggle states in the controlled lab — not production findings.",
            "vulnerabilities": data,
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Lab not reachable: {str(e)}")


# ==================== REPORT DOWNLOADS ====================
@app.get("/api/report/markdown")
def download_markdown_report(
    assessment_id: Optional[str] = None,
    db: Session = Depends(get_platform_db)
):
    all_findings = list_findings(assessment_id=assessment_id, db=db)
    stats = get_dashboard_overview(assessment_id=assessment_id, db=db)
    md_content = generate_markdown_report(all_findings, stats)
    return PlainTextResponse(
        content=md_content,
        headers={"Content-Disposition": "attachment; filename=World_Monitor_Security_Assessment_Report.md"}
    )


@app.get("/api/report/pdf")
def download_pdf_report(
    assessment_id: Optional[str] = None,
    db: Session = Depends(get_platform_db)
):
    all_findings = list_findings(assessment_id=assessment_id, db=db)
    stats = get_dashboard_overview(assessment_id=assessment_id, db=db)
    pdf_path = os.path.join(os.path.dirname(__file__), "..", "reports", "World_Monitor_Security_Report.pdf")
    generate_pdf_report(all_findings, stats, pdf_path)
    return FileResponse(
        path=pdf_path,
        filename="World_Monitor_Security_Report.pdf",
        media_type="application/pdf"
    )
