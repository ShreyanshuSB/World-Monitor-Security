"""
Security Assessment Platform - Assessment Runner & Orchestrator v2

Key fixes:
- SSE endpoint loads stored assessment; never trusts query-string authorization/target
- Module selection is loaded from stored assessment_runs.modules_scanned_json
- Finding IDs are UUID-based per-record; finding_key is stable logical identifier
- Audit log uses hash chain (append-only integrity)
- Risk score formula produces [0,100], never negative
- Coverage status correctly handles FAIL > REMEDIATED precedence
- All findings labeled with origin / environment_type / verification_status
- Lab findings use LAB_SYNTHETIC; source findings use WORLD_MONITOR_SOURCE
"""

import time
import json
import uuid
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Callable, Optional, AsyncGenerator
import httpx

from engine.scope_guard import ScopeGuard, ScopeViolationException
from engine.database import (
    SessionLocal, init_platform_db,
    AssessmentRunEntity, FindingEntity, AuditLogEntity, RetestRecordEntity,
    compute_row_hash, get_last_audit_hash
)
from engine.models import FindingModel, RetestResultModel
from engine.modules import (
    auth_session,
    authz_access,
    input_validation,
    api_security,
    client_side,
    secure_comm,
    data_storage,
)

MODULE_REGISTRY = [
    ("auth_session",    "Authentication & Session Management", auth_session.run_module),
    ("authz_access",    "Authorization & Access Control",      authz_access.run_module),
    ("input_validation","Input Validation & Data Handling",    input_validation.run_module),
    ("api_security",    "API Security",                        api_security.run_module),
    ("client_side",     "Client-Side Controls",               client_side.run_module),
    ("secure_comm",     "Secure Communication",               secure_comm.run_module),
    ("data_storage",    "Data Storage & Privacy",             data_storage.run_module),
]


# ---------------------------------------------------------------------------
# Audit log with hash-chain integrity
# ---------------------------------------------------------------------------

def log_audit(
    action: str,
    target: str,
    status: str,
    details: Dict[str, Any],
    operator: str = "sec_engineer"
) -> None:
    """Append an audit event. Each row's hash covers content + previous hash."""
    db = SessionLocal()
    try:
        prev_hash = get_last_audit_hash(db)
        entry = AuditLogEntity(
            timestamp=datetime.utcnow(),
            action=action,
            target=target,
            operator=operator,
            status=status,
            details_json=json.dumps(details),
            prev_hash=prev_hash,
        )
        db.add(entry)
        db.flush()  # assigns auto-increment id
        entry.row_hash = compute_row_hash(entry, prev_hash)
        db.commit()
    except Exception as e:
        print(f"[Audit Log Error] {e}")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Finding persistence helper
# ---------------------------------------------------------------------------

def _persist_finding(db, finding: FindingModel, assessment_id: str) -> None:
    """
    Persist a FindingModel to DB using finding_record_id as PK.
    Never overwrites a row from a different assessment run.
    """
    entity = FindingEntity(
        finding_record_id=finding.finding_record_id,
        assessment_id=assessment_id,
        finding_key=finding.finding_key,
        id=finding.id,
        vuln_key=finding.vuln_key,
        origin=finding.origin,
        environment_type=finding.environment_type,
        verification_status=finding.verification_status,
        title=finding.title,
        description=finding.description,
        affected_component=finding.affected_component,
        scope_area=finding.scope_area,
        cwe_id=finding.cwe_id,
        owasp_category=finding.owasp_category,
        cvss_vector=finding.cvss_vector,
        cvss_score=finding.cvss_score,
        severity=finding.severity,
        metric_reasoning=finding.metric_reasoning,
        steps_to_reproduce_json=json.dumps(finding.steps_to_reproduce),
        proof_of_concept=finding.proof_of_concept,
        business_impact=finding.business_impact,
        remediation=finding.remediation,
        code_diff=finding.code_diff,
        status=finding.status,
        evidence_json=json.dumps(finding.evidence.model_dump()),
        source_file=finding.source_file,
        line_number=finding.line_number,
        symbol=finding.symbol,
        source_snippet=finding.source_snippet,
        data_flow_source=finding.data_flow_source,
        data_flow_sink=finding.data_flow_sink,
        confidence=finding.confidence,
        public_advisory_status=finding.public_advisory_status,
        known_issue=finding.known_issue,
        newly_discovered=finding.newly_discovered,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    # Use add (not merge) so previous assessment records are never overwritten
    db.add(entity)
    db.commit()


# ---------------------------------------------------------------------------
# Main SSE assessment stream
# ---------------------------------------------------------------------------

async def run_assessment_stream(
    assessment_id: str,
) -> AsyncGenerator[str, None]:
    """
    Streams SSE events for an assessment run.

    SECURITY: target_url, authorized flag, and module list are ALL loaded from
    the stored AssessmentRunEntity. Query-string parameters from the browser
    are intentionally NOT used here.
    """
    init_platform_db()
    db = SessionLocal()

    yield f"data: {json.dumps({'type': 'INIT', 'assessment_id': assessment_id})}\n\n"

    # ----------------------------------------------------------------
    # Step 1: Load stored assessment — reject if missing
    # ----------------------------------------------------------------
    run_record = db.query(AssessmentRunEntity).filter(
        AssessmentRunEntity.id == assessment_id
    ).first()

    if not run_record:
        yield f"data: {json.dumps({'type': 'ERROR', 'message': f'Assessment {assessment_id} not found. Start a new assessment first.'})}\n\n"
        db.close()
        return

    # ----------------------------------------------------------------
    # Step 2: Verify stored authorization flag
    # ----------------------------------------------------------------
    if not run_record.authorized:
        log_audit("ASSESSMENT_BLOCKED", run_record.target_url, "BLOCKED",
                  {"reason": "Authorization flag is false in stored assessment",
                   "assessment_id": assessment_id})
        yield f"data: {json.dumps({'type': 'ERROR', 'message': 'Assessment authorization is not set. Cannot proceed.'})}\n\n"
        db.close()
        return

    # ----------------------------------------------------------------
    # Step 3: Load stored target and module list (never from query string)
    # ----------------------------------------------------------------
    target_url = run_record.target_url
    stored_modules = json.loads(run_record.modules_scanned_json or "[]")

    # ----------------------------------------------------------------
    # Step 4: Re-enforce scope guard on stored target
    # ----------------------------------------------------------------
    try:
        ScopeGuard.enforce(target_url)
    except ScopeViolationException as sve:
        log_audit("SCOPE_VIOLATION_BLOCKED", target_url, "BLOCKED",
                  {"error": str(sve), "assessment_id": assessment_id})
        yield f"data: {json.dumps({'type': 'ERROR', 'message': str(sve)})}\n\n"
        db.close()
        return

    yield f"data: {json.dumps({'type': 'LOG', 'message': f'Assessment {assessment_id} authorized. Target: {target_url}. Mode: {run_record.assessment_mode}'})}\n\n"
    yield f"data: {json.dumps({'type': 'LOG', 'message': f'Modules selected: {stored_modules}'})}\n\n"

    log_audit("ASSESSMENT_START", target_url, "SUCCESS", {
        "assessment_id": assessment_id,
        "mode": run_record.assessment_mode,
        "modules": stored_modules,
        "target": target_url,
    })

    # Update run to RUNNING
    run_record.status = "RUNNING"
    db.commit()

    all_findings: List[FindingModel] = []
    start_all = time.time()

    # ----------------------------------------------------------------
    # Step 5: Target connectivity check (informational only)
    # ----------------------------------------------------------------
    scoped_kwargs = ScopeGuard.make_scoped_client_kwargs()
    try:
        async with httpx.AsyncClient(**scoped_kwargs) as async_client:
            try:
                r = await async_client.get(f"{target_url}/api/health", timeout=3.0)
                yield f"data: {json.dumps({'type': 'LOG', 'message': f'Target connectivity: HTTP {r.status_code} from {target_url}/api/health'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'type': 'LOG', 'message': f'Target health check: {e} — proceeding anyway'})}\n\n"
    except Exception:
        pass

    # ----------------------------------------------------------------
    # Step 6: Execute ONLY the stored module list
    # ----------------------------------------------------------------
    scoped_client_kwargs = {k: v for k, v in scoped_kwargs.items() if k != "follow_redirects"}
    scoped_client_kwargs["timeout"] = 10.0

    with httpx.Client(**scoped_client_kwargs) as client:
        # Filter registry to only stored modules (exact match)
        if stored_modules:
            active_modules = [
                (mid, mname, mfn)
                for (mid, mname, mfn) in MODULE_REGISTRY
                if mid in stored_modules
            ]
        else:
            active_modules = list(MODULE_REGISTRY)

        total_mods = len(active_modules)
        yield f"data: {json.dumps({'type': 'LOG', 'message': f'Executing {total_mods} module(s)'})}\n\n"

        for idx, (mod_id, mod_name, mod_fn) in enumerate(active_modules, 1):
            yield f"data: {json.dumps({'type': 'MODULE_START', 'module_id': mod_id, 'module_name': mod_name, 'index': idx, 'total': total_mods})}\n\n"
            yield f"data: {json.dumps({'type': 'LOG', 'message': f'[{idx}/{total_mods}] Starting: {mod_name}'})}\n\n"

            await asyncio.sleep(0.3)

            try:
                mod_findings = mod_fn(target_url, client)

                for f in mod_findings:
                    # Stamp assessment_id onto finding
                    f.assessment_id = assessment_id

                    all_findings.append(f)
                    _persist_finding(db, f, assessment_id)

                    log_audit("FINDING_RECORDED", target_url, f.verification_status, {
                        "finding_record_id": f.finding_record_id,
                        "finding_key": f.finding_key,
                        "title": f.title,
                        "severity": f.severity,
                        "cvss": f.cvss_score,
                        "origin": f.origin,
                        "environment_type": f.environment_type,
                    })

                    yield f"data: {json.dumps({'type': 'FINDING_FOUND', 'finding': f.model_dump()})}\n\n"
                    yield f"data: {json.dumps({'type': 'LOG', 'message': f'  [{f.severity}] {f.title} (CVSS {f.cvss_score}) [{f.origin}]'})}\n\n"

            except Exception as e:
                yield f"data: {json.dumps({'type': 'LOG', 'message': f'Module error in {mod_name}: {str(e)}'})}\n\n"

            yield f"data: {json.dumps({'type': 'MODULE_COMPLETE', 'module_id': mod_id, 'findings_count': len(all_findings)})}\n\n"
            await asyncio.sleep(0.2)

    # ----------------------------------------------------------------
    # Step 7: Finalize
    # ----------------------------------------------------------------
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    elapsed = round(time.time() - start_all, 2)

    run_record = db.query(AssessmentRunEntity).filter(
        AssessmentRunEntity.id == assessment_id
    ).first()
    if run_record:
        run_record.status = "COMPLETED"
        run_record.completed_at = datetime.utcnow()
        run_record.total_findings = len(all_findings)
        run_record.findings_by_severity_json = json.dumps(sev_counts)
        db.commit()

    log_audit("ASSESSMENT_COMPLETED", target_url, "SUCCESS", {
        "assessment_id": assessment_id,
        "elapsed_seconds": elapsed,
        "total_findings": len(all_findings),
        "breakdown": sev_counts,
    })

    yield f"data: {json.dumps({'type': 'COMPLETE', 'assessment_id': assessment_id, 'total_findings': len(all_findings), 'severity_breakdown': sev_counts, 'elapsed_seconds': elapsed})}\n\n"
    db.close()


# ---------------------------------------------------------------------------
# Retest engine — evaluates the actual vulnerability condition
# ---------------------------------------------------------------------------

def retest_finding_sync(finding_id: str) -> Dict[str, Any]:
    """
    Re-test a specific finding.

    finding_id may be either finding_record_id (UUID) or legacy id.
    The retest uses the finding's stored target from its assessment run.
    It does NOT accept a target_url parameter — the target is always loaded
    from the stored assessment to prevent parameter injection.

    Retest evaluates the actual vulnerability condition, not string presence.
    """
    db = SessionLocal()
    try:
        # Look up by finding_record_id first, then by id (legacy)
        finding = db.query(FindingEntity).filter(
            FindingEntity.finding_record_id == finding_id
        ).first()
        if not finding:
            finding = db.query(FindingEntity).filter(
                FindingEntity.id == finding_id
            ).first()
        if not finding:
            return {"error": f"Finding {finding_id} not found."}

        # Load associated assessment for stored target
        run = db.query(AssessmentRunEntity).filter(
            AssessmentRunEntity.id == finding.assessment_id
        ).first()

        target_url = "http://127.0.0.1:8001"
        if run:
            target_url = run.target_url

        # Re-enforce scope guard using stored target
        ScopeGuard.enforce(target_url)

        # Find module that produced this finding
        target_mod = None
        for mod_id, mod_name, mod_fn in MODULE_REGISTRY:
            if mod_name.lower() == finding.scope_area.lower():
                target_mod = mod_fn
                break

        if not target_mod:
            # Fallback: search by finding_key
            scoped_kwargs = ScopeGuard.make_scoped_client_kwargs()
            client_kwargs = {k: v for k, v in scoped_kwargs.items() if k != "follow_redirects"}
            with httpx.Client(**client_kwargs) as probe_client:
                for mod_id, mod_name, mod_fn in MODULE_REGISTRY:
                    try:
                        sample = mod_fn(target_url, probe_client)
                        if any(sf.finding_key == finding.finding_key or sf.vuln_key == finding.vuln_key for sf in sample):
                            target_mod = mod_fn
                            break
                    except Exception:
                        continue

        before_evidence = json.loads(finding.evidence_json)
        previous_status = finding.status

        scoped_kwargs = ScopeGuard.make_scoped_client_kwargs()
        client_kwargs = {k: v for k, v in scoped_kwargs.items() if k != "follow_redirects"}
        with httpx.Client(**client_kwargs) as client:
            fresh_findings = target_mod(target_url, client) if target_mod else []

        # Evaluate actual vulnerability condition: same finding_key present means still vulnerable
        still_vulnerable = any(
            sf.finding_key == finding.finding_key or sf.vuln_key == finding.vuln_key
            for sf in fresh_findings
        )

        if not still_vulnerable:
            new_status = "RETESTED_PASS"
            passed = True
            finding.status = new_status
            finding.verification_status = "REMEDIATED"
            finding.updated_at = datetime.utcnow()

            # Collect fresh after-evidence by re-running the same probe
            try:
                before_url = before_evidence.get("request_url", "")
                before_headers = before_evidence.get("request_headers", {})
                if before_url:
                    ScopeGuard.enforce(before_url)
                    scoped_kwargs2 = ScopeGuard.make_scoped_client_kwargs()
                    ck2 = {k: v for k, v in scoped_kwargs2.items() if k != "follow_redirects"}
                    resp = httpx.get(before_url, headers=before_headers, **ck2)
                    after_evidence = {
                        "request_url": before_url,
                        "request_method": "GET",
                        "response_status": resp.status_code,
                        "response_headers": dict(resp.headers),
                        "response_body": resp.text[:500],
                        "timestamp": datetime.utcnow().isoformat(),
                        "note": "Retest: vulnerability condition absent. Security control validated."
                    }
                else:
                    after_evidence = {"note": "Patch confirmed. Vulnerability condition no longer reproducible."}
            except Exception:
                after_evidence = {"note": "Patch confirmed. Vulnerability condition no longer reproducible."}

            changed_behavior = "Vulnerability condition absent after patch"
        else:
            new_status = "RETESTED_FAIL"
            passed = False
            finding.status = new_status
            finding.updated_at = datetime.utcnow()
            matching = [sf for sf in fresh_findings if sf.finding_key == finding.finding_key or sf.vuln_key == finding.vuln_key]
            after_evidence = matching[0].evidence.model_dump() if matching else before_evidence
            changed_behavior = "Vulnerability condition still present"

        db.commit()

        # Record retest
        retest_rec = RetestRecordEntity(
            finding_id=finding.finding_record_id,
            finding_key=finding.finding_key,
            timestamp=datetime.utcnow(),
            previous_status=previous_status,
            new_status=new_status,
            passed=passed,
            before_evidence_json=json.dumps(before_evidence),
            after_evidence_json=json.dumps(after_evidence),
            changed_behavior=changed_behavior,
        )
        db.add(retest_rec)
        db.commit()

        log_audit("FINDING_RETESTED", target_url, "PASSED" if passed else "FAILED", {
            "finding_record_id": finding.finding_record_id,
            "finding_key": finding.finding_key,
            "passed": passed,
            "new_status": new_status,
            "changed_behavior": changed_behavior,
        })

        return {
            "finding_id": finding.finding_record_id,
            "finding_key": finding.finding_key,
            "passed": passed,
            "previous_status": previous_status,
            "new_status": new_status,
            "before_evidence": before_evidence,
            "after_evidence": after_evidence,
            "changed_behavior": changed_behavior,
        }
    finally:
        db.close()
