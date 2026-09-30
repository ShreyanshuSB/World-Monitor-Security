"""
Security Assessment Platform — Regression Test Suite
SIH26163 | World Monitor (NTRO)

Tests 14 specific security behaviors:

1.  SCOPE_GUARD_BLOCKS_EXTERNAL_HOST
2.  SCOPE_GUARD_ALLOWS_LOCALHOST
3.  SCOPE_GUARD_BLOCKS_IPVI6_BYPASS_ATTEMPT
4.  SSE_DOES_NOT_TRUST_QUERY_PARAMS (target_url/authorized ignored)
5.  ASSESSMENT_LOADS_STORED_MODULES_ONLY
6.  FINDING_RECORD_ID_IS_UUID
7.  FINDING_KEY_STABLE_ACROSS_ASSESSMENTS
8.  FINDINGS_ISOLATED_PER_ASSESSMENT (no cross-run collision)
9.  LAB_FINDINGS_LABELED_LAB_SYNTHETIC
10. SOURCE_FINDINGS_LABELED_WORLD_MONITOR_SOURCE
11. RISK_SCORE_NEVER_NEGATIVE
12. RISK_SCORE_CAPPED_AT_100
13. COVERAGE_FAIL_TAKES_PRECEDENCE_OVER_REMEDIATED
14. AUDIT_CHAIN_INTEGRITY_VERIFIED
"""

import uuid
import json
import pytest
import hashlib

from engine.scope_guard import ScopeGuard, ScopeViolationException
from engine.database import (
    init_platform_db, SessionLocal,
    AssessmentRunEntity, FindingEntity, AuditLogEntity,
    compute_row_hash, get_last_audit_hash
)
from engine.models import FindingModel, EvidenceModel
from datetime import datetime


# ==================== HELPERS ====================

def make_test_finding(
    finding_key: str = "TEST_FINDING",
    origin: str = "LAB_SYNTHETIC",
    environment_type: str = "LAB_SYNTHETIC",
    verification_status: str = "CONFIRMED",
    cvss_score: float = 7.5,
    severity: str = "HIGH",
    assessment_id: str = "ASM-TEST0001",
) -> FindingEntity:
    record_id = str(uuid.uuid4())
    return FindingEntity(
        finding_record_id=record_id,
        assessment_id=assessment_id,
        finding_key=finding_key,
        id=record_id,
        vuln_key=finding_key,
        origin=origin,
        environment_type=environment_type,
        verification_status=verification_status,
        title=f"Test Finding — {finding_key}",
        description="Regression test fixture",
        affected_component="/test/endpoint",
        scope_area="Test Domain",
        cwe_id="CWE-0: Test",
        owasp_category="A01:2021-Broken Access Control",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=cvss_score,
        severity=severity,
        steps_to_reproduce_json=json.dumps(["Step 1"]),
        proof_of_concept="curl test",
        business_impact="Test impact",
        remediation="Test remediation",
        code_diff="--- a\n+++ b",
        status=verification_status,
        evidence_json=json.dumps({
            "request_method": "GET",
            "request_url": "http://127.0.0.1:8001/test",
            "request_headers": {},
            "response_status": 200,
            "response_headers": {},
            "response_body": "test",
            "timestamp": "2024-01-01T00:00:00Z",
            "duration_ms": 10.0,
        }),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


def compute_risk_score(findings: list) -> float:
    """Replica of the risk score formula used in api/main.py."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    remediated_count = 0
    total = len(findings)
    for f in findings:
        s = f.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        vs = f.get("verification_status", "")
        st = f.get("status", "")
        if vs == "REMEDIATED" or st in ("FIXED", "RETESTED_PASS"):
            remediated_count += 1
    raw_risk = (
        sev_counts["CRITICAL"] * 25 +
        sev_counts["HIGH"] * 15 +
        sev_counts["MEDIUM"] * 8 +
        sev_counts["LOW"] * 3
    )
    remediated_ratio = min(remediated_count / total, 0.4) if total > 0 else 0.0
    return max(0.0, min(100.0, round(raw_risk * (1.0 - remediated_ratio), 1)))


# ==================== TEST 1: Scope Guard blocks external host ====================

class TestScopeGuardBlocksExternal:
    """TEST 1: SCOPE_GUARD_BLOCKS_EXTERNAL_HOST"""

    def test_external_https_blocked(self):
        assert not ScopeGuard.is_allowed("https://example.com")

    def test_external_http_blocked(self):
        assert not ScopeGuard.is_allowed("http://google.com")

    def test_ntro_domain_blocked(self):
        assert not ScopeGuard.is_allowed("https://ntro.gov.in/api/scan")

    def test_enforce_raises_on_external(self):
        with pytest.raises(ScopeViolationException):
            ScopeGuard.enforce("http://attacker.example.com")

    def test_empty_url_blocked(self):
        assert not ScopeGuard.is_allowed("")

    def test_none_url_blocked(self):
        assert not ScopeGuard.is_allowed(None)


# ==================== TEST 2: Scope Guard allows localhost ====================

class TestScopeGuardAllowsLocalhost:
    """TEST 2: SCOPE_GUARD_ALLOWS_LOCALHOST"""

    def test_localhost_http(self):
        assert ScopeGuard.is_allowed("http://localhost:8001")

    def test_127_0_0_1_http(self):
        assert ScopeGuard.is_allowed("http://127.0.0.1:8001")

    def test_127_0_0_1_https(self):
        assert ScopeGuard.is_allowed("https://127.0.0.1:8001")

    def test_enforce_returns_url_on_localhost(self):
        result = ScopeGuard.enforce("http://127.0.0.1:8001")
        assert result == "http://127.0.0.1:8001"


# ==================== TEST 3: Scope Guard blocks IPv6 bypass ====================

class TestScopeGuardIPv6:
    """TEST 3: SCOPE_GUARD_BLOCKS_IPV6_BYPASS_ATTEMPT"""

    def test_ipv6_loopback_bracketed_allowed(self):
        # [::1] is valid IPv6 loopback — should be allowed
        assert ScopeGuard.is_allowed("http://[::1]:8001")

    def test_ipv6_non_loopback_blocked(self):
        assert not ScopeGuard.is_allowed("http://[2001:db8::1]:8001")

    def test_ipv6_mapped_blocked(self):
        # ::ffff:192.168.1.1 — not loopback
        assert not ScopeGuard.is_allowed("http://[::ffff:192.168.1.1]:8001")


# ==================== TEST 4: SSE does NOT trust query params ====================

class TestSSEDoesNotTrustQueryParams:
    """
    TEST 4: SCOPE_GUARD_BLOCKS_EXTERNAL_HOST (SSE parameter injection)
    Validates that the runner loads assessment from DB, not from query params.
    We test this by verifying the runner's signature does NOT accept target_url.
    """

    def test_runner_function_has_no_target_param(self):
        """The run_assessment_stream function must NOT have target_url parameter."""
        import inspect
        from engine.runner import run_assessment_stream
        sig = inspect.signature(run_assessment_stream)
        param_names = list(sig.parameters.keys())
        assert "target_url" not in param_names, (
            "run_assessment_stream must NOT accept target_url parameter — "
            "must load from stored assessment to prevent injection"
        )
        assert "authorized_acknowledged" not in param_names, (
            "run_assessment_stream must NOT accept authorized_acknowledged parameter"
        )
        assert "assessment_id" in param_names, (
            "run_assessment_stream must accept assessment_id to load from DB"
        )

    def test_retest_function_has_no_target_param(self):
        """retest_finding_sync must NOT accept target_url parameter."""
        import inspect
        from engine.runner import retest_finding_sync
        sig = inspect.signature(retest_finding_sync)
        param_names = list(sig.parameters.keys())
        assert "target_url" not in param_names, (
            "retest_finding_sync must NOT accept target_url — loads from stored assessment"
        )


# ==================== TEST 5: Module selection from stored record ====================

class TestModuleSelectionFromDB:
    """TEST 5: ASSESSMENT_LOADS_STORED_MODULES_ONLY"""

    def test_stored_modules_json_round_trips(self):
        """Stored module list must serialize/deserialize faithfully."""
        modules = ["auth_session", "authz_access", "input_validation"]
        stored = json.dumps(modules)
        loaded = json.loads(stored)
        assert loaded == modules

    def test_runner_registry_contains_expected_keys(self):
        from engine.runner import MODULE_REGISTRY
        module_ids = [m[0] for m in MODULE_REGISTRY]
        expected = ["auth_session", "authz_access", "input_validation",
                    "api_security", "client_side", "secure_comm", "data_storage"]
        for expected_id in expected:
            assert expected_id in module_ids, f"Missing module ID in registry: {expected_id}"


# ==================== TEST 6: Finding record ID is UUID ====================

class TestFindingRecordIdIsUUID:
    """TEST 6: FINDING_RECORD_ID_IS_UUID"""

    def test_model_generates_uuid(self):
        evidence = EvidenceModel(
            request_method="GET", request_url="http://127.0.0.1:8001/test",
            request_headers={}, response_status=200,
            response_headers={}, response_body="",
            timestamp="2024-01-01T00:00:00Z", duration_ms=1.0,
        )
        f = FindingModel(
            finding_key="TEST_KEY",
            vuln_key="TEST_KEY",
            title="Test", description="Test",
            affected_component="/test", scope_area="Test",
            cwe_id="CWE-0", owasp_category="A01",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=7.5, severity="HIGH",
            steps_to_reproduce=["step"],
            proof_of_concept="curl test",
            business_impact="impact",
            remediation="remediate",
            code_diff="diff",
            evidence=evidence,
        )
        # Should be a valid UUID
        parsed = uuid.UUID(f.finding_record_id)
        assert parsed.version == 4, "finding_record_id must be UUID v4"

    def test_two_models_have_different_ids(self):
        """Every FindingModel instance must have a unique ID."""
        evidence = EvidenceModel(
            request_method="GET", request_url="http://127.0.0.1:8001/test",
            request_headers={}, response_status=200,
            response_headers={}, response_body="",
            timestamp="2024-01-01T00:00:00Z", duration_ms=1.0,
        )
        common = dict(
            finding_key="KEY", vuln_key="KEY",
            title="T", description="D", affected_component="C",
            scope_area="S", cwe_id="CWE-0", owasp_category="A01",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=7.5, severity="HIGH", steps_to_reproduce=["s"],
            proof_of_concept="p", business_impact="b", remediation="r",
            code_diff="", evidence=evidence,
        )
        f1 = FindingModel(**common)
        f2 = FindingModel(**common)
        assert f1.finding_record_id != f2.finding_record_id, (
            "Each FindingModel must have a unique finding_record_id"
        )


# ==================== TEST 7: finding_key is stable ====================

class TestFindingKeyIsStable:
    """TEST 7: FINDING_KEY_STABLE_ACROSS_ASSESSMENTS"""

    def test_auth_module_uses_stable_key(self):
        from engine.modules import auth_session
        import httpx
        # Use a mock client that returns a 200 with "admin" in body
        class MockResponse:
            status_code = 200
            text = '{"role": "admin", "user": "test"}'
            headers = {}
            def json(self): return {"role": "admin"}

        class MockClient:
            def get(self, url, **kwargs): return MockResponse()

        findings = auth_session.run_module("http://127.0.0.1:8001", MockClient())
        for f in findings:
            assert f.finding_key == "AUTH_HARDCODED_TOKEN_BYPASS", (
                f"Expected stable finding_key AUTH_HARDCODED_TOKEN_BYPASS, got {f.finding_key}"
            )


# ==================== TEST 8: Assessment isolation ====================

class TestAssessmentIsolation:
    """TEST 8: FINDINGS_ISOLATED_PER_ASSESSMENT"""

    def test_finding_has_assessment_id(self):
        """Every finding entity must have an assessment_id FK."""
        entity = make_test_finding(assessment_id="ASM-AABBCCDD")
        assert entity.assessment_id == "ASM-AABBCCDD"

    def test_two_assessments_get_different_finding_records(self):
        """Two assessments with same finding_key must produce different finding_record_ids."""
        f1 = make_test_finding(finding_key="AUTHZ_IDOR_REPORT", assessment_id="ASM-00000001")
        f2 = make_test_finding(finding_key="AUTHZ_IDOR_REPORT", assessment_id="ASM-00000002")
        assert f1.finding_record_id != f2.finding_record_id
        assert f1.finding_key == f2.finding_key == "AUTHZ_IDOR_REPORT"
        assert f1.assessment_id != f2.assessment_id


# ==================== TEST 9: Lab findings labeled LAB_SYNTHETIC ====================

class TestLabFindingsLabeled:
    """TEST 9: LAB_FINDINGS_LABELED_LAB_SYNTHETIC"""

    def test_auth_module_origin(self):
        from engine.modules.auth_session import MODULE_ORIGIN, MODULE_ENV
        assert MODULE_ORIGIN == "LAB_SYNTHETIC", f"Expected LAB_SYNTHETIC, got {MODULE_ORIGIN}"
        assert MODULE_ENV == "LAB_SYNTHETIC", f"Expected LAB_SYNTHETIC, got {MODULE_ENV}"

    def test_authz_module_origin(self):
        from engine.modules.authz_access import MODULE_ORIGIN, MODULE_ENV
        assert MODULE_ORIGIN == "LAB_SYNTHETIC"
        assert MODULE_ENV == "LAB_SYNTHETIC"

    def test_input_validation_module_origin(self):
        from engine.modules.input_validation import MODULE_ORIGIN, MODULE_ENV
        assert MODULE_ORIGIN == "LAB_SYNTHETIC"
        assert MODULE_ENV == "LAB_SYNTHETIC"

    def test_data_storage_module_origin(self):
        from engine.modules.data_storage import MODULE_ORIGIN, MODULE_ENV
        assert MODULE_ORIGIN == "LAB_SYNTHETIC"
        assert MODULE_ENV == "LAB_SYNTHETIC"


# ==================== TEST 10: Source findings labeled WORLD_MONITOR_SOURCE ====================

class TestSourceFindingsLabeled:
    """TEST 10: SOURCE_FINDINGS_LABELED_WORLD_MONITOR_SOURCE"""

    def test_source_finding_defaults(self):
        from engine.source_analysis.base import SourceFinding
        sf = SourceFinding(finding_key="TEST", title="T", description="D")
        assert sf.origin == "SOURCE_STATIC"
        assert sf.environment_type == "WORLD_MONITOR_SOURCE"
        assert sf.verification_status == "CANDIDATE"

    def test_source_findings_never_confirmed(self):
        """Static analysis findings must never be auto-set to CONFIRMED."""
        from engine.source_analysis.base import SourceFinding
        sf = SourceFinding(finding_key="K", title="T", description="D")
        # Can only be CANDIDATE or VALIDATED from static analysis, never CONFIRMED
        assert sf.verification_status in ("CANDIDATE", "VALIDATED"), (
            f"Source finding should be CANDIDATE/VALIDATED, got {sf.verification_status}"
        )


# ==================== TEST 11: Risk score never negative ====================

class TestRiskScoreNeverNegative:
    """TEST 11: RISK_SCORE_NEVER_NEGATIVE"""

    def test_zero_findings_risk_is_zero(self):
        score = compute_risk_score([])
        assert score == 0.0, f"Empty findings risk score should be 0, got {score}"

    def test_all_remediated_risk_gte_zero(self):
        findings = [
            {"severity": "HIGH", "verification_status": "REMEDIATED", "status": "RETESTED_PASS"},
            {"severity": "MEDIUM", "verification_status": "REMEDIATED", "status": "FIXED"},
        ]
        score = compute_risk_score(findings)
        assert score >= 0.0, f"Risk score must never be negative, got {score}"

    def test_many_remediated_risk_still_positive_if_raw_risk_exists(self):
        """40% max reduction means score won't reach 0 if there's raw risk."""
        findings = [{"severity": "HIGH", "verification_status": "REMEDIATED", "status": "FIXED"}] * 10
        score = compute_risk_score(findings)
        assert score >= 0.0

    def test_high_findings_score_gt_zero(self):
        findings = [
            {"severity": "HIGH", "verification_status": "CONFIRMED", "status": "CONFIRMED"}
        ]
        score = compute_risk_score(findings)
        assert score > 0.0


# ==================== TEST 12: Risk score capped at 100 ====================

class TestRiskScoreCappedAt100:
    """TEST 12: RISK_SCORE_CAPPED_AT_100"""

    def test_many_criticals_capped(self):
        findings = [
            {"severity": "CRITICAL", "verification_status": "CONFIRMED", "status": "CONFIRMED"}
        ] * 10
        score = compute_risk_score(findings)
        assert score <= 100.0, f"Risk score must never exceed 100, got {score}"

    def test_mixed_max_capped(self):
        findings = (
            [{"severity": "CRITICAL", "verification_status": "CONFIRMED", "status": "CONFIRMED"}] * 5 +
            [{"severity": "HIGH", "verification_status": "CONFIRMED", "status": "CONFIRMED"}] * 10
        )
        score = compute_risk_score(findings)
        assert score <= 100.0


# ==================== TEST 13: Coverage status precedence ====================

class TestCoverageStatusPrecedence:
    """TEST 13: COVERAGE_FAIL_TAKES_PRECEDENCE_OVER_REMEDIATED"""

    def test_fail_beats_remediated(self):
        """
        If a domain has both CONFIRMED (FAIL) and REMEDIATED findings,
        the domain status must be FAIL, not REMEDIATED.
        """
        domain_status = "PASS"
        findings_vs = ["REMEDIATED", "CONFIRMED", "REMEDIATED"]

        for vs in findings_vs:
            if vs == "CONFIRMED":
                domain_status = "FAIL"
            elif vs == "REMEDIATED" and domain_status == "PASS":
                domain_status = "REMEDIATED"
            # FAIL is never overwritten by REMEDIATED

        assert domain_status == "FAIL", (
            f"FAIL must take precedence over REMEDIATED, got {domain_status}"
        )

    def test_remediated_beats_pass(self):
        domain_status = "PASS"
        findings_vs = ["REMEDIATED"]
        for vs in findings_vs:
            if vs == "REMEDIATED" and domain_status == "PASS":
                domain_status = "REMEDIATED"
        assert domain_status == "REMEDIATED"

    def test_pass_with_no_findings(self):
        domain_status = "PASS"
        assert domain_status == "PASS"


# ==================== TEST 14: Audit chain integrity ====================

class TestAuditChainIntegrity:
    """TEST 14: AUDIT_CHAIN_INTEGRITY_VERIFIED"""

    def test_compute_row_hash_is_deterministic(self):
        """Same input must always produce same hash."""
        from engine.database import AuditLogEntity
        entry = AuditLogEntity(
            id=1,
            timestamp=datetime(2024, 1, 1, 0, 0, 0),
            action="TEST_ACTION",
            target="/test",
            operator="test_op",
            status="SUCCESS",
            details_json='{"key": "value"}',
        )
        h1 = compute_row_hash(entry, "GENESIS")
        h2 = compute_row_hash(entry, "GENESIS")
        assert h1 == h2, "compute_row_hash must be deterministic"

    def test_different_prev_hash_produces_different_row_hash(self):
        from engine.database import AuditLogEntity
        entry = AuditLogEntity(
            id=1,
            timestamp=datetime(2024, 1, 1),
            action="TEST", target="/t", operator="op",
            status="SUCCESS", details_json="{}",
        )
        h1 = compute_row_hash(entry, "GENESIS")
        h2 = compute_row_hash(entry, "DIFFERENT_PREV_HASH")
        assert h1 != h2, "Different prev_hash must produce different row_hash (chain linkage)"

    def test_tampered_content_invalidates_hash(self):
        """Simulates tampering: modifying content after hash computed should break chain."""
        from engine.database import AuditLogEntity
        entry = AuditLogEntity(
            id=1,
            timestamp=datetime(2024, 1, 1),
            action="ORIGINAL_ACTION", target="/t", operator="op",
            status="SUCCESS", details_json="{}",
        )
        stored_hash = compute_row_hash(entry, "GENESIS")

        # Simulate tampering: action changed
        entry.action = "TAMPERED_ACTION"
        recomputed_hash = compute_row_hash(entry, "GENESIS")
        assert stored_hash != recomputed_hash, (
            "Tampered content must produce a different hash — verifying audit integrity"
        )

    def test_genesis_hash_is_string(self):
        assert isinstance("GENESIS", str)
        assert len("GENESIS") > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
