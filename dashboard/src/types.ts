export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Legacy status values retained for UI backward-compat */
export type FindingStatus = 'VERIFIED' | 'FIXED' | 'RETESTED_PASS' | 'RETESTED_FAIL' | 'CONFIRMED' | 'CANDIDATE' | 'VALIDATED' | 'REMEDIATED';

/** Origin — where the finding was discovered */
export type FindingOrigin = 'SOURCE_STATIC' | 'DYNAMIC_LOCAL' | 'LAB_SYNTHETIC';

/** Environment type — what system was assessed */
export type EnvironmentType = 'WORLD_MONITOR_SOURCE' | 'WORLD_MONITOR_LOCAL' | 'LAB_SYNTHETIC';

/** Verification status — how well the finding has been confirmed */
export type VerificationStatus = 'CANDIDATE' | 'VALIDATED' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'REMEDIATED';

export interface Evidence {
  request_method: string;
  request_url: string;
  request_headers: Record<string, string>;
  request_body?: string | null;
  response_status: number;
  response_headers: Record<string, string>;
  response_body: string;
  timestamp: string;
  duration_ms: number;
  note?: string;
}

export interface RetestRecord {
  id: number;
  timestamp: string;
  previous_status: string;
  new_status: string;
  passed: boolean;
  before_evidence: Evidence;
  after_evidence: Evidence;
  changed_behavior?: string;
}

export interface Finding {
  finding_record_id: string;
  id: string;                         // legacy alias for finding_record_id
  assessment_id: string;
  finding_key: string;                // stable logical key e.g. AUTHZ_IDOR_REPORT
  vuln_key: string;

  /** Classification trinity — MANDATORY on every finding */
  origin: FindingOrigin;
  environment_type: EnvironmentType;
  verification_status: VerificationStatus;

  title: string;
  description: string;
  affected_component: string;
  scope_area: string;
  cwe_id: string;
  owasp_category: string;
  cvss_vector: string;
  cvss_score: number;
  severity: Severity;
  metric_reasoning?: string;

  steps_to_reproduce: string[];
  proof_of_concept: string;
  business_impact: string;
  remediation: string;
  code_diff: string;

  /** Legacy status for UI compat */
  status: FindingStatus;
  evidence: Evidence;
  retest_history?: RetestRecord[];

  /** Source analysis fields */
  source_file?: string;
  line_number?: number;
  symbol?: string;
  source_snippet?: string;
  data_flow_source?: string;
  data_flow_sink?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';

  known_issue?: boolean;
  newly_discovered?: boolean;
  created_at: string;
  updated_at?: string;
}

export interface AssessmentRun {
  id: string;
  target_url: string;
  assessment_mode: 'SOURCE' | 'DYNAMIC' | 'LAB';
  status: string;
  authorized: boolean;
  operator_identifier: string;
  started_at: string;
  completed_at?: string;
  total_findings: number;
  findings_by_severity: Record<Severity, number>;
  modules_scanned: string[];
}

export interface OverviewStats {
  risk_score: number;
  risk_rating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAR';
  total_findings: number;
  active_vulnerabilities: number;
  remediated_count: number;
  severity_breakdown: Record<Severity, number>;
  verification_status_breakdown: Record<VerificationStatus, number>;
  origin_breakdown: Record<FindingOrigin, number>;
  environment_type_breakdown: Record<EnvironmentType, number>;
  top_affected_components: { component: string; count: number }[];
  compliance_score_percent: number;
}

export interface ScopeDomainStat {
  name: string;
  findings_count: number;
  max_cvss: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  confirmed: number;
  candidate: number;
  remediated: number;
  status: 'PASS' | 'FAIL' | 'REMEDIATED' | 'CANDIDATE';
}

export interface OwaspStat {
  category: string;
  name: string;
  count: number;
  findings: string[];
}

export interface CoverageData {
  scope_domains: ScopeDomainStat[];
  owasp_coverage: OwaspStat[];
  total_active_checks: number;
  total_findings: number;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  action: string;
  target: string;
  operator: string;
  status: 'SUCCESS' | 'BLOCKED' | 'FAILED' | 'VERIFIED' | 'PASSED';
  details: Record<string, any>;
  prev_hash?: string;
  row_hash?: string;
}

export interface AuditChainVerification {
  verified: boolean;
  total_entries: number;
  broken_at_id?: number;
  note: string;
}
