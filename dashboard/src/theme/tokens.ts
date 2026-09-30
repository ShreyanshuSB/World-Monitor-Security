/**
 * Design Tokens & Theme Configuration (Single Source of Truth)
 * Conforming strictly to enterprise DevSecOps standards (Snyk / Wiz / Datadog).
 */

export interface SeverityDef {
  label: string;
  color: string;
  bg: string;
  border: string;
}

export interface StatusDef {
  label: string;
  color: string;
  bg: string;
  border: string;
  iconName?: string;
}

// Severity Token Definitions (Muted palette, 12% tint background, 28% border)
export const SEVERITY_TOKENS: Record<string, SeverityDef> = {
  CRITICAL: {
    label: 'Critical',
    color: 'var(--severity-critical)',
    bg: 'var(--severity-critical-bg)',
    border: 'var(--severity-critical-border)',
  },
  HIGH: {
    label: 'High',
    color: 'var(--severity-high)',
    bg: 'var(--severity-high-bg)',
    border: 'var(--severity-high-border)',
  },
  MEDIUM: {
    label: 'Medium',
    color: 'var(--severity-medium)',
    bg: 'var(--severity-medium-bg)',
    border: 'var(--severity-medium-border)',
  },
  LOW: {
    label: 'Low',
    color: 'var(--severity-low)',
    bg: 'var(--severity-low-bg)',
    border: 'var(--severity-low-border)',
  },
  INFO: {
    label: 'Info',
    color: 'var(--severity-info)',
    bg: 'var(--severity-info-bg)',
    border: 'var(--severity-info-border)',
  },
};

// Raw Hex Fallbacks for SVG / Canvas / Recharts charts (matching CSS variables)
export const CHART_COLORS = {
  CRITICAL: '#F26D78',
  HIGH: '#F2A65A',
  MEDIUM: '#E6C15A',
  LOW: '#6FA8F0',
  INFO: '#8A94A6',
  ACCENT: '#7C9CFF',
  SUCCESS: '#52C48F',
  MUTED: '#2E3846',
  TEXT_SECONDARY: '#A3ADBB',
};

/**
 * Maps raw backend enums to clean, human-readable labels.
 * Raw enums like 'RETESTED_PASS' or 'AUTHZ_IDOR_REPORT' MUST NEVER render to the user.
 */
export function getStatusLabel(status: string): string {
  if (!status) return 'Detected';
  const s = status.toUpperCase().trim();
  switch (s) {
    case 'RETESTED_PASS':
      return 'Re-tested: passed';
    case 'RETESTED_FAIL':
      return 'Re-tested: failed';
    case 'FIXED':
      return 'Fixed';
    case 'VERIFIED':
      return 'Verified';
    case 'DETECTED':
    default:
      return 'Detected';
  }
}

/**
 * Returns human-readable severity label in proper sentence case.
 */
export function getSeverityLabel(severity: string): string {
  if (!severity) return 'Info';
  const s = severity.toUpperCase().trim();
  switch (s) {
    case 'CRITICAL':
      return 'Critical';
    case 'HIGH':
      return 'High';
    case 'MEDIUM':
      return 'Medium';
    case 'LOW':
      return 'Low';
    default:
      return 'Info';
  }
}

/**
 * Returns human-readable domain label.
 */
export function formatDomainName(domain: string): string {
  if (!domain) return '';
  return domain.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
