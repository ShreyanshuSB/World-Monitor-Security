import React from 'react';
import { CoverageData } from '../types';
import { Card, CardHeader } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';
import { CardSkeleton } from '../components/common/Skeleton';

interface Props {
  coverage: CoverageData | null;
  onNavigateFindings: (domain: string) => void;
}

export const CoveragePage: React.FC<Props> = ({ coverage, onNavigateFindings }) => {
  if (!coverage) {
    return (
      <div className="space-y-6 max-w-[1440px] mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standardized Page Header */}
      <PageHeader
        title="Scope coverage and OWASP matrix"
        subtitle="Diagnostic mapping against the 7 mandatory SIH26163 scope domains and OWASP Top 10 standard"
        actions={
          <div className="flex items-center gap-2.5 text-[12px] tabular-nums">
            <div className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-3 py-1.5 rounded-[8px] text-[var(--text-secondary)]">
              Active checks: <strong className="text-[var(--text-primary)] font-semibold">{coverage.total_active_checks} modules</strong>
            </div>
            <div className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-3 py-1.5 rounded-[8px] text-[var(--text-secondary)]">
              Total findings: <strong className="text-[var(--text-primary)] font-semibold">{coverage.total_findings} flaws</strong>
            </div>
          </div>
        }
      />

      {/* 7 Scope Domains Grid */}
      <Card padding="md" className="space-y-4">
        <CardHeader
          title="7 core security scope domains"
          subtitle="Mandatory evaluation areas assessed by automated probes"
        />

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-1">
          {coverage.scope_domains.map((dom) => {
            const hasFlaws = dom.findings_count > 0;
            const isCritical = dom.critical > 0;
            const isRemediated = dom.remediated > 0 && dom.remediated === dom.findings_count;

            let badgeLabel = 'Pass';
            let badgeBg = 'var(--status-fixed-bg)';
            let badgeBorder = 'var(--status-fixed-border)';
            let badgeText = 'var(--status-fixed)';

            if (isCritical) {
              badgeLabel = 'CRITICAL RISK';
              badgeBg = 'var(--severity-critical-bg)';
              badgeBorder = 'var(--severity-critical-border)';
              badgeText = 'var(--severity-critical)';
            } else if (hasFlaws && !isRemediated) {
              badgeLabel = 'ACTIVE ISSUES';
              badgeBg = 'var(--severity-high-bg)';
              badgeBorder = 'var(--severity-high-border)';
              badgeText = 'var(--severity-high)';
            } else if (isRemediated) {
              badgeLabel = 'REMEDIATED';
              badgeBg = 'var(--status-retested-pass-bg)';
              badgeBorder = 'var(--status-retested-pass-border)';
              badgeText = 'var(--status-retested-pass)';
            }

            return (
              <div
                key={dom.name}
                onClick={() => onNavigateFindings(dom.name)}
                className="p-5 rounded-[12px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] hover:border-[var(--accent)] hover:bg-[var(--bg-hover)] cursor-pointer transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2.5">
                    <h4 className="text-[15px] leading-[22px] font-bold text-[var(--text-primary)]">
                      {dom.name}
                    </h4>
                    <span
                      style={{
                        backgroundColor: badgeBg,
                        borderColor: badgeBorder,
                        color: badgeText,
                      }}
                      className="text-[12px] px-2.5 py-0.5 rounded-[5px] border font-semibold select-none shrink-0 tracking-wider"
                    >
                      {badgeLabel}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2 text-center pt-3 mt-3 border-t border-[var(--border-subtle)] tabular-nums">
                  <div className="bg-[var(--bg-surface)] p-2 rounded-[6px] border border-[var(--border-subtle)]">
                    <div className="text-[12px] text-[var(--text-tertiary)]">Findings</div>
                    <div className="text-[15px] font-bold text-[var(--text-primary)] mt-0.5">{dom.findings_count}</div>
                  </div>
                  <div className="bg-[var(--bg-surface)] p-2 rounded-[6px] border border-[var(--border-subtle)]">
                    <div className="text-[12px] text-[var(--text-tertiary)]">Max CVSS</div>
                    <div className="text-[15px] font-bold text-[var(--text-primary)] mt-0.5">{dom.max_cvss.toFixed(1)}</div>
                  </div>
                  <div className="bg-[var(--bg-surface)] p-2 rounded-[6px] border border-[var(--border-subtle)]">
                    <div className="text-[12px] text-[var(--text-tertiary)]">Fixed</div>
                    <div className="text-[15px] font-bold text-[var(--status-fixed)] mt-0.5">{dom.remediated}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* OWASP Top 10 (2021) Mapping Matrix */}
      <Card padding="md" className="space-y-4">
        <CardHeader
          title="OWASP Top 10 standard alignment"
          subtitle="Cross-mapping of confirmed issues against industry categories"
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          {coverage.owasp_coverage.map((ow) => {
            const hasHits = ow.count > 0;
            return (
              <div
                key={ow.category}
                className="p-4 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] flex items-center justify-between text-[13px]"
              >
                <div className="flex items-center gap-3 min-w-0 pr-3">
                  <span className="font-mono text-[12px] font-bold px-2.5 py-1 rounded-[6px] bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-primary)] shrink-0">
                    {ow.category}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[14px] font-semibold text-[var(--text-primary)] truncate">{ow.name}</div>
                    <div className="text-[12px] text-[var(--text-tertiary)] mt-0.5">OWASP Top 10:2021</div>
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <span
                    className={`text-[12px] font-semibold px-2.5 py-1 rounded-[6px] border tabular-nums ${
                      hasHits
                        ? 'bg-[var(--severity-high-bg)] text-[var(--severity-high)] border-[var(--severity-high-border)]'
                        : 'bg-[var(--bg-surface)] text-[var(--text-tertiary)] border-[var(--border-subtle)]'
                    }`}
                  >
                    {ow.count} {ow.count === 1 ? 'issue' : 'issues'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
};
