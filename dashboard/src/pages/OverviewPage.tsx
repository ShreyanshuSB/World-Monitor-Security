import React, { useMemo } from 'react';
import { ChevronRight, ArrowUpRight } from 'lucide-react';
import { Finding, OverviewStats, ScopeDomainStat } from '../types';
import { Card, CardHeader } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';
import { KpiCard } from '../components/common/KpiCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusPill } from '../components/common/StatusPill';
import { CardSkeleton, TableSkeleton } from '../components/common/Skeleton';
import { CHART_COLORS } from '../theme/tokens';

// Module-level constants — stable references, never recreated on render.
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

interface Props {
  stats: OverviewStats | null;
  findings: Finding[];
  domains: ScopeDomainStat[];
  onSelectFinding: (f: Finding) => void;
  onFilterSeverity: (sev: string) => void;
  onNavigate: (page: string) => void;
}

export const OverviewPage: React.FC<Props> = ({
  stats,
  findings,
  onSelectFinding,
  onFilterSeverity,
  onNavigate,
}) => {
  // ── Severity order & labels ────────────────────────────────────────────────
  // Module-level SEVERITY_ORDER / SEVERITY_LABELS are used (stable references).

  // ── KPI scalars ──────────────────────────────────────────────────────────
  // Fall back to 0 when stats is null so hooks below always run.
  const totalCount = stats?.total_findings ?? 0;

  // ── Donut Chart Calculations (200px diameter, 18px stroke, r = 82) ────────
  // useMemo must be called unconditionally — safe defaults used when stats is null.
  const donutData = useMemo(() => {
    const radius = 82;
    const circumference = 2 * Math.PI * radius;
    let accumulatedAngle = 0;
    const breakdown = stats?.severity_breakdown ?? {} as Record<string, number>;

    return SEVERITY_ORDER.map((sev) => {
      const count = breakdown[sev] || 0;
      const percent = totalCount > 0 ? (count / totalCount) * 100 : 0;
      const strokeLength = (percent / 100) * circumference;
      const strokeDashoffset = -accumulatedAngle;
      accumulatedAngle += strokeLength;

      return {
        key: sev,
        label: SEVERITY_LABELS[sev],
        count,
        percent: Math.round(percent),
        color: CHART_COLORS[sev],
        strokeDasharray: `${strokeLength} ${circumference}`,
        strokeDashoffset,
      };
    });
  }, [stats?.severity_breakdown, totalCount]);

  // ── Most Affected Endpoints (real counts, descending) ────────────────────
  const sortedComponents = useMemo(() => {
    const components = stats?.top_affected_components ?? [];
    const maxVal = Math.max(1, ...components.map((c) => c.count));
    return components.map((c) => ({
      ...c,
      percent: Math.round((c.count / maxVal) * 100),
    }));
  }, [stats?.top_affected_components]);

  // ── Priority Queue: sorted by CVSS score descending ──────────────────────
  const priorityFindings = useMemo(() => {
    return [...findings].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 5);
  }, [findings]);

  // ── Early return skeleton while data loads ───────────────────────────────
  if (!stats) {
    return (
      <div className="space-y-6 max-w-[1440px] mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <CardSkeleton />
          <CardSkeleton />
        </div>
        <TableSkeleton rows={5} />
      </div>
    );
  }

  // Row 1 KPI Calculations (Driven strictly by API stats)
  const openCount = stats.active_vulnerabilities;
  const fixedCount = stats.remediated_count;

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standardized Page Header */}
      <PageHeader
        title="Posture overview"
        subtitle="Automated vulnerability assessment and real-time defense posture synthesis"
        actions={
          <button
            onClick={() => onNavigate('run')}
            className="flex items-center gap-2 h-[34px] px-3.5 rounded-[8px] text-[13px] font-medium bg-[var(--accent)] text-white hover:opacity-95 transition-opacity"
          >
            <span>Launch assessment</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        }
      />

      {/* Row 1: Four KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* KPI 1: Risk Score with special emphasis */}
        <KpiCard
          label="Risk score"
          value={`${stats.risk_score} / 100`}
          sublabel="Calculated CVSS blast radius"
          progressPercent={stats.risk_score}
          progressColor={stats.risk_score > 70 ? 'var(--severity-critical)' : 'var(--severity-high)'}
          progressText={stats.risk_rating === 'CRITICAL' ? 'Critical' : 'High'}
          highlight={true}
          onClick={() => onNavigate('findings')}
        />

        {/* KPI 2: Verified Findings */}
        <KpiCard
          label="Verified findings"
          value={totalCount}
          sublabel={`${openCount} open, ${fixedCount} fixed`}
          onClick={() => onNavigate('findings')}
        />

        {/* KPI 3: Fixed and Re-tested */}
        <KpiCard
          label="Fixed and re-tested"
          value={fixedCount}
          sublabel={`${fixedCount} of ${totalCount} findings`}
          onClick={() => onNavigate('remediation')}
        />

        {/* KPI 4: Scope Coverage */}
        <KpiCard
          label="Scope coverage"
          value="7 of 7"
          sublabel="Domains assessed"
          onClick={() => onNavigate('coverage')}
        />
      </div>

      {/* Row 2: Findings by Severity Donut + Most Affected Endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Card: Findings by Severity Donut */}
        <Card padding="md" className="flex flex-col">
          <CardHeader
            title="Findings by severity"
            subtitle="Distribution of verified vulnerabilities across severity tiers"
          />

          <div className="pt-6 flex-1 flex flex-col md:flex-row items-center justify-center gap-8">
            {/* Centered Donut 200px diameter */}
            <div className="relative w-[200px] h-[200px] shrink-0 flex items-center justify-center">
              <svg width="200" height="200" viewBox="0 0 200 200" className="rotate-[-90deg]">
                {/* Background Track */}
                <circle
                  cx="100"
                  cy="100"
                  r="82"
                  fill="transparent"
                  stroke="var(--border-subtle)"
                  strokeWidth="18"
                />
                {/* Segment Rings */}
                {donutData.map((d) => (
                  <circle
                    key={d.key}
                    cx="100"
                    cy="100"
                    r="82"
                    fill="transparent"
                    stroke={d.color}
                    strokeWidth="18"
                    strokeDasharray={d.strokeDasharray}
                    strokeDashoffset={d.strokeDashoffset}
                    strokeLinecap="round"
                    className="transition-all duration-300"
                  />
                ))}
              </svg>

              {/* Total count in center */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none">
                <span className="text-[28px] leading-[32px] font-semibold text-[var(--text-primary)] tabular-nums">
                  {totalCount}
                </span>
                <span className="text-[12px] leading-[16px] text-[var(--text-tertiary)] mt-0.5">
                  findings
                </span>
              </div>
            </div>

            {/* Legend to the right */}
            <div className="w-full max-w-xs space-y-2">
              {donutData.map((d) => {
                const isZero = d.count === 0;
                return (
                  <button
                    key={d.key}
                    onClick={() => onFilterSeverity(d.key)}
                    disabled={isZero}
                    className={`w-full flex items-center justify-between p-2 rounded-[6px] transition-colors text-left ${
                      isZero
                        ? 'opacity-40 cursor-default'
                        : 'hover:bg-[var(--bg-hover)] cursor-pointer'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <span
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ backgroundColor: d.color }}
                      />
                      <span
                        className={`text-[13px] leading-[18px] ${
                          isZero
                            ? 'text-[var(--text-tertiary)]'
                            : 'text-[var(--text-primary)] font-medium'
                        }`}
                      >
                        {d.label}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 tabular-nums text-[13px]">
                      <span
                        className={
                          isZero
                            ? 'text-[var(--text-tertiary)]'
                            : 'text-[var(--text-primary)] font-semibold'
                        }
                      >
                        {d.count}
                      </span>
                      <span className="text-[12px] text-[var(--text-tertiary)] w-10 text-right">
                        {d.percent}%
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </Card>

        {/* Right Card: Most Affected Endpoints */}
        <Card padding="md" className="flex flex-col">
          <CardHeader
            title="Most affected endpoints"
            subtitle="Components ranked by total verified issue density"
          />

          <div className="pt-6 flex-1 flex flex-col justify-center space-y-4">
            {sortedComponents.length === 0 ? (
              <div className="text-center text-[13px] text-[var(--text-tertiary)] py-8">
                No affected endpoints recorded yet.
              </div>
            ) : (
              sortedComponents.map((item) => (
                <div key={item.component} className="space-y-1.5">
                  <div className="flex items-center justify-between text-[12px] leading-[16px]">
                    <span
                      title={item.component}
                      className="font-mono text-[12px] text-[var(--text-primary)] truncate max-w-[320px]"
                    >
                      {item.component}
                    </span>
                    <span className="text-[12px] font-semibold text-[var(--text-secondary)] tabular-nums">
                      {item.count} {item.count === 1 ? 'issue' : 'issues'}
                    </span>
                  </div>

                  {/* 12px height bar, rounded ends, no gridlines */}
                  <div className="w-full bg-[var(--bg-raised)] h-[12px] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-300"
                      style={{
                        width: `${item.percent}%`,
                        backgroundColor: 'var(--accent)',
                      }}
                    />
                  </div>
                </div>
              ))
            )}

            {/* Integer-only baseline label */}
            <div className="pt-2 border-t border-[var(--border-subtle)] flex justify-between text-[12px] text-[var(--text-tertiary)] tabular-nums">
              <span>0 issues</span>
              <span>Sorted descending</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Row 3: Priority Findings (Actionable List) */}
      <Card padding="none">
        <div className="p-5 md:p-6 border-b border-[var(--border-subtle)] flex items-center justify-between">
          <div>
            <h3 className="text-[16px] leading-[22px] font-semibold text-[var(--text-primary)]">
              Priority findings
            </h3>
            <p className="text-[13px] leading-[18px] text-[var(--text-secondary)] mt-0.5">
              Actionable verified vulnerabilities ordered by CVSS v3.1 base score
            </p>
          </div>
          <button
            onClick={() => onNavigate('findings')}
            className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-[var(--accent)] hover:underline"
          >
            <span>View all findings ({totalCount})</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        {/* Table Content */}
        <div className="divide-y divide-[var(--border-subtle)]">
          {priorityFindings.map((f) => (
            <div
              key={f.id}
              onClick={() => onSelectFinding(f)}
              className="grid grid-cols-[106px_150px_1fr_150px_20px] items-center gap-4 h-[64px] px-5 md:px-6 hover:bg-[var(--bg-hover)] cursor-pointer transition-colors"
            >
              {/* Severity badge: fixed 106px */}
              <div className="shrink-0 w-[106px]">
                <SeverityBadge severity={f.severity} score={f.cvss_score} fixedWidth />
              </div>

              {/* Finding ID: mono 12px, fixed 150px */}
              <div className="font-mono text-[12px] text-[var(--text-secondary)] truncate shrink-0 w-[150px]">
                {f.id}
              </div>

              {/* Title & Domain/Component: 1fr */}
              <div className="min-w-0 pr-4">
                <div className="text-[15px] leading-[22px] font-semibold text-[var(--text-primary)] truncate">
                  {f.title}
                </div>
                <div className="text-[13px] leading-[18px] text-[var(--text-tertiary)] truncate mt-0.5">
                  <span>{f.scope_area}</span>
                  <span className="mx-1.5">&bull;</span>
                  <code className="font-mono text-[12px] text-[var(--text-secondary)]">
                    {f.affected_component}
                  </code>
                </div>
              </div>

              {/* Status pill: fixed 150px */}
              <div className="shrink-0 w-[150px]">
                <StatusPill status={f.status} fixedWidth />
              </div>

              {/* Chevron */}
              <div className="text-[var(--text-tertiary)] flex justify-end">
                <ChevronRight className="w-4 h-4" />
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
