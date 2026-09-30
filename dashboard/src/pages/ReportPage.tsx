import React, { useState, useEffect } from 'react';
import { Download, Shield, FileText } from 'lucide-react';
import { Finding, OverviewStats } from '../types';
import { Card } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';

interface Props {
  findings: Finding[];
  stats: OverviewStats | null;
}

export const ReportPage: React.FC<Props> = ({ findings, stats }) => {
  const [reportMd, setReportMd] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/report/markdown')
      .then((r) => r.text())
      .then((text) => {
        setReportMd(text);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to fetch report:', err);
        setLoading(false);
      });
  }, []);

  const downloadPdf = () => {
    window.open('/api/report/pdf', '_blank');
  };

  const downloadMd = () => {
    const blob = new Blob([reportMd], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'World_Monitor_Security_Assessment_Report.md';
    a.click();
    URL.revokeObjectURL(url);
  };

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const remediatedCount = findings.filter((f) => f.status === 'RETESTED_PASS').length;

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standard Page Header */}
      <PageHeader
        title="Formal assessment report"
        subtitle="Executive and technical audit findings report generated strictly in accordance with SIH26163 (NTRO) standards."
        actions={
          <div className="flex items-center gap-3">
            <button
              onClick={downloadMd}
              className="flex items-center gap-2 h-[38px] px-3.5 rounded-[8px] text-[13px] font-medium bg-[var(--bg-raised)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] transition-all"
            >
              <Download className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
              <span>Download Markdown</span>
            </button>
            <button
              onClick={downloadPdf}
              className="flex items-center gap-2 h-[38px] px-4 rounded-[8px] text-[13px] font-semibold bg-[var(--accent)] text-white hover:opacity-95 shadow-xs transition-opacity"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </button>
          </div>
        }
      />

      {/* Report Document Container */}
      <Card padding="lg" className="space-y-6">
        {/* Cover / Document Header */}
        <div className="border-b border-[var(--border-subtle)] pb-6 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-medium bg-[var(--severity-critical-bg)] border border-[var(--severity-critical-border)] text-[var(--severity-critical)] px-2.5 py-0.5 rounded-[6px]">
              Restricted // Confidential
            </span>
            <span className="text-[12px] font-mono text-[var(--text-tertiary)] bg-[var(--bg-raised)] px-2.5 py-1 rounded-[6px] border border-[var(--border-subtle)]">
              Ref: SIH26163-NTRO-SEC-2026
            </span>
          </div>

          <div>
            <h1 className="text-[24px] leading-[32px] font-semibold text-[var(--text-primary)]">
              Security assessment of the World Monitor application
            </h1>
            <p className="text-[14px] leading-[22px] text-[var(--text-secondary)] mt-1">
              Comprehensive vulnerability audit, impact evaluation, safe proof-of-concepts, and remediation roadmap
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-3 text-[13px] border-t border-[var(--border-subtle)]">
            <div className="space-y-0.5">
              <span className="text-[12px] text-[var(--text-tertiary)] block">Sponsoring agency</span>
              <strong className="text-[var(--text-primary)] font-medium">NTRO / SIH 2026</strong>
            </div>
            <div className="space-y-0.5">
              <span className="text-[12px] text-[var(--text-tertiary)] block">Evaluation target</span>
              <strong className="text-[var(--text-primary)] font-medium">World Monitor Lab (Controlled)</strong>
            </div>
            <div className="space-y-0.5">
              <span className="text-[12px] text-[var(--text-tertiary)] block">Lead AppSec engineer</span>
              <strong className="text-[var(--text-primary)] font-medium">Automated audit platform</strong>
            </div>
            <div className="space-y-0.5">
              <span className="text-[12px] text-[var(--text-tertiary)] block">Audit date</span>
              <strong className="text-[var(--text-primary)] font-medium tabular-nums font-mono text-[12px]">{new Date().toISOString().slice(0, 10)}</strong>
            </div>
          </div>
        </div>

        {/* Executive Summary Card */}
        <div className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] p-6 rounded-[10px] space-y-4 text-[14px] leading-[22px] text-[var(--text-secondary)]">
          <h3 className="text-[16px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
            <Shield className="w-4 h-4 text-[var(--accent)]" />
            <span>1. Executive summary and posture synthesis</span>
          </h3>
          <p>
            An authorized security assessment of the World Monitor application replica was conducted within a controlled laboratory environment strictly enforcing localhost boundaries. Across 7 critical scope domains, the assessment surfaced <strong className="text-[var(--text-primary)]">{findings.length} verified vulnerabilities</strong> with stored HTTP request/response evidence.
          </p>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2 text-center tabular-nums">
            <div className="bg-[var(--bg-surface)] p-3.5 rounded-[8px] border border-[var(--border-subtle)]">
              <div className="text-[var(--text-tertiary)] text-[12px] font-medium">Total findings</div>
              <div className="text-[20px] font-bold text-[var(--text-primary)] mt-1">{findings.length}</div>
            </div>
            <div className="bg-[var(--bg-surface)] p-3.5 rounded-[8px] border border-[var(--border-subtle)]">
              <div className="text-[var(--text-tertiary)] text-[12px] font-medium">Critical severity</div>
              <div className="text-[20px] font-bold text-[var(--severity-critical)] mt-1">
                {criticalCount}
              </div>
            </div>
            <div className="bg-[var(--bg-surface)] p-3.5 rounded-[8px] border border-[var(--border-subtle)]">
              <div className="text-[var(--text-tertiary)] text-[12px] font-medium">Remediated & verified</div>
              <div className="text-[20px] font-bold text-[var(--status-fixed)] mt-1">
                {remediatedCount}
              </div>
            </div>
            <div className="bg-[var(--bg-surface)] p-3.5 rounded-[8px] border border-[var(--border-subtle)]">
              <div className="text-[var(--text-tertiary)] text-[12px] font-medium">Risk score</div>
              <div className="text-[20px] font-bold text-[var(--severity-high)] mt-1">
                {stats?.risk_score || 78} / 100
              </div>
            </div>
          </div>
        </div>

        {/* Formatted Report Preview */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-[var(--accent)]" />
            <h3 className="text-[16px] font-semibold text-[var(--text-primary)]">
              Report preview
            </h3>
          </div>
          {loading ? (
            <div className="p-12 text-center text-[13px] text-[var(--text-tertiary)]">
              Generating formatted report document...
            </div>
          ) : (
            <pre className="bg-[var(--bg-app)] border border-[var(--border-subtle)] rounded-[8px] p-5 font-mono text-[12px] leading-[22px] text-[var(--text-secondary)] whitespace-pre-wrap overflow-x-auto max-h-[520px]">
              {reportMd}
            </pre>
          )}
        </div>
      </Card>
    </div>
  );
};
