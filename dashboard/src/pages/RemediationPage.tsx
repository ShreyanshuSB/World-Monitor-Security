import React, { useState } from 'react';
import {
  Wrench,
  RefreshCw,
  Code,
} from 'lucide-react';
import { Finding } from '../types';
import { Card, CardHeader } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusPill } from '../components/common/StatusPill';

interface Props {
  findings: Finding[];
  onApplyFix: (findingId: string) => Promise<void>;
  onRetest: (findingId: string) => Promise<any>;
  onSelectFinding: (f: Finding) => void;
}

export const RemediationPage: React.FC<Props> = ({
  findings,
  onApplyFix,
  onRetest,
}) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string>(findings[0]?.id || '');
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [retestResult, setRetestResult] = useState<any | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const selected = findings.find((f) => f.id === selectedFindingId) || findings[0];

  const handleApply = async (id: string) => {
    setLoadingAction(`patch-${id}`);
    setNotification('Applying patch to target laboratory...');
    try {
      await onApplyFix(id);
      setNotification('Remediation patch injected successfully. Ready to re-run verification check.');
    } catch (e: any) {
      setNotification(`Patch error: ${e.message}`);
    } finally {
      setLoadingAction(null);
      setTimeout(() => setNotification(null), 5000);
    }
  };

  const handleRetest = async (id: string) => {
    setLoadingAction(`retest-${id}`);
    setNotification('Re-running verification probe against target...');
    try {
      const result = await onRetest(id);
      setRetestResult(result);
      if (result.passed) {
        setNotification('Verification probe confirmed: Vulnerability successfully remediated! Status: Re-tested: passed.');
      } else {
        setNotification('Verification probe completed: Target still exhibits vulnerable behavior.');
      }
    } catch (e: any) {
      setNotification(`Retest error: ${e.message}`);
    } finally {
      setLoadingAction(null);
      setTimeout(() => setNotification(null), 6000);
    }
  };

  if (!selected) {
    return (
      <div className="p-8 text-center text-[14px] text-[var(--text-secondary)]">
        No findings available for remediation.
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standardized Page Header */}
      <PageHeader
        title="Remediation and re-test"
        subtitle="Apply targeted code mitigations to the lab replica and execute verification probes"
        actions={
          notification ? (
            <div className="bg-[var(--bg-raised)] border border-[var(--border-strong)] px-3.5 py-1.5 rounded-[8px] text-[13px] text-[var(--text-primary)] font-medium">
              {notification}
            </div>
          ) : undefined
        }
      />

      {/* Main Split: Left 30% Selector & Right 70% Action Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-10 gap-6">
        {/* Left Column: List of Findings (3 cols = 30%) */}
        <div className="lg:col-span-3 space-y-3">
          <div className="flex items-center justify-between text-[13px] font-medium text-[var(--text-secondary)] px-1">
            <span>Select vulnerability</span>
            <span className="font-mono text-[12px] text-[var(--text-tertiary)]">({findings.length})</span>
          </div>

          <div className="space-y-2.5 max-h-[780px] overflow-y-auto pr-1">
            {findings.map((f) => {
              const isCurrent = f.id === selected.id;
              return (
                <div
                  key={f.id}
                  onClick={() => {
                    setSelectedFindingId(f.id);
                    setRetestResult(null);
                  }}
                  className={`p-3.5 rounded-[10px] border cursor-pointer transition-all ${
                    isCurrent
                      ? 'bg-[var(--bg-raised)] border-[var(--accent)] ring-1 ring-[var(--accent)] shadow-xs'
                      : 'bg-[var(--bg-surface)] border-[var(--border-subtle)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-hover)]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-mono text-[12px] text-[var(--text-secondary)] font-medium">{f.id}</span>
                    <SeverityBadge severity={f.severity} score={f.cvss_score} fixedWidth />
                  </div>

                  <div className="text-[14px] leading-[20px] font-semibold text-[var(--text-primary)] line-clamp-2">
                    {f.title}
                  </div>

                  <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-[var(--border-subtle)] text-[12px]">
                    <span className="font-mono text-[12px] text-[var(--text-tertiary)] truncate max-w-[130px]">
                      {f.affected_component}
                    </span>
                    <StatusPill status={f.status} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: 7 cols = 70% Remediation Workspace */}
        <div className="lg:col-span-7 space-y-6">
          {/* Header Card */}
          <Card padding="md" className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="font-mono text-[12px] text-[var(--text-secondary)]">{selected.id}</span>
                  <SeverityBadge severity={selected.severity} score={selected.cvss_score} />
                  <StatusPill status={selected.status} />
                </div>
                <h3 className="text-[18px] md:text-[20px] leading-[26px] font-bold text-[var(--text-primary)]">
                  {selected.title}
                </h3>
                <div className="text-[13px] text-[var(--text-tertiary)] mt-1.5 font-mono">
                  Component: <span className="text-[var(--text-secondary)]">{selected.affected_component}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2.5 shrink-0">
                <button
                  onClick={() => handleApply(selected.id)}
                  disabled={loadingAction !== null}
                  className="flex items-center gap-2 h-[36px] px-3.5 rounded-[8px] text-[13px] font-medium bg-[var(--bg-raised)] text-[var(--text-primary)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] transition-colors disabled:opacity-50 cursor-pointer"
                >
                  <Wrench className={`w-4 h-4 ${loadingAction === `patch-${selected.id}` ? 'animate-spin' : ''}`} />
                  <span>Apply fix to lab</span>
                </button>
                <button
                  onClick={() => handleRetest(selected.id)}
                  disabled={loadingAction !== null}
                  className="flex items-center gap-2 h-[36px] px-3.5 rounded-[8px] text-[13px] font-semibold bg-[var(--accent)] text-white hover:opacity-95 transition-opacity disabled:opacity-50 cursor-pointer"
                >
                  <RefreshCw className={`w-4 h-4 ${loadingAction === `retest-${selected.id}` ? 'animate-spin' : ''}`} />
                  <span>Re-run check</span>
                </button>
              </div>
            </div>

            <div className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] p-4 rounded-[10px] text-[14px] leading-[22px] text-[var(--text-secondary)]">
              <strong className="text-[var(--text-primary)] block mb-1.5 font-semibold text-[14px]">
                1. Remediation strategy
              </strong>
              {selected.remediation}
            </div>
          </Card>

          {/* Unified Code Diff Viewer */}
          <Card padding="none" className="overflow-hidden">
            <div className="bg-[var(--bg-raised)] px-4 py-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
              <div className="flex items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
                <Code className="w-4 h-4 text-[var(--text-secondary)]" />
                <span>2. Unified source code diff</span>
              </div>
              <span className="text-[12px] text-[var(--text-tertiary)] font-mono">Unified diff format</span>
            </div>

            <div className="p-4 font-mono text-[12px] leading-[20px] overflow-x-auto whitespace-pre bg-[var(--bg-app)]">
              {selected.code_diff.split('\n').map((line, idx) => {
                let color = 'text-[var(--text-secondary)]';
                let bg = '';
                if (line.startsWith('+')) {
                  color = 'text-[var(--status-fixed)]';
                  bg = 'bg-[var(--status-fixed-bg)]';
                } else if (line.startsWith('-')) {
                  color = 'text-[var(--severity-critical)]';
                  bg = 'bg-[var(--severity-critical-bg)]';
                } else if (line.startsWith('@@')) {
                  color = 'text-[var(--accent)]';
                }
                return (
                  <div key={idx} className={`${color} ${bg} px-1.5 rounded-[3px]`}>
                    {line}
                  </div>
                );
              })}
            </div>
          </Card>

          {/* Before vs After Evidence Comparison */}
          <Card padding="md" className="space-y-4">
            <CardHeader
              title="3. Before and after verification evidence"
              subtitle="Empirical request and response telemetry comparison confirming vulnerability closure"
            />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[12px]">
              {/* Before Evidence */}
              <div className="bg-[var(--bg-app)] border border-[var(--severity-critical-border)] rounded-[8px] p-4 space-y-2">
                <div className="flex items-center justify-between text-[var(--severity-critical)] font-medium border-b border-[var(--border-subtle)] pb-2">
                  <span>Before: initial verified flaw</span>
                  <span className="font-mono tabular-nums">HTTP {selected.evidence.response_status}</span>
                </div>
                <div className="font-mono text-[12px] text-[var(--text-tertiary)] truncate">
                  {selected.evidence.request_method} {selected.evidence.request_url}
                </div>
                <div className="p-3 bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-[6px] font-mono text-[12px] text-[var(--text-secondary)] max-h-40 overflow-y-auto whitespace-pre-wrap">
                  {selected.evidence.response_body.slice(0, 360)}
                </div>
              </div>

              {/* After Evidence */}
              <div className="bg-[var(--bg-app)] border border-[var(--status-fixed-border)] rounded-[8px] p-4 space-y-2">
                <div className="flex items-center justify-between text-[var(--status-fixed)] font-medium border-b border-[var(--border-subtle)] pb-2">
                  <span>After: re-test validation</span>
                  <span className="font-mono tabular-nums">
                    {retestResult
                      ? `HTTP ${retestResult.after_evidence?.response_status || 403}`
                      : selected.status === 'RETESTED_PASS'
                      ? 'Protected'
                      : 'Pending re-test'}
                  </span>
                </div>
                <div className="font-mono text-[12px] text-[var(--text-tertiary)] truncate">
                  {selected.evidence.request_method} {selected.evidence.request_url}
                </div>
                <div className="p-3 bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-[6px] font-mono text-[12px] text-[var(--text-secondary)] max-h-40 overflow-y-auto whitespace-pre-wrap">
                  {retestResult ? (
                    retestResult.after_evidence?.note ||
                    retestResult.after_evidence?.response_body?.slice(0, 360) ||
                    JSON.stringify(retestResult.after_evidence, null, 2)
                  ) : selected.status === 'RETESTED_PASS' ? (
                    'Re-test executed: target successfully rejected unauthorized request or applied safe sanitization. Control validated.'
                  ) : (
                    'Click "Apply fix to lab" then "Re-run check" to capture fresh response.'
                  )}
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
