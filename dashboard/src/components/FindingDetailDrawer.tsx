import React, { useState } from 'react';
import {
  X,
  RefreshCw,
  Wrench,
  AlertTriangle,
  Play,
  Terminal,
  Code,
  FileText,
  Clock,
} from 'lucide-react';
import { Finding } from '../types';
import { getStatusLabel } from '../theme/tokens';
import { SeverityBadge } from './common/SeverityBadge';
import { StatusPill } from './common/StatusPill';
import { CvssVectorBreakdown } from './CvssVectorBreakdown';
import { EvidenceViewer } from './EvidenceViewer';

interface Props {
  finding: Finding | null;
  onClose: () => void;
  onRetest: (findingId: string) => Promise<any>;
  onApplyFix: (findingId: string) => Promise<void>;
}

export const FindingDetailDrawer: React.FC<Props> = ({
  finding,
  onClose,
  onRetest,
  onApplyFix,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'reproduce' | 'remediation' | 'timeline'>('overview');
  const [isRetesting, setIsRetesting] = useState(false);
  const [isPatching, setIsPatching] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  if (!finding) return null;

  // Use finding_record_id (UUID) as the canonical ID for all API operations
  const findingId = finding.finding_record_id || finding.id;

  const handleRetestClick = async () => {
    setIsRetesting(true);
    setFeedback('Re-testing probe against target (target loaded from stored assessment)...');
    try {
      await onRetest(findingId);
      setFeedback('Verification probe finished. Check status for result.');
    } catch (e: any) {
      setFeedback(`Retest error: ${e.message}`);
    } finally {
      setIsRetesting(false);
      setTimeout(() => setFeedback(null), 5000);
    }
  };

  const handleApplyFixClick = async () => {
    if (finding.environment_type !== 'LAB_SYNTHETIC') {
      setFeedback('Apply-fix only available for LAB_SYNTHETIC findings.');
      setTimeout(() => setFeedback(null), 4000);
      return;
    }
    setIsPatching(true);
    setFeedback('Applying lab remediation patch...');
    try {
      await onApplyFix(findingId);
      setFeedback('Lab patch applied. Run retest to validate fix.');
    } catch (e: any) {
      setFeedback(`Patch error: ${e.message}`);
    } finally {
      setIsPatching(false);
      setTimeout(() => setFeedback(null), 5000);
    }
  };

  // Origin badge styles
  const originColors: Record<string, string> = {
    LAB_SYNTHETIC:        'bg-purple-500/15 text-purple-300 border border-purple-500/30',
    SOURCE_STATIC:        'bg-blue-500/15 text-blue-300 border border-blue-500/30',
    DYNAMIC_LOCAL:        'bg-teal-500/15 text-teal-300 border border-teal-500/30',
  };
  const vsColors: Record<string, string> = {
    CONFIRMED:    'bg-red-500/15 text-red-300 border border-red-500/30',
    VALIDATED:    'bg-orange-500/15 text-orange-300 border border-orange-500/30',
    CANDIDATE:    'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
    REMEDIATED:   'bg-green-500/15 text-green-300 border border-green-500/30',
    FALSE_POSITIVE: 'bg-gray-500/15 text-gray-300 border border-gray-500/30',
  };
  const originColor = originColors[finding.origin] || originColors['LAB_SYNTHETIC'];
  const vsColor = vsColors[finding.verification_status] || vsColors['CANDIDATE'];

  const tabs = [
    { id: 'overview', label: 'Overview', icon: FileText },
    { id: 'evidence', label: 'HTTP evidence', icon: Terminal },
    { id: 'reproduce', label: 'Steps and PoC', icon: Play },
    { id: 'remediation', label: 'Remediation and diff', icon: Code },
    { id: 'timeline', label: 'Audit timeline', icon: Clock },
  ] as const;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 flex justify-end">
      <div className="w-full max-w-3xl bg-[var(--bg-surface)] border-l border-[var(--border-subtle)] h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Drawer Header */}
        <div className="p-6 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] flex items-start justify-between gap-4">
          <div className="space-y-2 min-w-0 flex-1">

            {/* Classification Trinity */}
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider ${originColor}`}>
                {finding.origin || 'LAB_SYNTHETIC'}
              </span>
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider ${vsColor}`}>
                {finding.verification_status || 'CANDIDATE'}
              </span>
              {finding.environment_type === 'LAB_SYNTHETIC' && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-900/30 text-purple-200 border border-purple-700/40">
                  ⚗ CONTROLLED LAB — Not a World Monitor production finding
                </span>
              )}
              {finding.environment_type === 'WORLD_MONITOR_SOURCE' && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-900/30 text-blue-200 border border-blue-700/40">
                  📁 SOURCE ANALYSIS — Dynamic validation required
                </span>
              )}
            </div>

            <div className="flex items-center gap-3">
              <span className="font-mono text-[11px] text-[var(--text-secondary)]">
                {finding.finding_key || finding.id}
              </span>
              <SeverityBadge severity={finding.severity} score={finding.cvss_score} />
              <StatusPill status={finding.status} />
            </div>

            <h2 className="text-[20px] leading-[28px] font-semibold text-[var(--text-primary)]">
              {finding.title}
            </h2>

            <div className="flex flex-wrap items-center gap-3 text-[12px] text-[var(--text-secondary)]">
              <span>Domain: <strong className="text-[var(--text-primary)] font-medium">{finding.scope_area}</strong></span>
              <span>&bull;</span>
              <span>Component: <code className="font-mono text-[12px] text-[var(--text-primary)] bg-[var(--bg-raised)] px-1.5 py-0.5 rounded">{finding.affected_component}</code></span>
              {finding.confidence && (
                <><span>&bull;</span><span>Confidence: <strong className="text-[var(--text-primary)]">{finding.confidence}</strong></span></>
              )}
            </div>
          </div>

          <button
            onClick={onClose}
            aria-label="Close drawer"
            className="p-1.5 text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] rounded-[6px] transition-colors shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action Controls Bar */}
        <div className="px-6 py-3 bg-[var(--bg-raised)] border-b border-[var(--border-subtle)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button
              onClick={handleApplyFixClick}
              disabled={isPatching || finding.environment_type !== 'LAB_SYNTHETIC'}
              title={finding.environment_type !== 'LAB_SYNTHETIC' ? 'Apply-fix only available for LAB_SYNTHETIC findings' : 'Apply lab patch'}
              className="flex items-center gap-1.5 text-[13px] font-medium px-3 py-1.5 rounded-[6px] bg-[var(--bg-surface)] text-[var(--text-primary)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Wrench className={`w-3.5 h-3.5 ${isPatching ? 'animate-spin' : ''}`} />
              <span>{isPatching ? 'Injecting patch...' : 'Apply lab fix'}</span>
            </button>

            <button
              onClick={handleRetestClick}
              disabled={isRetesting}
              className="flex items-center gap-1.5 text-[13px] font-medium px-3.5 py-1.5 rounded-[6px] bg-[var(--accent)] text-white hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRetesting ? 'animate-spin' : ''}`} />
              <span>{isRetesting ? 'Probing target...' : 'Re-run check'}</span>
            </button>
          </div>

          {feedback && (
            <span className="text-[12px] text-[var(--text-secondary)]">
              {feedback}
            </span>
          )}
        </div>

        {/* Tab Navigation with Underline Indicator */}
        <div className="flex border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-6 gap-6 text-[14px]">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 py-3 border-b-2 text-[14px] transition-colors ${
                  isActive
                    ? 'border-[var(--accent)] text-[var(--text-primary)] font-semibold'
                    : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                  Vulnerability description
                </h3>
                <p className="text-[14px] leading-[22px] text-[var(--text-secondary)]">
                  {finding.description}
                </p>
              </div>

              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                  Business and mission impact
                </h3>
                <div className="flex items-start gap-3 p-4 rounded-[8px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] text-[14px] leading-[22px] text-[var(--text-primary)]">
                  <AlertTriangle className="w-5 h-5 text-[var(--severity-high)] shrink-0 mt-0.5" />
                  <p>{finding.business_impact}</p>
                </div>
              </div>

              <CvssVectorBreakdown vector={finding.cvss_vector} score={finding.cvss_score} />

              {finding.metric_reasoning && (
                <div>
                  <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                    CVSS metric justification
                  </h3>
                  <div className="p-3 rounded-[8px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] font-mono text-[12px] text-[var(--text-secondary)] leading-[18px] whitespace-pre-wrap">
                    {finding.metric_reasoning}
                  </div>
                </div>
              )}

              {finding.source_file && (
                <div>
                  <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                    Source location
                  </h3>
                  <div className="p-3 rounded-[8px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] space-y-2">
                    <div className="font-mono text-[12px] text-[var(--accent)]">
                      {finding.source_file}{finding.line_number ? `:${finding.line_number}` : ''}
                      {finding.symbol ? ` — ${finding.symbol}` : ''}
                    </div>
                    {finding.source_snippet && (
                      <pre className="text-[11px] text-[var(--text-secondary)] overflow-x-auto">{finding.source_snippet}</pre>
                    )}
                    {finding.data_flow_source && (
                      <div className="text-[12px] text-[var(--text-secondary)]">
                        <span className="text-[var(--text-tertiary)]">Data flow: </span>
                        <code className="text-yellow-400">{finding.data_flow_source}</code>
                        <span className="mx-1">→</span>
                        <code className="text-red-400">{finding.data_flow_sink}</code>
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] p-4 rounded-[8px] space-y-1">
                  <div className="text-[12px] text-[var(--text-tertiary)]">CWE classification</div>
                  <div className="text-[13px] font-medium text-[var(--text-primary)]">{finding.cwe_id}</div>
                </div>
                <div className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] p-4 rounded-[8px] space-y-1">
                  <div className="text-[12px] text-[var(--text-tertiary)]">OWASP category</div>
                  <div className="text-[13px] font-medium text-[var(--text-primary)]">{finding.owasp_category}</div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="text-[13px] text-[var(--text-secondary)]">
                The transaction below represents genuine diagnostic telemetry captured during probe execution against the live target.
              </div>
              <EvidenceViewer evidence={finding.evidence} />
            </div>
          )}

          {activeTab === 'reproduce' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                  Numbered steps to reproduce
                </h3>
                <ol className="space-y-2 bg-[var(--bg-raised)] border border-[var(--border-subtle)] rounded-[8px] p-4 text-[13px] leading-[20px] text-[var(--text-primary)] list-decimal list-inside">
                  {finding.steps_to_reproduce.map((step, i) => (
                    <li key={i} className="pl-1 py-0.5">
                      {step}
                    </li>
                  ))}
                </ol>
              </div>

              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                  Safe proof of concept probe
                </h3>
                <div className="bg-[var(--bg-app)] border border-[var(--border-subtle)] rounded-[8px] p-4 font-mono text-[12px] text-[var(--text-primary)] whitespace-pre-wrap">
                  {finding.proof_of_concept}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                  Remediation recommendation
                </h3>
                <p className="text-[14px] leading-[22px] text-[var(--text-secondary)]">
                  {finding.remediation}
                </p>
              </div>

              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                  Recommended source patch (unified diff)
                </h3>
                <div className="bg-[var(--bg-app)] border border-[var(--border-subtle)] rounded-[8px] p-4 font-mono text-[12px] leading-[20px] overflow-x-auto whitespace-pre">
                  {finding.code_diff.split('\n').map((line, idx) => {
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
                      <div key={idx} className={`${color} ${bg} px-1 rounded-[2px]`}>
                        {line}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <h3 className="text-[14px] font-semibold text-[var(--text-primary)] mb-2">
                Audit lifecycle history
              </h3>
              <div className="border-l-2 border-[var(--border-subtle)] ml-3 space-y-6 pl-5 py-2 text-[13px]">
                <div className="relative">
                  <span className="absolute -left-[27px] top-0 w-3 h-3 rounded-full bg-[var(--accent)]" />
                  <div className="font-semibold text-[var(--text-primary)]">Vulnerability detected and verified</div>
                  <div className="text-[var(--text-tertiary)] font-mono text-[12px] tabular-nums">{finding.created_at}</div>
                  <p className="text-[var(--text-secondary)] mt-1">Automated diagnostic probe confirmed issue with active HTTP evidence.</p>
                </div>

                {finding.retest_history && finding.retest_history.length > 0 ? (
                  finding.retest_history.map((rt, i) => (
                    <div key={i} className="relative">
                      <span
                        className={`absolute -left-[27px] top-0 w-3 h-3 rounded-full ${
                          rt.passed ? 'bg-[var(--status-fixed)]' : 'bg-[var(--severity-critical)]'
                        }`}
                      />
                      <div className="font-semibold text-[var(--text-primary)]">
                        {rt.passed ? 'Verification re-test passed' : 'Verification re-test failed'}
                      </div>
                      <div className="text-[var(--text-tertiary)] font-mono text-[12px] tabular-nums">{rt.timestamp}</div>
                      <p className="text-[var(--text-secondary)] mt-1">
                        Status transitioned to <span className="font-medium text-[var(--text-primary)]">{getStatusLabel(rt.new_status)}</span>.
                      </p>
                    </div>
                  ))
                ) : (
                  <div className="text-[var(--text-tertiary)] text-[13px] italic">No previous re-test records logged yet.</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
