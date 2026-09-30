import React, { useState, useEffect } from 'react';
import { RefreshCw, Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { AuditLogEntry } from '../types';
import { Card } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';
import { TableSkeleton } from '../components/common/Skeleton';
import { EmptyState } from '../components/common/EmptyState';

export const AuditLogPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const fetchLogs = () => {
    setLoading(true);
    fetch('/api/audit-log')
      .then((r) => r.json())
      .then((data) => {
        setLogs(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to load audit logs:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const toggleExpand = (id: number) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standard Page Header */}
      <PageHeader
        title="Audit log ledger"
        subtitle="Cryptographically tracked immutable ledger of all probe requests, scope verifications, and remediation re-tests."
        actions={
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="flex items-center gap-2 h-[38px] px-4 rounded-[8px] text-[13px] font-medium bg-[var(--bg-raised)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[var(--text-secondary)] ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh ledger</span>
          </button>
        }
      />

      {/* Audit Log Table Card */}
      <Card padding="none" className="overflow-hidden">
        {loading && logs.length === 0 ? (
          <TableSkeleton rows={8} />
        ) : logs.length === 0 ? (
          <div className="py-16">
            <EmptyState
              title="No audit entries logged yet"
              description="Events will automatically appear here as diagnostic assessments and re-test probes execute."
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[var(--bg-raised)] border-b border-[var(--border-subtle)] text-[12px] text-[var(--text-tertiary)] font-medium">
                  <th className="py-3 px-5 w-20">Entry</th>
                  <th className="py-3 px-4 w-[200px]">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Action event</th>
                  <th className="py-3 px-4">Target endpoint</th>
                  <th className="py-3 px-4 w-[130px]">Operator</th>
                  <th className="py-3 px-4 w-[120px]">Status</th>
                  <th className="py-3 px-5 w-24 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {logs.map((e) => {
                  const isExpanded = expandedId === e.id;
                  const isSuccess = e.status === 'SUCCESS' || e.status === 'PASSED';
                  const isVerified = e.status === 'VERIFIED';

                  return (
                    <React.Fragment key={e.id}>
                      <tr
                        onClick={() => toggleExpand(e.id)}
                        className={`hover:bg-[var(--bg-hover)] cursor-pointer transition-colors ${
                          isExpanded ? 'bg-[var(--bg-raised)]/50' : ''
                        }`}
                      >
                        <td className="py-3.5 px-5 font-mono text-[12px] text-[var(--text-tertiary)] tabular-nums">
                          #{e.id.toString().padStart(4, '0')}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-[12px] text-[var(--text-secondary)] tabular-nums whitespace-nowrap">
                          {e.timestamp}
                        </td>
                        <td className="py-3.5 px-4 font-semibold text-[14px] text-[var(--text-primary)]">
                          {e.action}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-[12px] text-[var(--text-secondary)] truncate max-w-xs">
                          {e.target}
                        </td>
                        <td className="py-3.5 px-4 text-[13px] text-[var(--text-tertiary)]">
                          {e.operator}
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`inline-flex items-center px-2.5 py-0.5 rounded-[6px] text-[12px] font-medium border ${
                              isSuccess
                                ? 'bg-[var(--status-fixed-bg)] text-[var(--status-fixed)] border-[var(--status-fixed-border)]'
                                : isVerified
                                ? 'bg-[var(--status-verified-bg)] text-[var(--status-verified)] border-[var(--status-verified-border)]'
                                : 'bg-[var(--severity-critical-bg)] text-[var(--severity-critical)] border-[var(--severity-critical-border)]'
                            }`}
                          >
                            {e.status.charAt(0).toUpperCase() + e.status.slice(1).toLowerCase()}
                          </span>
                        </td>
                        <td className="py-3.5 px-5 text-right">
                          <button
                            type="button"
                            className="inline-flex items-center gap-1 text-[13px] text-[var(--accent)] font-medium hover:underline"
                          >
                            <span>{isExpanded ? 'Hide' : 'View'}</span>
                            {isExpanded ? (
                              <ChevronUp className="w-3.5 h-3.5" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-[var(--bg-app)]">
                          <td colSpan={7} className="p-5 border-t border-[var(--border-subtle)]">
                            <div className="space-y-2 max-w-4xl">
                              <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                                <Terminal className="w-4 h-4 text-[var(--accent)]" />
                                <span>Execution context & telemetry payload</span>
                              </div>
                              <pre className="font-mono text-[12px] leading-[20px] text-[var(--text-secondary)] bg-[var(--bg-surface)] border border-[var(--border-subtle)] p-4 rounded-[8px] overflow-x-auto whitespace-pre-wrap">
                                {JSON.stringify(e.details, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};
