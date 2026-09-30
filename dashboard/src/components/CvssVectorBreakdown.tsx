import React from 'react';

interface Props {
  vector: string;
  score: number;
}

export const CvssVectorBreakdown: React.FC<Props> = ({ vector, score }) => {
  const parts = vector.split('/');
  const metrics: Record<string, string> = {};
  parts.forEach((p) => {
    if (p.includes(':')) {
      const [k, v] = p.split(':');
      metrics[k] = v;
    }
  });

  const metricLabels: Record<string, { name: string; values: Record<string, string> }> = {
    AV: {
      name: 'Attack vector',
      values: { N: 'Network (remote)', A: 'Adjacent network', L: 'Local access', P: 'Physical' },
    },
    AC: {
      name: 'Attack complexity',
      values: { L: 'Low (trivial)', H: 'High (specialized)' },
    },
    PR: {
      name: 'Privileges required',
      values: { N: 'None (unauthenticated)', L: 'Low (standard user)', H: 'High (administrator)' },
    },
    UI: {
      name: 'User interaction',
      values: { N: 'None (autonomous)', R: 'Required (victim action)' },
    },
    S: {
      name: 'Scope',
      values: { U: 'Unchanged', C: 'Changed (cross-boundary)' },
    },
    C: {
      name: 'Confidentiality impact',
      values: { H: 'High (total disclosure)', L: 'Low (partial leak)', N: 'None' },
    },
    I: {
      name: 'Integrity impact',
      values: { H: 'High (total modification)', L: 'Low (partial modification)', N: 'None' },
    },
    A: {
      name: 'Availability impact',
      values: { H: 'High (complete outage)', L: 'Low (degraded)', N: 'None' },
    },
  };

  return (
    <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-2">
          <span className="text-[13px] font-semibold text-[var(--text-primary)]">
            CVSS v3.1 vector evaluation
          </span>
          <span className="text-[12px] font-mono tabular-nums px-2 py-0.5 rounded-[4px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] text-[var(--text-primary)] font-medium">
            Score {score.toFixed(1)}
          </span>
        </div>
        <span className="text-[12px] font-mono text-[var(--text-tertiary)] hidden sm:inline">
          {vector}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Object.entries(metricLabels).map(([key, def]) => {
          const val = metrics[key] || 'N/A';
          const label = def.values[val] || val;

          return (
            <div
              key={key}
              className="bg-[var(--bg-raised)] border border-[var(--border-subtle)] rounded-[8px] p-3 space-y-1"
            >
              <div className="flex items-center justify-between text-[12px] text-[var(--text-tertiary)]">
                <span>{def.name}</span>
                <span className="font-mono text-[12px] font-medium text-[var(--text-secondary)]">
                  {key}:{val}
                </span>
              </div>
              <div className="text-[13px] font-medium text-[var(--text-primary)] truncate">
                {label}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
