import React from 'react';
import { getSeverityLabel } from '../../theme/tokens';

interface Props {
  severity: string;
  score?: number;
  fixedWidth?: boolean;
  className?: string;
}

export const SeverityBadge: React.FC<Props> = ({
  severity,
  score,
  fixedWidth = false,
  className = '',
}) => {
  const sev = (severity || 'INFO').toUpperCase();
  const label = getSeverityLabel(sev);

  // Muted tokens from CSS variables (12% tint background + 1px 28% border)
  const styles: Record<string, { bg: string; border: string; text: string; dot: string }> = {
    CRITICAL: {
      bg: 'var(--severity-critical-bg)',
      border: 'var(--severity-critical-border)',
      text: 'var(--severity-critical)',
      dot: 'var(--severity-critical)',
    },
    HIGH: {
      bg: 'var(--severity-high-bg)',
      border: 'var(--severity-high-border)',
      text: 'var(--severity-high)',
      dot: 'var(--severity-high)',
    },
    MEDIUM: {
      bg: 'var(--severity-medium-bg)',
      border: 'var(--severity-medium-border)',
      text: 'var(--severity-medium)',
      dot: 'var(--severity-medium)',
    },
    LOW: {
      bg: 'var(--severity-low-bg)',
      border: 'var(--severity-low-border)',
      text: 'var(--severity-low)',
      dot: 'var(--severity-low)',
    },
    INFO: {
      bg: 'var(--severity-info-bg)',
      border: 'var(--severity-info-border)',
      text: 'var(--severity-info)',
      dot: 'var(--severity-info)',
    },
  };

  const current = styles[sev] || styles.INFO;

  return (
    <span
      style={{
        backgroundColor: current.bg,
        borderColor: current.border,
        color: current.text,
      }}
      className={`inline-flex items-center justify-between gap-1.5 px-2 py-0.5 rounded-[6px] border text-[12px] leading-[16px] font-medium select-none ${
        fixedWidth ? 'w-[106px] shrink-0' : ''
      } ${className}`}
    >
      <span className="flex items-center gap-1.5 whitespace-nowrap">
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ backgroundColor: current.dot }}
        />
        <span>{label}</span>
      </span>

      {score !== undefined && (
        <span
          className="font-mono text-[12px] tabular-nums opacity-90 pl-1.5 border-l shrink-0"
          style={{ borderColor: current.border }}
        >
          {score.toFixed(1)}
        </span>
      )}
    </span>
  );
};
