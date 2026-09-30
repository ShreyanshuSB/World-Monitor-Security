import React from 'react';
import { Card } from './Card';

interface Props {
  label: string;
  value: string | number;
  sublabel: string;
  icon?: React.ReactNode;
  progressPercent?: number;
  progressColor?: string;
  progressText?: string;
  highlight?: boolean;
  onClick?: () => void;
  className?: string;
}

export const KpiCard: React.FC<Props> = ({
  label,
  value,
  sublabel,
  icon,
  progressPercent,
  progressColor = 'var(--accent)',
  progressText,
  highlight = false,
  onClick,
  className = '',
}) => {
  return (
    <Card
      onClick={onClick}
      padding="md"
      className={`flex flex-col justify-between h-full transition-all ${
        highlight ? 'border-[var(--severity-critical-border)] bg-[var(--bg-surface)] ring-1 ring-[var(--severity-critical-border)]' : ''
      } ${
        onClick ? 'cursor-pointer hover:border-[var(--border-strong)]' : ''
      } ${className}`}
    >
      <div>
        <div className="flex items-center justify-between gap-2 mb-2">
          <span className="text-[13px] leading-[18px] text-[var(--text-secondary)] font-medium">
            {label}
          </span>
          {icon && <div className="text-[var(--text-tertiary)]">{icon}</div>}
        </div>

        <div className="flex items-baseline gap-2.5">
          <span className="text-[34px] md:text-[38px] leading-[40px] font-bold text-[var(--text-primary)] tabular-nums tracking-[-0.02em]">
            {value}
          </span>
          {progressText && (
            <span
              className="text-[12px] font-semibold px-2 py-0.5 rounded-[5px] uppercase tracking-wider"
              style={{
                backgroundColor: `${progressColor}18`,
                color: progressColor,
                border: `1px solid ${progressColor}35`,
              }}
            >
              {progressText}
            </span>
          )}
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] space-y-2">
        {progressPercent !== undefined && (
          <div className="w-full bg-[var(--bg-raised)] h-[6px] rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: `${Math.min(100, Math.max(0, progressPercent))}%`,
                backgroundColor: progressColor,
              }}
            />
          </div>
        )}
        <div className="text-[13px] leading-[18px] text-[var(--text-tertiary)]">
          {sublabel}
        </div>
      </div>
    </Card>
  );
};
