import React from 'react';
import { Check, AlertCircle, Wrench, Shield } from 'lucide-react';
import { getStatusLabel } from '../../theme/tokens';

interface Props {
  status: string;
  fixedWidth?: boolean;
  className?: string;
}

export const StatusPill: React.FC<Props> = ({
  status,
  fixedWidth = false,
  className = '',
}) => {
  const label = getStatusLabel(status);
  const s = (status || '').toUpperCase().trim();

  let bg = 'var(--status-detected-bg)';
  let border = 'var(--status-detected-border)';
  let text = 'var(--status-detected)';
  let Icon: React.FC<{ className?: string }> | null = null;

  if (s === 'RETESTED_PASS') {
    bg = 'var(--status-retested-pass-bg)';
    border = 'var(--status-retested-pass-border)';
    text = 'var(--status-retested-pass)';
    Icon = Check;
  } else if (s === 'FIXED') {
    bg = 'var(--status-fixed-bg)';
    border = 'var(--status-fixed-border)';
    text = 'var(--status-fixed)';
    Icon = Wrench;
  } else if (s === 'VERIFIED') {
    bg = 'var(--status-verified-bg)';
    border = 'var(--status-verified-border)';
    text = 'var(--status-verified)';
    Icon = Shield;
  } else if (s === 'RETESTED_FAIL') {
    bg = 'var(--status-failed-bg)';
    border = 'var(--status-failed-border)';
    text = 'var(--status-failed)';
    Icon = AlertCircle;
  }

  return (
    <span
      style={{
        backgroundColor: bg,
        borderColor: border,
        color: text,
      }}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-[6px] border text-[12px] leading-[16px] font-medium select-none ${
        fixedWidth ? 'w-[150px] shrink-0 justify-center' : ''
      } ${className}`}
    >
      {Icon && <Icon className="w-3.5 h-3.5 shrink-0" />}
      <span className="whitespace-nowrap">{label}</span>
    </span>
  );
};
