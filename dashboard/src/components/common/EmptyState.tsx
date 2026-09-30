import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';

interface Props {
  icon?: LucideIcon;
  title: string;
  description: string;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<Props> = ({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className = '',
}) => {
  return (
    <div className={`p-12 text-center flex flex-col items-center justify-center max-w-md mx-auto ${className}`}>
      <div className="w-12 h-12 rounded-[10px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--text-tertiary)] mb-4">
        <Icon className="w-6 h-6 stroke-[1.5]" />
      </div>
      <h3 className="text-[15px] leading-[22px] font-semibold text-[var(--text-primary)] mb-1">
        {title}
      </h3>
      <p className="text-[13px] leading-[20px] text-[var(--text-secondary)] mb-5 max-w-sm">
        {description}
      </p>
      {action && <div>{action}</div>}
    </div>
  );
};
