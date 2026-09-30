import React from 'react';

interface PageHeaderProps {
  title: string;
  subtitle: string;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  badge,
  actions,
  className = '',
}) => {
  return (
    <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1 ${className}`}>
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-[24px] leading-[30px] font-bold text-[var(--text-primary)] tracking-[-0.015em]">
            {title}
          </h1>
          {badge}
        </div>
        <p className="text-[14px] leading-[22px] text-[var(--text-secondary)] mt-1">
          {subtitle}
        </p>
      </div>

      {actions && (
        <div className="flex items-center gap-2.5 shrink-0">
          {actions}
        </div>
      )}
    </div>
  );
};
