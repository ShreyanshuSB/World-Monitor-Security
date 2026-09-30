import React from 'react';

export const Skeleton: React.FC<{
  className?: string;
  width?: string | number;
  height?: string | number;
  rounded?: string;
}> = ({ className = '', width, height, rounded = 'rounded-[6px]' }) => {
  return (
    <div
      style={{ width, height }}
      className={`bg-[var(--bg-raised)] animate-pulse ${rounded} ${className}`}
    />
  );
};

export const CardSkeleton: React.FC = () => (
  <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
    <Skeleton height={14} width="40%" />
    <Skeleton height={32} width="60%" />
    <Skeleton height={10} width="80%" />
  </div>
);

export const TableSkeleton: React.FC<{ rows?: number }> = ({ rows = 5 }) => (
  <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden">
    <div className="h-10 bg-[var(--bg-raised)] border-b border-[var(--border-subtle)] px-4 flex items-center gap-4">
      <Skeleton height={14} width="15%" />
      <Skeleton height={14} width="45%" />
      <Skeleton height={14} width="20%" />
      <Skeleton height={14} width="10%" />
    </div>
    <div className="divide-y divide-[var(--border-subtle)] p-2 space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-12 flex items-center gap-4 px-2">
          <Skeleton height={20} width="88px" />
          <Skeleton height={16} width="128px" />
          <div className="flex-1 space-y-1">
            <Skeleton height={16} width="70%" />
            <Skeleton height={12} width="40%" />
          </div>
          <Skeleton height={20} width="132px" />
        </div>
      ))}
    </div>
  </div>
);
