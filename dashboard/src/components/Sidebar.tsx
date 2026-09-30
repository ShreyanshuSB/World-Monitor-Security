import React from 'react';
import {
  LayoutDashboard,
  PlayCircle,
  ShieldAlert,
  GitBranch,
  Grid,
  RefreshCw,
  FileText,
  ListOrdered,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  Shield,
} from 'lucide-react';

interface Props {
  activePage: string;
  onNavigate: (page: string) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  findingsCount: number;
}

export const Sidebar: React.FC<Props> = ({
  activePage,
  onNavigate,
  collapsed,
  onToggleCollapse,
  findingsCount,
}) => {
  const navGroups = [
    {
      group: 'Assessment',
      items: [
        { id: 'overview', label: 'Posture overview', icon: LayoutDashboard },
        { id: 'run', label: 'Run assessment', icon: PlayCircle },
        { id: 'findings', label: 'Findings inventory', icon: ShieldAlert, badge: findingsCount },
      ],
    },
    {
      group: 'Deep analysis',
      items: [
        { id: 'attack-path', label: 'Attack paths', icon: GitBranch },
        { id: 'coverage', label: 'OWASP and domains', icon: Grid },
        { id: 'remediation', label: 'Remediation and re-test', icon: RefreshCw },
      ],
    },
    {
      group: 'Governance',
      items: [
        { id: 'report', label: 'Formal report', icon: FileText },
        { id: 'audit-log', label: 'Audit log ledger', icon: ListOrdered },
        { id: 'methodology', label: 'Methodology and scope', icon: BookOpen },
      ],
    },
  ];

  return (
    <aside
      className={`border-r border-[var(--border-subtle)] bg-[var(--bg-surface)] h-screen sticky top-0 flex flex-col justify-between transition-all duration-200 z-30 select-none ${
        collapsed ? 'w-[64px]' : 'w-[248px]'
      }`}
    >
      <div>
        {/* Brand Header */}
        <div className="h-[56px] border-b border-[var(--border-subtle)] flex items-center justify-between px-4">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] flex items-center justify-center shrink-0 text-[var(--accent)]">
              <Shield className="w-4 h-4 stroke-[2]" />
            </div>
            {!collapsed && (
              <div className="leading-tight truncate">
                <span className="font-semibold text-[14px] text-[var(--text-primary)]">World Monitor</span>
                <span className="block text-[12px] text-[var(--text-tertiary)] font-normal">Security assessment</span>
              </div>
            )}
          </div>
          <button
            onClick={onToggleCollapse}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="p-1 text-[var(--text-tertiary)] hover:text-[var(--text-primary)] rounded-[6px] hover:bg-[var(--bg-hover)] transition-colors"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <div className="p-2 space-y-5">
          {navGroups.map((grp) => (
            <div key={grp.group} className="space-y-1">
              {!collapsed && (
                <div className="text-[12px] font-medium text-[var(--text-tertiary)] uppercase tracking-[0.04em] px-3 mb-1.5">
                  {grp.group}
                </div>
              )}
              {grp.items.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onNavigate(item.id)}
                    className={`w-full flex items-center gap-3 px-3 h-[40px] rounded-[7px] text-[14px] leading-[20px] transition-all ${
                      isActive
                        ? 'bg-[var(--bg-raised)] text-[var(--text-primary)] font-semibold border-l-[3px] border-[var(--accent)] pl-[9px]'
                        : 'text-[var(--text-secondary)] font-medium hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                    } ${collapsed ? 'justify-center px-0' : ''}`}
                    title={collapsed ? item.label : undefined}
                  >
                    <Icon className={`w-[18px] h-[18px] shrink-0 ${isActive ? 'text-[var(--accent)]' : 'text-[var(--text-tertiary)]'}`} />
                    {!collapsed && (
                      <span className="flex-1 text-left truncate">{item.label}</span>
                    )}
                    {!collapsed && item.badge !== undefined && item.badge > 0 && (
                      <span className="text-[12px] font-mono tabular-nums text-[var(--text-secondary)] bg-[var(--bg-app)] border border-[var(--border-subtle)] px-2 py-0.5 rounded-[5px]">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Target info footer - compact card */}
      {!collapsed && (
        <div className="p-3 m-3 bg-[var(--bg-raised)] border border-[var(--border-subtle)] rounded-[8px] space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[var(--status-fixed)] animate-pulse shrink-0" />
            <span className="font-mono text-[12px] font-semibold text-[var(--text-primary)] tabular-nums">
              127.0.0.1:8001
            </span>
          </div>
          <div className="text-[12px] text-[var(--text-tertiary)] pl-4">
            Controlled lab replica
          </div>
        </div>
      )}
    </aside>
  );
};
