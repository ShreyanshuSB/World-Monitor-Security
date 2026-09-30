import React from 'react';
import { Search, Shield, Sun, Moon } from 'lucide-react';
import { useTheme } from '../theme/ThemeContext';

interface Props {
  activePage: string;
  onOpenCommandPalette: () => void;
  targetOnline: boolean;
}

export const Navbar: React.FC<Props> = ({ activePage, onOpenCommandPalette, targetOnline }) => {
  const { theme, toggleTheme } = useTheme();

  const pageTitles: Record<string, string> = {
    overview: 'Posture overview',
    run: 'Run assessment',
    findings: 'Findings inventory',
    remediation: 'Remediation and re-test',
    coverage: 'OWASP and domains',
    'attack-path': 'Attack paths',
    report: 'Formal report',
    'audit-log': 'Audit log ledger',
    methodology: 'Methodology and scope',
  };

  return (
    <header className="h-[56px] border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] sticky top-0 z-40 px-8 flex items-center justify-between">
      {/* Breadcrumbs - 13px IBM Plex Sans, sentence case, no mono */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-[13px] leading-[20px] text-[var(--text-secondary)]">
        <span className="text-[var(--text-tertiary)]">World Monitor</span>
        <span className="text-[var(--text-tertiary)] font-normal">/</span>
        <span className="text-[var(--text-primary)] font-medium">
          {pageTitles[activePage] || 'Dashboard'}
        </span>
      </nav>

      {/* Right Controls */}
      <div className="flex items-center gap-2.5">
        {/* Search trigger with Ctrl+K */}
        <button
          onClick={onOpenCommandPalette}
          aria-label="Open command palette"
          className="flex items-center gap-2.5 h-[34px] bg-[var(--bg-raised)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border-subtle)] px-3 rounded-[8px] text-[13px] transition-colors"
        >
          <Search className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
          <span className="text-[var(--text-secondary)]">Search...</span>
          <kbd className="bg-[var(--bg-surface)] border border-[var(--border-strong)] px-1.5 py-0.5 rounded-[5px] text-[12px] font-mono text-[var(--text-tertiary)]">
            Ctrl+K
          </kbd>
        </button>

        {/* Scope guard status with tooltip */}
        <div
          title="Scope guard active: 127.0.0.1 (fail-closed allowlist)"
          className="h-[34px] px-3 rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] flex items-center gap-1.5 text-[12px] text-[var(--text-secondary)] font-medium select-none cursor-help"
        >
          <Shield className="w-3.5 h-3.5 text-[var(--accent)]" />
          <span>Scope guard</span>
        </div>

        {/* ONE neutral environment chip with small green dot */}
        <div className="h-[34px] px-3 rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] flex items-center gap-2 text-[12px] text-[var(--text-primary)] font-medium select-none">
          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              targetOnline ? 'bg-[var(--status-fixed)] animate-pulse' : 'bg-[var(--severity-critical)]'
            }`}
          />
          <span>Lab environment</span>
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          aria-label="Toggle light/dark theme"
          className="w-[34px] h-[34px] rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] hover:bg-[var(--bg-hover)] flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-[var(--text-secondary)]" />
          ) : (
            <Moon className="w-4 h-4 text-[var(--text-secondary)]" />
          )}
        </button>
      </div>
    </header>
  );
};
