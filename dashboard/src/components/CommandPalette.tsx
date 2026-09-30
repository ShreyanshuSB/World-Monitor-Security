import React, { useState, useEffect } from 'react';
import { Search, ArrowRight } from 'lucide-react';
import { Finding } from '../types';
import { SeverityBadge } from './common/SeverityBadge';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  findings: Finding[];
  onSelectFinding: (f: Finding) => void;
  onNavigate: (page: string) => void;
}

export const CommandPalette: React.FC<Props> = ({
  isOpen,
  onClose,
  findings,
  onSelectFinding,
  onNavigate,
}) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filteredFindings = findings.filter(
    (f) =>
      f.title.toLowerCase().includes(query.toLowerCase()) ||
      f.id.toLowerCase().includes(query.toLowerCase()) ||
      f.scope_area.toLowerCase().includes(query.toLowerCase())
  );

  const pages = [
    { id: 'overview', name: 'Posture overview', category: 'Navigation' },
    { id: 'run', name: 'Run assessment', category: 'Action' },
    { id: 'findings', name: 'Findings inventory', category: 'Navigation' },
    { id: 'remediation', name: 'Remediation and re-test', category: 'Action' },
    { id: 'coverage', name: 'OWASP and domains', category: 'Navigation' },
    { id: 'attack-path', name: 'Attack paths', category: 'Analysis' },
    { id: 'report', name: 'Formal report', category: 'Reporting' },
    { id: 'audit-log', name: 'Audit log ledger', category: 'Governance' },
    { id: 'methodology', name: 'Methodology and scope', category: 'Documentation' },
  ];

  const filteredPages = pages.filter((p) => p.name.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center pt-24 px-4">
      <div className="bg-[var(--bg-surface)] border border-[var(--border-strong)] rounded-[10px] w-full max-w-xl shadow-2xl overflow-hidden animate-in fade-in duration-150">
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)]">
          <Search className="w-4 h-4 text-[var(--text-tertiary)] mr-3 shrink-0" />
          <input
            type="text"
            placeholder="Type a command, finding ID, or jump to page... (ESC to close)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full bg-transparent text-[14px] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-hidden"
          />
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-3 text-[13px]">
          {/* Quick Pages */}
          {filteredPages.length > 0 && (
            <div>
              <div className="text-[12px] font-medium text-[var(--text-tertiary)] px-3 py-1">
                Pages and actions
              </div>
              <div className="space-y-0.5">
                {filteredPages.map((page) => (
                  <button
                    key={page.id}
                    onClick={() => {
                      onNavigate(page.id);
                      onClose();
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-[6px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] text-left transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <ArrowRight className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
                      <span>{page.name}</span>
                    </div>
                    <span className="text-[12px] text-[var(--text-tertiary)] bg-[var(--bg-raised)] px-2 py-0.5 rounded-[4px] border border-[var(--border-subtle)]">
                      {page.category}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Findings */}
          {filteredFindings.length > 0 && (
            <div>
              <div className="text-[12px] font-medium text-[var(--text-tertiary)] px-3 py-1">
                Verified findings ({filteredFindings.length})
              </div>
              <div className="space-y-0.5">
                {filteredFindings.map((f) => (
                  <button
                    key={f.id}
                    onClick={() => {
                      onSelectFinding(f);
                      onClose();
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-[6px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] text-left transition-colors"
                  >
                    <div className="flex items-center gap-3 truncate max-w-md">
                      <span className="font-mono text-[12px] text-[var(--text-secondary)] shrink-0">{f.id}</span>
                      <span className="truncate">{f.title}</span>
                    </div>
                    <SeverityBadge severity={f.severity} />
                  </button>
                ))}
              </div>
            </div>
          )}

          {filteredPages.length === 0 && filteredFindings.length === 0 && (
            <div className="py-8 text-center text-[13px] text-[var(--text-tertiary)]">
              No matching pages or findings found for "{query}".
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
