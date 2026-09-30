import React, { useState, useMemo } from 'react';
import {
  Search,
  Download,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  RotateCcw,
} from 'lucide-react';
import { Finding } from '../types';
import { Card } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusPill } from '../components/common/StatusPill';
import { EmptyState } from '../components/common/EmptyState';

interface Props {
  findings: Finding[];
  onSelectFinding: (f: Finding) => void;
  selectedSeverityFilter?: string;
}

export const FindingsPage: React.FC<Props> = ({
  findings,
  onSelectFinding,
  selectedSeverityFilter = 'ALL',
}) => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>(selectedSeverityFilter);
  const [domainFilter, setDomainFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [originFilter, setOriginFilter] = useState<string>('ALL');
  const [deduplicate, setDeduplicate] = useState<boolean>(true);
  const [sortField, setSortField] = useState<'cvss_score' | 'title' | 'id' | 'severity'>('cvss_score');
  const [sortAsc, setSortAsc] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  // Unique domains
  const domains = useMemo(() => {
    return Array.from(new Set(findings.map((f) => f.scope_area)));
  }, [findings]);

  // Deduplicate by finding_key (keep highest CVSS per key = latest confirmed)
  const deduped = useMemo(() => {
    if (!deduplicate) return findings;
    const seen = new Map<string, Finding>();
    for (const f of findings) {
      const key = f.finding_key || f.vuln_key || f.id;
      const existing = seen.get(key);
      if (!existing || f.cvss_score >= existing.cvss_score) {
        seen.set(key, f);
      }
    }
    return Array.from(seen.values());
  }, [findings, deduplicate]);

  // Filtering & Sorting
  const filtered = useMemo(() => {
    return deduped
      .filter((f) => {
        if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
        if (domainFilter !== 'ALL' && f.scope_area !== domainFilter) return false;
        if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
        if (originFilter !== 'ALL' && (f.origin || 'LAB_SYNTHETIC') !== originFilter) return false;
        if (search) {
          const q = search.toLowerCase();
          return (
            f.title.toLowerCase().includes(q) ||
            (f.finding_key || f.id).toLowerCase().includes(q) ||
            f.affected_component.toLowerCase().includes(q) ||
            f.cwe_id.toLowerCase().includes(q)
          );
        }
        return true;
      })
      .sort((a, b) => {
        let diff = 0;
        if (sortField === 'cvss_score') diff = a.cvss_score - b.cvss_score;
        else if (sortField === 'title') diff = a.title.localeCompare(b.title);
        else if (sortField === 'id') diff = (a.finding_key || a.id).localeCompare(b.finding_key || b.id);
        else if (sortField === 'severity') {
          const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
          diff = (rank[a.severity] || 0) - (rank[b.severity] || 0);
        }
        return sortAsc ? diff : -diff;
      });
  }, [deduped, severityFilter, domainFilter, statusFilter, originFilter, search, sortField, sortAsc]);

  const toggleSelectAll = () => {
    if (selectedIds.length === filtered.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filtered.map((f) => f.id));
    }
  };

  const _toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter((i) => i !== id));
    } else {
      setSelectedIds([...selectedIds, id]);
    }
  };

  const exportCsv = () => {
    const headers = ['ID', 'Title', 'Severity', 'CVSS', 'Scope Area', 'Component', 'Status', 'CWE'];
    const rows = filtered.map((f) => [
      `"${f.id}"`,
      `"${f.title.replace(/"/g, '""')}"`,
      f.severity,
      f.cvss_score,
      `"${f.scope_area}"`,
      `"${f.affected_component}"`,
      f.status,
      `"${f.cwe_id}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `world_monitor_findings_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const isFiltered = severityFilter !== 'ALL' || domainFilter !== 'ALL' || statusFilter !== 'ALL' || search !== '';

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standardized Page Header */}
      <PageHeader
        title="Security findings"
        subtitle={`${deduped.length} unique findings across ${findings.length} total records`}
        actions={
          <div className="flex items-center gap-2.5">
            {selectedIds.length > 0 && (
              <span className="text-[12px] font-mono tabular-nums text-[var(--accent)] bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-2.5 py-1 rounded-[6px]">
                {selectedIds.length} selected
              </span>
            )}
            <button
              onClick={exportCsv}
              className="h-[36px] flex items-center gap-2 bg-[var(--bg-raised)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--border-subtle)] px-3.5 rounded-[8px] text-[13px] font-medium transition-colors cursor-pointer"
            >
              <Download className="w-4 h-4 text-[var(--text-secondary)]" />
              <span>Export CSV</span>
            </button>
          </div>
        }
      />

      {/* Prominent Search and Filter Row */}
      <Card padding="md" className="space-y-3.5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3.5">
          {/* Prominent Search Field */}
          <div className="relative flex-1 min-w-[280px]">
            <Search className="w-4 h-4 text-[var(--text-tertiary)] absolute left-3.5 top-3" />
            <input
              type="text"
              placeholder="Search finding ID, CWE, title, component endpoint..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-[38px] bg-[var(--bg-app)] border border-[var(--border-subtle)] rounded-[8px] pl-10 pr-3.5 text-[14px] text-[var(--text-primary)] placeholder-[var(--text-tertiary)] focus:outline-hidden focus:border-[var(--accent)] transition-colors"
            />
          </div>

          {/* Faceted Filter Controls */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="h-[36px] bg-[var(--bg-app)] border border-[var(--border-subtle)] text-[var(--text-primary)] rounded-[8px] px-3 text-[13px] font-medium focus:outline-hidden focus:border-[var(--accent)] cursor-pointer"
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Scope Domain Filter */}
            <select
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className="h-[36px] bg-[var(--bg-app)] border border-[var(--border-subtle)] text-[var(--text-primary)] rounded-[8px] px-3 text-[13px] font-medium focus:outline-hidden focus:border-[var(--accent)] max-w-[200px] cursor-pointer"
            >
              <option value="ALL">All domains</option>
              {domains.map((d) => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>

            {/* Origin Filter */}
            <select
              value={originFilter}
              onChange={(e) => setOriginFilter(e.target.value)}
              className="h-[36px] bg-[var(--bg-app)] border border-[var(--border-subtle)] text-[var(--text-primary)] rounded-[8px] px-3 text-[13px] font-medium focus:outline-hidden focus:border-[var(--accent)] cursor-pointer"
            >
              <option value="ALL">All origins</option>
              <option value="LAB_SYNTHETIC">Lab Synthetic</option>
              <option value="SOURCE_STATIC">Source Static</option>
              <option value="DYNAMIC_LOCAL">Dynamic Local</option>
            </select>

            {/* Deduplicate toggle */}
            <label className="flex items-center gap-1.5 h-[36px] px-2.5 text-[13px] font-medium text-[var(--text-secondary)] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={deduplicate}
                onChange={(e) => setDeduplicate(e.target.checked)}
                className="accent-[var(--accent)] rounded"
              />
              Deduplicate
            </label>

            {isFiltered && (
              <button
                onClick={() => {
                  setSeverityFilter('ALL');
                  setDomainFilter('ALL');
                  setStatusFilter('ALL');
                  setOriginFilter('ALL');
                  setSearch('');
                }}
                className="inline-flex items-center gap-1.5 h-[36px] px-2.5 text-[13px] font-medium text-[var(--accent)] hover:underline cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>

        {/* Counter Summary */}
        <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)] text-[13px] text-[var(--text-tertiary)]">
          <div>
            Showing <strong className="text-[var(--text-primary)] font-medium">{filtered.length}</strong> of {findings.length} findings
          </div>
          {isFiltered && (
            <span className="text-[12px] text-[var(--accent)] font-medium">Filtered results</span>
          )}
        </div>
      </Card>

      {/* Dense 13px Findings Table */}
      <Card padding="none" className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="bg-[var(--bg-raised)] border-b border-[var(--border-subtle)] text-[12px] text-[var(--text-tertiary)] font-medium">
                <th className="py-2.5 px-4 w-9 text-center">
                  <input
                    type="checkbox"
                    checked={filtered.length > 0 && selectedIds.length === filtered.length}
                    onChange={toggleSelectAll}
                    aria-label="Select all findings"
                    className="accent-[var(--accent)] rounded-[4px]"
                  />
                </th>
                <th
                  onClick={() => handleSort('severity')}
                  className="py-2.5 px-3 w-[110px] cursor-pointer hover:text-[var(--text-primary)] select-none"
                >
                  <div className="flex items-center gap-1">
                    <span>Severity</span>
                    {sortField === 'severity' && (sortAsc ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />)}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('id')}
                  className="py-2.5 px-3 w-[170px] cursor-pointer hover:text-[var(--text-primary)] select-none"
                >
                  <div className="flex items-center gap-1">
                    <span>Finding key</span>
                    {sortField === 'id' && (sortAsc ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />)}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('title')}
                  className="py-2.5 px-4 cursor-pointer hover:text-[var(--text-primary)] select-none"
                >
                  <div className="flex items-center gap-1">
                    <span>Title and component</span>
                    {sortField === 'title' && (sortAsc ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />)}
                  </div>
                </th>
                <th className="py-2.5 px-3 w-[140px] hidden xl:table-cell">Scope domain</th>
                <th className="py-2.5 px-3 w-[130px] text-center">Status</th>
                <th className="py-2.5 px-3 w-8"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12">
                    <EmptyState
                      title="No findings match filter"
                      description="Try adjusting your severity, scope area, or search query to view items."
                    />
                  </td>
                </tr>
              ) : (
                filtered.map((f) => {
                  const isSelected = selectedIds.includes(f.finding_record_id || f.id);
                  const shortKey = f.finding_key || f.vuln_key || (f.id?.slice(0, 8).toUpperCase());
                  const originColor: Record<string, string> = {
                    LAB_SYNTHETIC: 'text-purple-400',
                    SOURCE_STATIC: 'text-blue-400',
                    DYNAMIC_LOCAL: 'text-teal-400',
                  };
                  return (
                    <tr
                      key={f.finding_record_id || f.id}
                      onClick={() => onSelectFinding(f)}
                      className={`hover:bg-[var(--bg-hover)] cursor-pointer transition-colors ${
                        isSelected ? 'bg-[var(--bg-raised)]' : ''
                      }`}
                    >
                      <td className="py-3 px-4 text-center w-9" onClick={(e) => { e.stopPropagation(); const id = f.finding_record_id || f.id; setSelectedIds(prev => prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]); }}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          aria-label={`Select ${shortKey}`}
                          className="accent-[var(--accent)] rounded-[4px]"
                        />
                      </td>

                      <td className="py-3.5 px-3 w-[110px]">
                        <SeverityBadge severity={f.severity} score={f.cvss_score} fixedWidth />
                      </td>

                      <td className="py-3.5 px-3 w-[170px] max-w-[170px] overflow-hidden">
                        <div className="font-mono text-[11px] text-[var(--text-secondary)] truncate" title={f.finding_key || f.id}>
                          {shortKey}
                        </div>
                        <div className={`text-[10px] font-mono mt-0.5 truncate ${originColor[f.origin] || 'text-purple-400'}`}>
                          {f.origin || 'LAB_SYNTHETIC'}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 overflow-hidden">
                        <div className="text-[14px] leading-[20px] font-semibold text-[var(--text-primary)] truncate" title={f.title}>
                          {f.title}
                        </div>
                        <div className="text-[12px] leading-[16px] text-[var(--text-tertiary)] mt-0.5 truncate">
                          <code className="font-mono text-[11px] text-[var(--text-secondary)]">
                            {f.affected_component}
                          </code>
                          <span className="mx-1.5">•</span>
                          <span className="font-mono text-[11px]">{f.cwe_id?.split(':')[0]}</span>
                        </div>
                      </td>

                      <td className="py-3.5 px-3 w-[140px] text-[12px] text-[var(--text-secondary)] hidden xl:table-cell">
                        <div className="truncate" title={f.scope_area}>{f.scope_area}</div>
                      </td>

                      <td className="py-3.5 px-3 w-[130px] text-center">
                        <StatusPill status={f.status} fixedWidth />
                      </td>

                      <td className="py-3.5 px-3 w-8 text-[var(--text-tertiary)] text-right">
                        <ChevronRight className="w-4 h-4" />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
