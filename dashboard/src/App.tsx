import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { CommandPalette } from './components/CommandPalette';
import { FindingDetailDrawer } from './components/FindingDetailDrawer';
import { AttackPathGraph } from './components/AttackPathGraph';
import { OverviewPage } from './pages/OverviewPage';
import { RunAssessmentPage } from './pages/RunAssessmentPage';
import { FindingsPage } from './pages/FindingsPage';
import { RemediationPage } from './pages/RemediationPage';
import { CoveragePage } from './pages/CoveragePage';
import { ReportPage } from './pages/ReportPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { MethodologyPage } from './pages/MethodologyPage';
import { Finding, OverviewStats, CoverageData } from './types';

export function App() {
  const [activePage, setActivePage] = useState<string>('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState<boolean>(false);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [coverage, setCoverage] = useState<CoverageData | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [targetOnline, setTargetOnline] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const fetchData = async () => {
    try {
      // 1. Findings
      const fRes = await fetch('/api/findings');
      if (fRes.ok) {
        const fData = await fRes.json();
        setFindings(fData);
      }

      // 2. Overview Stats
      const sRes = await fetch('/api/stats/overview');
      if (sRes.ok) {
        const sData = await sRes.json();
        setStats(sData);
      }

      // 3. Coverage
      const cRes = await fetch('/api/coverage');
      if (cRes.ok) {
        const cData = await cRes.json();
        setCoverage(cData);
      }

      // 4. System Status
      const sysRes = await fetch('/api/system/status');
      setTargetOnline(sysRes.ok);
    } catch (err) {
      console.error('Fetch error:', err);
      setTargetOnline(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleApplyFix = async (findingId: string) => {
    const res = await fetch(`/api/findings/${findingId}/apply-fix`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Apply fix failed');
    }
    await fetchData();
    if (selectedFinding && selectedFinding.id === findingId) {
      const freshRes = await fetch(`/api/findings/${findingId}`);
      if (freshRes.ok) {
        setSelectedFinding(await freshRes.json());
      }
    }
  };

  const handleRetest = async (findingId: string) => {
    const res = await fetch(`/api/findings/${findingId}/retest`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Retest failed');
    }
    const result = await res.json();
    await fetchData();
    if (selectedFinding && selectedFinding.id === findingId) {
      const freshRes = await fetch(`/api/findings/${findingId}`);
      if (freshRes.ok) {
        setSelectedFinding(await freshRes.json());
      }
    }
    return result;
  };

  const handleFilterSeverity = (sev: string) => {
    setSeverityFilter(sev);
    setActivePage('findings');
  };

  return (
    <div className="flex min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)] font-sans">
      {/* Sidebar (248px / 64px) */}
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        findingsCount={findings.length}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar
          activePage={activePage}
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          targetOnline={targetOnline}
        />

        {/* 32px padding, centered 1440px container */}
        <main className="flex-1 p-6 md:p-8 overflow-y-auto">
          {activePage === 'overview' && (
            <OverviewPage
              stats={stats}
              findings={findings}
              domains={coverage?.scope_domains || []}
              onSelectFinding={setSelectedFinding}
              onFilterSeverity={handleFilterSeverity}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'run' && (
            <RunAssessmentPage
              onAssessmentCompleted={fetchData}
              onSelectFinding={setSelectedFinding}
            />
          )}

          {activePage === 'findings' && (
            <FindingsPage
              findings={findings}
              onSelectFinding={setSelectedFinding}
              selectedSeverityFilter={severityFilter}
            />
          )}

          {activePage === 'attack-path' && (
            <AttackPathGraph
              findings={findings}
              onSelectFinding={setSelectedFinding}
            />
          )}

          {activePage === 'coverage' && (
            <CoveragePage
              coverage={coverage}
              onNavigateFindings={(_domain) => {
                setActivePage('findings');
              }}
            />
          )}

          {activePage === 'remediation' && (
            <RemediationPage
              findings={findings}
              onApplyFix={handleApplyFix}
              onRetest={handleRetest}
              onSelectFinding={setSelectedFinding}
            />
          )}

          {activePage === 'report' && (
            <ReportPage findings={findings} stats={stats} />
          )}

          {activePage === 'audit-log' && <AuditLogPage />}

          {activePage === 'methodology' && <MethodologyPage />}
        </main>
      </div>

      {/* Slide-over Finding Detail Drawer */}
      <FindingDetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onRetest={handleRetest}
        onApplyFix={handleApplyFix}
      />

      {/* Ctrl+K Global Command Palette */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        findings={findings}
        onSelectFinding={setSelectedFinding}
        onNavigate={setActivePage}
      />
    </div>
  );
}

export default App;
