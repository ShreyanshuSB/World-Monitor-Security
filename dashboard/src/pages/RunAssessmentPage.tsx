import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  AlertCircle,
  Terminal,
  CheckSquare,
  Square,
  Activity,
  ArrowRight,
} from 'lucide-react';
import { Finding } from '../types';
import { Card, CardHeader } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';
import { SeverityBadge } from '../components/common/SeverityBadge';

interface Props {
  onAssessmentCompleted: () => void;
  onSelectFinding: (f: Finding) => void;
}

export const RunAssessmentPage: React.FC<Props> = ({ onAssessmentCompleted, onSelectFinding }) => {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8001');
  const [authorized, setAuthorized] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [currentModule, setCurrentModule] = useState<string | null>(null);
  const [moduleProgress, setModuleProgress] = useState<{ current: number; total: number }>({ current: 0, total: 7 });
  const [logs, setLogs] = useState<{ time: string; text: string; type?: string }[]>([]);
  const [streamFindings, setStreamFindings] = useState<Finding[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const timerRef = useRef<any>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // 7 Scope Modules
  // Mode C (Lab) module descriptions
  const availableModules = [
    { id: 'auth_session', name: 'Authentication & session management', desc: 'Hardcoded token prefix bypass, session fixation [Lab Synthetic]' },
    { id: 'authz_access', name: 'Authorization & access control', desc: 'BOLA/IDOR on classified reports, BFLA telemetry, unauth endpoints [Lab Synthetic]' },
    { id: 'input_validation', name: 'Input validation & data handling', desc: 'SQL injection (read demonstrated), HTML injection / potential stored XSS [Lab Synthetic]' },
    { id: 'api_security', name: 'API security', desc: 'Excessive data exposure in profile, absent login rate limiting [Lab Synthetic]' },
    { id: 'client_side', name: 'Client-side controls', desc: 'Synthetic credential-class values exposed in client config [Lab Synthetic]' },
    { id: 'secure_comm', name: 'Secure communication', desc: 'Missing defense-in-depth headers (CSP, X-Frame-Options, X-Content-Type-Options) [Lab Synthetic]' },
    { id: 'data_storage', name: 'Data storage & privacy', desc: 'Cleartext token in diagnostic logs, viewer log access [Lab Synthetic]' },
  ];

  const [selectedModules, setSelectedModules] = useState<string[]>(availableModules.map((m) => m.id));

  const toggleModule = (id: string) => {
    if (selectedModules.includes(id)) {
      if (selectedModules.length > 1) {
        setSelectedModules(selectedModules.filter((m) => m !== id));
      }
    } else {
      setSelectedModules([...selectedModules, id]);
    }
  };

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const startScan = async () => {
    if (!authorized) {
      setErrorMsg('You must check the authorization acknowledgment box before running active probes.');
      return;
    }
    setErrorMsg(null);
    setIsRunning(true);
    setLogs([]);
    setStreamFindings([]);
    setElapsed(0);
    setCurrentModule('Initializing');

    timerRef.current = setInterval(() => {
      setElapsed((prev) => prev + 1);
    }, 1000);

    try {
      const resp = await fetch('/api/assessments/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl,
          authorized_acknowledged: true,
          assessment_mode: 'LAB',
          modules: selectedModules,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Failed to start assessment run');
      }

      const runData = await resp.json();
      const asmId = runData.assessment_id;

      // SECURITY FIX: SSE URL does NOT pass target_url or authorized as query params.
      // The server loads target, authorization, and module list from the stored assessment record.
      const eventSource = new EventSource(`/api/assessments/${asmId}/events`);

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const nowStr = new Date().toLocaleTimeString();

          if (data.type === 'LOG') {
            setLogs((prev) => [...prev, { time: nowStr, text: data.message }]);
          } else if (data.type === 'MODULE_START') {
            setCurrentModule(data.module_name);
            setModuleProgress({ current: data.index, total: data.total });
            setLogs((prev) => [
              ...prev,
              { time: nowStr, text: `Starting module [${data.index}/${data.total}]: ${data.module_name}`, type: 'module' },
            ]);
          } else if (data.type === 'FINDING_FOUND') {
            setStreamFindings((prev) => [data.finding, ...prev]);
            const origin = data.finding.origin || 'LAB_SYNTHETIC';
            const vs = data.finding.verification_status || 'CANDIDATE';
            setLogs((prev) => [
              ...prev,
              {
                time: nowStr,
                text: `[${data.finding.severity}] ${data.finding.title} | CVSS ${data.finding.cvss_score} | ${origin} | ${vs}`,
                type: 'finding',
              },
            ]);
          } else if (data.type === 'COMPLETE') {
            eventSource.close();
            clearInterval(timerRef.current);
            setIsRunning(false);
            setCurrentModule('Assessment completed');
            setLogs((prev) => [
              ...prev,
              {
                time: nowStr,
                text: `Assessment completed [LAB SYNTHETIC]. ${data.total_findings} lab findings recorded. Assessment ID: ${asmId}`,
                type: 'complete',
              },
            ]);
            onAssessmentCompleted();
          } else if (data.type === 'ERROR') {
            eventSource.close();
            clearInterval(timerRef.current);
            setIsRunning(false);
            setErrorMsg(data.message);
          }
        } catch (e) {
          console.error('SSE parse error:', e);
        }
      };

      eventSource.onerror = () => {
        eventSource.close();
        clearInterval(timerRef.current);
        setIsRunning(false);
      };
    } catch (err: any) {
      clearInterval(timerRef.current);
      setIsRunning(false);
      setErrorMsg(err.message);
    }
  };

  const progressPercent = moduleProgress.total > 0
    ? Math.round((moduleProgress.current / moduleProgress.total) * 100)
    : 0;

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standard Page Header */}
      <PageHeader
        title="Assessment execution"
        subtitle="Configure target parameters, verify scope authorizations, and execute live diagnostic probes against the controlled replica."
        actions={
          isRunning ? (
            <div className="flex items-center gap-3 bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-4 py-2 rounded-[8px] text-[13px] tabular-nums">
              <span className="w-2 h-2 rounded-full bg-[var(--accent)] animate-pulse" />
              <span className="text-[var(--text-secondary)]">
                Elapsed: <strong className="text-[var(--text-primary)] font-semibold">{elapsed}s</strong>
              </span>
              <span className="text-[var(--text-tertiary)]">&bull;</span>
              <span className="text-[var(--text-primary)] font-medium max-w-xs truncate">{currentModule}</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-[12px] font-mono text-[var(--text-secondary)] bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-3 py-1.5 rounded-[8px]">
              <span className="w-2 h-2 rounded-full bg-[var(--status-fixed)]" />
              <span>Target: 127.0.0.1:8001</span>
            </div>
          )
        }
      />

      {errorMsg && (
        <div className="rounded-[10px] border border-[var(--severity-critical-border)] bg-[var(--severity-critical-bg)] p-4 text-[var(--severity-critical)] text-[13px] flex items-center gap-3">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span className="font-medium">{errorMsg}</span>
        </div>
      )}

      {/* Main Grid: 1/3 controls, 2/3 console & discovered feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Scope & Controls */}
        <div className="space-y-6">
          <Card padding="md" className="space-y-5">
            <CardHeader
              title="Target configuration"
              subtitle="Scope guard enforce fail-closed loopback"
            />

            <div className="space-y-2">
              <label className="text-[13px] text-[var(--text-secondary)] font-medium">
                Target base URL
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isRunning}
                className="w-full h-[38px] bg-[var(--bg-app)] border border-[var(--border-subtle)] rounded-[8px] px-3 font-mono text-[13px] text-[var(--text-primary)] focus:outline-hidden focus:border-[var(--accent)] transition-colors disabled:opacity-60"
              />
              <span className="text-[12px] text-[var(--text-tertiary)] block">
                Permitted loopback hosts: localhost, 127.0.0.1, ::1
              </span>
            </div>

            {/* Authorization Acknowledgment Checkbox */}
            <div className="pt-2 border-t border-[var(--border-subtle)]">
              <label className={`flex items-start gap-3 cursor-pointer p-3.5 rounded-[8px] border transition-all ${
                authorized
                  ? 'bg-[var(--bg-raised)] border-[var(--accent)] shadow-xs'
                  : 'bg-[var(--bg-app)] border-[var(--border-subtle)] hover:border-[var(--border-strong)]'
              }`}>
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  disabled={isRunning}
                  className="mt-0.5 accent-[var(--accent)] w-4 h-4 rounded-[4px] shrink-0"
                />
                <div className="text-[13px] leading-[18px]">
                  <span className="font-semibold text-[var(--text-primary)] block mb-0.5">Authorization acknowledged</span>
                  <span className="text-[12px] text-[var(--text-secondary)] leading-[18px] block">
                    I confirm this probe operates strictly against the authorized controlled replica under SIH26163 rules of engagement.
                  </span>
                </div>
              </label>
            </div>

            <button
              onClick={startScan}
              disabled={isRunning || !authorized}
              className={`w-full h-[40px] flex items-center justify-center gap-2 rounded-[8px] text-[14px] font-semibold transition-all ${
                isRunning || !authorized
                  ? 'bg-[var(--bg-raised)] text-[var(--text-tertiary)] cursor-not-allowed border border-[var(--border-subtle)]'
                  : 'bg-[var(--accent)] text-white hover:opacity-95 shadow-xs'
              }`}
            >
              <Play className="w-4 h-4" />
              <span>{isRunning ? 'Diagnostic execution in progress...' : 'Launch assessment'}</span>
            </button>
          </Card>

          {/* Module Checklist */}
          <Card padding="md" className="space-y-4">
            <CardHeader
              title={`Scope modules (${selectedModules.length}/7)`}
              action={
                <button
                  onClick={() =>
                    setSelectedModules(
                      selectedModules.length === availableModules.length
                        ? [availableModules[0].id]
                        : availableModules.map((m) => m.id)
                    )
                  }
                  className="text-[13px] font-medium text-[var(--accent)] hover:underline"
                >
                  {selectedModules.length === availableModules.length ? 'Deselect all' : 'Select all'}
                </button>
              }
            />

            <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
              {availableModules.map((m) => {
                const isChecked = selectedModules.includes(m.id);
                return (
                  <div
                    key={m.id}
                    onClick={() => !isRunning && toggleModule(m.id)}
                    className={`flex items-start gap-3 p-3 rounded-[8px] cursor-pointer transition-all border ${
                      isChecked
                        ? 'bg-[var(--bg-raised)] border-[var(--border-subtle)] text-[var(--text-primary)] shadow-xs'
                        : 'bg-[var(--bg-app)] border-transparent text-[var(--text-tertiary)] hover:bg-[var(--bg-hover)]'
                    }`}
                  >
                    <span className="mt-0.5 text-[var(--accent)] shrink-0">
                      {isChecked ? (
                        <CheckSquare className="w-4 h-4" />
                      ) : (
                        <Square className="w-4 h-4 text-[var(--text-tertiary)]" />
                      )}
                    </span>
                    <div className="min-w-0">
                      <div className="text-[13px] font-medium text-[var(--text-primary)] leading-[18px]">{m.name}</div>
                      <div className="text-[12px] text-[var(--text-secondary)] mt-0.5 leading-[16px]">{m.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>

        {/* Right 2 Columns: Live Progress, Streaming Console & Discovered Feed */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Progress Card */}
          {isRunning && (
            <Card padding="sm" className="space-y-2.5">
              <div className="flex items-center justify-between text-[13px] text-[var(--text-secondary)] tabular-nums">
                <span className="font-medium text-[var(--text-primary)]">
                  Scanning module {moduleProgress.current} of {moduleProgress.total}: {currentModule}
                </span>
                <span className="font-semibold text-[var(--accent)]">{progressPercent}%</span>
              </div>
              <div className="w-full bg-[var(--bg-raised)] h-[6px] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[var(--accent)] rounded-full transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </Card>
          )}

          {/* Log Console - ONLY large mono area */}
          <Card padding="none" className="overflow-hidden flex flex-col h-[340px]">
            <div className="bg-[var(--bg-raised)] px-5 py-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
              <div className="flex items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
                <Terminal className="w-4 h-4 text-[var(--accent)]" />
                <span>Live assessment event stream (SSE)</span>
              </div>
              <span className="text-[12px] font-mono text-[var(--text-tertiary)] bg-[var(--bg-surface)] px-2.5 py-0.5 rounded-[4px] border border-[var(--border-subtle)] tabular-nums">
                {logs.length} events
              </span>
            </div>

            <div
              ref={logContainerRef}
              className="flex-1 p-4 font-mono text-[12px] leading-[22px] overflow-y-auto space-y-1 bg-[var(--bg-app)]"
            >
              {logs.length === 0 ? (
                <div className="text-[var(--text-tertiary)] py-16 text-center font-sans">
                  <Activity className="w-6 h-6 mx-auto mb-2 opacity-40 text-[var(--accent)]" />
                  <p className="text-[13px] text-[var(--text-secondary)]">Console awaiting launch signal.</p>
                  <p className="text-[12px] text-[var(--text-tertiary)] mt-1">
                    Check authorization acknowledgment and click "Launch assessment" to begin probes.
                  </p>
                </div>
              ) : (
                logs.map((l, idx) => {
                  let color = 'text-[var(--text-secondary)]';
                  if (l.type === 'module') color = 'text-[var(--text-primary)] font-semibold pt-1';
                  else if (l.type === 'finding') color = 'text-[var(--severity-critical)] font-medium';
                  else if (l.type === 'complete') color = 'text-[var(--status-fixed)] font-semibold';
                  return (
                    <div key={idx} className={color}>
                      <span className="text-[var(--text-tertiary)] mr-2 tabular-nums">[{l.time}]</span>
                      <span>{l.text}</span>
                    </div>
                  );
                })
              )}
            </div>
          </Card>

          {/* Discovered Findings Feed */}
          <Card padding="md" className="space-y-4">
            <CardHeader
              title={`Discovered findings (${streamFindings.length})`}
              subtitle="Findings surfaced in real time during the current assessment session"
            />

            <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
              {streamFindings.length === 0 ? (
                <div className="text-[13px] text-[var(--text-tertiary)] py-8 text-center">
                  No findings surfaced yet in this scan session.
                </div>
              ) : (
                streamFindings.map((f) => (
                  <div
                    key={f.id}
                    onClick={() => onSelectFinding(f)}
                    className="p-3.5 rounded-[8px] bg-[var(--bg-raised)] hover:bg-[var(--bg-hover)] border border-[var(--border-subtle)] hover:border-[var(--border-strong)] flex items-center justify-between cursor-pointer transition-all group"
                  >
                    <div className="flex items-center gap-3.5 min-w-0">
                      <SeverityBadge severity={f.severity} score={f.cvss_score} fixedWidth />
                      <div className="min-w-0">
                        <div className="text-[14px] font-semibold text-[var(--text-primary)] group-hover:text-[var(--accent)] transition-colors truncate">
                          {f.title}
                        </div>
                        <div className="font-mono text-[12px] text-[var(--text-tertiary)] mt-0.5 truncate">
                          {f.affected_component}
                        </div>
                      </div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-[var(--text-tertiary)] group-hover:text-[var(--accent)] group-hover:translate-x-0.5 transition-all shrink-0 ml-3" />
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
