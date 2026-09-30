import React, { useState } from 'react';
import { ArrowRight, Info, ShieldCheck } from 'lucide-react';
import { Finding } from '../types';
import { Card, CardHeader } from './common/Card';
import { PageHeader } from './common/PageHeader';
import { SeverityBadge } from './common/SeverityBadge';

interface Props {
  findings: Finding[];
  onSelectFinding: (f: Finding) => void;
}

export const AttackPathGraph: React.FC<Props> = ({ findings, onSelectFinding }) => {
  const [selectedChain, setSelectedChain] = useState<number>(0);

  const attackChains = [
    {
      id: 0,
      title: 'Path 1: Client secret leakage -> session token forgery -> telemetry exfiltration',
      risk: 'CRITICAL',
      nodes: [
        {
          step: 1,
          type: 'Exposure',
          title: 'Config secret leak',
          findingId: 'FINDING-CLI-001',
          component: '/api/config/client',
          desc: 'Unauthenticated observer retrieves leaked satellite uplink keys and staging URLs from client bootstrap.',
        },
        {
          step: 2,
          type: 'Auth bypass',
          title: 'Weak token forgery',
          findingId: 'FINDING-AUTH-001',
          component: '/api/users/profile',
          desc: 'Forges administrative authorization header token using weak predictable signing secret.',
        },
        {
          step: 3,
          type: 'Escalation',
          title: 'Bulk data export',
          findingId: 'FINDING-AUTHZ-002',
          component: '/api/admin/telemetry-export',
          desc: 'Invokes administrative telemetry dump to siphon all ground-station coordinates.',
        },
      ],
    },
    {
      id: 1,
      title: 'Path 2: Low-privilege account -> object authorization bypass -> intelligence disclosure',
      risk: 'HIGH',
      nodes: [
        {
          step: 1,
          type: 'Authentication',
          title: 'Viewer account auth',
          findingId: 'FINDING-API-002',
          component: '/api/auth/login',
          desc: 'Access obtained via viewer account or brute force enabled by lack of login throttling.',
        },
        {
          step: 2,
          type: 'Authorization',
          title: 'BOLA / IDOR access',
          findingId: 'FINDING-AUTHZ-001',
          component: '/api/reports/3',
          desc: 'Directly queries report ID 3, bypassing lack of clearance classification checks.',
        },
        {
          step: 3,
          type: 'Impact',
          title: 'Classified report leak',
          findingId: 'FINDING-AUTHZ-001',
          component: 'Strategic Reconnaissance',
          desc: 'Extracts RESTRICTED_TOP_SECRET orbital inclination shift data without authorization.',
        },
      ],
    },
    {
      id: 2,
      title: 'Path 3: Search query injection -> complete relational table extraction',
      risk: 'CRITICAL',
      nodes: [
        {
          step: 1,
          type: 'Input probe',
          title: 'Unsanitized search query',
          findingId: 'FINDING-INP-001',
          component: '/api/reports?search=',
          desc: 'Supplies raw SQL string concatenation payload into intelligence reports query.',
        },
        {
          step: 2,
          type: 'Injection',
          title: 'SQL injection execution',
          findingId: 'FINDING-INP-001',
          component: 'SQLite Engine',
          desc: 'Executes injected UNION query against users table to dump password hashes and salts.',
        },
        {
          step: 3,
          type: 'Account takeover',
          title: 'Credential compromise',
          findingId: 'FINDING-API-001',
          component: '/api/users/profile',
          desc: 'Reuses harvested administrator recovery codes and hashes to compromise entire system.',
        },
      ],
    },
  ];

  const current = attackChains[selectedChain];

  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Page Header */}
      <PageHeader
        title="Multi-stage attack paths"
        subtitle="Graph model illustrating chained lateral progression and composite blast-radius across vulnerabilities."
        actions={
          <div className="flex items-center gap-2 text-[12px] font-mono text-[var(--text-secondary)] bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-3 py-1.5 rounded-[8px]">
            <span>Model: 3 Critical vectors</span>
          </div>
        }
      />

      {/* Notice Banner */}
      <Card padding="sm" className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Info className="w-5 h-5 text-[var(--accent)] shrink-0" />
          <div className="text-[13px] text-[var(--text-secondary)] leading-[20px]">
            <strong className="text-[var(--text-primary)]">Defensive attack-path analysis:</strong> Visual mapping of how multi-stage vulnerabilities can be chained together across the World Monitor application.
            <span className="block text-[12px] text-[var(--text-tertiary)] mt-0.5">Strictly for defensive risk prioritization and root-cause blast-radius modeling.</span>
          </div>
        </div>
        <span className="text-[12px] font-mono text-[var(--text-tertiary)] bg-[var(--bg-raised)] px-2.5 py-1 rounded-[6px] border border-[var(--border-subtle)] shrink-0 hidden sm:inline">
          Controlled lab simulation
        </span>
      </Card>

      {/* Path Selector Tabs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {attackChains.map((c) => (
          <button
            key={c.id}
            onClick={() => setSelectedChain(c.id)}
            className={`p-4 rounded-[12px] border text-left transition-all ${
              selectedChain === c.id
                ? 'bg-[var(--bg-raised)] border-[var(--accent)] shadow-xs ring-1 ring-[var(--accent)]/30'
                : 'bg-[var(--bg-surface)] border-[var(--border-subtle)] hover:border-[var(--border-strong)] text-[var(--text-secondary)]'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[12px] font-medium text-[var(--text-tertiary)]">Pathway #{c.id + 1}</span>
              <SeverityBadge severity={c.risk} />
            </div>
            <div className="text-[14px] font-semibold text-[var(--text-primary)] line-clamp-2 leading-[20px]">
              {c.title}
            </div>
          </button>
        ))}
      </div>

      {/* Visual Workflow Graph */}
      <Card padding="md" className="space-y-6">
        <CardHeader
          title="Stage transition diagram"
          subtitle="Sequential progression of chained weaknesses"
        />

        <div className="flex flex-col md:flex-row items-stretch justify-between gap-4 pt-2">
          {current.nodes.map((node, idx) => {
            const linkedFinding = findings.find((f) => f.id === node.findingId);

            return (
              <React.Fragment key={idx}>
                {/* Node Box */}
                <div
                  onClick={() => linkedFinding && onSelectFinding(linkedFinding)}
                  className="flex-1 rounded-[10px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] p-5 space-y-3 cursor-pointer hover:border-[var(--border-strong)] transition-all group shadow-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="w-7 h-7 rounded-full bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--accent)] flex items-center justify-center text-[13px] font-bold tabular-nums">
                      {node.step}
                    </span>
                    <span className="text-[12px] font-medium text-[var(--text-secondary)] bg-[var(--bg-surface)] border border-[var(--border-subtle)] px-2.5 py-0.5 rounded-[6px]">
                      {node.type}
                    </span>
                  </div>

                  <div>
                    <h4 className="text-[15px] font-semibold text-[var(--text-primary)] group-hover:text-[var(--accent)] transition-colors">
                      {node.title}
                    </h4>
                    <code className="font-mono text-[12px] text-[var(--text-secondary)] block mt-1 bg-[var(--bg-surface)] px-2 py-0.5 rounded-[4px] border border-[var(--border-subtle)] truncate">
                      {node.component}
                    </code>
                  </div>

                  <p className="text-[13px] leading-[20px] text-[var(--text-secondary)]">{node.desc}</p>

                  <div className="pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between text-[12px] text-[var(--text-tertiary)]">
                    <span className="font-mono">{node.findingId}</span>
                    <span className="text-[var(--accent)] font-medium opacity-0 group-hover:opacity-100 transition-opacity">
                      Inspect finding &rarr;
                    </span>
                  </div>
                </div>

                {/* Transition Arrow */}
                {idx < current.nodes.length - 1 && (
                  <div className="hidden md:flex flex-col items-center justify-center text-[var(--text-tertiary)] px-2">
                    <ArrowRight className="w-5 h-5 text-[var(--accent)]" />
                    <span className="text-[12px] font-medium mt-1">Enables</span>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Countermeasure Box */}
        <div className="p-4 rounded-[8px] bg-[var(--status-fixed-bg)] border border-[var(--status-fixed-border)] text-[14px] leading-[22px] text-[var(--text-primary)] space-y-1">
          <div className="font-semibold text-[var(--status-fixed)] flex items-center gap-2">
            <ShieldCheck className="w-4 h-4" />
            <span>Root choke-point mitigation</span>
          </div>
          <p className="text-[var(--text-secondary)] text-[13px]">
            Remediating <strong>Stage 1</strong> in this sequence eliminates the prerequisites for downstream exploitation, neutralizing subsequent exposure before lateral progression can take place.
          </p>
        </div>
      </Card>
    </div>
  );
};
