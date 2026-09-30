import React from 'react';
import { ShieldCheck } from 'lucide-react';
import { Card, CardHeader } from '../components/common/Card';
import { PageHeader } from '../components/common/PageHeader';

export const MethodologyPage: React.FC = () => {
  return (
    <div className="space-y-6 max-w-[1440px] mx-auto">
      {/* Standard Page Header */}
      <PageHeader
        title="Methodology & rules of engagement"
        subtitle="National Technical Research Organisation (NTRO) &bull; Smart India Hackathon 2026 &bull; Problem Statement SIH26163"
        actions={
          <div className="flex items-center gap-2 text-[12px] font-mono text-[var(--accent)] bg-[var(--bg-raised)] border border-[var(--border-subtle)] px-3 py-1.5 rounded-[8px]">
            <ShieldCheck className="w-4 h-4" />
            <span>Ethical AppSec Framework</span>
          </div>
        }
      />

      <div className="max-w-4xl space-y-6">
        {/* 1. Controlled Lab Target Notice */}
        <Card padding="md" className="space-y-4">
          <CardHeader
            title="Controlled lab target environment"
            subtitle="Intentional vulnerability testbed for authorized evaluation"
          />
          <p className="text-[14px] leading-[22px] text-[var(--text-secondary)]">
            To satisfy SIH26163 requirements with absolute integrity and zero synthetic findings, the platform operates against an authorized local replica labeled:
          </p>
          <div className="p-4 rounded-[8px] bg-[var(--bg-raised)] border border-[var(--border-subtle)] font-mono text-[13px] text-[var(--text-primary)] font-semibold text-center">
            "INTENTIONALLY VULNERABLE LAB TARGET - controlled environment"
          </div>
          <p className="text-[14px] leading-[22px] text-[var(--text-secondary)]">
            Every finding surfaced in this dashboard originates from genuine network requests executed against this local target. No mock findings, hardcoded tables, or placeholder CVEs exist in the system.
          </p>
        </Card>

        {/* 2. Fail-Closed Scope Guard */}
        <Card padding="md" className="space-y-4">
          <CardHeader
            title="Automated scope guard architecture"
            subtitle="Network perimeter controls and execution gating"
          />
          <p className="text-[14px] leading-[22px] text-[var(--text-secondary)]">
            The core diagnostic engine embeds a fail-closed perimeter guard (<code className="font-mono text-[12px] text-[var(--text-primary)] bg-[var(--bg-raised)] px-1.5 py-0.5 rounded-[4px]">engine/scope_guard.py</code>). The platform verifies every target URL prior to issuing any HTTP packet:
          </p>
          <div className="space-y-3 bg-[var(--bg-raised)] p-5 rounded-[8px] border border-[var(--border-subtle)] text-[14px] leading-[22px] text-[var(--text-secondary)]">
            <div className="flex items-start gap-2.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] mt-2 shrink-0" />
              <div>
                <strong className="text-[var(--text-primary)]">Allowed hosts:</strong> Strictly loopback interfaces (<code className="font-mono text-[12px]">localhost</code>, <code className="font-mono text-[12px]">127.0.0.1</code>, <code className="font-mono text-[12px]">::1</code>).
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] mt-2 shrink-0" />
              <div>
                <strong className="text-[var(--text-primary)]">External boundary blocking:</strong> Any non-loopback IP, public domain, or intranet subnet raises <code className="font-mono text-[12px]">ScopeViolationException</code> and immediately terminates the probe.
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] mt-2 shrink-0" />
              <div>
                <strong className="text-[var(--text-primary)]">Authorization gate:</strong> An explicit signed acknowledgment is mandatory before launching assessment suites.
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] mt-2 shrink-0" />
              <div>
                <strong className="text-[var(--text-primary)]">Non-destructive principle:</strong> Rate-limited, non-DoS diagnostic probes using non-persistent credentials.
              </div>
            </div>
          </div>
        </Card>

        {/* 3. Transitioning to a Self-Hosted World Monitor Instance */}
        <Card padding="md" className="space-y-4">
          <CardHeader
            title="Targeting a self-hosted World Monitor instance"
            subtitle="Procedure for pointing the engine at air-gapped staging targets"
          />
          <p className="text-[14px] leading-[22px] text-[var(--text-secondary)]">
            When authorized evaluators deploy the official self-hosted World Monitor production or staging container, the assessment engine can be pointed directly at the newly instantiated target:
          </p>
          <div className="bg-[var(--bg-app)] border border-[var(--border-subtle)] p-5 rounded-[8px] font-mono text-[12px] leading-[22px] text-[var(--text-secondary)] space-y-2 overflow-x-auto">
            <div className="text-[var(--text-tertiary)] font-sans text-[13px] font-medium"># Step 1: Deploy World Monitor container on local loopback:</div>
            <div className="text-[var(--text-primary)]">docker run -d -p 8080:8080 --name world-monitor-target ntro/world-monitor:latest</div>
            <div className="text-[var(--text-tertiary)] font-sans text-[13px] font-medium mt-3"># Step 2: Configure target in platform engine:</div>
            <div className="text-[var(--text-primary)]">export WM_TARGET_URL="http://127.0.0.1:8080"</div>
            <div className="text-[var(--text-tertiary)] font-sans text-[13px] font-medium mt-3"># Step 3: Run comprehensive diagnostic suite:</div>
            <div className="text-[var(--text-primary)]">python -m engine.runner --target http://127.0.0.1:8080 --authorized</div>
          </div>
        </Card>
      </div>
    </div>
  );
};
