import React, { useState } from 'react';
import { Copy, Check, Clock } from 'lucide-react';
import { Evidence } from '../types';

interface Props {
  evidence: Evidence;
}

export const EvidenceViewer: React.FC<Props> = ({ evidence }) => {
  const [copiedReq, setCopiedReq] = useState(false);
  const [copiedResp, setCopiedResp] = useState(false);
  const [activeTab, setActiveTab] = useState<'response' | 'headers'>('response');

  const copyToClipboard = (text: string, isReq: boolean) => {
    navigator.clipboard.writeText(text);
    if (isReq) {
      setCopiedReq(true);
      setTimeout(() => setCopiedReq(false), 2000);
    } else {
      setCopiedResp(true);
      setTimeout(() => setCopiedResp(false), 2000);
    }
  };

  const getStatusColor = (code: number) => {
    if (code >= 200 && code < 300) return 'text-[var(--status-fixed)]';
    if (code >= 400 && code < 500) return 'text-[var(--severity-high)]';
    return 'text-[var(--severity-critical)]';
  };

  const responseLines = (evidence.response_body || '').split('\n');

  return (
    <div className="space-y-4 text-[13px]">
      {/* Request Block */}
      <div className="rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-app)] overflow-hidden">
        <div className="bg-[var(--bg-raised)] px-4 py-2.5 border-b border-[var(--border-subtle)] flex items-center justify-between">
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="font-mono text-[12px] font-semibold px-2 py-0.5 rounded-[4px] bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-primary)]">
              {evidence.request_method}
            </span>
            <code className="font-mono text-[12px] text-[var(--text-secondary)] truncate">
              {evidence.request_url}
            </code>
          </div>
          <button
            onClick={() =>
              copyToClipboard(
                `${evidence.request_method} ${evidence.request_url}\n${JSON.stringify(evidence.request_headers, null, 2)}`,
                true
              )
            }
            className="flex items-center gap-1.5 text-[12px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors shrink-0"
          >
            {copiedReq ? <Check className="w-3.5 h-3.5 text-[var(--status-fixed)]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedReq ? 'Copied' : 'Copy request'}</span>
          </button>
        </div>

        {evidence.request_headers && (
          <div className="p-3.5 border-b border-[var(--border-subtle)] font-mono text-[12px] text-[var(--text-secondary)] space-y-1 bg-[var(--bg-surface)]">
            <div className="text-[12px] font-sans font-medium text-[var(--text-tertiary)] mb-1">
              Request headers:
            </div>
            {Object.entries(evidence.request_headers).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <span className="text-[var(--text-tertiary)]">{k}:</span>
                <span className="text-[var(--text-primary)] truncate">{v}</span>
              </div>
            ))}
          </div>
        )}

        {evidence.request_body && (
          <div className="p-3.5 font-mono text-[12px] text-[var(--text-primary)] bg-[var(--bg-app)] overflow-x-auto">
            {evidence.request_body}
          </div>
        )}
      </div>

      {/* Response Block */}
      <div className="rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-app)] overflow-hidden">
        <div className="bg-[var(--bg-raised)] px-4 py-2.5 border-b border-[var(--border-subtle)] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className={`font-mono text-[12px] font-semibold ${getStatusColor(evidence.response_status)}`}>
              HTTP {evidence.response_status}
            </span>
            <span className="flex items-center gap-1 text-[12px] text-[var(--text-tertiary)] tabular-nums">
              <Clock className="w-3.5 h-3.5" />
              <span>{evidence.duration_ms} ms</span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex rounded-[4px] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-0.5">
              <button
                onClick={() => setActiveTab('response')}
                className={`px-2.5 py-0.5 rounded-[3px] text-[12px] transition-colors ${
                  activeTab === 'response'
                    ? 'bg-[var(--bg-raised)] text-[var(--text-primary)] font-medium'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                Payload
              </button>
              <button
                onClick={() => setActiveTab('headers')}
                className={`px-2.5 py-0.5 rounded-[3px] text-[12px] transition-colors ${
                  activeTab === 'headers'
                    ? 'bg-[var(--bg-raised)] text-[var(--text-primary)] font-medium'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                Headers
              </button>
            </div>

            <button
              onClick={() => copyToClipboard(evidence.response_body, false)}
              className="flex items-center gap-1.5 text-[12px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors ml-2"
            >
              {copiedResp ? <Check className="w-3.5 h-3.5 text-[var(--status-fixed)]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedResp ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {activeTab === 'response' ? (
          <div className="p-3.5 font-mono text-[12px] leading-[20px] max-h-[360px] overflow-y-auto overflow-x-auto bg-[var(--bg-surface)]">
            <table className="w-full border-collapse">
              <tbody>
                {responseLines.map((line, idx) => (
                  <tr key={idx} className="hover:bg-[var(--bg-hover)]">
                    <td className="w-10 select-none text-[var(--text-tertiary)] text-right pr-4 align-top font-mono text-[12px] tabular-nums">
                      {idx + 1}
                    </td>
                    <td className="text-[var(--text-primary)] font-mono whitespace-pre-wrap break-all">
                      {line}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-3.5 font-mono text-[12px] space-y-1 max-h-[360px] overflow-y-auto bg-[var(--bg-surface)]">
            {Object.entries(evidence.response_headers || {}).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <span className="text-[var(--text-tertiary)]">{k}:</span>
                <span className="text-[var(--text-primary)] truncate">{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
