/**
 * popup/components/QuickActions.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Action buttons: Report site, Always trust domain, View settings.
 *
 * Phase 1 wiring:
 * - "Report site" → writes to storage + console log (Phase 5: real backend)
 * - "Always trust" → adds to allowlist via storage.ts (Phase 5: cloud sync)
 * - "View settings" → opens options page via messaging.ts
 */

import React, { useState } from 'react';
import { sendMessage } from '../../shared/messaging';

interface QuickActionsProps {
  url: string | null;
  domain: string | null;
  disabled?: boolean;
}

export const QuickActions: React.FC<QuickActionsProps> = ({
  url,
  domain,
  disabled = false,
}) => {
  const [reportState, setReportState] = useState<'idle' | 'sent' | 'error'>('idle');
  const [trustState, setTrustState] = useState<'idle' | 'sent' | 'error'>('idle');

  const handleReport = async () => {
    if (!url) return;
    try {
      await sendMessage({ type: 'REPORT_SITE', url });
      setReportState('sent');
      setTimeout(() => setReportState('idle'), 2000);
    } catch {
      setReportState('error');
    }
  };

  const handleTrust = async () => {
    if (!domain) return;
    try {
      await sendMessage({ type: 'TRUST_DOMAIN', domain });
      setTrustState('sent');
      setTimeout(() => setTrustState('idle'), 2000);
    } catch {
      setTrustState('error');
    }
  };

  const handleOpenSettings = async () => {
    await sendMessage({ type: 'OPEN_OPTIONS' });
  };

  return (
    <div className="flex flex-col gap-2">
      {/* Report */}
      <button
        id="btn-report-site"
        onClick={handleReport}
        disabled={disabled || !url}
        className={`
          flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
          border transition-all duration-200
          ${disabled || !url
            ? 'opacity-40 cursor-not-allowed border-slate-700 text-slate-500 bg-slate-800/30'
            : reportState === 'sent'
            ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400 cursor-default'
            : 'border-slate-700/60 bg-slate-800/40 text-slate-300 hover:bg-red-500/10 hover:border-red-500/40 hover:text-red-400 active:scale-95'
          }
        `}
      >
        <span className="text-base leading-none">
          {reportState === 'sent' ? '✓' : '⚑'}
        </span>
        <span>
          {reportState === 'sent' ? 'Reported!' : 'Report this site'}
        </span>
      </button>

      {/* Trust domain */}
      <button
        id="btn-trust-domain"
        onClick={handleTrust}
        disabled={disabled || !domain}
        className={`
          flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
          border transition-all duration-200
          ${disabled || !domain
            ? 'opacity-40 cursor-not-allowed border-slate-700 text-slate-500 bg-slate-800/30'
            : trustState === 'sent'
            ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400 cursor-default'
            : 'border-slate-700/60 bg-slate-800/40 text-slate-300 hover:bg-emerald-500/10 hover:border-emerald-500/40 hover:text-emerald-400 active:scale-95'
          }
        `}
      >
        <span className="text-base leading-none">
          {trustState === 'sent' ? '✓' : '🛡'}
        </span>
        <span>
          {trustState === 'sent' ? 'Domain trusted!' : 'Always trust this domain'}
        </span>
      </button>

      {/* Settings */}
      <button
        id="btn-view-settings"
        onClick={handleOpenSettings}
        className="
          flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
          border border-slate-700/60 bg-slate-800/40 text-slate-400
          hover:bg-slate-700/50 hover:text-slate-200 hover:border-slate-600
          transition-all duration-200 active:scale-95
        "
      >
        <span className="text-base leading-none">⚙</span>
        <span>View settings</span>
      </button>
    </div>
  );
};

export default QuickActions;
