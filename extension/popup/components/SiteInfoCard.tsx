/**
 * popup/components/SiteInfoCard.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Displays the current domain, HTTPS status, and page load timestamp.
 */

import React from 'react';

interface SiteInfoCardProps {
  url: string | null;
  timestamp?: string | null;
}

function parseDomain(url: string): { domain: string; isHttps: boolean } {
  try {
    const parsed = new URL(url);
    return {
      domain: parsed.hostname,
      isHttps: parsed.protocol === 'https:',
    };
  } catch {
    return { domain: url, isHttps: false };
  }
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return ts;
  }
}

export const SiteInfoCard: React.FC<SiteInfoCardProps> = ({ url, timestamp }) => {
  if (!url) {
    return (
      <div className="bg-slate-800/40 border border-slate-700/40 rounded-xl px-4 py-3">
        <p className="text-slate-500 text-xs text-center">No site info available</p>
      </div>
    );
  }

  const { domain, isHttps } = parseDomain(url);

  return (
    <div className="bg-slate-800/40 border border-slate-700/40 rounded-xl px-4 py-3 space-y-2">
      {/* Domain */}
      <div className="flex items-center gap-2 overflow-hidden">
        <span className="text-slate-500 text-xs flex-shrink-0">Site</span>
        <span
          className="text-slate-200 text-sm font-medium truncate"
          title={domain}
        >
          {domain}
        </span>
      </div>

      {/* HTTPS status */}
      <div className="flex items-center gap-2">
        <span className="text-slate-500 text-xs flex-shrink-0">Connection</span>
        <div className="flex items-center gap-1.5">
          <span
            className={`w-2 h-2 rounded-full flex-shrink-0 ${
              isHttps ? 'bg-emerald-400' : 'bg-amber-400'
            }`}
          />
          <span
            className={`text-xs font-medium ${
              isHttps ? 'text-emerald-400' : 'text-amber-400'
            }`}
          >
            {isHttps ? 'HTTPS (encrypted)' : 'HTTP (not encrypted)'}
          </span>
        </div>
      </div>

      {/* Timestamp */}
      {timestamp && (
        <div className="flex items-center gap-2">
          <span className="text-slate-500 text-xs flex-shrink-0">Checked</span>
          <span className="text-slate-400 text-xs">
            {formatTimestamp(timestamp)}
          </span>
        </div>
      )}
    </div>
  );
};

export default SiteInfoCard;
