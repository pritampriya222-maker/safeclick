/**
 * popup/components/VerdictBadge.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Renders the colored safety verdict badge.
 * Designed to leave room for Phase 3's reasons/explanation list.
 */

import React from 'react';
import type { Verdict, VerdictLevel } from '../../shared/types';

interface VerdictBadgeProps {
  verdict: Verdict | null;
  isLoading?: boolean;
}

interface BadgeConfig {
  label: string;
  bgClass: string;
  borderClass: string;
  textClass: string;
  dotClass: string;
  glowClass: string;
  icon: string;
}

function getBadgeConfig(level: VerdictLevel): BadgeConfig {
  switch (level) {
    case 'safe':
      return {
        label: 'Safe',
        bgClass: 'bg-emerald-500/15',
        borderClass: 'border-emerald-500/40',
        textClass: 'text-emerald-400',
        dotClass: 'bg-emerald-400',
        glowClass: 'shadow-emerald-500/20',
        icon: '✓',
      };
    case 'suspicious':
      return {
        label: 'Suspicious',
        bgClass: 'bg-amber-500/15',
        borderClass: 'border-amber-500/40',
        textClass: 'text-amber-400',
        dotClass: 'bg-amber-400',
        glowClass: 'shadow-amber-500/20',
        icon: '⚠',
      };
    case 'dangerous':
      return {
        label: 'Dangerous',
        bgClass: 'bg-red-500/15',
        borderClass: 'border-red-500/40',
        textClass: 'text-red-400',
        dotClass: 'bg-red-400',
        glowClass: 'shadow-red-500/20',
        icon: '✕',
      };
    case 'not_applicable':
      return {
        label: 'Not Applicable',
        bgClass: 'bg-slate-500/15',
        borderClass: 'border-slate-500/40',
        textClass: 'text-slate-400',
        dotClass: 'bg-slate-400',
        glowClass: 'shadow-slate-500/20',
        icon: '—',
      };
    default:
      return {
        label: 'Unknown',
        bgClass: 'bg-slate-500/15',
        borderClass: 'border-slate-500/40',
        textClass: 'text-slate-400',
        dotClass: 'bg-slate-400',
        glowClass: 'shadow-slate-500/20',
        icon: '?',
      };
  }
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({
  verdict,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="flex flex-col items-center gap-3 py-4">
        <div className="w-16 h-16 rounded-full border-2 border-slate-600 border-t-indigo-400 animate-spin" />
        <span className="text-slate-400 text-sm">Analyzing…</span>
      </div>
    );
  }

  if (!verdict) {
    return (
      <div className="flex flex-col items-center gap-2 py-4">
        <div className="w-16 h-16 rounded-full bg-slate-700/50 border border-slate-600 flex items-center justify-center">
          <span className="text-slate-400 text-2xl">?</span>
        </div>
        <span className="text-slate-400 text-sm">No data available</span>
      </div>
    );
  }

  const config = getBadgeConfig(verdict.level);

  return (
    <div className="flex flex-col items-center gap-3 py-2">
      {/* Main verdict circle */}
      <div
        className={`
          relative w-20 h-20 rounded-full border-2
          ${config.bgClass} ${config.borderClass}
          flex items-center justify-center
          shadow-lg ${config.glowClass}
          transition-all duration-300
        `}
      >
        {/* Animated pulse dot */}
        <span
          className={`
            absolute top-1.5 right-1.5 w-3 h-3 rounded-full
            ${config.dotClass} animate-pulse
          `}
        />
        {/* Icon */}
        <span className={`text-3xl font-bold ${config.textClass}`}>
          {config.icon}
        </span>
      </div>

      {/* Label + Score */}
      <div className="text-center">
        <div className={`text-lg font-semibold ${config.textClass}`}>
          {config.label}
        </div>
        {verdict.level !== 'not_applicable' && (
          <div className="text-slate-500 text-xs mt-0.5">
            Risk score: {verdict.score}/100
          </div>
        )}
      </div>

      {/* Reasons list — Phase 3 will populate with real ML/rule reasons.
          Phase 1 shows the stub message here so the UI contract is already correct. */}
      <div className="w-full mt-1">
        {verdict.isStub && verdict.level !== 'not_applicable' ? (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-2.5 text-center">
            <p className="text-slate-500 text-xs">
              No detailed analysis yet — Phase 2/3 pending
            </p>
          </div>
        ) : (
          <ul className="space-y-1.5">
            {verdict.reasons.map((reason, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2 bg-slate-800/40 rounded-lg px-2.5 py-1.5"
              >
                <span className={`text-xs mt-0.5 flex-shrink-0 ${config.textClass}`}>
                  •
                </span>
                <span className="text-slate-300 text-xs leading-relaxed">
                  {reason}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default VerdictBadge;
