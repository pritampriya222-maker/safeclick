import React, { useState } from 'react';
import type { HistoryEntry } from '../shared/historyStore';
import type { VerdictLevel } from '../shared/types';

interface HistoryViewProps {
  entries: HistoryEntry[];
  onClearHistory: () => Promise<void>;
}

export function HistoryView({ entries, onClearHistory }: HistoryViewProps) {
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [confirmingClear, setConfirmingClear] = useState<boolean>(false);

  const filtered = entries.filter((e) => {
    if (levelFilter !== 'all' && e.level !== levelFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        e.domain.toLowerCase().includes(q) ||
        e.url.toLowerCase().includes(q) ||
        e.summary.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleClearConfirm = async () => {
    await onClearHistory();
    setConfirmingClear(false);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <span>Local Safe Browsing History</span>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono">
              {filtered.length} {filtered.length === 1 ? 'entry' : 'entries'}
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Stored locally on your device (capped at 500 entries max).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative min-w-[200px]">
            <input
              type="text"
              placeholder="Search domain or URL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          {/* Level Filter Dropdown */}
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 transition-colors"
          >
            <option value="all">All Verdicts</option>
            <option value="dangerous">Dangerous Blocked</option>
            <option value="suspicious">Suspicious Flagged</option>
            <option value="safe">Safe Sites</option>
          </select>

          {/* Clear History Button */}
          {entries.length > 0 && (
            <button
              onClick={() => setConfirmingClear(true)}
              className="px-3.5 py-2 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-medium transition-colors"
            >
              Clear History
            </button>
          )}
        </div>
      </div>

      {/* History Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center text-slate-500 space-y-2">
          <svg className="w-10 h-10 mx-auto text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-sm font-medium">No history entries found.</p>
          {searchQuery && <p className="text-xs text-slate-600">Try adjusting your search or filter criteria.</p>}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Domain / URL</th>
                <th className="py-3 px-4">Summary</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((entry) => (
                <tr key={entry.id} className="hover:bg-slate-800/30 transition-colors">
                  {/* Verdict Badge */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <LevelBadge level={entry.level} />
                  </td>

                  {/* Domain & URL */}
                  <td className="py-3.5 px-4 max-w-xs">
                    <div className="font-semibold text-white truncate" title={entry.domain}>
                      {entry.domain}
                    </div>
                    <div className="text-[11px] text-slate-500 truncate" title={entry.url}>
                      {entry.url}
                    </div>
                  </td>

                  {/* Summary */}
                  <td className="py-3.5 px-4 max-w-sm text-slate-300">
                    <span className="line-clamp-2" title={entry.summary}>
                      {entry.summary}
                    </span>
                  </td>

                  {/* Score */}
                  <td className="py-3.5 px-4 whitespace-nowrap font-mono">
                    <span className={getScoreColorClass(entry.score)}>
                      {entry.score}/100
                    </span>
                  </td>

                  {/* Timestamp */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap text-slate-500">
                    {formatTimestamp(entry.timestamp)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Confirmation Modal */}
      {confirmingClear && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-sm w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Clear Security History?</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              This will permanently delete all {entries.length} local security log entries from your device. This action cannot be undone.
            </p>
            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => setConfirmingClear(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClearConfirm}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition-colors"
              >
                Clear History
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function LevelBadge({ level }: { level: VerdictLevel }) {
  let badgeStyle = 'bg-slate-800 text-slate-400 border-slate-700';
  let label = level;

  if (level === 'dangerous') {
    badgeStyle = 'bg-rose-500/20 text-rose-400 border-rose-500/40';
    label = 'Dangerous';
  } else if (level === 'suspicious') {
    badgeStyle = 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    label = 'Suspicious';
  } else if (level === 'safe') {
    badgeStyle = 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    label = 'Safe';
  }

  return (
    <span className={`inline-block px-2.5 py-1 rounded-full text-[11px] font-semibold border ${badgeStyle} capitalize`}>
      {label}
    </span>
  );
}

function getScoreColorClass(score: number): string {
  if (score >= 70) return 'text-rose-400 font-bold';
  if (score >= 30) return 'text-amber-400 font-medium';
  return 'text-emerald-400';
}

function formatTimestamp(isoStr: string): string {
  try {
    const d = new Date(isoStr);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoStr;
  }
}
