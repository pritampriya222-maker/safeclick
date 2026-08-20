import React, { useState, useEffect } from 'react';
import {
  getHistoryEntries,
  clearHistory,
  calculateHistoryStats,
  HistoryEntry,
  HistoryStats,
} from '../shared/historyStore';
import { HistoryView } from './HistoryView';
import { EXTENSION_VERSION } from '../shared/constants';

export function Dashboard() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [stats, setStats] = useState<HistoryStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const loadData = async () => {
    setLoading(true);
    const data = await getHistoryEntries();
    setEntries(data);
    setStats(calculateHistoryStats(data));
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleClearHistory = async () => {
    await clearHistory();
    await loadData();
  };

  if (loading || !stats) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-slate-400 font-medium">Loading Security Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-10 space-y-8 max-w-7xl mx-auto selection:bg-indigo-500 selection:text-white">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-slate-800 pb-6">
        <div className="flex items-center space-x-4">
          <div className="w-12 h-12 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shadow-lg shadow-indigo-500/10">
            <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-2xl font-extrabold text-white tracking-tight">SafeClick</h1>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                v{EXTENSION_VERSION}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Local Security Dashboard & Safe Browsing Analytics
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-medium transition-colors flex items-center space-x-2"
        >
          <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <span>Refresh</span>
        </button>
      </header>

      {/* Summary Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Total Checked */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-2">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Sites Analyzed</div>
          <div className="text-3xl font-extrabold text-white">{stats.totalAllTime}</div>
          <div className="text-xs text-slate-500">
            <span className="text-indigo-400 font-semibold">{stats.totalToday}</span> today •{' '}
            <span className="text-indigo-400 font-semibold">{stats.totalThisWeek}</span> this week
          </div>
        </div>

        {/* Dangerous Blocked */}
        <div className="bg-slate-900 border border-rose-500/20 rounded-2xl p-5 shadow-lg space-y-2">
          <div className="text-xs font-semibold text-rose-400 uppercase tracking-wider">Dangerous Blocked</div>
          <div className="text-3xl font-extrabold text-rose-400">{stats.dangerousBlocked}</div>
          <div className="text-xs text-slate-500">
            {stats.totalAllTime > 0
              ? `${((stats.dangerousBlocked / stats.totalAllTime) * 100).toFixed(1)}% of all sites checked`
              : '0% total'}
          </div>
        </div>

        {/* Suspicious Flagged */}
        <div className="bg-slate-900 border border-amber-500/20 rounded-2xl p-5 shadow-lg space-y-2">
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Suspicious Flagged</div>
          <div className="text-3xl font-extrabold text-amber-400">{stats.suspiciousFlagged}</div>
          <div className="text-xs text-slate-500">
            {stats.totalAllTime > 0
              ? `${((stats.suspiciousFlagged / stats.totalAllTime) * 100).toFixed(1)}% of all sites checked`
              : '0% total'}
          </div>
        </div>

        {/* Safe Sites */}
        <div className="bg-slate-900 border border-emerald-500/20 rounded-2xl p-5 shadow-lg space-y-2">
          <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Safe Sites</div>
          <div className="text-3xl font-extrabold text-emerald-400">{stats.safeCount}</div>
          <div className="text-xs text-slate-500">Clean browsing record</div>
        </div>
      </div>

      {/* Grid: 30-Day Trend Chart & Top Flagged Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* 30-Day Activity Chart */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white">30-Day Threat Detection Activity</h2>
            <div className="flex items-center space-x-3 text-xs">
              <span className="flex items-center space-x-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"/> <span className="text-slate-400">Safe</span></span>
              <span className="flex items-center space-x-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block"/> <span className="text-slate-400">Suspicious</span></span>
              <span className="flex items-center space-x-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"/> <span className="text-slate-400">Dangerous</span></span>
            </div>
          </div>

          {/* SVG Bar Chart */}
          <div className="h-44 w-full pt-4 flex items-end justify-between space-x-1">
            {stats.dailyTrend.map((point) => {
              const maxVal = Math.max(1, ...stats.dailyTrend.map((p) => p.total));
              const heightPercent = Math.max(8, (point.total / maxVal) * 100);

              return (
                <div
                  key={point.date}
                  className="flex-1 flex flex-col items-center group relative h-full justify-end"
                >
                  {/* Tooltip */}
                  <div className="absolute -top-12 left-1/2 -translate-x-1/2 bg-slate-950 text-slate-200 text-[10px] py-1 px-2 rounded border border-slate-800 shadow-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-20">
                    <div>{point.date}</div>
                    <div className="font-semibold">{point.total} checks ({point.dangerous} dangerous, {point.suspicious} suspicious)</div>
                  </div>

                  {/* Bar */}
                  <div
                    style={{ height: `${heightPercent}%` }}
                    className="w-full rounded-t flex flex-col overflow-hidden transition-all group-hover:brightness-125"
                  >
                    {point.dangerous > 0 && <div style={{ flex: point.dangerous }} className="bg-rose-500" />}
                    {point.suspicious > 0 && <div style={{ flex: point.suspicious }} className="bg-amber-500" />}
                    {point.safe > 0 && <div style={{ flex: point.safe }} className="bg-emerald-500" />}
                    {point.total === 0 && <div className="h-full bg-slate-800/40" />}
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex justify-between text-[10px] text-slate-500 pt-1">
            <span>30 days ago ({stats.dailyTrend[0]?.date})</span>
            <span>Today ({stats.dailyTrend[stats.dailyTrend.length - 1]?.date})</span>
          </div>
        </div>

        {/* Top Flagged Domains Ranking */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-bold text-white border-b border-slate-800 pb-3">Top Flagged Domains</h2>
            {stats.topDomains.length === 0 ? (
              <p className="text-xs text-slate-500 py-8 text-center">No flagged domains recorded yet.</p>
            ) : (
              <div className="space-y-3 pt-3">
                {stats.topDomains.map((item, idx) => (
                  <div key={item.domain} className="flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2 truncate max-w-[180px]">
                      <span className="w-5 font-mono text-slate-500 text-right">{idx + 1}.</span>
                      <span className="font-semibold text-slate-200 truncate" title={item.domain}>{item.domain}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-[11px] text-rose-400 font-bold">{item.maxScore}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">{item.count}×</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* History Table View */}
      <HistoryView entries={entries} onClearHistory={handleClearHistory} />
    </div>
  );
}
