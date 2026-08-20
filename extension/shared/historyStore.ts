/**
 * extension/shared/historyStore.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 4: Local Safe Browsing History Store.
 *
 * Persists a local, size-capped log of security verdicts to chrome.storage.local.
 * Completely separate from browser native history.
 *
 * Requirements:
 * - Max 500 entries (HISTORY_MAX_ENTRIES), FIFO eviction when exceeded.
 * - Privacy respecting: respects `settings.historyLoggingEnabled`.
 * - One-click clear function.
 * - Stat calculation functions feeding the Phase 4 Dashboard.
 */

import type { VerdictLevel, Settings } from './types';
import { HISTORY_MAX_ENTRIES } from './constants';
import { getSettings } from './storage';

export const HISTORY_STORAGE_KEY = 'safeclick_history';

export interface HistoryEntry {
  id: string;
  url: string;
  domain: string;
  level: VerdictLevel;
  score: number;
  summary: string;
  timestamp: string; // ISO 8601
}

export interface DailyTrendPoint {
  date: string; // YYYY-MM-DD
  safe: number;
  suspicious: number;
  dangerous: number;
  total: number;
}

export interface DomainFlagCount {
  domain: string;
  count: number;
  dangerousCount: number;
  suspiciousCount: number;
  maxScore: number;
}

export interface HistoryStats {
  totalAllTime: number;
  totalToday: number;
  totalThisWeek: number;
  dangerousBlocked: number;
  suspiciousFlagged: number;
  safeCount: number;
  topDomains: DomainFlagCount[];
  dailyTrend: DailyTrendPoint[];
}

/**
 * Retrieve all stored history entries (sorted newest first).
 */
export async function getHistoryEntries(): Promise<HistoryEntry[]> {
  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) {
      return [];
    }
    const data = await chrome.storage.local.get(HISTORY_STORAGE_KEY);
    const list = (data[HISTORY_STORAGE_KEY] as HistoryEntry[]) || [];
    return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  } catch (err) {
    console.error('[SafeClick] Error reading history store:', err);
    return [];
  }
}

/**
 * Add a new verdict entry to history log.
 * Respects `settings.historyLoggingEnabled` and enforces 500 max entry cap (FIFO).
 */
export async function addHistoryEntry(
  item: Omit<HistoryEntry, 'id'> & { id?: string },
  settings?: Settings
): Promise<HistoryEntry[]> {
  const currentSettings = settings || (await getSettings());

  // Respect user privacy toggle
  if (!currentSettings.historyLoggingEnabled) {
    return getHistoryEntries();
  }

  // Do not log non-analyzable pages
  if (item.level === 'not_applicable' || item.level === 'unknown') {
    return getHistoryEntries();
  }

  const newEntry: HistoryEntry = {
    id: item.id || `hist_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    url: item.url,
    domain: item.domain || extractDomain(item.url),
    level: item.level,
    score: item.score,
    summary: item.summary,
    timestamp: item.timestamp || new Date().toISOString(),
  };

  const existing = await getHistoryEntries();

  // Deduplicate consecutive identical logs within 5 seconds for the same tab/URL
  if (existing.length > 0) {
    const latest = existing[0];
    const timeDiff = new Date(newEntry.timestamp).getTime() - new Date(latest.timestamp).getTime();
    if (latest.url === newEntry.url && Math.abs(timeDiff) < 5000) {
      return existing;
    }
  }

  // Prepend new entry
  let updated = [newEntry, ...existing];

  // Enforce size cap (evict oldest if > HISTORY_MAX_ENTRIES)
  if (updated.length > HISTORY_MAX_ENTRIES) {
    updated = updated.slice(0, HISTORY_MAX_ENTRIES);
  }

  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      await chrome.storage.local.set({ [HISTORY_STORAGE_KEY]: updated });
    }
  } catch (err) {
    console.error('[SafeClick] Failed to save history entry:', err);
  }

  return updated;
}

/**
 * Clear all history entries from local storage.
 */
export async function clearHistory(): Promise<void> {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      await chrome.storage.local.remove(HISTORY_STORAGE_KEY);
    }
  } catch (err) {
    console.error('[SafeClick] Failed to clear history store:', err);
  }
}

/**
 * Aggregate local statistics from history entries.
 */
export function calculateHistoryStats(entries: HistoryEntry[], now = new Date()): HistoryStats {
  const todayStr = now.toISOString().split('T')[0];

  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const thirtyDaysAgo = new Date(now);
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  let totalToday = 0;
  let totalThisWeek = 0;
  let dangerousBlocked = 0;
  let suspiciousFlagged = 0;
  let safeCount = 0;

  const domainMap = new Map<string, DomainFlagCount>();
  const trendMap = new Map<string, DailyTrendPoint>();

  // Pre-populate 30 days trend map with 0 counts
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const dateKey = d.toISOString().split('T')[0];
    trendMap.set(dateKey, { date: dateKey, safe: 0, suspicious: 0, dangerous: 0, total: 0 });
  }

  for (const entry of entries) {
    const entryDate = new Date(entry.timestamp);
    const entryDateStr = entry.timestamp.split('T')[0];

    // Counts
    if (entryDateStr === todayStr) {
      totalToday++;
    }
    if (entryDate >= sevenDaysAgo) {
      totalThisWeek++;
    }

    if (entry.level === 'dangerous') dangerousBlocked++;
    else if (entry.level === 'suspicious') suspiciousFlagged++;
    else if (entry.level === 'safe') safeCount++;

    // Domain breakdown (only for flagged/analyzed domains)
    if (entry.domain) {
      const existing = domainMap.get(entry.domain) || {
        domain: entry.domain,
        count: 0,
        dangerousCount: 0,
        suspiciousCount: 0,
        maxScore: 0,
      };

      existing.count++;
      if (entry.level === 'dangerous') existing.dangerousCount++;
      if (entry.level === 'suspicious') existing.suspiciousCount++;
      existing.maxScore = Math.max(existing.maxScore, entry.score);

      domainMap.set(entry.domain, existing);
    }

    // Daily Trend
    if (trendMap.has(entryDateStr)) {
      const trend = trendMap.get(entryDateStr)!;
      trend.total++;
      if (entry.level === 'dangerous') trend.dangerous++;
      else if (entry.level === 'suspicious') trend.suspicious++;
      else if (entry.level === 'safe') trend.safe++;
    }
  }

  // Sort top domains by total count, then maxScore
  const topDomains = Array.from(domainMap.values())
    .sort((a, b) => b.count - a.count || b.maxScore - a.maxScore)
    .slice(0, 10);

  const dailyTrend = Array.from(trendMap.values());

  return {
    totalAllTime: entries.length,
    totalToday,
    totalThisWeek,
    dangerousBlocked,
    suspiciousFlagged,
    safeCount,
    topDomains,
    dailyTrend,
  };
}

/**
 * Helper to extract domain from URL string.
 */
function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return url;
  }
}
