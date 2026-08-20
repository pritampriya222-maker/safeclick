/**
 * tests/historyStore.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Vitest tests for shared/historyStore.ts.
 * Covers:
 * - 500-entry max capping (FIFO eviction)
 * - Privacy settings respect (historyLoggingEnabled = false)
 * - Stat calculation functions (today, week, top domains, daily trend)
 * - Clear history helper
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  calculateHistoryStats,
  addHistoryEntry,
  getHistoryEntries,
  clearHistory,
  HISTORY_STORAGE_KEY,
  HistoryEntry,
} from '../shared/historyStore';
import type { Settings } from '../shared/types';
import { DEFAULT_SETTINGS } from '../shared/constants';

// ── Mock chrome.storage.local ──────────────────────────────────────────────────

const mockStorage: Record<string, any> = {};

global.chrome = {
  storage: {
    local: {
      get: vi.fn((key: string) => Promise.resolve({ [key]: mockStorage[key] })),
      set: vi.fn((obj: Record<string, any>) => {
        Object.assign(mockStorage, obj);
        return Promise.resolve();
      }),
      remove: vi.fn((key: string) => {
        delete mockStorage[key];
        return Promise.resolve();
      }),
    },
  },
} as any;

describe('calculateHistoryStats', () => {
  const now = new Date('2026-08-20T12:00:00Z');

  it('returns zeroes for empty history list', () => {
    const stats = calculateHistoryStats([], now);
    expect(stats.totalAllTime).toBe(0);
    expect(stats.totalToday).toBe(0);
    expect(stats.totalThisWeek).toBe(0);
    expect(stats.dangerousBlocked).toBe(0);
    expect(stats.suspiciousFlagged).toBe(0);
    expect(stats.safeCount).toBe(0);
    expect(stats.topDomains).toHaveLength(0);
    expect(stats.dailyTrend).toHaveLength(30);
  });

  it('aggregates counts and breakdowns correctly', () => {
    const entries: HistoryEntry[] = [
      {
        id: '1',
        url: 'https://paypal-fake.tk/login',
        domain: 'paypal-fake.tk',
        level: 'dangerous',
        score: 85,
        summary: 'Phishing domain detected.',
        timestamp: '2026-08-20T10:00:00Z', // Today
      },
      {
        id: '2',
        url: 'https://example.com/suspicious',
        domain: 'example.com',
        level: 'suspicious',
        score: 45,
        summary: 'Suspicious path pattern.',
        timestamp: '2026-08-18T14:00:00Z', // This week
      },
      {
        id: '3',
        url: 'https://google.com',
        domain: 'google.com',
        level: 'safe',
        score: 0,
        summary: 'Top domain.',
        timestamp: '2026-08-15T09:00:00Z', // This week
      },
    ];

    const stats = calculateHistoryStats(entries, now);

    expect(stats.totalAllTime).toBe(3);
    expect(stats.totalToday).toBe(1);
    expect(stats.totalThisWeek).toBe(3);
    expect(stats.dangerousBlocked).toBe(1);
    expect(stats.suspiciousFlagged).toBe(1);
    expect(stats.safeCount).toBe(1);

    // Top domains
    expect(stats.topDomains).toHaveLength(3);
    expect(stats.topDomains[0].domain).toBe('paypal-fake.tk');
    expect(stats.topDomains[0].maxScore).toBe(85);
  });

  it('populates 30-day daily trend timeline', () => {
    const entries: HistoryEntry[] = [
      {
        id: '1',
        url: 'https://danger.tk',
        domain: 'danger.tk',
        level: 'dangerous',
        score: 90,
        summary: 'Danger',
        timestamp: '2026-08-20T10:00:00Z',
      },
    ];

    const stats = calculateHistoryStats(entries, now);
    expect(stats.dailyTrend).toHaveLength(30);

    const todayPoint = stats.dailyTrend.find((p) => p.date === '2026-08-20');
    expect(todayPoint).toBeDefined();
    expect(todayPoint?.dangerous).toBe(1);
    expect(todayPoint?.total).toBe(1);
  });
});

describe('addHistoryEntry & eviction', () => {
  beforeEach(() => {
    delete mockStorage[HISTORY_STORAGE_KEY];
    vi.clearAllMocks();
  });

  it('adds an entry when history logging is enabled', async () => {
    const settings: Settings = { ...DEFAULT_SETTINGS, historyLoggingEnabled: true };
    const entry = {
      url: 'https://phishing.tk/login',
      domain: 'phishing.tk',
      level: 'dangerous' as const,
      score: 90,
      summary: 'Dangerous phishing site.',
      timestamp: new Date().toISOString(),
    };

    const updated = await addHistoryEntry(entry, settings);
    expect(updated).toHaveLength(1);
    expect(updated[0].domain).toBe('phishing.tk');
  });

  it('does NOT add an entry when history logging is disabled', async () => {
    const settings: Settings = { ...DEFAULT_SETTINGS, historyLoggingEnabled: false };
    const entry = {
      url: 'https://phishing.tk/login',
      domain: 'phishing.tk',
      level: 'dangerous' as const,
      score: 90,
      summary: 'Dangerous phishing site.',
      timestamp: new Date().toISOString(),
    };

    const updated = await addHistoryEntry(entry, settings);
    expect(updated).toHaveLength(0);
  });

  it('enforces 500-entry max cap (FIFO eviction)', async () => {
    const settings: Settings = { ...DEFAULT_SETTINGS, historyLoggingEnabled: true };

    // Fill storage with 500 entries
    const initialList: HistoryEntry[] = [];
    for (let i = 1; i <= 500; i++) {
      initialList.push({
        id: `entry_${i}`,
        url: `https://example${i}.com`,
        domain: `example${i}.com`,
        level: 'safe',
        score: 0,
        summary: `Safe site ${i}`,
        timestamp: new Date(Date.now() - (500 - i) * 60000).toISOString(),
      });
    }
    mockStorage[HISTORY_STORAGE_KEY] = initialList;

    // Add 501st entry
    const newEntry = {
      url: 'https://newest-entry.com',
      domain: 'newest-entry.com',
      level: 'suspicious' as const,
      score: 45,
      summary: 'New entry',
      timestamp: new Date().toISOString(),
    };

    const updated = await addHistoryEntry(newEntry, settings);

    expect(updated).toHaveLength(500); // capped at 500
    expect(updated[0].domain).toBe('newest-entry.com'); // newest is first
    expect(updated.some((e) => e.id === 'entry_1')).toBe(false); // oldest (entry_1) evicted
  });

  it('clears history correctly', async () => {
    mockStorage[HISTORY_STORAGE_KEY] = [
      {
        id: '1',
        url: 'https://test.com',
        domain: 'test.com',
        level: 'safe',
        score: 0,
        summary: 'Safe',
        timestamp: new Date().toISOString(),
      },
    ];

    await clearHistory();
    expect(mockStorage[HISTORY_STORAGE_KEY]).toBeUndefined();
  });
});
