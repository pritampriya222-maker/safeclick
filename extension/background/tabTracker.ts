/**
 * background/tabTracker.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Tracks active tabs and maintains the per-tab verdict state.
 *
 * Architecture notes:
 * - In-memory map (tabRecords) for fast synchronous access within the worker.
 * - chrome.storage.session is used to persist state across service worker
 *   restarts (MV3 workers are non-persistent and can be terminated at any time).
 *   storage.session survives worker restarts but is cleared on browser close.
 * - Verdict computation is delegated exclusively to verdictStub.ts (Phase 2
 *   replaces that file's internals without touching this file).
 * - After computing a verdict, we broadcast it to any open popup via messaging.ts.
 */

import type { SiteRecord, PageSignals, Verdict } from '../shared/types';
import { getVerdict } from './verdictStub';
import { broadcastMessage } from '../shared/messaging';
import { STORAGE_KEYS } from '../shared/constants';

// ─── In-memory state ──────────────────────────────────────────────────────────

/**
 * In-memory map of tabId → SiteRecord.
 * This is the fast-path for lookups within a single worker lifetime.
 * Always sync to session storage after writes.
 */
const tabRecords = new Map<number, SiteRecord>();

// ─── Session storage helpers ──────────────────────────────────────────────────

async function persistTabRecord(record: SiteRecord): Promise<void> {
  const key = `${STORAGE_KEYS.TAB_RECORD_PREFIX}${record.tabId}`;
  await chrome.storage.session.set({ [key]: record });
}

async function loadTabRecord(tabId: number): Promise<SiteRecord | null> {
  const key = `${STORAGE_KEYS.TAB_RECORD_PREFIX}${tabId}`;
  const result = await chrome.storage.session.get(key);
  return (result[key] as SiteRecord | undefined) ?? null;
}

async function clearTabRecord(tabId: number): Promise<void> {
  const key = `${STORAGE_KEYS.TAB_RECORD_PREFIX}${tabId}`;
  tabRecords.delete(tabId);
  await chrome.storage.session.remove(key);
}

// ─── Tab record management ────────────────────────────────────────────────────

/**
 * Get the current SiteRecord for a tab.
 * Checks in-memory first, then falls back to session storage
 * (handles the case where the worker was restarted since the tab was created).
 */
export async function getTabRecord(tabId: number): Promise<SiteRecord | null> {
  const inMemory = tabRecords.get(tabId);
  if (inMemory) return inMemory;

  // Worker may have restarted — try restoring from session storage.
  const persisted = await loadTabRecord(tabId);
  if (persisted) {
    tabRecords.set(tabId, persisted);
  }
  return persisted;
}

/**
 * Retrieve the last-known verdict for a tab.
 * Returns null if no verdict has been computed yet.
 */
export async function getTabVerdict(tabId: number): Promise<Verdict | null> {
  const record = await getTabRecord(tabId);
  return record?.verdict ?? null;
}

// ─── URL processing ───────────────────────────────────────────────────────────

/**
 * Called whenever a tab navigates to a new URL.
 * Creates/updates the SiteRecord and triggers verdict computation.
 */
export async function handleTabUrl(tabId: number, url: string): Promise<void> {
  const now = new Date().toISOString();
  const existing = await getTabRecord(tabId);

  // Don't re-analyze if the URL hasn't changed.
  if (existing?.url === url && existing.verdict !== null) {
    return;
  }

  const record: SiteRecord = {
    tabId,
    url,
    firstSeen: existing?.firstSeen ?? now,
    lastChecked: now,
    verdict: null, // will be set after analysis
    pageSignals: existing?.pageSignals ?? null,
  };

  tabRecords.set(tabId, record);
  await persistTabRecord(record);

  // Compute verdict asynchronously (verdictStub.ts in Phase 1, real engine in Phase 2+).
  try {
    const verdict = await getVerdict(url);
    record.verdict = verdict;
    record.lastChecked = new Date().toISOString();
    tabRecords.set(tabId, record);
    await persistTabRecord(record);

    // Broadcast to any open popup so it can update without polling.
    await broadcastMessage({
      type: 'VERDICT_UPDATE',
      tabId,
      verdict,
    });
  } catch (err) {
    console.error(`[SafeClick] getVerdict failed for ${url}:`, err);
  }
}

/**
 * Called by the content script when it captures page signals.
 * Updates the SiteRecord and optionally re-triggers verdict (Phase 2 will do this).
 */
export async function handlePageSignals(signals: PageSignals): Promise<void> {
  const record = await getTabRecord(signals.tabId);
  if (!record) return;

  record.pageSignals = signals;
  tabRecords.set(signals.tabId, record);
  await persistTabRecord(record);

  // Phase 2: re-trigger verdict with updated page signals if needed.
  // For Phase 1, we just store the signals for later consumption.
}

// ─── Tab lifecycle ────────────────────────────────────────────────────────────

/**
 * Initialize tab listeners. Called once by service-worker.ts.
 */
export function initTabTracker(): void {
  // Listen for tab activation (user switches tabs).
  chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab.url) {
        await handleTabUrl(tabId, tab.url);
      }
    } catch (err) {
      console.debug('[SafeClick] onActivated error (tab may have closed):', err);
    }
  });

  // Listen for tab navigation completion.
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
      await handleTabUrl(tabId, tab.url);
    }
  });

  // Clean up when a tab is closed (prevent memory/storage leaks).
  chrome.tabs.onRemoved.addListener(async (tabId) => {
    await clearTabRecord(tabId);
  });

  console.log('[SafeClick] Tab tracker initialized.');
}
