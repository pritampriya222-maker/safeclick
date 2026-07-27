/**
 * shared/storage.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Typed wrapper around chrome.storage.local.
 * All extension code that reads/writes persistent settings must go through
 * this module — never call chrome.storage directly from popup or background.
 *
 * Design decisions:
 * - Returns typed results (no `any` in the public API)
 * - Initializes defaults on first run automatically
 * - Provides a subscribe() helper for reactive updates
 * - chrome.storage.session is used by tabTracker.ts for ephemeral tab data;
 *   this module only manages chrome.storage.local (persistent settings)
 */

import type { Settings } from './types';
import { STORAGE_KEYS, DEFAULT_SETTINGS } from './constants';

// ─── Types ────────────────────────────────────────────────────────────────────

type StorageChangeCallback<T> = (newValue: T, oldValue: T | undefined) => void;

// ─── Initialization ───────────────────────────────────────────────────────────

/**
 * Initialize storage with default settings if this is the first run.
 * Call once from the service worker's install event.
 */
export async function initializeStorage(): Promise<void> {
  const existing = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
  if (!existing[STORAGE_KEYS.SETTINGS]) {
    await chrome.storage.local.set({
      [STORAGE_KEYS.SETTINGS]: DEFAULT_SETTINGS,
    });
    console.log('[SafeClick] Storage initialized with default settings.');
  }
}

// ─── Settings ─────────────────────────────────────────────────────────────────

/**
 * Retrieve the current user settings.
 * If settings don't exist (shouldn't happen after initializeStorage), returns defaults.
 */
export async function getSettings(): Promise<Settings> {
  const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
  const stored = result[STORAGE_KEYS.SETTINGS] as Partial<Settings> | undefined;

  if (!stored) {
    return { ...DEFAULT_SETTINGS };
  }

  // Merge with defaults to handle settings added in newer versions
  return { ...DEFAULT_SETTINGS, ...stored };
}

/**
 * Persist a partial settings update.
 * Merges with existing settings — no field is accidentally erased by a partial write.
 */
export async function setSettings(update: Partial<Settings>): Promise<void> {
  const current = await getSettings();
  const updated: Settings = { ...current, ...update };
  await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: updated });
}

/**
 * Reset all settings to factory defaults.
 */
export async function resetSettings(): Promise<void> {
  await chrome.storage.local.set({
    [STORAGE_KEYS.SETTINGS]: { ...DEFAULT_SETTINGS },
  });
}

// ─── Allowlist / Denylist helpers ─────────────────────────────────────────────

export async function addToAllowlist(domain: string): Promise<void> {
  const settings = await getSettings();
  const normalized = normalizeDomain(domain);
  if (!settings.allowlist.includes(normalized)) {
    await setSettings({ allowlist: [...settings.allowlist, normalized] });
  }
}

export async function removeFromAllowlist(domain: string): Promise<void> {
  const settings = await getSettings();
  const normalized = normalizeDomain(domain);
  await setSettings({
    allowlist: settings.allowlist.filter((d) => d !== normalized),
  });
}

export async function addToDenylist(domain: string): Promise<void> {
  const settings = await getSettings();
  const normalized = normalizeDomain(domain);
  if (!settings.denylist.includes(normalized)) {
    await setSettings({ denylist: [...settings.denylist, normalized] });
  }
}

export async function removeFromDenylist(domain: string): Promise<void> {
  const settings = await getSettings();
  const normalized = normalizeDomain(domain);
  await setSettings({
    denylist: settings.denylist.filter((d) => d !== normalized),
  });
}

export function isInAllowlist(domain: string, settings: Settings): boolean {
  return settings.allowlist.includes(normalizeDomain(domain));
}

export function isInDenylist(domain: string, settings: Settings): boolean {
  return settings.denylist.includes(normalizeDomain(domain));
}

// ─── Subscribe ────────────────────────────────────────────────────────────────

/**
 * Subscribe to settings changes.
 * Returns an unsubscribe function — always call it on component teardown.
 *
 * @example
 * const unsub = subscribeToSettings((newSettings) => { ... });
 * // Later:
 * unsub();
 */
export function subscribeToSettings(
  callback: StorageChangeCallback<Settings>
): () => void {
  const listener = (
    changes: { [key: string]: chrome.storage.StorageChange },
    areaName: string
  ) => {
    if (areaName !== 'local') return;
    if (STORAGE_KEYS.SETTINGS in changes) {
      const change = changes[STORAGE_KEYS.SETTINGS];
      callback(
        { ...DEFAULT_SETTINGS, ...(change.newValue as Partial<Settings>) },
        change.oldValue
          ? { ...DEFAULT_SETTINGS, ...(change.oldValue as Partial<Settings>) }
          : undefined
      );
    }
  };

  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}

// ─── Generic storage helpers ──────────────────────────────────────────────────

/**
 * Generic typed get from chrome.storage.local.
 * Prefer the typed helpers above for settings; use this for other data.
 */
export async function storageGet<T>(key: string): Promise<T | undefined> {
  const result = await chrome.storage.local.get(key);
  return result[key] as T | undefined;
}

/**
 * Generic typed set to chrome.storage.local.
 */
export async function storageSet<T>(key: string, value: T): Promise<void> {
  await chrome.storage.local.set({ [key]: value });
}

/**
 * Remove a key from chrome.storage.local.
 */
export async function storageRemove(key: string): Promise<void> {
  await chrome.storage.local.remove(key);
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function normalizeDomain(domain: string): string {
  return domain.toLowerCase().replace(/^www\./, '').trim();
}
