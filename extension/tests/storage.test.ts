/**
 * tests/storage.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for shared/storage.ts.
 * Verifies: get/set/defaults, allowlist/denylist helpers, subscribe callback.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  getSettings,
  setSettings,
  resetSettings,
  addToAllowlist,
  removeFromAllowlist,
  addToDenylist,
  removeFromDenylist,
  isInAllowlist,
  isInDenylist,
  subscribeToSettings,
  initializeStorage,
} from '../shared/storage';
import { DEFAULT_SETTINGS } from '../shared/constants';

describe('storage.ts — initializeStorage', () => {
  it('sets default settings on first run', async () => {
    await initializeStorage();
    const settings = await getSettings();
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });

  it('does not overwrite existing settings on subsequent calls', async () => {
    await initializeStorage();
    await setSettings({ enabled: false });
    await initializeStorage(); // should not reset
    const settings = await getSettings();
    expect(settings.enabled).toBe(false);
  });
});

describe('storage.ts — getSettings', () => {
  it('returns defaults when nothing is stored', async () => {
    const settings = await getSettings();
    expect(settings.enabled).toBe(DEFAULT_SETTINGS.enabled);
    expect(settings.notificationPreference).toBe(DEFAULT_SETTINGS.notificationPreference);
    expect(settings.allowlist).toEqual([]);
    expect(settings.denylist).toEqual([]);
  });

  it('merges stored partial settings with defaults', async () => {
    // Simulate a stored partial (e.g., from an older version of the extension).
    await chrome.storage.local.set({
      safeclick_settings: { enabled: false },
    });
    const settings = await getSettings();
    expect(settings.enabled).toBe(false);
    // Defaults should fill in any missing fields.
    expect(settings.notificationPreference).toBe(DEFAULT_SETTINGS.notificationPreference);
    expect(settings.cursorIndicatorEnabled).toBe(DEFAULT_SETTINGS.cursorIndicatorEnabled);
  });
});

describe('storage.ts — setSettings', () => {
  it('persists settings and retrieves them', async () => {
    await setSettings({ enabled: false, notificationPreference: 'toast' });
    const settings = await getSettings();
    expect(settings.enabled).toBe(false);
    expect(settings.notificationPreference).toBe('toast');
  });

  it('performs a partial update without erasing other fields', async () => {
    await initializeStorage();
    await setSettings({ enabled: false });
    const settings = await getSettings();
    // enabled changed
    expect(settings.enabled).toBe(false);
    // other fields are unchanged
    expect(settings.notificationPreference).toBe(DEFAULT_SETTINGS.notificationPreference);
    expect(settings.shareAnonymizedThreatData).toBe(false);
  });
});

describe('storage.ts — resetSettings', () => {
  it('restores factory defaults', async () => {
    await setSettings({ enabled: false, notificationPreference: 'silent' });
    await resetSettings();
    const settings = await getSettings();
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });
});

describe('storage.ts — allowlist helpers', () => {
  it('adds a domain to the allowlist', async () => {
    await initializeStorage();
    await addToAllowlist('example.com');
    const settings = await getSettings();
    expect(settings.allowlist).toContain('example.com');
  });

  it('normalizes domains (strips www, lowercases)', async () => {
    await initializeStorage();
    await addToAllowlist('WWW.Example.COM');
    const settings = await getSettings();
    expect(settings.allowlist).toContain('example.com');
  });

  it('does not add duplicates', async () => {
    await initializeStorage();
    await addToAllowlist('example.com');
    await addToAllowlist('example.com');
    const settings = await getSettings();
    expect(settings.allowlist.filter((d) => d === 'example.com').length).toBe(1);
  });

  it('removes a domain from the allowlist', async () => {
    await initializeStorage();
    await addToAllowlist('example.com');
    await removeFromAllowlist('example.com');
    const settings = await getSettings();
    expect(settings.allowlist).not.toContain('example.com');
  });

  it('isInAllowlist returns true for listed domains', async () => {
    await initializeStorage();
    await addToAllowlist('trusted.com');
    const settings = await getSettings();
    expect(isInAllowlist('trusted.com', settings)).toBe(true);
    expect(isInAllowlist('www.trusted.com', settings)).toBe(true);
    expect(isInAllowlist('other.com', settings)).toBe(false);
  });
});

describe('storage.ts — denylist helpers', () => {
  it('adds and checks denylist entries', async () => {
    await initializeStorage();
    await addToDenylist('phishing.com');
    const settings = await getSettings();
    expect(isInDenylist('phishing.com', settings)).toBe(true);
    expect(isInDenylist('safe.com', settings)).toBe(false);
  });

  it('removes from denylist', async () => {
    await initializeStorage();
    await addToDenylist('bad.com');
    await removeFromDenylist('bad.com');
    const settings = await getSettings();
    expect(isInDenylist('bad.com', settings)).toBe(false);
  });
});

describe('storage.ts — subscribeToSettings', () => {
  it('calls callback when settings change', async () => {
    await initializeStorage();
    const callback = vi.fn();
    const unsub = subscribeToSettings(callback);

    await setSettings({ enabled: false });

    expect(callback).toHaveBeenCalledOnce();
    const [newSettings] = callback.mock.calls[0];
    expect(newSettings.enabled).toBe(false);

    unsub();
  });

  it('does not call callback after unsubscribe', async () => {
    await initializeStorage();
    const callback = vi.fn();
    const unsub = subscribeToSettings(callback);
    unsub();

    await setSettings({ enabled: false });
    expect(callback).not.toHaveBeenCalled();
  });
});
