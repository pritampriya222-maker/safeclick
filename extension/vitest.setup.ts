/**
 * vitest.setup.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Chrome Extension API mocks for Vitest unit tests.
 * The chrome.* APIs don't exist in jsdom — we mock the minimal surface
 * used by Phase 1 code (storage.local, runtime.sendMessage, etc.).
 *
 * Each test that needs specific behavior can override these mocks locally
 * using vi.mocked() or by overwriting the globalThis.chrome properties.
 */

import { vi } from 'vitest';

// ─── In-memory storage implementation ────────────────────────────────────────

const localStore: Record<string, unknown> = {};
const sessionStore: Record<string, unknown> = {};
const changeListeners: Array<
  (changes: Record<string, chrome.storage.StorageChange>, area: string) => void
> = [];

const makeStorageArea = (store: Record<string, unknown>) => ({
  get: vi.fn(async (keys: string | string[] | null) => {
    if (keys === null) return { ...store };
    const keyArr = typeof keys === 'string' ? [keys] : keys;
    return Object.fromEntries(keyArr.map((k) => [k, store[k]]));
  }),
  set: vi.fn(async (items: Record<string, unknown>) => {
    const changes: Record<string, chrome.storage.StorageChange> = {};
    for (const [key, newValue] of Object.entries(items)) {
      changes[key] = { oldValue: store[key], newValue };
      store[key] = newValue;
    }
    changeListeners.forEach((l) => l(changes, 'local'));
  }),
  remove: vi.fn(async (keys: string | string[]) => {
    const keyArr = typeof keys === 'string' ? [keys] : keys;
    const changes: Record<string, chrome.storage.StorageChange> = {};
    keyArr.forEach((k) => {
      changes[k] = { oldValue: store[k], newValue: undefined };
      delete store[k];
    });
    changeListeners.forEach((l) => l(changes, 'local'));
  }),
  clear: vi.fn(async () => {
    Object.keys(store).forEach((k) => delete store[k]);
  }),
});

// ─── Global chrome mock ───────────────────────────────────────────────────────

globalThis.chrome = {
  storage: {
    local: makeStorageArea(localStore) as unknown as chrome.storage.LocalStorageArea,
    session: makeStorageArea(sessionStore) as unknown as chrome.storage.SessionStorageArea,
    onChanged: {
      addListener: vi.fn((listener) => changeListeners.push(listener)),
      removeListener: vi.fn((listener) => {
        const idx = changeListeners.indexOf(listener);
        if (idx > -1) changeListeners.splice(idx, 1);
      }),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
      addRules: vi.fn(),
      removeRules: vi.fn(),
      getRules: vi.fn(),
    } as unknown as chrome.storage.StorageChangedEvent,
    sync: makeStorageArea({}) as unknown as chrome.storage.SyncStorageArea,
    managed: makeStorageArea({}) as unknown as chrome.storage.StorageArea,
  } as unknown as typeof chrome.storage,

  runtime: {
    sendMessage: vi.fn(async () => ({ success: true })),
    onMessage: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
    } as unknown as chrome.runtime.ExtensionMessageEvent,
    onInstalled: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
    } as unknown as chrome.runtime.RuntimeInstalledEvent,
    onStartup: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
    } as unknown as chrome.runtime.RuntimeEvent,
    openOptionsPage: vi.fn(async () => {}),
    getURL: vi.fn((path: string) => `chrome-extension://fake-id/${path}`),
    id: 'fake-extension-id',
    lastError: undefined,
  } as unknown as typeof chrome.runtime,

  tabs: {
    query: vi.fn(async () => [
      { id: 1, url: 'https://example.com', active: true },
    ]),
    get: vi.fn(async (tabId: number) => ({
      id: tabId,
      url: 'https://example.com',
    })),
    sendMessage: vi.fn(async () => ({ success: true })),
    onActivated: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
    } as unknown as chrome.tabs.TabActivatedEvent,
    onUpdated: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
    } as unknown as chrome.tabs.TabUpdatedEvent,
    onRemoved: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(),
      hasListeners: vi.fn(),
    } as unknown as chrome.tabs.TabRemovedEvent,
  } as unknown as typeof chrome.tabs,
} as unknown as typeof chrome;

// ─── Reset store between tests ────────────────────────────────────────────────
beforeEach(() => {
  Object.keys(localStore).forEach((k) => delete localStore[k]);
  Object.keys(sessionStore).forEach((k) => delete sessionStore[k]);
  changeListeners.length = 0;
  vi.clearAllMocks();
});
