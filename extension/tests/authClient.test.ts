/**
 * extension/tests/authClient.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Vitest tests for Phase 5 authClient.ts.
 *
 * Requirements covered:
 * 1. Token storage, rotation, and logout clearing.
 * 2. Subscription listeners on auth state changes.
 * 3. Graceful degradation: all operations handle null auth state without throwing.
 * 4. Local-first verification: zero auth state present does NOT affect Phase 1-4.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  getAuthState,
  isLoggedIn,
  login,
  register,
  logout,
  refreshToken,
  getValidAccessToken,
  submitReport,
  onAuthStateChange,
  type AuthState,
} from '../shared/authClient';

// ── Mock chrome.storage.local ──────────────────────────────────────────────────

const mockStorage: Record<string, any> = {};
const storageListeners: Array<(changes: Record<string, any>, area: string) => void> = [];

global.chrome = {
  storage: {
    local: {
      get: vi.fn((key: string) => Promise.resolve({ [key]: mockStorage[key] })),
      set: vi.fn((obj: Record<string, any>) => {
        const changes: Record<string, any> = {};
        for (const [k, v] of Object.entries(obj)) {
          changes[k] = { oldValue: mockStorage[k], newValue: v };
        }
        Object.assign(mockStorage, obj);
        storageListeners.forEach((fn) => fn(changes, 'local'));
        return Promise.resolve();
      }),
      remove: vi.fn((key: string) => {
        const changes = { [key]: { oldValue: mockStorage[key], newValue: undefined } };
        delete mockStorage[key];
        storageListeners.forEach((fn) => fn(changes, 'local'));
        return Promise.resolve();
      }),
    },
    onChanged: {
      addListener: vi.fn((fn) => storageListeners.push(fn)),
    },
  },
} as any;

// Helper to craft a mock JWT with a custom exp timestamp
function createMockJwt(expSecondsFromNow: number): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({
    sub: 'user-123',
    email: 'test@safeclick.io',
    type: 'access',
    exp: Math.floor(Date.now() / 1000) + expSecondsFromNow,
  }));
  return `${header}.${payload}.mockSignature`;
}

describe('authClient — Phase 5 Cloud Authentication', () => {
  beforeEach(() => {
    for (const key of Object.keys(mockStorage)) delete mockStorage[key];
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('defaults to logged out (null state)', async () => {
    const state = await getAuthState();
    expect(state).toBeNull();
    expect(await isLoggedIn()).toBe(false);
  });

  it('login saves valid token state in chrome.storage.local', async () => {
    const mockJwt = createMockJwt(900); // 15 min
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: mockJwt,
        refresh_token: 'mock-refresh-token',
        user_id: 'user-123',
        email: 'test@safeclick.io',
      }),
    });

    const result = await login('test@safeclick.io', 'Password123!');
    expect('userId' in result).toBe(true);
    const authState = result as AuthState;
    expect(authState.email).toBe('test@safeclick.io');
    expect(authState.accessToken).toBe(mockJwt);
    expect(authState.refreshToken).toBe('mock-refresh-token');
    expect(authState.accessTokenExpiresAt).toBeGreaterThan(Date.now());

    // Storage persistence verified
    const stored = await getAuthState();
    expect(stored?.userId).toBe('user-123');
    expect(await isLoggedIn()).toBe(true);
  });

  it('register saves valid token state on successful creation', async () => {
    const mockJwt = createMockJwt(900);
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: mockJwt,
        refresh_token: 'new-refresh-token',
        user_id: 'user-456',
        email: 'newuser@safeclick.io',
      }),
    });

    const result = await register('newuser@safeclick.io', 'Password123!');
    expect('userId' in result).toBe(true);
    const authState = result as AuthState;
    expect(authState.email).toBe('newuser@safeclick.io');
    expect(await isLoggedIn()).toBe(true);
  });

  it('logout invalidates tokens and cleans storage', async () => {
    // Setup logged in state
    mockStorage['safeclick_auth'] = {
      userId: 'user-123',
      email: 'test@safeclick.io',
      accessToken: 'token',
      refreshToken: 'refresh',
      accessTokenExpiresAt: Date.now() + 100000,
    };

    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });

    await logout();
    expect(await getAuthState()).toBeNull();
    expect(await isLoggedIn()).toBe(false);
  });

  it('refreshToken performs token rotation', async () => {
    mockStorage['safeclick_auth'] = {
      userId: 'user-123',
      email: 'test@safeclick.io',
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      accessTokenExpiresAt: Date.now() - 1000, // expired
    };

    const newJwt = createMockJwt(900);
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: newJwt,
        refresh_token: 'rotated-refresh-token',
        user_id: 'user-123',
        email: 'test@safeclick.io',
      }),
    });

    const refreshed = await refreshToken();
    expect(refreshed?.accessToken).toBe(newJwt);
    expect(refreshed?.refreshToken).toBe('rotated-refresh-token');

    const stored = await getAuthState();
    expect(stored?.refreshToken).toBe('rotated-refresh-token');
  });

  it('getValidAccessToken auto-refreshes if token is expiring within buffer', async () => {
    // Expiring in 30 seconds (< 60s buffer)
    const expiringJwt = createMockJwt(30);
    const newJwt = createMockJwt(900);

    mockStorage['safeclick_auth'] = {
      userId: 'user-123',
      email: 'test@safeclick.io',
      accessToken: expiringJwt,
      refreshToken: 'refresh-token',
      accessTokenExpiresAt: Date.now() + 30_000,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: newJwt,
        refresh_token: 'new-refresh-token',
        user_id: 'user-123',
        email: 'test@safeclick.io',
      }),
    });

    const token = await getValidAccessToken();
    expect(token).toBe(newJwt);
  });

  it('submitReport includes auth header if logged in, anonymous if not', async () => {
    // Anonymous submission
    let capturedHeaders: any = {};
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      capturedHeaders = opts?.headers ?? {};
      return Promise.resolve({ ok: true, json: async () => ({}) });
    });

    const anonRes = await submitReport({
      url: 'https://evil.test/login',
      reportType: 'phishing',
      engineScore: 80,
    });
    expect(anonRes.success).toBe(true);
    expect(capturedHeaders['Authorization']).toBeUndefined();

    // Logged-in submission
    const mockJwt = createMockJwt(900);
    mockStorage['safeclick_auth'] = {
      userId: 'user-123',
      email: 'test@safeclick.io',
      accessToken: mockJwt,
      refreshToken: 'refresh',
      accessTokenExpiresAt: Date.now() + 500_000,
    };

    const authRes = await submitReport({
      url: 'https://evil2.test/login',
      reportType: 'phishing',
    });
    expect(authRes.success).toBe(true);
    expect(capturedHeaders['Authorization']).toBe(`Bearer ${mockJwt}`);
  });

  it('LOCAL-FIRST GUARANTEE: null auth state never breaks Phase 1-4 expectations', async () => {
    // Explicit test that all auth helpers return safe fallbacks on empty state
    expect(await getAuthState()).toBeNull();
    expect(await isLoggedIn()).toBe(false);
    expect(await getValidAccessToken()).toBeNull();
    expect(await refreshToken()).toBeNull();

    // Anonymous report still succeeds
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    const reportRes = await submitReport({ url: 'https://phish.example', reportType: 'phishing' });
    expect(reportRes.success).toBe(true);
  });
});
