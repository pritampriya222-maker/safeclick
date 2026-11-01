/**
 * extension/shared/authClient.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 5: Cloud authentication client for the SafeClick extension.
 *
 * Token storage decision (documented tradeoff):
 *   Chrome MV3 extensions cannot use httpOnly cookies for token storage.
 *   The background service worker has no HTTP cookie jar. Tokens are stored
 *   in chrome.storage.local under the key STORAGE_KEY.
 *   Mitigations:
 *     - Access tokens have a 15-minute TTL
 *     - Refresh tokens are stored hashed in the DB (not plaintext)
 *     - The extension origin (chrome-extension://<id>) is isolated from web origins
 *   This tradeoff is documented here and in docs/architecture.md, not hidden.
 *
 * Local-first guarantee:
 *   All Phase 1–4 features (heuristics, ML scoring, reputation lookup, history,
 *   dashboard, interstitial) work when getAuthState() returns null.
 *   This file MUST NOT introduce any blocking dependency for those features.
 */

const API_BASE = 'http://localhost:8000/api/v1';
const STORAGE_KEY = 'safeclick_auth';
const REFRESH_BUFFER_MS = 60_000; // refresh 1 min before access token expires

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuthState {
  userId: string;
  email: string;
  accessToken: string;
  refreshToken: string;
  /** Unix timestamp (ms) when the access token expires */
  accessTokenExpiresAt: number;
}

export interface AuthError {
  message: string;
  status?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseJwtExp(token: string): number | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp ? payload.exp * 1000 : null; // convert to ms
  } catch {
    return null;
  }
}

async function saveAuthState(state: AuthState): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: state });
}

async function clearAuthState(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function apiFetch(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  });
}

// ── Auth state access ─────────────────────────────────────────────────────────

/**
 * Returns the current auth state from storage, or null if not logged in.
 * All Phase 1–4 features MUST handle a null return here gracefully.
 */
export async function getAuthState(): Promise<AuthState | null> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return (result[STORAGE_KEY] as AuthState) ?? null;
}

/**
 * Returns true if the user is currently logged in with a valid (or refreshable) token.
 */
export async function isLoggedIn(): Promise<boolean> {
  const state = await getAuthState();
  return state !== null;
}

// ── Auth operations ───────────────────────────────────────────────────────────

/**
 * Register a new account.
 * On success, tokens are saved to storage and the user is logged in.
 */
export async function register(
  email: string,
  password: string,
): Promise<AuthState | AuthError> {
  try {
    const res = await apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Registration failed' }));
      return { message: err.detail ?? 'Registration failed', status: res.status };
    }

    const data = await res.json();
    const state: AuthState = {
      userId: data.user_id,
      email: data.email,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      accessTokenExpiresAt: parseJwtExp(data.access_token) ?? Date.now() + 15 * 60_000,
    };
    await saveAuthState(state);
    return state;
  } catch (err) {
    return { message: `Network error: ${String(err)}` };
  }
}

/**
 * Login with email and password.
 * On success, tokens are saved to storage.
 */
export async function login(
  email: string,
  password: string,
): Promise<AuthState | AuthError> {
  try {
    const res = await apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }));
      return { message: err.detail ?? 'Login failed', status: res.status };
    }

    const data = await res.json();
    const state: AuthState = {
      userId: data.user_id,
      email: data.email,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      accessTokenExpiresAt: parseJwtExp(data.access_token) ?? Date.now() + 15 * 60_000,
    };
    await saveAuthState(state);
    return state;
  } catch (err) {
    return { message: `Network error: ${String(err)}` };
  }
}

/**
 * Logout: invalidates the refresh token server-side and clears local storage.
 */
export async function logout(): Promise<void> {
  const state = await getAuthState();
  if (state?.refreshToken) {
    try {
      await apiFetch('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: state.refreshToken }),
      });
    } catch {
      // Best-effort — always clear local state even if network fails
    }
  }
  await clearAuthState();
}

/**
 * Refresh the access token using the stored refresh token.
 * Implements rotation: both tokens are replaced on success.
 * Returns the updated AuthState, or null if refresh fails (triggers re-login).
 */
export async function refreshToken(): Promise<AuthState | null> {
  const state = await getAuthState();
  if (!state?.refreshToken) return null;

  try {
    const res = await apiFetch('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: state.refreshToken }),
    });

    if (!res.ok) {
      // Refresh token expired or revoked — clear state, user must re-login
      await clearAuthState();
      return null;
    }

    const data = await res.json();
    const newState: AuthState = {
      userId: data.user_id,
      email: data.email,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      accessTokenExpiresAt: parseJwtExp(data.access_token) ?? Date.now() + 15 * 60_000,
    };
    await saveAuthState(newState);
    return newState;
  } catch {
    return null;
  }
}

/**
 * Get a valid access token, refreshing if necessary.
 * Returns null if no auth state (unauthenticated — caller handles gracefully).
 */
export async function getValidAccessToken(): Promise<string | null> {
  const state = await getAuthState();
  if (!state) return null;

  const needsRefresh = Date.now() >= state.accessTokenExpiresAt - REFRESH_BUFFER_MS;
  if (needsRefresh) {
    const newState = await refreshToken();
    return newState?.accessToken ?? null;
  }

  return state.accessToken;
}

/**
 * Submit a phishing/FP report from the extension.
 * Attaches auth token if available; falls back to anonymous if not.
 */
export async function submitReport(payload: {
  url: string;
  reportType: 'phishing' | 'false_positive' | 'malware';
  engineScore?: number;
  notes?: string;
}): Promise<{ success: boolean; message?: string }> {
  const token = await getValidAccessToken();
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const res = await apiFetch('/reports', {
      method: 'POST',
      body: JSON.stringify({
        url: payload.url,
        report_type: payload.reportType,
        engine_score: payload.engineScore,
        notes: payload.notes,
      }),
      headers,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Report submission failed' }));
      return { success: false, message: err.detail };
    }
    return { success: true };
  } catch (err) {
    return { success: false, message: `Network error: ${String(err)}` };
  }
}

// ── Auth state subscription ───────────────────────────────────────────────────

type AuthStateListener = (state: AuthState | null) => void;
const _listeners: Set<AuthStateListener> = new Set();

/**
 * Subscribe to auth state changes. Callback receives null when logged out.
 * Returns an unsubscribe function.
 */
export function onAuthStateChange(listener: AuthStateListener): () => void {
  _listeners.add(listener);
  return () => _listeners.delete(listener);
}

// Wire up chrome.storage.onChanged to notify subscribers
if (typeof chrome !== 'undefined' && chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes[STORAGE_KEY]) {
      const newState = (changes[STORAGE_KEY].newValue as AuthState) ?? null;
      _listeners.forEach((fn) => fn(newState));
    }
  });
}
