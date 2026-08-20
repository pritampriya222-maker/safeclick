/**
 * extension/background/warningManager.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 4: Warning Interstitial Manager & Bypass Store.
 *
 * Manages navigation interception for dangerous websites and 1-hour temporary
 * session bypasses (when user clicks "Proceed anyway" and confirms).
 */

import type { Verdict } from '../shared/types';

const BYPASS_STORAGE_KEY = 'safeclick_warning_bypasses';
const BYPASS_TTL_MS = 60 * 60 * 1000; // 1 hour temporary bypass

export interface BypassEntry {
  domain: string;
  bypassedAt: string; // ISO 8601
  expiresAt: string;  // ISO 8601
}

/**
 * Check if a domain has an active, non-expired temporary warning bypass.
 */
export async function isDomainBypassed(domain: string): Promise<boolean> {
  if (!domain) return false;
  const normalized = domain.toLowerCase().replace(/^www\./, '');

  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.session) {
      return false;
    }
    const data = await chrome.storage.session.get(BYPASS_STORAGE_KEY);
    const bypasses: Record<string, BypassEntry> = data[BYPASS_STORAGE_KEY] || {};

    const entry = bypasses[normalized];
    if (!entry) return false;

    // Check expiration
    if (new Date(entry.expiresAt).getTime() < Date.now()) {
      // Remove expired bypass
      delete bypasses[normalized];
      await chrome.storage.session.set({ [BYPASS_STORAGE_KEY]: bypasses });
      return false;
    }

    return true;
  } catch (err) {
    console.error('[SafeClick] Error checking warning bypass:', err);
    return false;
  }
}

/**
 * Add a temporary 1-hour session bypass for a domain when user clicks "Proceed anyway".
 */
export async function addDomainBypass(domain: string): Promise<void> {
  if (!domain) return;
  const normalized = domain.toLowerCase().replace(/^www\./, '');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + BYPASS_TTL_MS);

  const entry: BypassEntry = {
    domain: normalized,
    bypassedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };

  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.session) {
      const data = await chrome.storage.session.get(BYPASS_STORAGE_KEY);
      const bypasses: Record<string, BypassEntry> = data[BYPASS_STORAGE_KEY] || {};
      bypasses[normalized] = entry;
      await chrome.storage.session.set({ [BYPASS_STORAGE_KEY]: bypasses });
      console.log(`[SafeClick] Temporary 1h bypass granted for ${normalized}`);
    }
  } catch (err) {
    console.error('[SafeClick] Failed to save domain bypass:', err);
  }
}

/**
 * Construct the local chrome-extension warning page URL for a dangerous site.
 */
export function buildWarningUrl(targetUrl: string, verdict: Verdict): string {
  const extensionId = typeof chrome !== 'undefined' && chrome.runtime?.id ? chrome.runtime.id : '';
  const baseUrl = extensionId
    ? `chrome-extension://${extensionId}/warning/warning.html`
    : '/warning/warning.html';

  const params = new URLSearchParams();
  params.set('url', targetUrl);
  params.set('score', verdict.score.toString());
  params.set('reason', verdict.explanation?.summary || verdict.reasons[0] || 'Phishing threat detected');
  params.set('confidence', verdict.confidence?.level || 'high');
  if (verdict.reasons && verdict.reasons.length > 0) {
    params.set('reasons', JSON.stringify(verdict.reasons.slice(0, 3)));
  }

  return `${baseUrl}?${params.toString()}`;
}
