/**
 * shared/constants.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Single source of truth for all thresholds, lists, and configuration values.
 * Every module that needs a threshold reads it from here — never hardcode
 * magic numbers inline in any other file.
 */

// ─── Risk Score Thresholds ────────────────────────────────────────────────────
/**
 * Verdict level boundaries for the 0–100 risk score.
 * Phase 3's confidence layer and Phase 4's UI both read these constants —
 * changing a threshold here changes the behavior everywhere consistently.
 */
export const RISK_THRESHOLDS = {
  /** 0–29: Site considered safe. */
  SAFE_MAX: 29,
  /** 30–69: Site is suspicious, show amber badge but no interstitial. */
  SUSPICIOUS_MAX: 69,
  /** 70–100: Site is dangerous, show full warning interstitial (Phase 4). */
  DANGEROUS_MIN: 70,
} as const;

// ─── Message Types ────────────────────────────────────────────────────────────
export const MESSAGE_TYPES = {
  GET_VERDICT: 'GET_VERDICT',
  VERDICT_UPDATE: 'VERDICT_UPDATE',
  PAGE_SIGNALS: 'PAGE_SIGNALS',
  REPORT_SITE: 'REPORT_SITE',
  TRUST_DOMAIN: 'TRUST_DOMAIN',
  GET_SETTINGS: 'GET_SETTINGS',
  SET_SETTINGS: 'SET_SETTINGS',
  OPEN_OPTIONS: 'OPEN_OPTIONS',
} as const;

// ─── Storage Keys ─────────────────────────────────────────────────────────────
export const STORAGE_KEYS = {
  SETTINGS: 'safeclick_settings',
  /** Prefix for per-tab session records (appended with tabId). */
  TAB_RECORD_PREFIX: 'tab_',
} as const;

// ─── Default Settings ─────────────────────────────────────────────────────────
import type { Settings } from './types';

export const DEFAULT_SETTINGS: Settings = {
  enabled: true,
  notificationPreference: 'badge_only',
  allowlist: [],
  denylist: [],
  cursorIndicatorEnabled: true,
  shareAnonymizedThreatData: false,
  historyLoggingEnabled: true,
} as const;

// ─── Tracking Query Params (Phase 2 will use these for URL normalization) ─────
/**
 * Query parameters that should be stripped during URL normalization.
 * Source: common tracking param lists (utm_*, Google, Meta, etc.).
 * Maintained here so both TypeScript (extension) and Python (backend/ml)
 * can reference the same canonical list via the shared/constants.ts contract.
 */
export const TRACKING_QUERY_PARAMS: readonly string[] = [
  // Google Analytics / UTM
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'utm_id',
  // Google Ads
  'gclid',
  'gclsrc',
  'dclid',
  // Meta / Facebook
  'fbclid',
  'fb_action_ids',
  'fb_action_types',
  'fb_source',
  // Microsoft Ads
  'msclkid',
  // HubSpot
  '_hsenc',
  '_hsmi',
  'hsa_acc',
  'hsa_cam',
  'hsa_grp',
  'hsa_ad',
  'hsa_src',
  'hsa_tgt',
  'hsa_kw',
  'hsa_mt',
  'hsa_net',
  'hsa_ver',
  // Mailchimp
  'mc_cid',
  'mc_eid',
  // Marketo
  'mkt_tok',
  // Twitter / X
  'twclid',
  // TikTok
  'ttclid',
  // Misc
  'ref',
  'referrer',
  'yclid',
] as const;

// ─── Suspicious Brand Keywords (Phase 2 will expand this list) ───────────────
/**
 * Brand names commonly impersonated in phishing URLs.
 * Phase 2's suspiciousKeywords.ts heuristic reads from here.
 */
export const SUSPICIOUS_BRAND_KEYWORDS: readonly string[] = [
  'paypal',
  'amazon',
  'apple',
  'google',
  'microsoft',
  'facebook',
  'instagram',
  'whatsapp',
  'netflix',
  'spotify',
  'bank',
  'secure',
  'login',
  'verify',
  'account',
  'update',
  'confirm',
  'wallet',
  'crypto',
  'coinbase',
] as const;

// ─── Non-applicable URL Schemes ───────────────────────────────────────────────
/**
 * URL schemes where SafeClick cannot/should not analyze.
 * The popup shows "Not applicable" for these.
 */
export const NON_APPLICABLE_SCHEMES: readonly string[] = [
  'chrome:',
  'chrome-extension:',
  'edge:',
  'about:',
  'data:',
  'javascript:',
  'file:',
  'moz-extension:',
] as const;

// ─── Extension Metadata ───────────────────────────────────────────────────────
export const EXTENSION_VERSION = '0.1.0';
export const API_BASE_URL = 'http://localhost:8000'; // Phase 2 backend, configurable

// ─── Reputation Client Timeout (ms) ──────────────────────────────────────────
/** Phase 2: max time to wait for backend reputation lookup before graceful degradation. */
export const REPUTATION_TIMEOUT_MS = 800;

// ─── History Store ────────────────────────────────────────────────────────────
/** Phase 4: maximum number of history entries before oldest is evicted. */
export const HISTORY_MAX_ENTRIES = 500;
