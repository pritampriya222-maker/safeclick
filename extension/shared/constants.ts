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

// ─── Suspicious Brand Keywords ───────────────────────────────────────────────
/**
 * Brand name substrings that should NOT appear in the subdomain or path
 * of a URL unless the registered domain IS that brand's domain.
 * Used by Phase 2's suspiciousKeywords.ts heuristic.
 * Keep alphabetical for readability.
 */
export const SUSPICIOUS_BRAND_KEYWORDS: readonly string[] = [
  'adobe', 'amazon', 'amex', 'apple', 'att',
  'bankofamerica', 'binance', 'bitcoin', 'blockchain',
  'capitalone', 'chase', 'citibank', 'coinbase', 'crypto',
  'docusign', 'dropbox',
  'ebay', 'etsy',
  'facebook', 'fedex',
  'gmail', 'google',
  'hotmail', 'hsbc',
  'icloud', 'instagram',
  'linkedin', 'live',
  'mastercard', 'microsoft',
  'netflix',
  'office365', 'outlook',
  'paypal', 'pinterest',
  'reddit',
  'samsung', 'snapchat', 'spotify', 'steam',
  'tiktok', 'twitter',
  'uber', 'ups',
  'venmo', 'visa',
  'wallet', 'walmart', 'wellsfargo', 'whatsapp',
  'yahoo', 'youtube',
  'zoom',
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
export const EXTENSION_VERSION = '0.2.0';
export const API_BASE_URL = 'http://localhost:8000'; // Phase 2 backend, configurable

// ─── Reputation Client Timeout (ms) ──────────────────────────────────────────
/** Phase 2: max time to wait for backend reputation lookup before graceful degradation. */
export const REPUTATION_TIMEOUT_MS = 800;

// ─── History Store ────────────────────────────────────────────────────────────
/** Phase 4: maximum number of history entries before oldest is evicted. */
export const HISTORY_MAX_ENTRIES = 500;

// ─── Phase 2: Heuristic Weights ───────────────────────────────────────────────
/**
 * Maximum contribution of each heuristic/signal to the final risk score (0–100).
 * These are documented here so Phase 3's rule engine can read/override them.
 * The risk scorer uses these as ceilings — triggered heuristics contribute
 * their full weight; non-triggered contribute 0.
 *
 * Total: if ALL heuristics fire + reputation + phishing patterns, score = 100.
 * Weighted sum is clipped to [0, 100].
 */
export const HEURISTIC_WEIGHTS = {
  /** Length/entropy — long URL or high-entropy randomized-looking subdomain. */
  LENGTH_ENTROPY: 15,
  /** Suspicious brand keywords in subdomain or path. */
  SUSPICIOUS_KEYWORDS: 20,
  /** URL structure issues: raw IP, @ obfuscation, deep subdomains, hyphen brands. */
  URL_STRUCTURE: 20,
  /** Login form on untrusted/unknown domain. */
  LOGIN_FORM_SIGNAL: 15,
  /** Reputation: domain confirmed malicious by VT or OpenPhish. */
  REPUTATION_MALICIOUS: 40,
  /** Phishing: typosquatting match against known brand. */
  PHISHING_TYPOSQUAT: 35,
  /** Phishing: IDN homograph / confusable character detected. */
  PHISHING_HOMOGRAPH: 30,
  /** Phishing: suspicious TLD combined with brand keyword. */
  PHISHING_SUSPICIOUS_TLD: 20,
} as const;

// ─── Phase 2: URL Analysis Thresholds ────────────────────────────────────────
export const URL_ANALYSIS = {
  /** URLs longer than this character count are flagged as suspicious. */
  SUSPICIOUS_LENGTH: 100,
  /** Shannon entropy above this for subdomains/paths is flagged (max theoretical = ~4.0 for random hex). */
  SUSPICIOUS_ENTROPY: 3.5,
  /** More subdomain labels than this is flagged (e.g. a.b.c.d.example.com = 4 labels). */
  MAX_SUBDOMAIN_DEPTH: 3,
  /** Levenshtein distance ≤ this to a known brand domain is flagged as typosquatting. */
  TYPOSQUAT_DISTANCE: 2,
} as const;

// ─── Phase 2: Suspicious TLDs ────────────────────────────────────────────────
/**
 * TLDs commonly associated with free/dirt-cheap domain registrations that
 * phishers frequently abuse. Being on this list alone does NOT make a domain
 * malicious — it's a signal that COMBINES with other factors (e.g., brand keyword).
 */
export const SUSPICIOUS_TLDS: readonly string[] = [
  '.tk', '.ml', '.ga', '.cf', '.gq',   // Freenom free TLDs (heavily abused)
  '.xyz', '.top', '.club', '.work',
  '.loan', '.click', '.download', '.link',
  '.review', '.science', '.win', '.bid',
  '.trade', '.date', '.racing', '.party',
  '.stream', '.gdn', '.icu',
] as const;

// ─── Phase 2: Known Brand Domains (for typosquatting checks) ─────────────────
/**
 * Registered domains of known brands used as baseline for typosquatting distance.
 * Phase 3's rule engine will extend this list via the rule bundle format.
 */
export const KNOWN_BRAND_DOMAINS: readonly string[] = [
  'google.com', 'gmail.com', 'youtube.com', 'googlemail.com',
  'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
  'apple.com', 'icloud.com',
  'microsoft.com', 'outlook.com', 'office.com', 'live.com', 'hotmail.com',
  'amazon.com', 'amazonaws.com',
  'paypal.com',
  'netflix.com',
  'twitter.com', 'x.com',
  'linkedin.com',
  'github.com',
  'dropbox.com',
  'coinbase.com',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
  'ebay.com',
  'spotify.com',
  'adobe.com',
] as const;
