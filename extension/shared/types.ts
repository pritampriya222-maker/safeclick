/**
 * shared/types.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * The FROZEN Phase 1 contract. Every later phase extends these types additively.
 * Do NOT remove or rename existing fields — doing so breaks all downstream consumers.
 *
 * Phase extension guide:
 *   Phase 2 – adds heuristic/reputation fields to Verdict
 *   Phase 3 – adds ml, confidence, explanation fields to Verdict
 *   Phase 4 – adds history/dashboard types
 *   Phase 5 – adds auth/cloud sync types
 *   Phase 6 – adds org/policy types
 */

// ─── Verdict ─────────────────────────────────────────────────────────────────

/**
 * The top-level safety verdict for a URL.
 * verdictStub.ts is the ONLY Phase 1 producer of this type.
 * Phase 2 replaces verdictStub.ts internals without changing this shape.
 */
export type VerdictLevel = 'safe' | 'suspicious' | 'dangerous' | 'unknown' | 'not_applicable';

export interface Verdict {
  /** The URL that was analyzed (normalized where possible). */
  url: string;

  /** The safety determination. */
  level: VerdictLevel;

  /**
   * A 0–100 risk score.
   * 0–29  → safe
   * 30–69 → suspicious
   * 70–100 → dangerous
   * Thresholds defined in shared/constants.ts (single source of truth).
   */
  score: number;

  /**
   * Human-readable reason strings, ordered descending by contribution to score.
   * MUST always have at least one entry — a bare score with no explanation
   * violates the project's explainability constraint.
   */
  reasons: string[];

  /**
   * Structured rule triggers for future machine consumption / UI rendering.
   * Phase 2 populates these with real heuristic names.
   */
  ruleTriggers: RuleTrigger[];

  /** ISO timestamp of when the verdict was computed. */
  timestamp: string;

  /** True if this verdict came from the Phase 1 stub, not a real engine. */
  isStub: boolean;

  // ── Phase 2 additions (additive — all optional, Phase 1 consumers unaffected) ─
  /** Heuristic results that contributed to this verdict. Phase 2+. */
  heuristics?: HeuristicResult[];
  /** Reputation lookup result. Phase 2+. */
  reputation?: ReputationResult;
  /** Phishing detection patterns that fired. Phase 2+. */
  phishingPatterns?: PhishingPattern[];

  // ── Phase 3 additions (additive — all optional) ────────────────────────────
  /** ML model prediction. Phase 3+. */
  ml?: MlVerdict;
  /** Version of the server-side rule engine used. Phase 3+. */
  ruleEngineVersion?: string;
  /** Confidence in the combined verdict. Phase 3+. */
  confidence?: ConfidenceInfo;
  /** Structured plain-English explanation for UI and audit. Phase 3+. */
  explanation?: ExplanationInfo;
}

// ─── Phase 3 Types ────────────────────────────────────────────────────────────

/**
 * A single feature that contributed to the ML model's prediction.
 * Used to make the ML path explainable (SHAP or global feature importance).
 */
export interface FeatureContribution {
  /** Feature name, e.g. "url_length", "subdomain_entropy". */
  featureName: string;
  /** Human-readable label for display. */
  label: string;
  /** The feature value for this URL. */
  value: number;
  /** Contribution to phishing probability (-1 to +1). Positive = toward phishing. */
  contribution: number;
}

/**
 * ML model prediction result.
 * Returned by /api/v1/predict and stored in Verdict.ml.
 */
export interface MlVerdict {
  /** Probability 0–1 that this URL is phishing. */
  score: number | null;
  /** "phishing" or "benign", null if ML unavailable. */
  label: 'phishing' | 'benign' | null;
  /** Semantic version of the model used, e.g. "1.0.0". */
  modelVersion: string;
  /** Top feature contributions (sorted by abs contribution descending). */
  topContributingFeatures: FeatureContribution[];
  /** Source of the ML result. */
  source: 'model' | 'unavailable';
}

/**
 * Confidence in the combined verdict from rule engine + ML model.
 * Surfaces agreement/disagreement transparently — never silently picks one.
 */
export interface ConfidenceInfo {
  /** How confident we are in the final verdict. */
  level: 'high' | 'medium' | 'low';
  /** True if rule engine and ML model broadly agree (within 0.3 distance). */
  agreement: boolean;
  /**
   * The blended 0–1 score used to determine the final verdict.
   * formula: 0.5 * (ruleScore/100) + 0.5 * mlScore - disagreementPenalty
   */
  combinedScore: number;
  /** Human-readable note, e.g. "Rule engine and ML model agree this is safe." */
  note: string;
}

/**
 * Structured plain-English explanation of the verdict.
 * Feeds Phase 4's UI tooltip/panel and is fully auditable.
 */
export interface ExplanationInfo {
  /** One-sentence summary for the popup badge tooltip. */
  summary: string;
  /** Reasons from Phase 2/3 rule engine, ordered by weight. */
  ruleReasons: string[];
  /** Reasons from ML model, phrased in plain English. */
  mlReasons: string[];
}

// ─── Phase 2 Types ────────────────────────────────────────────────────────────

/**
 * Output of the URL normalization step.
 * Preserved as a structured signal — IDN/punycode flags are evidence of
 * phishing intent and must NOT be silently stripped.
 */
export interface NormalizedUrl {
  /** The original URL as passed in. */
  original: string;
  /** The cleaned, normalized URL string. */
  normalized: string;
  /** Extracted hostname (lowercased). */
  hostname: string;
  /** Registered domain (eTLD+1), e.g. "example.com" from "sub.example.com". */
  registeredDomain: string;
  /** True if the hostname contains non-ASCII characters (Internationalized Domain Name). */
  isIDN: boolean;
  /** True if the hostname uses xn-- punycode encoding. */
  isPunycode: boolean;
  /** True if the URL contains suspicious percent-encoding patterns. */
  hasSuspiciousEncoding: boolean;
  /** True if a non-standard port is used (not 80 for http, not 443 for https). */
  portIsNonStandard: boolean;
  /** The URL scheme (lowercased), e.g. "https". */
  scheme: string;
  /** The path component of the URL. */
  path: string;
  /** Remaining query params after tracking params are stripped. */
  cleanQuery: string;
}

/**
 * Result from a single heuristic analysis module.
 * Each module is a pure function: (NormalizedUrl, PageSignals | null) → HeuristicResult.
 */
export interface HeuristicResult {
  /** Unique rule identifier, e.g. "heuristic:length_entropy". */
  ruleId: string;
  /** Human-readable display name. */
  name: string;
  /** Whether this heuristic triggered (fired) for this URL. */
  triggered: boolean;
  /**
   * Raw contribution to the risk score (0–100 scale, per-heuristic maximum).
   * Only applied to final score if triggered === true.
   */
  weight: number;
  /** One-sentence plain-English explanation of why this heuristic triggered. */
  explanation: string;
}

/**
 * Result of the domain reputation lookup.
 * The backend returns this; the extension reputationClient.ts wraps it.
 */
export interface ReputationResult {
  domain: string;
  knownMalicious: boolean;
  /** Data source that made the determination. */
  source: 'virustotal' | 'openphish' | 'local_blocklist' | 'top_domain_list' | 'unavailable' | 'cache';
  /** ISO timestamp of when this was last checked. */
  lastChecked: string;
  /** 0–1 confidence score. 0 = unknown/unavailable, 1 = high confidence. */
  confidence: number;
  /** Human-readable description of the source finding. */
  detail?: string;
}

/**
 * A specific phishing detection pattern that fired.
 * Produced by phishingDetector.ts.
 */
export interface PhishingPattern {
  /** Pattern identifier, e.g. "phishing:typosquatting". */
  patternId: string;
  /** Human-readable name. */
  name: string;
  /** Risk score contribution (0–100). */
  weight: number;
  /** Plain-English explanation of what was detected. */
  explanation: string;
}

/**
 * A single named rule or heuristic that contributed to the verdict.
 * Phase 2 fills these; Phase 1 stub returns an empty array.
 */
export interface RuleTrigger {
  /** Unique rule identifier, e.g. "heuristic:length_entropy". */
  ruleId: string;
  /** Display name. */
  name: string;
  /** Whether the rule fired. */
  triggered: boolean;
  /** Relative weight this rule has in the final score (0–100 scale). */
  weight: number;
  /** One-sentence human-readable explanation of why this rule triggered. */
  explanation: string;
}

// ─── Settings ────────────────────────────────────────────────────────────────

/**
 * Persisted user settings. Stored in chrome.storage.local via storage.ts.
 * Phase 1 defines the schema; later phases may add fields (additive only).
 */
export interface Settings {
  /** Master kill-switch for the extension. */
  enabled: boolean;

  /**
   * How the extension notifies the user of threats.
   * 'toast'       → show a browser notification for dangerous sites
   * 'badge_only'  → only update the popup badge, no notification
   * 'silent'      → update badge only, no popup highlight
   */
  notificationPreference: 'toast' | 'badge_only' | 'silent';

  /**
   * Domains the user has explicitly marked as trusted.
   * These bypass verdict warnings (still analyzed, but UI suppressed).
   */
  allowlist: string[];

  /**
   * Domains the user has explicitly marked as always-dangerous.
   * These always produce a Dangerous verdict regardless of engine output.
   */
  denylist: string[];

  /**
   * Phase 4 cursor indicator setting — declared here so Phase 4 can read it
   * without a settings schema migration.
   * @default true
   */
  cursorIndicatorEnabled: boolean;

  /**
   * Placeholder for Phase 5 cloud sync.
   * MUST remain disabled and greyed-out in the Phase 1–4 UI.
   * @default false
   */
  shareAnonymizedThreatData: boolean;

  /**
   * Whether to log visited sites to local history (Phase 4 feature).
   * Declared here so Phase 4 can read it without a schema migration.
   * @default true
   */
  historyLoggingEnabled: boolean;
}

// ─── SiteRecord ──────────────────────────────────────────────────────────────

/**
 * Per-tab runtime record maintained in the background service worker.
 * Ephemeral — stored in chrome.storage.session (survives worker restart,
 * cleared on browser close).
 */
export interface SiteRecord {
  /** Chrome tab ID. */
  tabId: number;
  /** The current URL of the tab. */
  url: string;
  /** ISO timestamp of when this URL was first seen in this session. */
  firstSeen: string;
  /** ISO timestamp of the last verdict computation for this tab. */
  lastChecked: string | null;
  /** Most recent verdict for this tab. Null until first check completes. */
  verdict: Verdict | null;
  /** Signals captured by the content script on this page. */
  pageSignals: PageSignals | null;
}

// ─── PageSignals ─────────────────────────────────────────────────────────────

/**
 * Signals extracted by contentScript.ts and sent to the background worker.
 * Phase 2 consumes these for heuristic analysis.
 */
export interface PageSignals {
  /** Tab ID this signal came from. */
  tabId: number;
  /** True if the page contains <form> with <input type="password">. */
  hasLoginForm: boolean;
  /** Page's declared charset, e.g. "UTF-8". */
  charset: string | null;
  /** Page's <title> content. */
  title: string | null;
  /** ISO timestamp of when signals were captured. */
  capturedAt: string;
}

// ─── Messages ────────────────────────────────────────────────────────────────

/**
 * All inter-component messages pass through messaging.ts which enforces
 * these types. Add new message types here; never inline ad-hoc message shapes.
 */
export type MessageType =
  | 'GET_VERDICT'
  | 'VERDICT_UPDATE'
  | 'PAGE_SIGNALS'
  | 'REPORT_SITE'
  | 'TRUST_DOMAIN'
  | 'GET_SETTINGS'
  | 'SET_SETTINGS'
  | 'OPEN_OPTIONS';

export interface BaseMessage {
  type: MessageType;
}

export interface GetVerdictMessage extends BaseMessage {
  type: 'GET_VERDICT';
  tabId: number;
}

export interface VerdictUpdateMessage extends BaseMessage {
  type: 'VERDICT_UPDATE';
  tabId: number;
  verdict: Verdict;
}

export interface PageSignalsMessage extends BaseMessage {
  type: 'PAGE_SIGNALS';
  signals: PageSignals;
}

export interface ReportSiteMessage extends BaseMessage {
  type: 'REPORT_SITE';
  url: string;
  reason?: string;
}

export interface TrustDomainMessage extends BaseMessage {
  type: 'TRUST_DOMAIN';
  domain: string;
}

export interface GetSettingsMessage extends BaseMessage {
  type: 'GET_SETTINGS';
}

export interface SetSettingsMessage extends BaseMessage {
  type: 'SET_SETTINGS';
  settings: Partial<Settings>;
}

export interface OpenOptionsMessage extends BaseMessage {
  type: 'OPEN_OPTIONS';
}

export type ExtensionMessage =
  | GetVerdictMessage
  | VerdictUpdateMessage
  | PageSignalsMessage
  | ReportSiteMessage
  | TrustDomainMessage
  | GetSettingsMessage
  | SetSettingsMessage
  | OpenOptionsMessage;

// ─── Message Responses ───────────────────────────────────────────────────────

export interface MessageResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}
