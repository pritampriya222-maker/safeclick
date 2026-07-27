# SafeClick — API Contracts

> **Version:** 0.1.0 (Phase 1)
> All contracts defined here are versioned. Breaking changes require a new version prefix.

---

## Phase 1 — Internal Extension Contracts

Phase 1 has no HTTP API endpoints (the backend is introduced in Phase 2). This document captures the **TypeScript interface contracts** from `extension/shared/types.ts` that all later phases must preserve.

---

## Core TypeScript Interfaces

### `Verdict`

The primary output of the detection engine. Every consumer (popup, options, dashboard) reads verdicts through this interface.

```typescript
interface Verdict {
  url: string;            // The analyzed URL (may be normalized)
  level: VerdictLevel;    // 'safe' | 'suspicious' | 'dangerous' | 'unknown' | 'not_applicable'
  score: number;          // 0–100 risk score (thresholds in constants.ts)
  reasons: string[];      // ≥1 human-readable explanation strings. NEVER empty.
  ruleTriggers: RuleTrigger[];  // Structured rule/heuristic results (Phase 2 populates)
  timestamp: string;      // ISO 8601 datetime of verdict computation
  isStub: boolean;        // true = Phase 1 stub, false = real engine (Phase 2+)
}

type VerdictLevel = 'safe' | 'suspicious' | 'dangerous' | 'unknown' | 'not_applicable';
```

**Constraints:**
- `reasons` must always have at least one entry (explainability constraint — non-negotiable)
- `score` must be in [0, 100] inclusive
- `timestamp` must be a valid ISO 8601 string

**Phase 3 extension (additive):**
```typescript
// These fields will be added to Verdict in Phase 3 — existing fields unchanged:
// ml?: MlVerdict
// confidence?: ConfidenceInfo
// explanation?: ExplanationInfo
```

---

### `RuleTrigger`

```typescript
interface RuleTrigger {
  ruleId: string;       // Unique identifier, e.g. "heuristic:length_entropy"
  name: string;         // Human-readable name
  triggered: boolean;   // Whether the rule fired for this URL
  weight: number;       // Relative contribution weight (0–100 scale)
  explanation: string;  // One-sentence plain-English explanation
}
```

---

### `Settings`

Persisted user preferences. Stored in `chrome.storage.local` under key `"safeclick_settings"`.

```typescript
interface Settings {
  enabled: boolean;
  notificationPreference: 'toast' | 'badge_only' | 'silent';
  allowlist: string[];           // Trusted domains (normalized, no www)
  denylist: string[];            // Blocked domains (normalized, no www)
  cursorIndicatorEnabled: boolean;       // Phase 4 (declared Phase 1)
  shareAnonymizedThreatData: boolean;   // Phase 5 (placeholder, always false Phase 1-4)
  historyLoggingEnabled: boolean;       // Phase 4 (declared Phase 1)
}
```

**Default values:** See `extension/shared/constants.ts → DEFAULT_SETTINGS`.

---

### `SiteRecord`

Ephemeral per-tab state. Stored in `chrome.storage.session` under key `"tab_{tabId}"`.

```typescript
interface SiteRecord {
  tabId: number;
  url: string;
  firstSeen: string;       // ISO 8601
  lastChecked: string | null;
  verdict: Verdict | null; // null until first verdict computed
  pageSignals: PageSignals | null;
}
```

---

### `PageSignals`

Captured by `content/contentScript.ts` and sent to the background worker.

```typescript
interface PageSignals {
  tabId: number;
  hasLoginForm: boolean;   // True if <input type="password"> found
  charset: string | null;  // Page declared charset
  title: string | null;    // Page <title>
  capturedAt: string;      // ISO 8601
}
```

---

## Message Contracts

All messages between popup, background, and content scripts use these typed shapes (enforced by `shared/messaging.ts`).

### `GET_VERDICT` (popup → background)
```typescript
{ type: 'GET_VERDICT'; tabId: number }
// Response: MessageResponse<Verdict | null>
```

### `VERDICT_UPDATE` (background → popup)
```typescript
{ type: 'VERDICT_UPDATE'; tabId: number; verdict: Verdict }
// No response expected (broadcast)
```

### `PAGE_SIGNALS` (content → background)
```typescript
{ type: 'PAGE_SIGNALS'; signals: PageSignals }
// Response: MessageResponse<void>
```

### `REPORT_SITE` (popup → background)
```typescript
{ type: 'REPORT_SITE'; url: string; reason?: string }
// Response: MessageResponse<void>
// Phase 1: logs to console. Phase 5: sends to backend API.
```

### `TRUST_DOMAIN` (popup → background)
```typescript
{ type: 'TRUST_DOMAIN'; domain: string }
// Response: MessageResponse<void>
```

### `GET_SETTINGS` (any → background)
```typescript
{ type: 'GET_SETTINGS' }
// Response: MessageResponse<Settings>
```

### `SET_SETTINGS` (any → background)
```typescript
{ type: 'SET_SETTINGS'; settings: Partial<Settings> }
// Response: MessageResponse<void>
```

### `OPEN_OPTIONS` (popup → background)
```typescript
{ type: 'OPEN_OPTIONS' }
// Response: MessageResponse<void>
```

---

## Risk Score Thresholds

Defined in `extension/shared/constants.ts`. All phases must import from here — never hardcode these values.

| Score Range | Verdict Level | UX Behavior (Phase 4) |
|-------------|--------------|----------------------|
| 0–29 | `safe` | Green badge, no notification |
| 30–69 | `suspicious` | Amber badge + cursor indicator only (no interstitial) |
| 70–100 | `dangerous` | Red badge + full-page warning interstitial |

---

## Phase 2 Planned Additions

The following endpoints will be documented here when Phase 2 is implemented:

### `GET /api/v1/reputation?domain={domain}`
```
Request:  ?domain=example.com
Response: {
  domain: string,
  knownMalicious: boolean,
  source: string,
  lastChecked: string,   // ISO 8601
  confidence: number     // 0–1
}
```

---

## Versioning Policy

- All HTTP API endpoints are versioned under `/api/v1/`.
- TypeScript interfaces are extended **additively only** — no fields removed or renamed after they appear in a shipped phase.
- Breaking changes require bumping the API version prefix and updating this document.
