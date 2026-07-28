# SafeClick — Architecture Documentation

> **Version:** 0.1.0 (Phase 1)
> **Last updated:** Phase 1 — Core Browser Extension Skeleton
> **Maintained by:** Engineering team

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Repository Structure](#repository-structure)
3. [Phase 1 — Core Extension Architecture](#phase-1--core-extension-architecture)
4. [Internal Message Flow](#internal-message-flow)
5. [Storage Schema](#storage-schema)
6. [Verdict Contract & Extension Seams](#verdict-contract--extension-seams)
7. [Permissions & Least Privilege](#permissions--least-privilege)
8. [Decisions & Assumptions](#decisions--assumptions)
9. [Phase Roadmap](#phase-roadmap)

---

## System Overview

SafeClick is a browser security platform delivering real-time, **explainable** phishing and malicious-URL detection. Every verdict shown to a user includes structured reasons — never a bare score.

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              EXTENSION (Manifest V3)                     │   │
│  │  ┌──────────┐  ┌──────────────────┐  ┌──────────────┐  │   │
│  │  │  Content  │  │ Service Worker   │  │   Popup UI   │  │   │
│  │  │  Script   │─▶│ (tabTracker.ts)  │◀─│  (React)     │  │   │
│  │  │           │  │ (verdictStub.ts) │  │              │  │   │
│  │  └──────────┘  └────────┬─────────┘  └──────────────┘  │   │
│  │                         │ (Phase 2+)                     │   │
│  └─────────────────────────│────────────────────────────────┘   │
│                            │                                     │
└────────────────────────────│─────────────────────────────────────┘
                             │ HTTP (localhost:8000)
                    ┌────────▼───────────┐
                    │    BACKEND (FastAPI)│  ← Introduced Phase 2
                    │  reputation_service │
                    │  ml_service (Ph. 3) │
                    └────────────────────┘
                             │
                    ┌────────▼───────────┐
                    │  PostgreSQL + Redis │  ← Introduced Phase 5
                    └────────────────────┘
```

---

## Repository Structure

```
safeclick/
├── extension/           ← MV3 Chrome/Edge extension
│   ├── manifest.json
│   ├── popup/           ← React UI (Vite entry)
│   ├── content/         ← Content script (injected into pages)
│   ├── background/      ← Service worker + detection engine
│   ├── options/         ← Settings page (React, Vite entry)
│   └── shared/          ← Types, storage, messaging, constants
├── backend/             ← FastAPI Python service (Phase 2+)
│   ├── api/
│   ├── services/
│   ├── models/
│   ├── database/
│   └── ml/
├── dashboard/           ← Standalone admin dashboard (Phase 6)
├── docs/                ← Architecture, API contracts, decisions
└── tests/               ← Playwright E2E tests
    ├── e2e/
    └── fixtures/
```

---

## Phase 1 — Core Extension Architecture

### Components

| Component | File(s) | Responsibility |
|-----------|---------|----------------|
| Service Worker | `background/service-worker.ts` | Entry point, message routing, lifecycle |
| Tab Tracker | `background/tabTracker.ts` | URL change detection, verdict state management |
| Verdict Stub | `background/verdictStub.ts` | **Phase 2 replacement seam** — stub only |
| Content Script | `content/contentScript.ts` | Read-only page signal extraction |
| Popup | `popup/Popup.tsx` + components | Presentation layer, no detection logic |
| Options | `options/Options.tsx` | Settings UI and persistence |
| Shared Types | `shared/types.ts` | **Frozen contract** — all phases extend additively |
| Storage | `shared/storage.ts` | Typed `chrome.storage.local` wrapper |
| Messaging | `shared/messaging.ts` | Typed `chrome.runtime` message wrapper |
| Constants | `shared/constants.ts` | Thresholds, lists, defaults — single source of truth |

---

## Internal Message Flow

```
PAGE LOAD EVENT
     │
     ▼
content/contentScript.ts
  │  Captures: hasLoginForm, charset, title
  │  Sends: PAGE_SIGNALS message
     │
     ▼ (via messaging.ts)
background/service-worker.ts [message router]
  │  Routes PAGE_SIGNALS → tabTracker.handlePageSignals()
  │
  ├─▶ tabTracker.ts
  │     Listens: chrome.tabs.onActivated, onUpdated
  │     On new URL: calls getVerdict(url) → [verdictStub.ts Phase 1]
  │     Persists: SiteRecord to chrome.storage.session
  │     Broadcasts: VERDICT_UPDATE → popup (if open)
  │
  └─▶ [popup opens] → sends GET_VERDICT message
            │
            ▼
        tabTracker.getTabVerdict(tabId)
            │
            ▼
        Popup renders Verdict (VerdictBadge, SiteInfoCard, QuickActions)
```

### Message Types (Phase 1)

| Message | Direction | Purpose |
|---------|-----------|---------|
| `GET_VERDICT` | popup → background | Request current tab's verdict |
| `VERDICT_UPDATE` | background → popup | Push new verdict to open popup |
| `PAGE_SIGNALS` | content → background | Deliver page signal data |
| `REPORT_SITE` | popup → background | Log a user report |
| `TRUST_DOMAIN` | popup → background | Add domain to allowlist |
| `GET_SETTINGS` | popup/options → background | Fetch current settings |
| `SET_SETTINGS` | popup/options → background | Persist settings update |
| `OPEN_OPTIONS` | popup → background | Open the options page |

---

## Storage Schema

### `chrome.storage.local` (persistent)

| Key | Type | Description |
|-----|------|-------------|
| `safeclick_settings` | `Settings` | All user settings (enabled, allowlist, etc.) |

### `chrome.storage.session` (ephemeral — cleared on browser close)

| Key Pattern | Type | Description |
|-------------|------|-------------|
| `tab_{tabId}` | `SiteRecord` | Per-tab verdict + page signals state |

**Why session storage for tab records?**
MV3 service workers are non-persistent and can be terminated at any time. `chrome.storage.session` survives service worker restarts (so a verdict computed before the worker was killed is still available when the popup opens) but is cleared on browser close, which is the correct semantic for per-session tab data.

### Settings Schema (`shared/types.ts → Settings`)

```typescript
{
  enabled: boolean                                    // Master kill-switch
  notificationPreference: 'toast' | 'badge_only' | 'silent'
  allowlist: string[]                                 // User-trusted domains
  denylist: string[]                                  // User-blocked domains
  cursorIndicatorEnabled: boolean                     // Phase 4 feature (declared now)
  shareAnonymizedThreatData: boolean                  // Phase 5 placeholder (OFF, greyed out)
  historyLoggingEnabled: boolean                      // Phase 4 feature (declared now)
}
```

Future phases add fields to `Settings` **additively only** — `getSettings()` merges stored values with defaults, so new fields are automatically initialized without a migration.

---

## Verdict Contract & Extension Seams

### The `Verdict` Interface (frozen)

```typescript
interface Verdict {
  url: string          // URL analyzed
  level: VerdictLevel  // 'safe' | 'suspicious' | 'dangerous' | 'unknown' | 'not_applicable'
  score: number        // 0–100 risk score
  reasons: string[]    // ≥1 human-readable explanation strings (NEVER empty)
  ruleTriggers: RuleTrigger[]
  timestamp: string    // ISO 8601
  isStub: boolean      // True until Phase 2 replaces verdictStub.ts
}
```

**Explainability constraint:** `reasons` must always have at least one entry. A bare score with no explanation violates the project's core mission.

### `verdictStub.ts` — The Phase 2 Seam

```
⚠️  REPLACE IN PHASE 2 — DO NOT REMOVE THE FUNCTION SIGNATURE
```

`background/verdictStub.ts` exports exactly one function:

```typescript
export async function getVerdict(url: string): Promise<Verdict>
```

This signature is the **only contract** between the detection engine and the rest of the extension. Phase 2 replaces this file's internals. `tabTracker.ts` is the only importer — no other file may depend on `verdictStub.ts` directly.

**Phase 2 action:**
1. Implement the real detection pipeline inside `verdictStub.ts`, **or** rename it to `verdictEngine.ts` and update the single import in `tabTracker.ts`.
2. Set `isStub: false` in all real verdicts.
3. Confirm zero changes required in `popup/`, `options/`, or `content/`.

### Risk Score Thresholds (from `shared/constants.ts`)

| Range | Level |
|-------|-------|
| 0–29 | `safe` |
| 30–69 | `suspicious` |
| 70–100 | `dangerous` |

These thresholds are the single source of truth. Phase 3's confidence layer and Phase 4's UI both import from `constants.ts`.

---

## Permissions & Least Privilege

| Permission | Reason |
|-----------|--------|
| `activeTab` | Read the active tab's URL when popup opens |
| `storage` | Persist settings (`.local`) and tab verdicts (`.session`) |
| `scripting` | Fallback content script injection if declarative injection fails |
| `tabs` | Listen to `chrome.tabs.onActivated` / `onUpdated` for URL changes |
| `host: localhost:8000` | Phase 2 backend reputation service — narrowly scoped, not `<all_urls>` |

`<all_urls>` host permission is explicitly **not requested**. Phase 5 will add the production API URL to `host_permissions` when it exists, still narrowly scoped.

---

## Decisions & Assumptions

### D1: `chrome.storage.session` for tab records
**Decision:** Use `chrome.storage.session` (not `storage.local`) for per-tab `SiteRecord` data.
**Rationale:** Tab verdicts are session-ephemeral — they become stale on browser restart. `.session` automatically clears them without requiring explicit cleanup, while still surviving service worker restarts.

### D2: Tailwind CSS in the extension
**Decision:** Use Tailwind CSS as specified in the Global Context fixed tech stack.
**Rationale:** Consistent with the project constitution. Tailwind's utility classes work well in extension popups where the styling surface is contained and predictable.

### D3: Content script runs at `document_idle`
**Decision:** `run_at: "document_idle"` in manifest.json.
**Rationale:** Login form detection (`<input type="password">`) requires a fully parsed DOM. Running at `document_start` would miss dynamically rendered forms; `document_idle` is the correct semantic.

### D4: Popup does not re-implement detection
**Decision:** Popup requests the verdict from background via `GET_VERDICT` message, never computing it locally.
**Rationale:** Single source of truth for verdicts. If the popup were to re-run detection, it would be running different code (potentially) from the background worker, leading to inconsistency.

### D5: `sendMessage` graceful error handling
**Decision:** `messaging.ts`'s `sendMessage` catches "Receiving end does not exist" specifically and returns a non-throwing error response.
**Rationale:** MV3 service workers can be unloaded between popup opens. The popup must handle this gracefully (show a "not ready" state) rather than crashing.

### D6: Settings merged with defaults on read
**Decision:** `getSettings()` merges stored values with `DEFAULT_SETTINGS`.
**Rationale:** Allows Phase 2–6 to add new settings fields without a migration — new fields default automatically on first read after an extension update.

---

---

## Phase 3 — Intelligence Layer Architecture

### Overview
Phase 3 wraps and augments Phase 2's local heuristic+reputation pipeline with a genuine machine learning model (`XGBoost`) and a declarative rule engine (`phishing_rules.json`), combining both into a transparent, confidence-scored, fully explainable result.

```
URL input
   │
   ├── [Phase 2] normalizer → heuristics → reputationClient
   │                                                         │
   │      ┌──────────────────────────────────────────────────┤
   │      │ (parallel network calls)                         │
   │      ▼                                                  ▼
   │  intelligenceClient.ts          reputationClient.ts
   │  → POST /api/v1/predict         → GET /api/v1/reputation
   │    { mlScore, mlLabel,            { knownMalicious, ... }
   │      topContributingFeatures }
   │
   ▼
   confidence_scorer (client-side merge in intelligenceClient.ts)
   → { level: 'high'|'medium'|'low', agreement: boolean }
   │
   ▼
   Verdict (Phase 3 extended fields):
     ml: { score, label, modelVersion, topContributingFeatures }
     ruleEngineVersion: string
     confidence: { level, agreement, combinedScore }
     explanation: { summary, ruleReasons[], mlReasons[] }
```

### Confidence Formula (Documented & Frozen)

```
rule_fraction = rule_score / 100                  (0–1)
ml_fraction   = ml_score                          (0–1, 0.5 default if unavailable)
agreement     = |rule_fraction - ml_fraction| < 0.30

combined      = 0.5 * rule_fraction + 0.5 * ml_fraction
penalty       = 0.20 if not agreement else 0.0
combined      = max(0.0, combined - penalty)

level = 'high'   if combined >= 0.65 and agreement
      = 'medium' if 0.35 <= combined < 0.65
      = 'low'    otherwise (or always when ML is unavailable)
```

- **50/50 blend**: Equal weight keeps rule engine and ML model balanced.
- **Disagreement penalty (−0.20)**: Intentionally reduces combined score when signals conflict, so the verdict reflects uncertainty rather than silently picking one.
- **ML unavailable**: `ml_fraction` defaults to 0.5 (maximum uncertainty) and level is capped at `'low'`.

### ML Model Card Summary

- **Model Type**: XGBClassifier (GradientBoostingClassifier fallback)
- **Version**: `1.0.0`
- **Features**: 22 structural, entropy, and pattern features (`backend/ml/features.py`)
- **Dataset**: Stratified 80/20 train/test split on labeled phishing/benign URLs (`sample_dataset.csv`)
- **Validation Metrics**:
  - Accuracy: `98.2%`
  - Precision: `96.2%`
  - Recall: `100.0%`
  - F1 Score: `0.980`
  - ROC AUC: `0.997`
- **Explainability**: SHAP `TreeExplainer` for per-request feature contributions (<300ms budget), falling back to global feature importances if SHAP is slow.
- **Full Model Card**: `backend/ml/model_card.md`

---

## Phase Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | Core extension skeleton, stub verdict, settings, storage |
| **Phase 2** | ✅ Complete | Threat Detection Engine (heuristics, reputation, real scoring) |
| **Phase 3** | ✅ Complete | Intelligence Layer (ML model, rule engine, confidence scoring) |
| Phase 4 | ⬜ Pending | User Experience (warning interstitials, history, dashboard) |
| Phase 5 | ⬜ Pending | Cloud Backend (accounts, PostgreSQL, crowdsourced threat intel) |
| Phase 6 | ⬜ Pending | Enterprise Features (org policies, admin dashboard, team analytics) |

