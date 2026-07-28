# Changelog

All notable changes to SafeClick are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — Phase 2: Threat Detection Engine

### Added

**Detection Pipeline**
- `extension/shared/urlNormalizer.ts` — pure URL normalization: IDN/punycode detection (preserved as phishing evidence), tracking param stripping, suspicious encoding detection, registered domain extraction
- `extension/shared/topDomains.json` — bundled 500+ top global domains for zero-latency "trusted" short-circuits and typosquatting baseline

**Heuristic Modules (all pure, independently testable)**
- `extension/background/heuristics/lengthAndEntropy.ts` — Shannon entropy on subdomains/paths, URL length threshold
- `extension/background/heuristics/suspiciousKeywords.ts` — brand-impersonation keyword detection in subdomain/path (30+ brands)
- `extension/background/heuristics/urlStructure.ts` — raw IP detection, @ obfuscation, subdomain depth, brand hyphen mimicry
- `extension/background/heuristics/loginFormSignal.ts` — high-weight flag for login form on non-trusted domain

**Phishing Detector**
- `extension/background/phishingDetector.ts` — typosquatting (Damerau-Levenshtein ≤2), IDN homograph confusable-char detection, suspicious TLD + brand keyword combo

**Risk Scorer**
- `extension/background/riskScorer.ts` — transparent weighted sum, 0–100 clipped, reasons ordered by contribution descending, all rule triggers exposed for auditability

**Verdict Engine (replaces stub)**
- `extension/background/verdictEngine.ts` — full pipeline: normalizer → heuristics → reputation client → phishing detector → risk scorer → Verdict. `isStub: false` on all real verdicts.
- `extension/background/tabTracker.ts` — one import line changed (`verdictStub` → `verdictEngine`). Zero other changes to `popup/`, `options/`, `content/` (Phase 1 contract validated ✓)
- `extension/background/reputationClient.ts` — top-domain short-circuit, 800ms timeout, graceful degradation to "unavailable" on backend downtime

**FastAPI Backend (minimal, Phase 2)**
- `backend/main.py` — FastAPI app with startup OpenPhish feed loading
- `backend/api/reputation.py` — `GET /api/v1/reputation?domain=X`
- `backend/services/reputation_service.py` — VirusTotal free tier (500/day, rate-limited at 4/min) + OpenPhish community feed + in-process TTL cache (6h) + optional Redis

**Phase 2 constants (added to `shared/constants.ts`)**
- `HEURISTIC_WEIGHTS` — documented per-heuristic score contributions
- `URL_ANALYSIS` — length/entropy/subdomain thresholds + Levenshtein distance
- `SUSPICIOUS_TLDS` — 20+ cheap/free TLDs abused by phishers
- `KNOWN_BRAND_DOMAINS` — 30+ brand domains for typosquatting baseline
- `SUSPICIOUS_BRAND_KEYWORDS` — expanded to 40+ brands (merged Phase 1 stub list)

**Types (additive to Phase 1 contract)**
- `NormalizedUrl`, `HeuristicResult`, `ReputationResult`, `PhishingPattern` added to `shared/types.ts`
- `Verdict` extended with optional `heuristics?`, `reputation?`, `phishingPatterns?`

**Testing**
- Vitest: `urlNormalizer.test.ts` (25 tests), `heuristics.test.ts` (30 tests), `riskScorer.test.ts` (13 tests)
- All tests pass: **114/114** (Phase 1: 46 + Phase 2: 68)
- Pytest: `backend/tests/test_reputation.py` (13 tests — OpenPhish parsing, VT mocking, API contract, cache, error cases)
- E2E fixture: `tests/fixtures/phishing-lookalike.html` + Phase 2 Playwright test added

**Documentation**
- `docs/architecture.md` — Phase 2 pipeline diagram, VT+OpenPhish decision note
- `docs/api-contracts.md` — `/api/v1/reputation` contract, Phase 2 interfaces
- `backend/.env.example` — VT API key, OpenPhish URL, Redis, TTL configuration

### Changed
- `extension/shared/constants.ts` — `EXTENSION_VERSION` bumped to `0.2.0`
- `extension/shared/constants.ts` — `SUSPICIOUS_BRAND_KEYWORDS` expanded from 9 to 40+ entries

### Phase 1 Contract Verification ✓
- `popup/`, `options/`, `content/` — **zero files changed**
- `tabTracker.ts` — **one import line only** (`verdictStub` → `verdictEngine`)
- `Verdict` interface — **additive only** (all Phase 1 fields preserved)

---

## [0.1.0] — Phase 1: Core Extension Skeleton

### Added

**Extension skeleton (Manifest V3)**
- `extension/manifest.json` — MV3 manifest with minimal permissions: `activeTab`, `storage`, `scripting`, `tabs`. No `<all_urls>` host permission. Inline comments document each permission's rationale.
- Service worker (`background/service-worker.ts`) — thin orchestrator wiring tab tracker, storage, and message routing.
- Tab tracker (`background/tabTracker.ts`) — listens to `chrome.tabs.onActivated` / `onUpdated`, maintains in-memory + `chrome.storage.session` tab state, broadcasts verdict updates to popup.
- Verdict stub (`background/verdictStub.ts`) — deterministic, clearly-labeled Phase 1 placeholder. Exports `getVerdict(url: string): Promise<Verdict>` — the frozen seam Phase 2 replaces without touching any other file.
- Content script (`content/contentScript.ts`) — read-only signal extraction: detects login forms (`<input type="password">`), captures charset and page title. No blocking behavior.

**Popup UI (React + TypeScript + Tailwind CSS)**
- `popup/Popup.tsx` — state machine: loading / verdict / error / not_applicable. Requests verdict from background via messaging.ts.
- `popup/components/VerdictBadge.tsx` — colored badge (green/amber/red) with animated pulse dot, score, and Phase 3 reasons placeholder.
- `popup/components/SiteInfoCard.tsx` — domain, HTTPS indicator, check timestamp.
- `popup/components/QuickActions.tsx` — Report site, Always trust domain, View settings buttons with optimistic UI feedback.

**Options page (React + Tailwind)**
- `options/Options.tsx` — full settings page: enable toggle, notification preference, allowlist/denylist domain editors, cursor indicator toggle, history logging toggle, and Phase 5 cloud sync placeholder (greyed out, disabled).

**Shared layer (frozen contracts)**
- `shared/types.ts` — core interfaces: `Verdict`, `VerdictLevel`, `RuleTrigger`, `Settings`, `SiteRecord`, `PageSignals`, all message types. **Frozen — Phase 2–6 extend additively only.**
- `shared/constants.ts` — risk thresholds (0–29 Safe, 30–69 Suspicious, 70–100 Dangerous), tracking param list, brand keywords, storage keys, defaults. Single source of truth.
- `shared/storage.ts` — typed `chrome.storage.local` wrapper with `get/set/reset`, allowlist/denylist helpers, `subscribeToSettings()`.
- `shared/messaging.ts` — typed `chrome.runtime.sendMessage / onMessage` wrapper with graceful "Receiving end does not exist" handling.

**Build tooling**
- Multi-entry Vite build: popup, options (HTML entries), background (ES module), content script. Outputs to `extension/dist/`.
- TypeScript 5 strict mode, tsconfig with path aliases.
- Tailwind CSS 3 + PostCSS + autoprefixer.
- `generate-icons.mjs` — generates placeholder SVG shield icons at 16/32/48/128px.

**Testing**
- Vitest unit tests: `storage.test.ts`, `messaging.test.ts`, `verdictStub.test.ts` (Chrome API mocked via `vitest.setup.ts`).
- Playwright E2E test (`tests/e2e/phase1.spec.ts`): loads unpacked extension into Chromium, opens popup, asserts Safe badge, Not Applicable state, options page, allowlist persistence.
- Local fixture server for E2E (`tests/fixtures/test-page.html`).

**Documentation**
- `docs/architecture.md` — system overview, component table, message flow diagram, storage schema, verdict contract, permissions rationale, 6 documented design decisions.
- `docs/api-contracts.md` — all `shared/types.ts` interfaces, message contracts, risk thresholds, Phase 2 planned additions.
- `extension/README.md` — step-by-step "Load unpacked extension in Chrome" instructions.

### Architecture decisions recorded
- D1: `chrome.storage.session` for ephemeral tab records (survives worker restart, cleared on browser close).
- D2: Tailwind CSS per fixed tech stack.
- D3: Content script at `document_idle` (DOM must be fully parsed for form detection).
- D4: Popup is presentation-only — verdict computation exclusively in background.
- D5: `sendMessage` catches "Receiving end does not exist" gracefully.
- D6: Settings merged with defaults on every read (forward-compatible with new fields from later phases).

### Out of scope (Phase 2)
- Real threat detection (URL normalization, heuristics, reputation lookup, risk scoring).
- Backend FastAPI service.
- Any ML inference.

---

*Next: [0.2.0] — Phase 2: Threat Detection Engine*
