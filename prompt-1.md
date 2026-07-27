# SafeClick — Extended Antigravity Master Build Prompt

**Project:** SafeClick — Real-Time, Explainable Browser Threat Detection Platform
**Author context:** Rebuild of the original BITS Goa TechXcelerate hackathon project ("Safe Click"), now scoped as a full company-grade product across 6 phases.
**Purpose of this document:** A single reference file containing (1) the global project constitution that must be pasted/attached at the start of every Antigravity session, and (2) one extended, standalone prompt per phase. Each phase prompt is self-contained — copy the "GLOBAL CONTEXT" block once per new Antigravity session, then paste the relevant phase prompt.

---

## 0. GLOBAL CONTEXT (paste this at the start of every Antigravity session, every phase)

```
PROJECT: SafeClick — a browser security platform for real-time, explainable phishing
and malicious-URL detection.

MISSION: Make browsing safer through real-time, explainable threat detection.
TARGET USERS: Individuals, students, small businesses, and organizations.
CORE VALUE: Fast, transparent, privacy-conscious security warnings — the user should
always be able to see WHY a site was flagged, never a black-box verdict.
LONG-TERM VISION: This is not "another URL checker." It is the foundation of a browser
security platform — every phase must be built so later phases (ML intelligence, cloud
sync, enterprise policy) can be bolted on without rewriting earlier code.

HARD ARCHITECTURAL CONSTRAINTS (apply to every phase, no exceptions):
1. Manifest V3 only. No Manifest V2 APIs, no deprecated background pages (service
   worker only, no persistent background page).
2. Strict modularity. The repository root layout is fixed as:

   safeclick/
   ├── extension/
   │   ├── popup/
   │   ├── content/
   │   ├── background/
   │   ├── options/
   │   └── shared/
   ├── backend/
   │   ├── api/
   │   ├── services/
   │   ├── models/
   │   ├── database/
   │   └── ml/
   ├── dashboard/
   ├── docs/
   └── tests/

   Never place logic outside its designated folder. Never let the extension talk
   directly to the database — all backend access goes through backend/api.
   Every module must be independently testable and independently replaceable
   (e.g., swapping the ML model in backend/ml must not require touching
   backend/api or extension/background).
3. Tech stack (fixed, do not substitute unless explicitly told otherwise):
   - Extension: Manifest V3, React + TypeScript, Tailwind CSS, Vite as the build tool
   - Backend: FastAPI (Python 3.11+)
   - Database: PostgreSQL (via SQLAlchemy + Alembic migrations)
   - Cache: Redis (design the code so Redis is optional/pluggable — do not hard-fail
     if Redis is unavailable in early phases)
   - ML: scikit-learn / XGBoost initially; design the prediction interface so a
     future model swap (e.g., to a neural net) requires no API contract changes
   - Deployment: Docker + docker-compose for local/dev; document (do not yet build)
     a path to VPS/cloud deployment
   - Testing: Vitest for extension/frontend unit tests, Playwright for E2E extension
     testing, Pytest for backend
4. Budget constraint: every external service/API used must have a genuine free tier
   with no credit card requirement. Do not introduce paid-only dependencies. If a
   free-tier service has rate limits, build in graceful degradation (cache, backoff,
   local fallback heuristics) rather than assuming unlimited calls.
5. Explainability constraint: every single verdict the extension shows to a user
   (safe / suspicious / dangerous) must be accompanied by a structured reason object
   (not just a score) — e.g. { verdict, score, reasons: [...], ruleTriggers: [...] }.
   Never surface a bare number with no explanation, at any phase.
6. Privacy constraint: do not transmit full browsing history to any backend without
   explicit user opt-in. Local-first by default; cloud sync (Phase 5) is opt-in only.
7. Documentation constraint: every phase must produce/update:
   - docs/architecture.md (what was built, why, and how it connects to other modules)
   - docs/api-contracts.md (any new API endpoints, request/response schemas)
   - A CHANGELOG.md entry
8. Testing constraint: no phase is "done" without passing unit tests for new logic
   and at least one E2E test proving the feature works end-to-end in a real Chromium
   instance loaded via Playwright.

Build phases (for your awareness — only execute the phase specified in the prompt
that follows this context block):
Phase 1 – Core Browser Extension
Phase 2 – Threat Detection Engine
Phase 3 – Intelligence Layer (ML + rules + confidence + explainability)
Phase 4 – User Experience (warning pages, history, dashboard, stats)
Phase 5 – Cloud Backend (DB, API, accounts, shared threat intel, analytics)
Phase 6 – Enterprise Features (admin dashboard, org policies, team analytics, reports)

Do not skip ahead to a later phase's features. Do not silently simplify the fixed
tech stack. If a requirement is ambiguous, make the most defensible engineering
decision, document it in docs/architecture.md under a "Decisions & Assumptions"
section, and proceed — do not stall waiting for clarification.
```

---

## PHASE 1 — Core Browser Extension

### Goal of this phase
Ship a working, installable Manifest V3 Chrome/Edge extension that can detect the URL of the active tab, show a popup UI reflecting a (currently stubbed) safety verdict, persist basic settings locally, and run a background service worker that will later host the real detection engine. This phase produces zero real threat intelligence — it produces the *skeleton* every later phase plugs into.

### Extended Antigravity Prompt

```
Build Phase 1 of SafeClick: the Core Browser Extension skeleton.

CONTEXT: This is the foundation extension shell. No real threat detection exists
yet — Phase 2 will add that. Your job is to build a clean, modular, fully working
Manifest V3 extension whose popup, background worker, options page, and storage
layer are wired together correctly, using a STUBBED verdict function that later
phases will replace without touching this phase's code.

Work inside extension/ following this exact structure:

extension/
├── manifest.json
├── popup/
│   ├── Popup.tsx
│   ├── popup.html
│   ├── popup.css (Tailwind)
│   └── components/
│       ├── VerdictBadge.tsx
│       ├── SiteInfoCard.tsx
│       └── QuickActions.tsx
├── background/
│   ├── service-worker.ts
│   ├── tabTracker.ts
│   └── verdictStub.ts
├── content/
│   └── contentScript.ts   (minimal — just reports current URL + basic page signals
│                            like presence of login forms, for future use; no
│                            blocking behavior yet)
├── options/
│   ├── Options.tsx
│   ├── options.html
│   └── options.css
└── shared/
    ├── types.ts            (shared TypeScript interfaces: Verdict, Settings,
    │                         SiteRecord, etc. — this is the CONTRACT other
    │                         phases will extend, so design it carefully)
    ├── storage.ts           (wrapper around chrome.storage.local, typed)
    ├── messaging.ts         (typed wrapper around chrome.runtime.sendMessage /
    │                         onMessage, so all message passing between popup,
    │                         background, and content script is type-safe)
    └── constants.ts

REQUIREMENTS:

1. manifest.json
   - Manifest V3, minimum required permissions only: "activeTab", "storage",
     "scripting", "tabs". Do NOT request "<all_urls>" host permissions yet —
     scope host_permissions narrowly and document in a comment why each
     permission is needed (a security-focused extension must model least
     privilege from day one).
   - Register the service worker (type: "module"), the popup, the options page,
     and a content script matching all http/https pages.
   - Set a proper name, description, version (0.1.0), and icons (generate simple
     placeholder SVG-based PNG icons at 16/32/48/128px if none exist).

2. URL detection (background/tabTracker.ts)
   - Listen to chrome.tabs.onActivated and chrome.tabs.onUpdated (status ===
     'complete') to detect the current active tab's URL.
   - Maintain an in-memory map of tabId -> { url, lastChecked, verdict } inside
     the service worker, understanding that Manifest V3 service workers are
     non-persistent and can be terminated — so also persist the last-known
     verdict per tab to chrome.storage.session (NOT storage.local, since this
     is per-browser-session ephemeral data) so state survives worker restarts.
   - On every new URL, call the stub verdict function (see #4) and broadcast
     the result via the messaging wrapper to any open popup.

3. Popup UI (popup/Popup.tsx)
   - Built with React + TypeScript + Tailwind CSS, bundled via Vite in a
     multi-entry-point config (popup, options, background, content as separate
     Vite build entries — set this up in vite.config.ts under extension/).
   - On open, request the current tab's verdict from the background worker via
     messaging.ts (do not re-implement detection logic in the popup — popup is
     presentation only).
   - VerdictBadge.tsx: a colored badge (green/yellow/red) + label
     (Safe/Suspicious/Dangerous) + the numeric score, laid out to leave room for
     the "reasons" list that Phase 3 will populate (render an empty/placeholder
     "No detailed analysis yet — Phase 2/3 pending" state now so the UI contract
     is already correct).
   - SiteInfoCard.tsx: shows the current domain, whether HTTPS is used, and
     page load timestamp.
   - QuickActions.tsx: buttons for "Report this site," "Always trust this
     domain," "View settings" — wire "View settings" to open options.html;
     "Report" and "Always trust" should write to shared storage and log to
     console for now (their real backend wiring comes in Phase 5).
   - Popup must handle and gracefully display three states: loading, verdict
     available, and error (e.g., cannot access chrome:// or extension:// pages
     — detect these URL schemes and show a neutral "Not applicable" state rather
     than erroring).

4. verdictStub.ts (background/verdictStub.ts)
   - Export a single async function getVerdict(url: string): Promise<Verdict>
     matching the Verdict interface defined in shared/types.ts.
   - For now, implement a deterministic, clearly-labeled placeholder: return
     "safe" for any URL, with reasons: ["Phase 1 stub — real detection engine
     not yet implemented"]. This function signature is the exact seam Phase 2
     will replace — do not let any other file depend on its internal logic,
     only on its type signature.

5. Settings & local storage (options/Options.tsx, shared/storage.ts)
   - Settings schema (define in shared/types.ts): enable/disable extension,
     notification preferences (toast on dangerous site vs. silent badge only),
     a user-maintained allowlist/denylist of domains, and a placeholder toggle
     for "Share anonymized threat data" (default OFF, disabled/greyed out with
     a tooltip "Available in a future update" since cloud sync doesn't exist
     until Phase 5 — do not implement functionality behind this toggle yet).
   - storage.ts must expose typed get/set/subscribe helpers wrapping
     chrome.storage.local, with sensible defaults if no settings exist yet
     (first-run initialization).
   - Options page must let the user view and edit the allowlist/denylist,
     persisted via storage.ts.

6. Content script (content/contentScript.ts)
   - Keep minimal for this phase: on page load, detect (a) whether the page
     contains a <form> with an <input type="password"> (a login-form signal for
     future phishing heuristics) and (b) the page's declared charset/title.
   - Send this as a structured message to the background worker via
     messaging.ts and store it against the current tab's record. Do not act on
     it yet (no warnings, no blocking) — Phase 2/4 will consume this signal.

7. Build tooling
   - Set up package.json, tsconfig.json, tailwind.config.js, and vite.config.ts
     for the extension workspace, with a build script that outputs a loadable
     unpacked extension to extension/dist/.
   - Add a README.md inside extension/ with exact "load unpacked extension in
     Chrome" instructions for local development on the author's hardware
     (Windows, RTX 5060 / Intel Core Ultra 7 255HX — no GPU dependency needed
     for this phase, purely CPU/Node build).

8. Testing
   - Vitest unit tests for storage.ts (get/set/defaults), messaging.ts
     (message shape validation), and verdictStub.ts.
   - One Playwright E2E test that: loads the unpacked extension into a
     Chromium instance, navigates to a test page, opens the popup, and asserts
     the VerdictBadge renders the stubbed "Safe" state.

9. Documentation
   - Write docs/architecture.md describing the extension's internal message
     flow (content script -> background -> popup), the storage schema, and
     explicitly flag verdictStub.ts as "replace in Phase 2, do not remove the
     function signature."
   - Write docs/api-contracts.md documenting the shared/types.ts interfaces
     (Verdict, Settings, SiteRecord, Message types) since these are the
     contracts every later phase depends on.
   - Add a CHANGELOG.md with a "0.1.0 — Phase 1: Core Extension Skeleton" entry.

DELIVERABLE: A fully buildable, loadable, working extension where opening any
http/https tab shows a popup with a (stubbed) green "Safe" verdict, settings
persist across browser restarts, and all tests pass. Do not implement any real
threat detection logic in this phase — that is explicitly out of scope and
belongs to Phase 2.
```

---

## PHASE 2 — Threat Detection Engine

### Goal of this phase
Replace `verdictStub.ts` with a real, local, explainable detection engine: URL normalization, heuristic analysis, domain reputation checks (via free-tier APIs, cached), phishing pattern detection, and a combined risk score — all still running client-side/local wherever possible, with the backend introduced only as an optional reputation lookup service.

### Extended Antigravity Prompt

```
Build Phase 2 of SafeClick: the Threat Detection Engine.

CONTEXT: Phase 1 built the extension skeleton with a stubbed verdict function
(background/verdictStub.ts) that always returns "safe." Your job now is to
build a real detection engine and swap it in behind the EXACT SAME
getVerdict(url: string): Promise<Verdict> signature, so extension/popup and
extension/background/tabTracker.ts require zero changes. Introduce a minimal
backend service ONLY for domain reputation lookups that cannot reasonably run
client-side (e.g., calling an external threat-intel API) — everything else
(normalization, heuristics, phishing pattern checks, scoring) must run locally
inside the extension for speed and privacy.

Work across extension/ (new detection modules) and backend/ (new reputation
service), following the fixed repo structure.

REQUIREMENTS:

1. URL normalization — extension/shared/urlNormalizer.ts
   - Implement a pure, thoroughly unit-tested normalization function that:
     lowercases scheme/host, strips default ports (80/443), resolves and
     strips tracking query params (utm_*, fbclid, gclid, etc. — maintain this
     list in shared/constants.ts), decodes percent-encoding safely, strips
     trailing slashes consistently, and detects/flags IDN homograph risks
     (punycode domains, mixed-script domains) as a SEPARATE structured signal
     (do not silently normalize away a homograph attempt — that itself is
     evidence of phishing intent and must be preserved in the output).
   - Output a NormalizedUrl object: { original, normalized, hostname, isIDN,
     isPunycode, hasSuspiciousEncoding, portIsNonStandard }.

2. Heuristic analysis — extension/background/heuristics/
   - Build heuristics as small, independently testable, independently scored
     modules in their own files (one file per heuristic family), each
     exporting a function of shape (normalizedUrl, pageSignals) => HeuristicResult
     where HeuristicResult = { name, triggered, weight, explanation }.
   - Implement at minimum these heuristic modules:
     a) lengthAndEntropy.ts — flags abnormally long URLs and high-entropy
        (randomized-looking) subdomains/paths.
     b) suspiciousKeywords.ts — flags brand-impersonation keyword patterns in
        subdomains/paths (e.g., "paypal-secure-login", "verify-account") using
        a maintained keyword+brand list in shared/constants.ts. Be careful to
        avoid false-positive-prone naive substring matching alone — combine
        with domain-age/reputation context from module (4) before a heuristic
        can push the verdict to "dangerous" on its own.
     c) urlStructure.ts — flags excessive subdomain depth, use of raw IP
        addresses instead of domains, "@"-based URL obfuscation, and
        suspicious use of hyphens mimicking known brand domains.
     d) loginFormSignal.ts — consumes the page signal already captured by
        Phase 1's content script (password input present) and combines it
        with domain trust level: a login form on an untrusted/newly-seen
        domain is weighted much higher than one on an allowlisted domain.
   - Each heuristic must be pure/testable in isolation with unit tests
     covering both a triggering and a non-triggering example URL.

3. Domain reputation checks
   - backend/services/reputation_service.py (FastAPI service, new minimal
     backend introduced this phase) wraps calls to at least one genuinely
     free-tier, no-credit-card threat intel API (e.g., Google Safe Browsing
     API free tier or virustotal api key for free api with includes a good database,
     or a comparable free/community blocklist source — verify
     current free-tier terms before hardcoding assumptions, and if in doubt
     prefer maintaining a locally-cached open-source phishing domain blocklist,
     e.g. a periodically-refreshed OpenPhish/PhishTank community feed, to avoid
     any paid dependency).
   - Cache reputation lookups in Redis if available, else an in-process TTL
     cache (respect the Phase 0 "Redis optional/pluggable" constraint) with a
     sensible TTL (e.g., 6–24h) to respect free-tier rate limits.
   - backend/api/reputation.py exposes GET /api/v1/reputation?domain=example.com
     returning { domain, knownMalicious: bool, source, lastChecked, confidence }.
     Document this contract in docs/api-contracts.md.
   - extension/background/reputationClient.ts calls this endpoint with a
     short timeout (e.g., 800ms) and MUST fail gracefully to a
     "reputation: unknown" state if the backend is unreachable — the
     extension must never hang or crash browsing due to backend downtime.
   - Maintain a local, bundled allowlist of top global domains (Tranco/Majestic
     top-N style list, a static JSON file in extension/shared/) so
     well-known, high-traffic domains short-circuit to "trusted" without a
     network call at all, saving both latency and API quota.

4. Phishing detection — extension/background/phishingDetector.ts
   - Combine normalization output, all heuristic results, page signals, and
     reputation data into a single phishingDetector.analyze() function.
   - Implement specific, named detection patterns beyond generic heuristics:
     typosquatting distance-check against the bundled top-domain list
     (Levenshtein/Damerau-Levenshtein distance <=2 against a known brand with
     a DIFFERENT registered domain owner is a strong signal), homograph/IDN
     confusable-character detection (leverage a confusables mapping table),
     and suspicious TLD combined with brand keyword (e.g., a free/very-cheap
     TLD plus a well-known brand name in the domain).

5. Risk scoring — extension/background/riskScorer.ts
   - Implement a transparent, weighted scoring function (NOT a black box):
     riskScore = weighted sum of triggered heuristics + reputation signal +
     phishing pattern matches, clipped to a documented 0–100 scale.
   - Define clear, documented thresholds in shared/constants.ts (e.g., 0–29
     Safe, 30–69 Suspicious, 70–100 Dangerous) — do not hardcode magic numbers
     inline; centralize them so Phase 3's confidence layer and Phase 4's UI
     can reference the same thresholds.
   - The scorer's output MUST populate the Verdict.reasons array with one
     human-readable explanation string per triggered signal, in descending
     order of contribution to the score — this is non-negotiable per the
     Phase 0 explainability constraint.

6. Wire it in
   - Replace the internals of background/verdictStub.ts (or rename it to
     verdictEngine.ts and update the single import site in tabTracker.ts —
     keep the function signature identical) so getVerdict(url) now calls
     normalizer -> heuristics -> reputation client -> phishing detector ->
     risk scorer, and returns a real Verdict.
   - Confirm zero changes are required in popup/, options/, or content/ as a
     result of this swap (this proves Phase 1's contract design was correct —
     if changes ARE required, document why in docs/architecture.md as a
     "Phase 1 contract gap" note).

7. Testing
   - Unit tests (Vitest) for urlNormalizer.ts, every heuristic module, and
     riskScorer.ts, each with both benign and malicious example URLs (use
     clearly fictional/example.com-style malicious lookalikes in test fixtures
     — do not embed real active phishing URLs in the test suite).
   - Pytest tests for reputation_service.py and the reputation API endpoint,
     mocking the external API call.
   - An updated Playwright E2E test: load a locally-hosted fixture "phishing-
     lookalike" test page (served from tests/fixtures/) and assert the popup
     now shows a Suspicious/Dangerous badge with at least one populated reason.

8. Documentation
   - Update docs/architecture.md with a diagram (ASCII or Mermaid) of the
     Phase 2 detection pipeline: URL -> normalize -> heuristics (parallel) ->
     reputation lookup -> phishing detector -> risk scorer -> Verdict.
   - Update docs/api-contracts.md with the new /api/v1/reputation contract.
   - Add "0.2.0 — Phase 2: Threat Detection Engine" to CHANGELOG.md.

DELIVERABLE: The extension now produces real, explainable verdicts for actual
URLs, backed by local heuristics plus an optional/gracefully-degrading backend
reputation check, all within free-tier API limits, with the full Phase 1 UI
and storage layer untouched.
```

---

## PHASE 3 — Intelligence Layer

### Goal of this phase
Add a genuine ML prediction path (trained on a labeled phishing/benign URL dataset), a formal rule engine (making the Phase 2 heuristics configurable/extensible rather than hardcoded), confidence scoring that reflects agreement/disagreement between the ML model and the rule engine, and a structured "explainable results" object that both feeds Phase 4's UI and is fully auditable.

### Extended Antigravity Prompt

```
Build Phase 3 of SafeClick: the Intelligence Layer.

CONTEXT: Phase 2 built a working local heuristic + reputation-based detection
engine producing a Verdict with a weighted risk score and text reasons. Phase 3
adds a real machine learning prediction path alongside a formalized rule
engine, and combines both into a confidence-scored, fully explainable result.
This phase must NOT remove or bypass Phase 2's heuristic/reputation pipeline —
it wraps and augments it. The final Verdict object gains new fields; existing
consumers (popup badge, etc.) must continue to work with the old fields
present and unchanged.

Work primarily in backend/ml/ and backend/services/, with a new
extension/background/intelligenceClient.ts to call it, following the fixed
repo structure.

REQUIREMENTS:

1. Dataset & training pipeline — backend/ml/data/, backend/ml/train.py
   - Source a legitimate, freely-licensed phishing-vs-benign URL dataset
     (e.g., a well-known public Kaggle/UCI phishing URL dataset, or PhishTank's
     public feed combined with a Tranco top-domain list for benign examples —
     verify current licensing/availability before hardcoding a specific
     source, and document the chosen dataset's license in docs/architecture.md).
   - backend/ml/features.py: implement a feature extraction function reusing
     as much of Phase 2's normalization/heuristic signal logic as possible
     (port the relevant pure logic to Python, or expose it as shared JSON-
     serializable feature definitions consumed by both TypeScript and Python
     to avoid feature-definition drift between the extension and the model).
   - Train an initial XGBoost (or scikit-learn GradientBoosting as a lighter
     fallback given local hardware constraints — RTX 5060/32GB DDR5 easily
     handles this, no GPU training required for a tabular model) classifier
     on the extracted features. Target CPU-only training completing in
     minutes, not hours, given the hardware.
   - Save the trained model (joblib/pickle) plus a versioned model card
     (backend/ml/model_card.md) documenting training data size, features used,
     validation accuracy/precision/recall/F1, and known limitations/biases
     (e.g., "may underperform on non-English brand names" if true of the
     chosen dataset).
   - Include a reproducible train/test split and a held-out evaluation report
     saved as backend/ml/eval_report.json.

2. Prediction service — backend/services/ml_service.py, backend/api/predict.py
   - Load the trained model once at service startup (not per-request).
   - Expose POST /api/v1/predict accepting a URL (or pre-extracted feature
     vector) and returning { mlScore: 0-1, mlLabel, modelVersion,
     topContributingFeatures: [...] } — use a model-agnostic explainability
     method (e.g., SHAP values, or feature importance if SHAP is too heavy for
     the free-tier hosting target) to populate topContributingFeatures so the
     ML path is explainable too, not a black box.
   - This endpoint must respond within a documented latency budget (e.g.,
     <300ms) since it sits in the interactive verdict path; if SHAP
     computation is too slow for real-time use, precompute/cache global
     feature importances and only do fast per-request inference, falling back
     to global importances for the "explanation" rather than doing expensive
     per-request SHAP.

3. Rule engine — backend/services/rule_engine.py (and a thin extension-side
   mirror if any rules must run fully offline/client-side)
   - Formalize Phase 2's heuristics into a declarative rule format (e.g., a
     JSON/YAML rule definition: { id, description, condition, weight,
     category }) rather than hardcoded TypeScript functions, so rules can be
     added/updated (Phase 6 will expose this to org admins) WITHOUT a code
     deploy.
   - Build a small, safe rule-condition evaluator (do NOT use raw eval() /
     exec() on user-supplied strings — implement a constrained expression
     evaluator or a structured condition schema, since this must be safe even
     if Phase 6 later lets org admins define custom rules).
   - Migrate Phase 2's existing heuristics into this new rule format as the
     default rule set, proving backward compatibility: re-run Phase 2's
     heuristic test fixtures through the new rule engine and confirm
     equivalent trigger behavior.

4. Confidence scoring — backend/services/confidence_scorer.py
   - Combine the rule engine's weighted score (from Phase 2) and the ML
     model's probability (from #2) into a single confidence-scored verdict:
     - If rule engine and ML strongly agree (both high or both low) ->
       high confidence.
     - If they disagree significantly -> lower confidence, and surface BOTH
       signals transparently to the user rather than silently picking one
       (this is critical to the explainability mission — never hide a
       disagreement between detection methods).
   - Define and document the combination formula precisely in
     docs/architecture.md (e.g., a documented weighted average with a
     disagreement penalty, or a simple max-of-concern approach) — the exact
     formula must be written down, not left implicit in code.

5. Explainable results — extend shared/types.ts's Verdict interface (additive
   only, do not break existing fields) with:
   {
     ...existing Phase 2 fields,
     ml: { score, label, modelVersion, topContributingFeatures },
     ruleEngineVersion,
     confidence: { level: 'high'|'medium'|'low', agreement: boolean },
     explanation: {
       summary: string,          // one-sentence plain-English summary
       ruleReasons: string[],    // from Phase 2/3 rule engine
       mlReasons: string[],      // from ML topContributingFeatures, phrased
                                  // in plain English, not raw feature names
     }
   }
   - extension/background/intelligenceClient.ts calls /api/v1/predict
     alongside the existing reputation call (parallelize both network calls),
     merges results via confidence_scorer logic (call a corresponding
     /api/v1/confidence endpoint, or replicate the lightweight merge logic
     client-side if latency matters more than a network round trip — decide
     and document which, in docs/architecture.md).
   - As with Phase 2's reputation client, if the ML backend is unreachable,
     gracefully degrade to rule-engine-only verdicts with confidence marked
     "low — ML unavailable," never crash or hang.

6. Testing
   - Pytest tests for features.py (feature extraction correctness),
     ml_service.py (prediction endpoint contract + latency budget check),
     rule_engine.py (condition evaluator safety — explicitly test that
     malicious rule strings cannot execute arbitrary code), and
     confidence_scorer.py (agreement/disagreement scenarios).
   - Vitest tests for intelligenceClient.ts merge/fallback logic.
   - Update the Playwright E2E test to assert the popup (once Phase 4 wires
     the UI — for this phase, assert via a direct message to background/console
     output or a temporary debug panel if Phase 4 UI isn't ready yet) reflects
     a confidence level and both rule + ML reasons for a known test fixture.

7. Documentation
   - docs/architecture.md: full Phase 3 pipeline diagram, the confidence
     formula, and the model_card.md summary linked in.
   - docs/api-contracts.md: /api/v1/predict and any confidence endpoint
     contracts.
   - CHANGELOG.md: "0.3.0 — Phase 3: Intelligence Layer."

DELIVERABLE: Verdicts are now produced by a genuine ML model plus a formalized,
data-driven rule engine, combined into a transparent, confidence-scored,
fully explainable result — with graceful degradation if the intelligence
backend is unavailable, and zero breakage of Phase 1/2 functionality.
```

---

## PHASE 4 — User Experience

### Goal of this phase
Turn the now-accurate, explainable verdicts into a genuinely good user experience: subtle visual cues (cursor color changes) reflecting live risk, full-page warning interstitials for dangerous sites, a local safe-browsing history log, and a dashboard with statistics — all still local-first, no backend account required yet.

### Extended Antigravity Prompt

```
Build Phase 4 of SafeClick: User Experience.

CONTEXT: By now the extension produces accurate, confidence-scored, fully
explainable verdicts (Phase 3). This phase is entirely about surfacing that
intelligence to the user in a genuinely useful, non-intrusive, trustworthy way.
No new detection logic should be added here — this phase consumes the Verdict
object as-is and focuses purely on presentation, history, and local analytics.

Work in extension/content/, extension/popup/, and a new extension/dashboard/
(or extend dashboard/ at the repo root if it's meant to be a full standalone
web app rather than an extension page — default to an extension-hosted full
page for now unless told otherwise, since Phase 5's cloud dashboard will be
the eventual standalone version).

REQUIREMENTS:

1. Cursor color changes — extension/content/cursorIndicator.ts
   - Implement a subtle, non-intrusive visual signal: inject a CSS custom
     cursor (or a small fixed-position corner indicator dot if a full custom
     cursor proves too invasive/laggy on some pages — evaluate both and pick
     the one that performs better, documenting the choice) that shifts color
     based on the live verdict: green (safe), amber (suspicious), red
     (dangerous).
   - This must be strictly opt-in via the Phase 1 settings schema (add a new
     setting: cursorIndicatorEnabled, default true but easily toggleable,
     since some users will find any custom cursor behavior undesirable) and
     must never break normal cursor functionality (text-select cursor over
     text, pointer cursor over links, etc. — the color indicator should
     layer on top of, not replace, native cursor semantics).
   - Ensure zero perceptible input lag: benchmark and document the
     performance impact in docs/architecture.md; if a custom cursor causes
     any measurable jank, fall back to the corner-indicator-dot approach by
     default.

2. Warning pages — extension/background/warningInterstitial.ts +
   extension/warning/WarningPage.tsx
   - For verdicts crossing the "Dangerous" threshold (from Phase 2/3's
     documented thresholds), intercept navigation (using
     chrome.webNavigation or a declarativeNetRequest redirect rule, whichever
     is appropriate under Manifest V3's constraints — declarativeNetRequest
     is generally preferred for MV3 blocking behavior since webRequest
     blocking is restricted; investigate and use whichever actually works
     under MV3 for redirecting to a local warning page) and redirect to a
     full-page, clearly-designed warning interstitial before the real page
     loads.
   - The warning page must display: the plain-English explanation.summary
     from the Verdict, the top 2–3 specific reasons (from ruleReasons/
     mlReasons), the confidence level, and three clear actions: "Go back to
     safety" (default/primary button), "Proceed anyway" (secondary, smaller,
     requires an explicit confirmation click — do not make this the easy
     path), and "Report a mistake" (logs a local false-positive report for
     now; wired to a real backend in Phase 5).
   - "Suspicious" (but not "Dangerous") verdicts must NOT trigger a full-page
     interstitial — only the cursor indicator plus popup badge, to avoid
     alert fatigue; document this threshold-to-UX mapping explicitly in
     docs/architecture.md.

3. Safe browsing history — extension/shared/historyStore.ts,
   extension/dashboard/HistoryView.tsx
   - Persist a local, size-capped (e.g., last 500 entries, oldest evicted
     first) log of { url (normalized, no query-string PII beyond what's
     needed), verdict summary, timestamp } to chrome.storage.local, entirely
     separate from the browser's native history (this is SafeClick's own
     security-relevant log, e.g., useful for "sites I was warned about this
     week").
   - Respect user privacy: provide a one-click "Clear history" action in
     settings, and make logging itself toggleable (default on, since it's the
     core value prop, but must be a clearly visible, respected toggle).
   - HistoryView.tsx renders this as a filterable, sortable table (filter by
     verdict level, search by domain).

4. Dashboard & statistics — extension/dashboard/Dashboard.tsx
   - Build a full extension page (chrome-extension://.../dashboard.html,
     linked from both the popup and options page) showing:
     a) A summary stat row: sites checked today/this week/all-time, dangerous
        sites blocked, suspicious sites flagged.
     b) A simple time-series chart (use a lightweight charting approach
        consistent with the existing React+Tailwind stack — e.g., Recharts)
        of verdict counts over the last 30 days.
     c) A "Top flagged domains" list.
     d) The HistoryView table from #3.
   - All statistics computed client-side from historyStore.ts data — no
     backend dependency yet (Phase 5 adds cloud analytics on top of, not
     instead of, this local view).

5. Testing
   - Vitest tests for historyStore.ts (capping/eviction logic, clear
     function), and the stat-aggregation functions feeding the dashboard.
   - Playwright E2E tests: (a) navigating to a fixture "dangerous" test page
     triggers the warning interstitial and "Go back to safety" correctly
     navigates away; (b) "Proceed anyway" requires the confirmation
     interaction and then allows navigation; (c) the dashboard renders
     correct counts after a sequence of simulated verdicts.
   - A manual performance check note in docs/architecture.md for the cursor
     indicator's measured input-lag impact.

6. Documentation
   - docs/architecture.md: verdict-to-UX threshold mapping, warning
     interstitial navigation-interception mechanism (webNavigation vs
     declarativeNetRequest decision and why), and history/dashboard data flow.
   - CHANGELOG.md: "0.4.0 — Phase 4: User Experience."

DELIVERABLE: A polished, trustworthy end-user experience — ambient cursor
cues, a genuinely protective (not just informative) warning interstitial for
dangerous sites, a respectful local history log, and a real dashboard with
statistics — entirely local-first with no account or cloud dependency
required to get full value from the extension.
```

---

## PHASE 5 — Cloud Backend

### Goal of this phase
Introduce accounts, a real persistent database, a full API surface, and shared/crowdsourced threat intelligence — turning SafeClick from a single-device tool into a platform, while preserving every local-first feature already built (nothing in Phases 1–4 should require an account to keep working).

### Extended Antigravity Prompt

```
Build Phase 5 of SafeClick: Cloud Backend.

CONTEXT: Phases 1–4 built a fully-functional local-first extension. This phase
adds an OPT-IN cloud layer: user accounts, persistent PostgreSQL storage,
a complete versioned API, and shared/crowdsourced threat intelligence so one
user's confirmed phishing report can protect others. Critically: every
existing Phase 1–4 feature must continue to work fully for users who never
create an account. Cloud sync, shared threat intel, and cross-device history
are additive premium-feeling features, not requirements.

Work in backend/ (expanding it into a real production-shaped service) and
extension/shared/authClient.ts + extension/options/AccountSection.tsx.

REQUIREMENTS:

1. Database — backend/database/, backend/models/
   - Design a PostgreSQL schema (SQLAlchemy models + Alembic migrations) with
     at least: users, devices, reported_sites (crowdsourced reports: url,
     reporter_user_id nullable for anonymous, report_type [phishing/false-
     positive/malware], status [pending/confirmed/rejected], created_at),
     shared_threat_intel (aggregated/confirmed malicious domains derived from
     reported_sites once a confirmation threshold is met), and
     analytics_events (anonymized, aggregate-only event logs — no full URL
     browsing history stored server-side unless a user has explicitly opted
     into "Sync my history," which must be a distinctly separate, clearly-
     labeled, off-by-default setting from basic account creation).
   - Write a data-retention note in docs/architecture.md: how long
     reported_sites/analytics_events are retained, and the exact conditions
     under which a report contributes to shared_threat_intel (e.g., N
     independent user reports plus one automated corroboration signal from
     Phase 2/3's own detection engine, to avoid trivial report-flooding
     attacks from being able to blacklist arbitrary innocent domains).

2. API — backend/api/
   - Version the API under /api/v1/ (already used in earlier phases — audit
     and confirm consistency).
   - Auth endpoints: POST /api/v1/auth/register, /login, /refresh, /logout,
     using secure password hashing (bcrypt/argon2) and short-lived JWT access
     tokens + longer-lived refresh tokens (httpOnly-cookie-style pattern
     adapted for an extension client — document exactly how tokens are stored
     extension-side, since chrome.storage.local is the only real option; note
     this in docs/architecture.md as a documented tradeoff, not silently).
   - CRUD-appropriate endpoints for reported_sites (submit report, list own
     reports), and a read endpoint for shared_threat_intel
     (GET /api/v1/threat-intel/lookup?domain=...) that the extension's
     Phase 2 reputation client can now ALSO check (in addition to its
     existing external reputation source), merging both signals.
   - Rate-limit all public endpoints (especially report submission, to
     prevent abuse) — implement basic rate limiting (e.g., slowapi or a
     Redis-backed token bucket if Redis is available, else an in-memory
     fallback per the earlier "Redis optional" constraint).
   - Full OpenAPI schema auto-generated by FastAPI; export it into
     docs/api-contracts.md (or link to the live /docs endpoint and summarize
     key contracts in the doc).

3. User accounts — extension-side wiring
   - extension/shared/authClient.ts: register/login/logout/token-refresh
     calls, secure token storage, and an auth-state subscription other
     extension modules can react to.
   - extension/options/AccountSection.tsx: a clearly optional "Create an
     account" section, explaining exactly what syncs (settings + reports;
     history sync is a SEPARATE opt-in toggle as noted above) and what stays
     local (everything, by default).
   - Confirm and test: uninstalling/reinstalling the extension without an
     account preserves zero cloud state (as expected) but with an account,
     settings/allowlist sync back on login to a new device.

4. Shared threat intelligence — the crowdsourcing loop
   - backend/services/threat_intel_aggregator.py: a scheduled/background job
     (document how it's triggered — a simple cron-style periodic task is
     sufficient for this phase, avoid over-engineering a message queue this
     early) that promotes reported_sites entries meeting the confirmation
     threshold into shared_threat_intel.
   - Extension's reputation lookup (Phase 2) now queries BOTH the original
     external reputation API/local blocklist AND this new crowdsourced
     endpoint, merging results with clear provenance in the Verdict's
     explanation (e.g., "Flagged by 12 SafeClick users in the last 7 days" as
     one of the explanation.ruleReasons entries) — crowdsourced signals must
     be labeled as such, never presented as indistinguishable from the
     original automated detection.

5. Analytics — backend/services/analytics_service.py
   - Aggregate-only, privacy-respecting analytics: counts of verdicts served
     by level, most-reported domains (domain-level only, never per-user
     browsing patterns), API latency/error rates for the team's own
     operational visibility. This is infrastructure for Phase 6's team
     analytics, not a per-user surveillance feature — enforce this
     distinction explicitly in code review comments and docs/architecture.md.

6. Testing
   - Pytest: auth flow (register/login/refresh/logout, including invalid-
     credential and expired-token cases), reported_sites CRUD + rate
     limiting, threat_intel_aggregator promotion-threshold logic (unit test
     with fabricated report counts), and analytics aggregation correctness.
   - Vitest: authClient.ts token storage/refresh logic, including a test that
     confirms all Phase 1–4 features still function with zero auth state
     present (no account = full functionality, verified explicitly).
   - A Playwright E2E test covering: create account -> change a setting ->
     log out -> log back in on a "fresh" storage state -> confirm setting
     synced back.

7. Deployment
   - Add a docker-compose.yml at repo root wiring backend + PostgreSQL +
     Redis (optional profile) for one-command local spin-up
     (docker-compose up), plus a documented (not yet executed) path to
     deploying this compose stack to a free/low-cost VPS tier, noting
     realistic free-tier hosting constraints honestly (most "free" VPS/DB
     tiers have real limits — document them rather than assuming infinite
     free capacity).

8. Documentation
   - docs/architecture.md: full auth flow diagram, crowdsourcing/promotion
     pipeline diagram, and an explicit "what requires an account vs. what
     doesn't" table.
   - docs/api-contracts.md: complete auth + reported_sites + threat-intel
     endpoint contracts.
   - CHANGELOG.md: "0.5.0 — Phase 5: Cloud Backend."

DELIVERABLE: A real accounts-and-database-backed platform with crowdsourced
threat intelligence, while every Phase 1–4 feature continues to work fully,
by design, for users who never sign up.
```

---

## PHASE 6 — Enterprise Features

### Goal of this phase
Layer organization-level features on top of the Phase 5 platform: an admin dashboard, centrally-managed org policies (pushed down to member devices), team-wide analytics, formal threat reports, and automatic rule/model update distribution — without disrupting individual-user functionality built in Phases 1–5.

### Extended Antigravity Prompt

```
Build Phase 6 of SafeClick: Enterprise Features.

CONTEXT: Phase 5 turned SafeClick into an accounts-and-database platform with
crowdsourced threat intel. Phase 6 adds an organizational layer on top:
organizations, admin roles, centrally-pushed policy, team analytics, and
distributable rule/model updates. Individual (non-org) users from Phase 5 must
be entirely unaffected — organization membership is an additive layer, not a
replacement for the individual account model.

Work in backend/models/, backend/api/, a new dashboard/ (this phase justifies
building dashboard/ as a genuine standalone web app — React + TypeScript +
Tailwind + Vite, separate from the extension, served independently, since an
admin dashboard is not something users access via the browser extension popup)
and extension/background/policyEnforcer.ts.

REQUIREMENTS:

1. Organizations & roles — backend/models/organization.py
   - Schema additions: organizations (id, name, plan_tier, created_at),
     organization_members (user_id, org_id, role [admin/member], joined_at),
     org_policies (org_id, policy JSON, version, updated_at, updated_by).
   - Role-based access control middleware in backend/api/ ensuring only
     org "admin" role members can read/write org_policies, view team
     analytics, or manage member invitations — write explicit Pytest cases
     proving a "member"-role user is rejected (403) from admin-only
     endpoints, not just that admins are accepted.
   - Invitation flow: POST /api/v1/orgs/{id}/invite (email-based invite,
     accept/decline endpoints) — keep this simple (no full email-sending
     infrastructure required this phase; generate an invite token/link the
     admin can share manually, and note in docs/architecture.md that
     transactional email delivery is a documented future improvement rather
     than something to half-build now).

2. Admin dashboard — dashboard/ (standalone web app)
   - Org admin login (reuses Phase 5 auth, scoped to users with an
     organization_members admin role).
   - Views: Organization overview (member count, plan tier), Policy editor
     (see #3), Team analytics (see #4), Threat reports (see #5).
   - Build this as a clean, distinctly "admin tool" visual style (denser
     information, data-table-heavy) versus the consumer extension's popup —
     consult frontend-design conventions for a professional B2B dashboard
     aesthetic rather than reusing the lightweight consumer popup styling
     verbatim.

3. Organization policies — backend/api/org_policies.py,
   extension/background/policyEnforcer.ts
   - Policy schema (JSON, versioned): allowed risk-threshold overrides (an
     org can tighten, but explicitly should NOT be allowed to loosen below a
     documented safety floor — enforce this floor server-side, do not trust
     the extension client to self-enforce a minimum), org-wide domain
     allowlist/denylist (layered ON TOP of, not replacing, each individual
     user's personal allowlist from Phase 1 — document the precedence order
     explicitly: org denylist > org allowlist > personal denylist > personal
     allowlist > engine verdict, or whatever precedence you choose, but
     WRITE IT DOWN and test it), and whether "Proceed anyway" past a warning
     interstitial is permitted for org members at all (some orgs may want to
     hard-block, not just warn).
   - policyEnforcer.ts: when a device's authenticated user belongs to an
     org, fetch and cache the current policy, apply it in the verdict
     pipeline (still calling through the same Phase 2/3 getVerdict contract —
     policy is an overlay/post-processing step, not a fork of the core
     engine) and re-fetch on a reasonable interval or via a lightweight push
     mechanism (polling is acceptable for this phase; document websocket/push
     as a future optimization rather than building it now).

4. Team analytics — backend/services/team_analytics_service.py,
   dashboard's Team Analytics view
   - Aggregate, per-organization: verdict counts by level across all members
     (never per-member browsing detail beyond what's needed for security
     triage — respect the same privacy posture as Phase 5's analytics
     constraint, scoped now to "team" rather than "global" aggregate), most-
     encountered dangerous domains across the org, and policy-override
     effectiveness (e.g., "3 sites were blocked by org policy that individual
     engine scoring alone would have marked Suspicious, not Dangerous").
   - Expose via GET /api/v1/orgs/{id}/analytics with admin-only access.

5. Threat reports — backend/services/threat_report_service.py
   - Generate a periodic (e.g., weekly), admin-downloadable report (PDF or
     structured HTML — reuse existing project conventions if any exist for
     report generation, otherwise implement a clean, simple templated report)
     summarizing team analytics, top flagged domains, and notable incidents
     for that org over the period, with a clear plain-English executive
     summary at the top (rather than raw tables only) so a non-technical org
     stakeholder can understand it.

6. Automatic rule updates — backend/services/rule_distribution_service.py
   - Extend Phase 3's rule engine format so a new rule-set version can be
     published centrally and pulled by extensions on a schedule, WITHOUT a
     browser extension store update — versioned rule bundles served via
     GET /api/v1/rules/latest?since_version=N, with the extension caching
     the last-known-good bundle locally and falling back to it if a fetch
     fails (never leave a device with zero rules due to a failed update).
   - Sign/validate rule bundles server-side before distribution (even a
     simple checksum/signature scheme) so a compromised or malformed rule
     bundle cannot be silently pushed to every device — document the
     validation approach in docs/architecture.md.
   - This benefits both org and individual users identically (rule updates
     are a platform-wide improvement, not an enterprise-exclusive feature —
     only POLICY, not rule/detection quality, is the org-exclusive layer;
     be explicit about this distinction in the docs).

7. Testing
   - Pytest: RBAC enforcement (admin vs member access, explicitly testing
     rejection cases), policy precedence logic (a matrix of org-allow/org-
     deny/personal-allow/personal-deny combinations with expected outcomes
     for each), team analytics aggregation correctness, and rule bundle
     signature validation (including a test that a tampered bundle is
     rejected).
   - Vitest/Playwright: policyEnforcer.ts applying a fetched org policy
     correctly overriding a default verdict, and graceful fallback to cached
     rules when the rule-update fetch fails.
   - A full end-to-end scenario test: an org admin sets a stricter policy in
     the dashboard -> a member device picks it up -> a site that would
     normally be "Suspicious" is now blocked outright per the stricter
     policy -> the block is reflected in team analytics.

8. Documentation
   - docs/architecture.md: RBAC model, policy precedence order (explicitly
     written out, not just implied by code), rule distribution/signature
     scheme, and a clear statement of what remains free/individual-tier vs.
     what requires an organization (e.g., paid plan_tier, if you choose to
     model monetization at this stage — note this is a business decision,
     not a purely technical one, and should be flagged to the project owner
     rather than assumed).
   - docs/api-contracts.md: all new org/policy/analytics/rule-distribution
     endpoint contracts.
   - CHANGELOG.md: "0.6.0 — Phase 6: Enterprise Features."

DELIVERABLE: A genuine enterprise layer — role-based org management, centrally
enforced (with a hard safety floor) policy, team-wide analytics, human-
readable threat reports, and a signed rule-update distribution mechanism
benefiting all users — built entirely on top of the existing platform without
disrupting individual-user functionality from Phases 1–5.
```

---

## How to use this document

1. Start a fresh Antigravity session for each phase.
2. Paste the **Global Context** block (Section 0) first, every time — it is the constitution the agent must not violate.
3. Paste the phase's extended prompt immediately after.
4. Do not start Phase *N+1* until Phase *N*'s tests pass and its `docs/` updates exist — each phase prompt explicitly assumes the previous phase's contracts (`Verdict`, API routes, folder structure) are already in place.
5. If Antigravity proposes deviating from the fixed tech stack or folder structure, treat that as a signal to stop and reassess rather than to accept silently — the modularity constraint is what makes Phases 2–6 buildable without rewrites.
