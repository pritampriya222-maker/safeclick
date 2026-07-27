# SafeClick Extension — Developer README

## Load Unpacked Extension in Chrome (Windows)

### Prerequisites

- **Node.js** 18+ and **npm** (verify: `node -v`, `npm -v`)
- **Google Chrome** or **Microsoft Edge** (any recent version)
- **Windows** (RTX 5060 / Intel Core Ultra 7 255HX — no GPU dependency for this phase)

---

## Step 1: Install Dependencies

```powershell
# From the safeclick/extension/ directory:
cd c:\pritam\safeclick\extension
npm install
```

---

## Step 2: Generate Icons

```powershell
node generate-icons.mjs
```

This creates SVG placeholder icons in `extension/icons/`. For Chrome to accept them as PNGs:
- **Quick method (dev only):** Rename `icon16.svg` → `icon16.png`, etc. Chrome accepts SVGs with a `.png` extension when loaded as unpacked.
- **Proper method:** See `extension/icons/README.md` for Inkscape/ImageMagick instructions.

---

## Step 3: Build the Extension

```powershell
npm run build
```

This compiles TypeScript, processes Tailwind CSS, and outputs the loadable extension to:
```
extension/dist/
├── manifest.json       ← copied from extension/manifest.json
├── icons/
├── popup/
│   └── popup.html
├── options/
│   └── options.html
├── background/
│   └── service-worker.js
├── content/
│   └── contentScript.js
└── assets/
    └── *.js, *.css
```

> **Development mode (watch):** `npm run dev` — rebuilds automatically on file changes.

---

## Step 4: Load in Chrome

1. Open Chrome and navigate to: `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **"Load unpacked"**
4. Select the `c:\pritam\safeclick\extension\dist\` folder
5. SafeClick should appear in your extensions list ✓

### Verify it works:
- Open any `https://` website
- Click the SafeClick icon (shield) in the Chrome toolbar
- You should see a **green "Safe" badge** (Phase 1 stub verdict)
- Click **"View settings"** → settings page opens in a new tab

---

## Step 5: Run Unit Tests

```powershell
npm run test
```

All Vitest unit tests should pass. Coverage report at `coverage/`.

---

## Step 6: Run E2E Tests (Optional)

```powershell
# From the tests/ directory:
cd c:\pritam\safeclick\tests
npm install
npm run install:browsers  # Downloads Playwright's Chromium
npm run test:e2e
```

---

## Development Notes

### Rebuilding after code changes
```powershell
npm run build
# Then in Chrome: chrome://extensions/ → click the reload ↺ button on SafeClick
```

### Viewing background worker logs
1. `chrome://extensions/` → SafeClick → click **"Service Worker"** link
2. DevTools opens for the service worker — Console tab shows `[SafeClick]` log lines

### Viewing popup DevTools
Right-click the SafeClick popup → Inspect

### Common Issues

| Issue | Solution |
|-------|----------|
| "Manifest file is missing or unreadable" | Make sure you selected `extension/dist/`, not `extension/` |
| Service worker not starting | Check `chrome://extensions/` for error details; rebuild with `npm run build` |
| Popup shows "Error" state | Open the popup DevTools Console; usually a build issue |
| Icons showing as broken | Run `node generate-icons.mjs` and rename `.svg` → `.png` |

---

## Project Structure (Phase 1)

```
extension/
├── manifest.json          ← Chrome extension manifest (MV3)
├── package.json
├── tsconfig.json
├── vite.config.ts         ← Multi-entry build config
├── tailwind.config.js
├── postcss.config.js
├── vitest.config.ts
├── vitest.setup.ts        ← Chrome API mocks for unit tests
├── generate-icons.mjs     ← Icon generator
├── icons/                 ← Icon assets
├── shared/
│   ├── types.ts           ← Core interfaces (FROZEN contract)
│   ├── constants.ts       ← Risk thresholds, defaults, lists
│   ├── storage.ts         ← chrome.storage.local wrapper
│   └── messaging.ts       ← chrome.runtime message wrapper
├── background/
│   ├── service-worker.ts  ← MV3 service worker entry
│   ├── tabTracker.ts      ← URL change detection + tab state
│   └── verdictStub.ts     ← Phase 2 replacement seam ⚠️
├── content/
│   └── contentScript.ts   ← Read-only page signal extraction
├── popup/
│   ├── popup.html
│   ├── index.tsx
│   ├── Popup.tsx
│   ├── popup.css
│   └── components/
│       ├── VerdictBadge.tsx
│       ├── SiteInfoCard.tsx
│       └── QuickActions.tsx
├── options/
│   ├── options.html
│   ├── index.tsx
│   ├── Options.tsx
│   └── options.css
├── tests/
│   ├── storage.test.ts
│   ├── messaging.test.ts
│   └── verdictStub.test.ts
└── dist/                  ← Build output (git-ignored)
```

---

## Phase 1 → Phase 2 Handoff

When starting Phase 2 (Threat Detection Engine):

1. **Replace `verdictStub.ts` internals** — keep the exact function signature:
   ```typescript
   export async function getVerdict(url: string): Promise<Verdict>
   ```
2. **Set `isStub: false`** in all real verdicts.
3. **Verify zero changes** required in `popup/`, `options/`, or `content/` — this proves Phase 1's contract design was correct.
4. See `docs/architecture.md` for the full Phase 2 detection pipeline specification.
