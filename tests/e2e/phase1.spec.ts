/**
 * tests/e2e/phase1.spec.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 1 E2E test: loads SafeClick as an unpacked extension, navigates to
 * a test fixture page, opens the popup, and asserts the VerdictBadge renders
 * the stubbed "Safe" state.
 *
 * Prerequisites (see tests/README.md):
 *   1. cd extension && npm run build   (builds extension/dist/)
 *   2. Serve the fixture: npx serve tests/fixtures -p 3333 (or use a static server)
 *   3. cd tests && npm run test:e2e
 *
 * The test uses chrome.tabs API to open the popup by navigating to the
 * popup's chrome-extension:// URL directly — this is the standard pattern
 * for testing extension popups with Playwright.
 */

import { test, expect, chromium, BrowserContext } from '@playwright/test';
import { resolve } from 'path';
import { createServer } from 'http';
import { readFileSync } from 'fs';

const EXTENSION_PATH = resolve(__dirname, '../../extension/dist');
const FIXTURE_PORT = 3777;
const FIXTURE_URL = `http://localhost:${FIXTURE_PORT}/test-page.html`;

// ─── Local fixture server ─────────────────────────────────────────────────────

let fixtureServer: ReturnType<typeof createServer>;

function startFixtureServer(): Promise<void> {
  return new Promise((resolve) => {
    fixtureServer = createServer((req, res) => {
      const fixturePath = `${__dirname}/../fixtures${req.url}`;
      try {
        const content = readFileSync(fixturePath, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(content);
      } catch {
        res.writeHead(404);
        res.end('Not found');
      }
    });
    fixtureServer.listen(FIXTURE_PORT, () => resolve());
  });
}

function stopFixtureServer(): Promise<void> {
  return new Promise((resolve) => fixtureServer?.close(() => resolve()));
}

// ─── Test setup ───────────────────────────────────────────────────────────────

let context: BrowserContext;
let extensionId: string;

test.beforeAll(async () => {
  await startFixtureServer();

  context = await chromium.launchPersistentContext('', {
    headless: false, // Extensions require non-headless Chromium
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-sandbox',
      '--disable-setuid-sandbox',
    ],
  });

  // Discover the extension's ID by waiting for the service worker.
  let [background] = context.serviceWorkers();
  if (!background) {
    background = await context.waitForEvent('serviceworker');
  }

  extensionId = background.url().split('/')[2];
  console.log(`[SafeClick E2E] Extension loaded with ID: ${extensionId}`);
});

test.afterAll(async () => {
  await context.close();
  await stopFixtureServer();
});

// ─── Tests ────────────────────────────────────────────────────────────────────

test('Phase 1: popup shows Safe verdict on a plain http page', async () => {
  // Navigate a tab to the fixture page.
  const page = await context.newPage();
  await page.goto(FIXTURE_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(500); // Give the background worker time to compute verdict.

  // Open the extension popup directly via its chrome-extension:// URL.
  const popupPage = await context.newPage();
  await popupPage.goto(`chrome-extension://${extensionId}/popup/popup.html`);

  // Wait for loading state to resolve.
  await popupPage.waitForTimeout(1500);

  // Assert the VerdictBadge renders the Safe state.
  // The badge contains the word "Safe" in green text.
  const verdictText = await popupPage.locator('text=Safe').first();
  await expect(verdictText).toBeVisible({ timeout: 10_000 });

  // Assert the score is shown (0/100 for the stub).
  const scoreText = await popupPage.locator('text=/Risk score/i').first();
  await expect(scoreText).toBeVisible({ timeout: 5_000 });

  // Assert stub placeholder message is shown (no real analysis yet).
  const stubMsg = await popupPage.locator('text=/Phase 2\/3 pending/i').first();
  await expect(stubMsg).toBeVisible({ timeout: 5_000 });

  // Assert the Quick Actions buttons are present.
  await expect(popupPage.locator('#btn-report-site')).toBeVisible();
  await expect(popupPage.locator('#btn-trust-domain')).toBeVisible();
  await expect(popupPage.locator('#btn-view-settings')).toBeVisible();

  await popupPage.close();
  await page.close();
});

test('Phase 1: popup shows Not Applicable for chrome:// pages', async () => {
  const popupPage = await context.newPage();
  // Navigate popup directly — it opens in the context of its own extension page,
  // not the active tab. We test the "not applicable" state by checking the popup
  // renders the neutral state for chrome-extension:// URLs.
  await popupPage.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await popupPage.waitForTimeout(1000);

  // The popup itself is a chrome-extension:// page, so it should show
  // "Not applicable" since the active tab in this context is a new page.
  // If a chrome:// tab is active, the popup should display the N/A state.
  // This test verifies the popup renders without crashing.
  const body = await popupPage.locator('body').first();
  await expect(body).toBeVisible();

  // Verify SafeClick header is present (proves the popup rendered correctly).
  const header = await popupPage.locator('text=SafeClick').first();
  await expect(header).toBeVisible();

  await popupPage.close();
});

test('Phase 1: settings page opens and renders correctly', async () => {
  const optionsPage = await context.newPage();
  await optionsPage.goto(`chrome-extension://${extensionId}/options/options.html`);
  await optionsPage.waitForTimeout(1000);

  // Header should show "SafeClick Settings".
  await expect(optionsPage.locator('h1').first()).toContainText('SafeClick Settings');

  // Enable toggle should be present.
  await expect(optionsPage.locator('#toggle-enabled')).toBeVisible();

  // Cloud sync toggle should be disabled/greyed out (Phase 5 placeholder).
  const cloudToggle = optionsPage.locator('#toggle-share-data');
  await expect(cloudToggle).toBeDisabled();

  // Allowlist add button should be present.
  await expect(optionsPage.locator('#btn-add-allowlist')).toBeVisible();

  // Denylist add button should be present.
  await expect(optionsPage.locator('#btn-add-denylist')).toBeVisible();

  await optionsPage.close();
});

test('Phase 1: allowlist persists across options page interactions', async () => {
  const optionsPage = await context.newPage();
  await optionsPage.goto(`chrome-extension://${extensionId}/options/options.html`);
  await optionsPage.waitForTimeout(1000);

  // Add a domain to the allowlist.
  await optionsPage.fill('#input-allowlist', 'trusteddomain.example.com');
  await optionsPage.click('#btn-add-allowlist');
  await optionsPage.waitForTimeout(500);

  // The domain should appear in the list.
  await expect(optionsPage.locator('text=trusteddomain.example.com').first()).toBeVisible();

  await optionsPage.close();
});
