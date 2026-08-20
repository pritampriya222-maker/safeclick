/**
 * tests/e2e/phase4.spec.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 4 E2E Playwright test: asserts that:
 * 1. Warning Interstitial page renders correctly with summary, score, and actions.
 * 2. Proceed anyway confirmation modal opens on click.
 * 3. Security Dashboard page renders summary stats, trend chart section, and history table.
 */

import { test, expect, chromium, BrowserContext } from '@playwright/test';
import { resolve } from 'path';

const EXTENSION_PATH = resolve(__dirname, '../../extension/dist');

let context: BrowserContext;
let extensionId: string;

test.beforeAll(async () => {
  context = await chromium.launchPersistentContext('', {
    headless: true,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
    ],
  });

  let background: any;
  if (context.serviceWorkers().length > 0) {
    background = context.serviceWorkers()[0];
  } else {
    background = await context.waitForEvent('serviceworker');
  }

  extensionId = background.url().split('/')[2];
});

test.afterAll(async () => {
  await context?.close();
});

test('Phase 4: Warning Interstitial page renders threat details and actions', async () => {
  const warningUrl = `chrome-extension://${extensionId}/warning/warning.html?url=http%3A%2F%2Fpaypal-fake.tk%2Flogin&score=90&reason=Phishing+domain+impersonating+brand&confidence=high`;
  const page = await context.newPage();
  await page.goto(warningUrl, { waitUntil: 'domcontentloaded' });

  // Assert Title & Domain
  const header = page.locator('text=Dangerous Site Blocked').first();
  await expect(header).toBeVisible({ timeout: 10_000 });

  const domain = page.locator('text=paypal-fake.tk').first();
  await expect(domain).toBeVisible();

  // Assert Score
  const score = page.locator('text=90 / 100').first();
  await expect(score).toBeVisible();

  // Assert Buttons
  const backBtn = page.locator('text=Back to Safety').first();
  await expect(backBtn).toBeVisible();

  const proceedBtn = page.locator('text=Proceed Anyway').first();
  await expect(proceedBtn).toBeVisible();

  // Test Proceed Modal Trigger
  await proceedBtn.click();
  const modalTitle = page.locator('text=Confirm Navigation Warning').first();
  await expect(modalTitle).toBeVisible();

  await page.close();
});

test('Phase 4: Security Dashboard page renders stat cards and history view', async () => {
  const dashboardUrl = `chrome-extension://${extensionId}/dashboard/dashboard.html`;
  const page = await context.newPage();
  await page.goto(dashboardUrl, { waitUntil: 'domcontentloaded' });

  // Assert Header
  const title = page.locator('text=SafeClick').first();
  await expect(title).toBeVisible({ timeout: 10_000 });

  // Assert Stat Cards
  const totalChecked = page.locator('text=Sites Analyzed').first();
  await expect(totalChecked).toBeVisible();

  const dangerousBlocked = page.locator('text=Dangerous Blocked').first();
  await expect(dangerousBlocked).toBeVisible();

  // Assert History Table Section
  const historyHeading = page.locator('text=Local Safe Browsing History').first();
  await expect(historyHeading).toBeVisible();

  await page.close();
});
