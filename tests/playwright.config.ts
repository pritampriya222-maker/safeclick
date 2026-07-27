import { defineConfig, devices } from '@playwright/test';
import { resolve } from 'path';

/**
 * playwright.config.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Playwright configuration for SafeClick E2E tests.
 *
 * The extension must be built before running E2E tests:
 *   cd extension && npm run build
 *   cd .. && npx playwright test
 *
 * We run against Chromium only (Chrome extension APIs are Chromium-specific).
 * Firefox/WebKit extension testing requires separate APIs not covered here.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',

  use: {
    // Run tests in headed mode by default for local dev (easier to debug).
    // Set PLAYWRIGHT_HEADLESS=1 for CI.
    headless: process.env.PLAYWRIGHT_HEADLESS === '1',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium-extension',
      use: {
        ...devices['Desktop Chrome'],
        // Load the built extension as unpacked.
        // The extension must be built before running these tests.
        launchOptions: {
          args: [
            `--disable-extensions-except=${resolve(__dirname, '../extension/dist')}`,
            `--load-extension=${resolve(__dirname, '../extension/dist')}`,
            '--no-sandbox',
          ],
        },
      },
    },
  ],
});
