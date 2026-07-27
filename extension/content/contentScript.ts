/**
 * content/contentScript.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Minimal Phase 1 content script.
 *
 * Responsibilities (Phase 1 ONLY — no blocking, no warnings):
 * 1. Detect whether the page contains a login form (password input field).
 * 2. Capture page metadata (charset, title).
 * 3. Send these as structured PageSignals to the background worker.
 *
 * Phase 2 consumes loginFormSignal to weight the phishing risk score.
 * Phase 4 injects cursorIndicator.ts alongside this script.
 *
 * CRITICAL: This script must NEVER block navigation or display UI elements.
 * Read-only observation only, in Phase 1.
 */

import { sendMessage } from '../shared/messaging';
import type { PageSignals, PageSignalsMessage } from '../shared/types';

// ─── Capture signals ──────────────────────────────────────────────────────────

async function captureAndSendSignals(): Promise<void> {
  const signals = capturePageSignals();

  const message: PageSignalsMessage = {
    type: 'PAGE_SIGNALS',
    signals,
  };

  const response = await sendMessage(message);

  if (!response.success) {
    console.debug('[SafeClick] Failed to send page signals:', response.error);
  }
}

function capturePageSignals(): PageSignals {
  const tabId = -1; // Content scripts don't know their own tabId — background resolves via sender.tab.id.

  // Detect login form: any <form> containing an <input type="password">
  const hasLoginForm = detectLoginForm();

  // Page metadata
  const charset =
    document.characterSet ||
    document.querySelector('meta[charset]')?.getAttribute('charset') ||
    null;

  const title = document.title || null;

  return {
    tabId, // Background will override this with sender.tab.id
    hasLoginForm,
    charset,
    title,
    capturedAt: new Date().toISOString(),
  };
}

/**
 * Detect whether the page has a login form.
 * A login form is defined as any <form> element that contains at least one
 * <input type="password"> — this is the most reliable signal for phishing
 * credential-harvesting pages.
 *
 * Edge cases handled:
 * - Password inputs outside a <form> element (standalone inputs)
 * - Multiple forms on the same page (e.g., signup + login widgets)
 */
function detectLoginForm(): boolean {
  // Check for password inputs inside form elements
  const formsWithPassword = document.querySelectorAll(
    'form input[type="password"]'
  );
  if (formsWithPassword.length > 0) return true;

  // Also check for standalone password inputs (not wrapped in a form tag —
  // common in SPA login flows that handle submission via JS)
  const allPasswordInputs = document.querySelectorAll('input[type="password"]');
  return allPasswordInputs.length > 0;
}

// ─── Main execution ───────────────────────────────────────────────────────────

// Run after the DOM is ready.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', captureAndSendSignals);
} else {
  // DOM already loaded (script injected late).
  captureAndSendSignals();
}
