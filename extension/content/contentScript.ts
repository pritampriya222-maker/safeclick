/**
 * content/contentScript.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * SafeClick Content Script:
 * 1. Captures page signals (login forms, metadata) for intelligence scoring.
 * 2. Manages the top-right ambient safety dot (CursorIndicator).
 * 3. Real-time link hover safety inspection on all page hyperlinks.
 */

import { sendMessage, onMessage } from '../shared/messaging';
import type {
  PageSignals,
  PageSignalsMessage,
  VerdictUpdateMessage,
  Verdict,
} from '../shared/types';
import { CursorIndicator } from './cursorIndicator';

// Initialize ambient cursor indicator & link safety inspector
const indicator = new CursorIndicator();

// Listen for VERDICT_UPDATE messages sent directly to this tab
onMessage<VerdictUpdateMessage>('VERDICT_UPDATE', (message) => {
  if (message.verdict) {
    indicator.update(message.verdict);
  }
  return { success: true };
});

// ─── Initial Page Analysis & Signal Capture ───────────────────────────────────

async function initPageCheck(): Promise<void> {
  // 1. Immediately request the page verdict to display the ambient dot
  try {
    const res = await sendMessage<Verdict>({
      type: 'GET_VERDICT',
      url: window.location.href,
    });
    if (res.success && res.data) {
      indicator.update(res.data);
    }
  } catch (err) {
    console.debug('[SafeClick] Initial verdict fetch error:', err);
  }

  // 2. Capture and send page signals (e.g. login form detection)
  await captureAndSendSignals();
}

async function captureAndSendSignals(): Promise<void> {
  try {
    const signals = capturePageSignals();
    const message: PageSignalsMessage = {
      type: 'PAGE_SIGNALS',
      signals,
    };
    await sendMessage(message);
  } catch (err) {
    console.debug('[SafeClick] Failed to send page signals:', err);
  }
}

function capturePageSignals(): PageSignals {
  const tabId = -1; // Background will assign sender.tab.id

  const hasLoginForm = detectLoginForm();
  const charset =
    document.characterSet ||
    document.querySelector('meta[charset]')?.getAttribute('charset') ||
    null;
  const title = document.title || null;

  return {
    tabId,
    hasLoginForm,
    charset,
    title,
    capturedAt: new Date().toISOString(),
  };
}

function detectLoginForm(): boolean {
  const formsWithPassword = document.querySelectorAll('form input[type="password"]');
  if (formsWithPassword.length > 0) return true;

  const allPasswordInputs = document.querySelectorAll('input[type="password"]');
  return allPasswordInputs.length > 0;
}

// ─── Real-time Link Hover Inspector ───────────────────────────────────────────

function findAnchor(target: EventTarget | null): HTMLAnchorElement | null {
  if (!target || !(target instanceof Element)) return null;
  const anchor = target.closest('a');
  if (anchor && anchor.href && (anchor.href.startsWith('http://') || anchor.href.startsWith('https://'))) {
    return anchor;
  }
  return null;
}

document.addEventListener('mouseover', (e: MouseEvent) => {
  const anchor = findAnchor(e.target);
  if (anchor && anchor.href) {
    indicator.inspectLink(anchor.href, e.clientX, e.clientY);
  }
}, { passive: true });

document.addEventListener('mousemove', (e: MouseEvent) => {
  indicator.updateLinkPosition(e.clientX, e.clientY);
}, { passive: true });

document.addEventListener('mouseout', (e: MouseEvent) => {
  const anchor = findAnchor(e.target);
  const relatedAnchor = findAnchor(e.relatedTarget);
  // If moving out of the anchor element entirely
  if (anchor && (!relatedAnchor || relatedAnchor !== anchor)) {
    indicator.clearLinkInspection();
  }
}, { passive: true });

// ─── Startup ──────────────────────────────────────────────────────────────────

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initPageCheck, { once: true });
} else {
  initPageCheck();
}
