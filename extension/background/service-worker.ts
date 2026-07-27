/**
 * background/service-worker.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Manifest V3 service worker entry point.
 *
 * Responsibilities:
 * - Bootstrap tab tracking on install/startup
 * - Initialize storage defaults on first install
 * - Route all incoming messages from popup and content scripts
 *
 * Architecture: This file is intentionally thin — it only wires together
 * tabTracker.ts, storage.ts, and messaging.ts. No business logic lives here.
 */

import { initTabTracker, getTabVerdict, handlePageSignals } from './tabTracker';
import { initializeStorage, getSettings, setSettings, addToAllowlist, addToDenylist } from '../shared/storage';
import { onAnyMessage } from '../shared/messaging';
import type {
  ExtensionMessage,
  GetVerdictMessage,
  PageSignalsMessage,
  ReportSiteMessage,
  TrustDomainMessage,
  GetSettingsMessage,
  SetSettingsMessage,
  MessageResponse,
} from '../shared/types';

// ─── Install / Startup ────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  console.log(`[SafeClick] Extension installed/updated. Reason: ${reason}`);
  await initializeStorage();
  initTabTracker();
});

chrome.runtime.onStartup.addListener(() => {
  console.log('[SafeClick] Browser started — re-initializing tab tracker.');
  initTabTracker();
});

// Ensure tab tracker is active even when the worker restarts mid-session.
initTabTracker();

// ─── Message Router ───────────────────────────────────────────────────────────

onAnyMessage(async (message: ExtensionMessage, sender): Promise<MessageResponse | undefined> => {
  switch (message.type) {
    case 'GET_VERDICT': {
      const msg = message as GetVerdictMessage;
      const verdict = await getTabVerdict(msg.tabId);
      return { success: true, data: verdict };
    }

    case 'PAGE_SIGNALS': {
      const msg = message as PageSignalsMessage;
      await handlePageSignals(msg.signals);
      return { success: true };
    }

    case 'REPORT_SITE': {
      const msg = message as ReportSiteMessage;
      // Phase 1: log locally. Phase 5 will wire this to the backend API.
      console.log('[SafeClick] Site reported:', msg.url, msg.reason);
      return { success: true };
    }

    case 'TRUST_DOMAIN': {
      const msg = message as TrustDomainMessage;
      await addToAllowlist(msg.domain);
      console.log('[SafeClick] Domain added to allowlist:', msg.domain);
      return { success: true };
    }

    case 'GET_SETTINGS': {
      const settings = await getSettings();
      return { success: true, data: settings };
    }

    case 'SET_SETTINGS': {
      const msg = message as SetSettingsMessage;
      await setSettings(msg.settings);
      return { success: true };
    }

    case 'OPEN_OPTIONS': {
      await chrome.runtime.openOptionsPage();
      return { success: true };
    }

    default:
      return undefined;
  }
});

console.log('[SafeClick] Service worker active.');
