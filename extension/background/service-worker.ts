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
import { getVerdict } from './verdictEngine';
import { initializeStorage, getSettings, setSettings, addToAllowlist, addToDenylist } from '../shared/storage';
import { onAnyMessage } from '../shared/messaging';
import type {
  ExtensionMessage,
  GetVerdictMessage,
  CheckLinkMessage,
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

  chrome.contextMenus.create({
    id: 'safeclick-scan-link',
    title: 'Scan with SafeClick',
    contexts: ['link']
  });
});

chrome.runtime.onStartup.addListener(() => {
  console.log('[SafeClick] Browser started — re-initializing tab tracker.');
  initTabTracker();
});

// Ensure tab tracker is active even when the worker restarts mid-session.
initTabTracker();

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'safeclick-scan-link' && info.linkUrl) {
    const verdict = await getVerdict(info.linkUrl);
    
    let emoji = '🟢';
    if (verdict.level === 'suspicious') emoji = '🟡';
    if (verdict.level === 'dangerous') emoji = '🔴';
    
    const message = `Risk Level: ${verdict.level.toUpperCase()} (Score: ${Math.round(verdict.score)})\n${verdict.reasons[0] || 'No specific threats detected.'}`;
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: `${emoji} SafeClick Scan`,
      message: message
    });
  }
});

// ─── Message Router ───────────────────────────────────────────────────────────

onAnyMessage(async (message: ExtensionMessage, sender): Promise<MessageResponse | undefined> => {
  switch (message.type) {
    case 'GET_VERDICT': {
      const msg = message as GetVerdictMessage;
      const tabId = msg.tabId ?? sender.tab?.id;
      let verdict = tabId !== undefined ? await getTabVerdict(tabId) : null;
      if (!verdict && msg.url) {
        verdict = await getVerdict(msg.url);
      }
      return { success: true, data: verdict };
    }

    case 'CHECK_LINK': {
      const msg = message as CheckLinkMessage;
      if (!msg.url) return { success: false, error: 'Missing link URL' };
      const verdict = await getVerdict(msg.url);
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
