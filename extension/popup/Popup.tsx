/**
 * popup/Popup.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Root popup component. Presentation-only — no detection logic lives here.
 *
 * State machine:
 *   loading → (verdict received) → verdict
 *                                → error (cannot access tab URL)
 *                                → not_applicable (chrome://, extension://, etc.)
 */

import React, { useEffect, useState } from 'react';
import { VerdictBadge } from './components/VerdictBadge';
import { SiteInfoCard } from './components/SiteInfoCard';
import { QuickActions } from './components/QuickActions';
import { sendMessage } from '../shared/messaging';
import type { Verdict } from '../shared/types';
import { NON_APPLICABLE_SCHEMES } from '../shared/constants';

type PopupState = 'loading' | 'verdict' | 'error' | 'not_applicable';

interface PopupData {
  state: PopupState;
  verdict: Verdict | null;
  url: string | null;
  domain: string | null;
  errorMessage?: string;
}

function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function isNonApplicable(url: string): boolean {
  return NON_APPLICABLE_SCHEMES.some((scheme) => url.startsWith(scheme));
}

export const Popup: React.FC = () => {
  const [data, setData] = useState<PopupData>({
    state: 'loading',
    verdict: null,
    url: null,
    domain: null,
  });

  useEffect(() => {
    let cancelled = false;

    async function loadVerdict() {
      try {
        // Get the active tab.
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });

        if (!tab?.id) {
          if (!cancelled) {
            setData({
              state: 'error',
              verdict: null,
              url: null,
              domain: null,
              errorMessage: 'Cannot determine active tab.',
            });
          }
          return;
        }

        const url = tab.url ?? '';

        // Handle non-applicable URL schemes.
        if (!url || isNonApplicable(url)) {
          if (!cancelled) {
            setData({
              state: 'not_applicable',
              verdict: null,
              url: url || null,
              domain: null,
            });
          }
          return;
        }

        // Request verdict from background worker.
        const response = await sendMessage<Verdict | null>({
          type: 'GET_VERDICT',
          tabId: tab.id,
        });

        if (!cancelled) {
          setData({
            state: 'verdict',
            verdict: response.data ?? null,
            url,
            domain: extractDomain(url),
          });
        }
      } catch (err) {
        if (!cancelled) {
          setData({
            state: 'error',
            verdict: null,
            url: null,
            domain: null,
            errorMessage:
              err instanceof Error ? err.message : 'An unexpected error occurred.',
          });
        }
      }
    }

    loadVerdict();

    // Listen for real-time verdict updates pushed from the background.
    const listener = (message: unknown) => {
      const msg = message as { type: string; verdict?: Verdict; tabId?: number };
      if (msg.type === 'VERDICT_UPDATE' && msg.verdict && !cancelled) {
        setData((prev) => ({
          ...prev,
          state: 'verdict',
          verdict: msg.verdict ?? null,
        }));
      }
    };
    chrome.runtime.onMessage.addListener(listener);

    return () => {
      cancelled = true;
      chrome.runtime.onMessage.removeListener(listener);
    };
  }, []);

  return (
    <div className="w-80 min-h-[420px] bg-slate-900 text-white flex flex-col">
      {/* Header */}
      <header className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-800/80 bg-slate-900/95 backdrop-blur-sm">
        <div className="w-6 h-6 rounded-md bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center flex-shrink-0">
          <span className="text-white text-xs font-bold">S</span>
        </div>
        <span className="text-sm font-semibold text-slate-100 tracking-wide">
          SafeClick
        </span>
        <span className="ml-auto text-xs text-slate-600 font-mono">v0.1.0</span>
      </header>

      {/* Body */}
      <main className="flex-1 flex flex-col px-4 py-3 gap-3">
        {/* Loading state */}
        {data.state === 'loading' && (
          <VerdictBadge verdict={null} isLoading={true} />
        )}

        {/* Not applicable state */}
        {data.state === 'not_applicable' && (
          <div className="flex flex-col items-center gap-3 py-6">
            <div className="w-16 h-16 rounded-full bg-slate-800/60 border border-slate-700 flex items-center justify-center">
              <span className="text-slate-500 text-2xl">—</span>
            </div>
            <div className="text-center">
              <p className="text-slate-300 text-sm font-medium">Not applicable</p>
              <p className="text-slate-500 text-xs mt-1">
                SafeClick doesn't analyze this page type.
              </p>
            </div>
          </div>
        )}

        {/* Error state */}
        {data.state === 'error' && (
          <div className="flex flex-col items-center gap-3 py-4">
            <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
              <span className="text-red-400 text-2xl">!</span>
            </div>
            <div className="text-center">
              <p className="text-slate-300 text-sm font-medium">Error</p>
              <p className="text-slate-500 text-xs mt-1 max-w-[200px]">
                {data.errorMessage ?? 'Could not analyze this page.'}
              </p>
            </div>
          </div>
        )}

        {/* Verdict state */}
        {data.state === 'verdict' && (
          <>
            <VerdictBadge verdict={data.verdict} />
            <SiteInfoCard
              url={data.url}
              timestamp={data.verdict?.timestamp ?? null}
            />
            <QuickActions
              url={data.url}
              domain={data.domain}
              disabled={!data.url}
            />
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="px-4 py-2 border-t border-slate-800/60 text-center">
        <p className="text-slate-700 text-[10px]">
          SafeClick — Real-Time Browser Threat Detection
        </p>
      </footer>
    </div>
  );
};

export default Popup;
