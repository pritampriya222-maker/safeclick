/**
 * extension/content/cursorIndicator.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Ambient Risk Indicator Dot & Real-time Link Hover Safety Inspector.
 *
 * Visual Features:
 * 1. Top-Right Ambient Dot:
 *    - Glassmorphic, floating badge showing current page safety.
 *    - Green (Safe), Amber (Suspicious), Red (Dangerous with pulse).
 *    - Expandable hover tooltip detailing risk score & rule reasons.
 *
 * 2. Link Hover Safety Inspector & Cursor Aura:
 *    - When hovering over any link (e.g., search results, emails, forums),
 *      evaluates the target URL in real-time.
 *    - Renders a floating safety halo badge following the cursor.
 *    - Shows safety level, registered domain, and threat reasons.
 *
 * Robustness:
 * - Isolated DOM styling (`all: initial` + inline scoped CSS).
 * - Zero lag, throttled event handling, fast in-memory cache for link lookups.
 * - Respects `settings.cursorIndicatorEnabled`.
 */

import type { Verdict, VerdictLevel } from '../shared/types';
import { getSettings } from '../shared/storage';
import { sendMessage } from '../shared/messaging';

const ROOT_ID = 'safeclick-ambient-root';
const LINK_TOOLTIP_ID = 'safeclick-link-inspector';

export class CursorIndicator {
  private rootElement: HTMLElement | null = null;
  private linkTooltip: HTMLElement | null = null;
  private currentVerdict: Verdict | null = null;
  private enabled: boolean = true;
  private linkCache: Map<string, Verdict> = new Map();
  private activeHoverUrl: string | null = null;
  private pendingFetchUrl: string | null = null;

  constructor() {
    this.init();
  }

  private async init() {
    try {
      const settings = await getSettings();
      this.enabled = settings.cursorIndicatorEnabled ?? true;
      if (this.currentVerdict && this.enabled) {
        this.renderAmbientDot(this.currentVerdict);
      }
    } catch {
      this.enabled = true;
    }
  }

  public setEnabled(enabled: boolean) {
    this.enabled = enabled;
    if (!enabled) {
      this.destroy();
    } else if (this.currentVerdict) {
      this.renderAmbientDot(this.currentVerdict);
    }
  }

  public destroy() {
    if (this.rootElement) {
      this.rootElement.remove();
      this.rootElement = null;
    }
    if (this.linkTooltip) {
      this.linkTooltip.remove();
      this.linkTooltip = null;
    }
  }

  // ─── Top-Right Ambient Dot ──────────────────────────────────────────────────

  public update(verdict: Verdict) {
    this.currentVerdict = verdict;
    if (!this.enabled) return;

    if (verdict.level === 'not_applicable' || window.location.protocol.includes('extension')) {
      this.destroy();
      return;
    }

    this.renderAmbientDot(verdict);
  }

  private renderAmbientDot(verdict: Verdict) {
    const attach = () => {
      if (!document.body) return;

      if (!this.rootElement || !document.getElementById(ROOT_ID)) {
        this.rootElement = this.createRootElement();
        document.body.appendChild(this.rootElement);
      }

      this.applyVerdictStyles(verdict);
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', attach, { once: true });
    } else {
      attach();
    }
  }

  private createRootElement(): HTMLElement {
    const root = document.createElement('div');
    root.id = ROOT_ID;
    root.style.cssText = `
      all: initial;
      position: fixed !important;
      top: 16px !important;
      right: 16px !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      pointer-events: auto !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
      user-select: none !important;
    `;

    const container = document.createElement('div');
    container.className = 'safeclick-dot-container';
    container.style.cssText = `
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    `;

    const pulse = document.createElement('div');
    pulse.className = 'safeclick-pulse';
    pulse.style.cssText = `
      position: absolute;
      width: 22px;
      height: 22px;
      border-radius: 9999px;
      opacity: 0.75;
      animation: safeclick-ping 2s cubic-bezier(0, 0, 0.2, 1) infinite;
    `;

    const dot = document.createElement('div');
    dot.className = 'safeclick-dot';
    dot.style.cssText = `
      position: relative;
      width: 14px;
      height: 14px;
      border-radius: 9999px;
      border: 2px solid #ffffff;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
      transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), background-color 0.3s;
    `;

    const tooltip = document.createElement('div');
    tooltip.className = 'safeclick-ambient-tooltip';
    tooltip.style.cssText = `
      position: absolute;
      top: 24px;
      right: 0;
      width: 260px;
      padding: 12px 14px;
      background: rgba(15, 23, 42, 0.96);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 12px;
      color: #f8fafc;
      font-size: 11px;
      line-height: 1.45;
      box-shadow: 0 16px 32px -6px rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(12px);
      opacity: 0;
      visibility: hidden;
      transform: translateY(-6px) scale(0.96);
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      pointer-events: none;
    `;

    container.appendChild(pulse);
    container.appendChild(dot);
    container.appendChild(tooltip);
    root.appendChild(container);

    // Hover expand
    container.addEventListener('mouseenter', () => {
      dot.style.transform = 'scale(1.25)';
      tooltip.style.opacity = '1';
      tooltip.style.visibility = 'visible';
      tooltip.style.transform = 'translateY(0) scale(1)';
    });

    container.addEventListener('mouseleave', () => {
      dot.style.transform = 'scale(1)';
      tooltip.style.opacity = '0';
      tooltip.style.visibility = 'hidden';
      tooltip.style.transform = 'translateY(-6px) scale(0.96)';
    });

    // Keyframe style tag for ping animation
    if (!document.getElementById('safeclick-keyframes')) {
      const style = document.createElement('style');
      style.id = 'safeclick-keyframes';
      style.textContent = `
        @keyframes safeclick-ping {
          75%, 100% {
            transform: scale(2);
            opacity: 0;
          }
        }
      `;
      document.head?.appendChild(style);
    }

    return root;
  }

  private applyVerdictStyles(verdict: Verdict) {
    if (!this.rootElement) return;

    const dot = this.rootElement.querySelector('.safeclick-dot') as HTMLElement;
    const pulse = this.rootElement.querySelector('.safeclick-pulse') as HTMLElement;
    const tooltip = this.rootElement.querySelector('.safeclick-ambient-tooltip') as HTMLElement;

    if (!dot || !tooltip || !pulse) return;

    let color = '#10b981'; // Emerald
    let glow = 'rgba(16, 185, 129, 0.5)';
    let badgeText = 'Safe Site';
    let icon = '🛡️';

    if (verdict.level === 'suspicious') {
      color = '#f59e0b'; // Amber
      glow = 'rgba(245, 158, 11, 0.6)';
      badgeText = 'Suspicious Site';
      icon = '⚠️';
    } else if (verdict.level === 'dangerous') {
      color = '#f43f5e'; // Rose
      glow = 'rgba(244, 63, 94, 0.8)';
      badgeText = 'Dangerous Site';
      icon = '⛔';
    }

    dot.style.backgroundColor = color;
    dot.style.boxShadow = `0 0 12px ${glow}`;
    pulse.style.backgroundColor = color;
    pulse.style.display = verdict.level === 'safe' ? 'none' : 'block';

    const reason = verdict.explanation?.summary || verdict.reasons[0] || 'Site analyzed by SafeClick';

    tooltip.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
        <span style="font-weight: 700; color: ${color}; font-size: 12px;">${icon} ${badgeText}</span>
        <span style="background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 6px; font-weight: 600; color: #94a3b8; font-size: 10px;">Score: ${verdict.score}/100</span>
      </div>
      <div style="color: #cbd5e1; font-size: 11px; margin-bottom: 6px;">${escapeHtml(reason)}</div>
      <div style="font-size: 9.5px; color: #64748b; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 6px; display: flex; justify-content: space-between;">
        <span>SafeClick Active</span>
        <span>Confidence: ${verdict.confidence?.level ? verdict.confidence.level.toUpperCase() : 'HIGH'}</span>
      </div>
    `;
  }

  // ─── Link Hover Inspector ───────────────────────────────────────────────────

  public async inspectLink(url: string, clientX: number, clientY: number) {
    if (!this.enabled) return;
    if (!url.startsWith('http://') && !url.startsWith('https://')) return;

    this.activeHoverUrl = url;

    // 1. Show immediate loading/cached halo
    const cached = this.linkCache.get(url);
    if (cached) {
      this.renderLinkTooltip(cached, clientX, clientY);
      return;
    }

    // Fast-path: check if it's a known top domain or same origin
    try {
      const parsed = new URL(url);
      const isCurrentOrigin = parsed.origin === window.location.origin;
      if (isCurrentOrigin && this.currentVerdict?.level === 'safe') {
        this.renderLinkTooltip({
          url,
          level: 'safe',
          score: 0,
          reasons: ['Internal page link'],
          ruleTriggers: [],
          timestamp: new Date().toISOString(),
          isStub: false,
        }, clientX, clientY);
        return;
      }
    } catch {
      return;
    }

    // Show a loading tooltip immediately so the user knows it's being scanned
    this.renderLinkTooltip({
      url,
      level: 'unknown',
      score: 0,
      reasons: ['Analyzing link safety...'],
      ruleTriggers: [],
      timestamp: new Date().toISOString(),
      isStub: true,
    }, clientX, clientY);

    // 2. Fetch verdict from background worker
    if (this.pendingFetchUrl === url) return;
    this.pendingFetchUrl = url;

    try {
      const res = await sendMessage<Verdict>({ type: 'CHECK_LINK', url });
      this.pendingFetchUrl = null;
      if (res.success && res.data) {
        this.linkCache.set(url, res.data);
        if (this.activeHoverUrl === url) {
          this.renderLinkTooltip(res.data, clientX, clientY);
        }
      }
    } catch {
      this.pendingFetchUrl = null;
    }
  }

  public updateLinkPosition(clientX: number, clientY: number) {
    if (this.linkTooltip) {
      const offset = 16;
      let left = clientX + offset;
      let top = clientY + offset;

      // Keep inside viewport
      if (left + 220 > window.innerWidth) {
        left = clientX - 230;
      }
      if (top + 80 > window.innerHeight) {
        top = clientY - 80;
      }

      this.linkTooltip.style.left = `${left}px`;
      this.linkTooltip.style.top = `${top}px`;
    }
  }

  public clearLinkInspection() {
    this.activeHoverUrl = null;
    if (this.linkTooltip) {
      this.linkTooltip.style.opacity = '0';
      this.linkTooltip.style.transform = 'scale(0.95)';
    }
  }

  private renderLinkTooltip(verdict: Verdict, clientX: number, clientY: number) {
    if (!document.body) return;

    if (!this.linkTooltip) {
      this.linkTooltip = document.createElement('div');
      this.linkTooltip.id = LINK_TOOLTIP_ID;
      this.linkTooltip.style.cssText = `
        all: initial;
        position: fixed !important;
        z-index: 2147483647 !important;
        pointer-events: none !important;
        padding: 6px 10px !important;
        background: rgba(15, 23, 42, 0.95) !important;
        border-radius: 8px !important;
        color: #f8fafc !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        font-size: 11px !important;
        line-height: 1.3 !important;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5) !important;
        backdrop-filter: blur(8px) !important;
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
        opacity: 0;
        transform: scale(0.95);
        transition: opacity 0.15s ease, transform 0.15s ease;
      `;
      document.body.appendChild(this.linkTooltip);
    }

    let color = '#10b981';
    let label = 'Safe';
    let borderColor = 'rgba(16, 185, 129, 0.3)';

    if (verdict.level === 'suspicious') {
      color = '#f59e0b';
      label = 'Suspicious';
      borderColor = 'rgba(245, 158, 11, 0.4)';
    } else if (verdict.level === 'dangerous') {
      color = '#f43f5e';
      label = 'Dangerous';
      borderColor = 'rgba(244, 63, 94, 0.6)';
    } else if (verdict.level === 'unknown') {
      color = '#94a3b8';
      label = 'Scanning';
      borderColor = 'rgba(148, 163, 184, 0.4)';
    }

    let domain = '';
    try {
      domain = new URL(verdict.url).hostname.replace(/^www\./, '');
    } catch {
      domain = verdict.url;
    }

    this.linkTooltip.style.border = `1px solid ${borderColor}`;
    this.linkTooltip.innerHTML = `
      <div style="width: 8px; height: 8px; border-radius: 9999px; background: ${color}; box-shadow: 0 0 8px ${color}; flex-shrink: 0;"></div>
      <div>
        <span style="font-weight: 600; color: ${color};">${label} Link:</span>
        <span style="color: #e2e8f0; margin-left: 3px;">${escapeHtml(domain)}</span>
        <span style="color: #64748b; font-size: 9.5px; margin-left: 4px;">(${verdict.score}/100)</span>
      </div>
    `;

    this.updateLinkPosition(clientX, clientY);
    this.linkTooltip.style.opacity = '1';
    this.linkTooltip.style.transform = 'scale(1)';
  }
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
