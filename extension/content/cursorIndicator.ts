/**
 * extension/content/cursorIndicator.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 4: Ambient Risk Indicator Dot.
 *
 * Injects a subtle, glassmorphic top-right corner indicator dot on pages:
 * - Green: Safe site
 * - Amber: Suspicious site (hover shows reasons)
 * - Red: Dangerous site (pulsing glow + hover tooltip)
 *
 * Respects settings.cursorIndicatorEnabled.
 * Zero input lag, zero layout shift, zero native cursor interference.
 */

import type { Verdict, VerdictLevel, Settings } from '../shared/types';
import { getSettings } from '../shared/storage';

const INDICATOR_ID = 'safeclick-indicator-dot';

export class CursorIndicator {
  private element: HTMLElement | null = null;
  private currentVerdict: Verdict | null = null;
  private enabled: boolean = true;

  constructor() {
    this.init();
  }

  private async init() {
    try {
      const settings = await getSettings();
      this.enabled = settings.cursorIndicatorEnabled ?? true;
    } catch {
      this.enabled = true;
    }
  }

  public setEnabled(enabled: boolean) {
    this.enabled = enabled;
    if (!enabled && this.element) {
      this.element.remove();
      this.element = null;
    } else if (enabled && this.currentVerdict) {
      this.update(this.currentVerdict);
    }
  }

  public update(verdict: Verdict) {
    this.currentVerdict = verdict;
    if (!this.enabled || !document.body) return;

    // Don't inject on internal extension pages or not-applicable pages
    if (verdict.level === 'not_applicable' || window.location.protocol.includes('extension')) {
      if (this.element) {
        this.element.remove();
        this.element = null;
      }
      return;
    }

    if (!this.element) {
      this.element = this.createElement();
      document.body.appendChild(this.element);
    }

    this.applyVerdictStyles(verdict);
  }

  private createElement(): HTMLElement {
    const el = document.createElement('div');
    el.id = INDICATOR_ID;
    el.style.cssText = `
      position: fixed;
      top: 14px;
      right: 14px;
      z-index: 2147483647;
      display: flex;
      items-center;
      justify-content: center;
      pointer-events: auto;
      user-select: none;
      font-family: system-ui, -apple-system, sans-serif;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    `;

    // Tooltip wrapper inside
    const dot = document.createElement('div');
    dot.className = 'safeclick-dot-inner';
    dot.style.cssText = `
      width: 12px;
      height: 12px;
      border-radius: 9999px;
      transition: all 0.25s ease;
      cursor: pointer;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
    `;

    const tooltip = document.createElement('div');
    tooltip.className = 'safeclick-tooltip';
    tooltip.style.cssText = `
      position: absolute;
      top: 20px;
      right: 0;
      width: 240px;
      padding: 10px 12px;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      color: #f8fafc;
      font-size: 11px;
      line-height: 1.4;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(8px);
      opacity: 0;
      transform: translateY(-4px);
      pointer-events: none;
      transition: all 0.2s ease;
    `;

    el.appendChild(dot);
    el.appendChild(tooltip);

    el.addEventListener('mouseenter', () => {
      tooltip.style.opacity = '1';
      tooltip.style.transform = 'translateY(0)';
    });

    el.addEventListener('mouseleave', () => {
      tooltip.style.opacity = '0';
      tooltip.style.transform = 'translateY(-4px)';
    });

    return el;
  }

  private applyVerdictStyles(verdict: Verdict) {
    if (!this.element) return;

    const dot = this.element.querySelector('.safeclick-dot-inner') as HTMLElement;
    const tooltip = this.element.querySelector('.safeclick-tooltip') as HTMLElement;

    if (!dot || !tooltip) return;

    let color = '#10b981'; // Green (safe)
    let glow = 'rgba(16, 185, 129, 0.5)';
    let titleText = 'SafeClick: Safe Site';

    if (verdict.level === 'suspicious') {
      color = '#f59e0b'; // Amber
      glow = 'rgba(245, 158, 11, 0.7)';
      titleText = 'SafeClick: Suspicious Site';
    } else if (verdict.level === 'dangerous') {
      color = '#f43f5e'; // Red
      glow = 'rgba(244, 63, 94, 0.9)';
      titleText = 'SafeClick: Dangerous Site';
    }

    dot.style.backgroundColor = color;
    dot.style.boxShadow = `0 0 12px ${glow}`;

    const mainReason = verdict.explanation?.summary || verdict.reasons[0] || 'Site analyzed';

    tooltip.innerHTML = `
      <div style="font-weight: 700; color: ${color}; margin-bottom: 4px;">${titleText}</div>
      <div style="color: #cbd5e1;">${escapeHtml(mainReason)}</div>
      <div style="margin-top: 6px; font-size: 10px; color: #94a3b8;">Risk score: ${verdict.score}/100</div>
    `;
  }
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
