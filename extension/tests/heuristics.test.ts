/**
 * tests/heuristics.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for all four heuristic modules.
 * Each test covers: triggering URL + non-triggering URL.
 * Uses clearly fictional/example.com-style test domains — no real phishing URLs.
 */

import { describe, it, expect } from 'vitest';
import { analyzeLengthAndEntropy, shannonEntropy } from '../background/heuristics/lengthAndEntropy';
import { analyzeSuspiciousKeywords } from '../background/heuristics/suspiciousKeywords';
import { analyzeUrlStructure, isRawIpAddress, countSubdomainDepth, detectBrandHyphenMimicry } from '../background/heuristics/urlStructure';
import { analyzeLoginFormSignal } from '../background/heuristics/loginFormSignal';
import { normalizeUrl } from '../shared/urlNormalizer';
import type { NormalizedUrl, PageSignals } from '../shared/types';

// ─── Test helpers ─────────────────────────────────────────────────────────────

function makeNormalizedUrl(url: string): NormalizedUrl {
  const result = normalizeUrl(url);
  if (!result) throw new Error(`Could not normalize: ${url}`);
  return result;
}

function makePageSignals(hasLoginForm: boolean, tabId = 1): PageSignals {
  return {
    tabId,
    hasLoginForm,
    charset: 'UTF-8',
    title: 'Test Page',
    capturedAt: new Date().toISOString(),
  };
}

// ─── lengthAndEntropy ─────────────────────────────────────────────────────────

describe('lengthAndEntropy — shannonEntropy()', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for single repeated character', () => {
    expect(shannonEntropy('aaaaaaa')).toBe(0);
  });

  it('returns higher entropy for random-looking string', () => {
    const randomish = 'xk4jq2ab9zf';
    const simple = 'aaabbbccc';
    expect(shannonEntropy(randomish)).toBeGreaterThan(shannonEntropy(simple));
  });
});

describe('lengthAndEntropy — analyzeLengthAndEntropy()', () => {
  it('triggers for an abnormally long URL', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(150);
    const result = analyzeLengthAndEntropy(makeNormalizedUrl(longUrl), null);
    expect(result.triggered).toBe(true);
    expect(result.explanation).toMatch(/long/i);
  });

  it('triggers for a high-entropy subdomain (phishing kit pattern)', () => {
    // Simulates: https://xk4jq2ab9zf.phishing-example.com/
    const result = analyzeLengthAndEntropy(
      makeNormalizedUrl('https://xk4jq2ab9zf.phishing-example.com/login'),
      null
    );
    expect(result.triggered).toBe(true);
    expect(result.explanation).toMatch(/entropy/i);
  });

  it('does NOT trigger for normal safe URL', () => {
    const result = analyzeLengthAndEntropy(
      makeNormalizedUrl('https://google.com/search?q=test'),
      null
    );
    expect(result.triggered).toBe(false);
  });

  it('always returns the correct ruleId', () => {
    const result = analyzeLengthAndEntropy(makeNormalizedUrl('https://example.com'), null);
    expect(result.ruleId).toBe('heuristic:length_entropy');
  });
});

// ─── suspiciousKeywords ───────────────────────────────────────────────────────

describe('analyzeSuspiciousKeywords()', () => {
  it('triggers when brand keyword appears in subdomain of different domain', () => {
    // "paypal" keyword in subdomain, but registered domain is "attacker-example.com"
    const result = analyzeSuspiciousKeywords(
      makeNormalizedUrl('https://paypal-secure.attacker-example.com/login'),
      null
    );
    expect(result.triggered).toBe(true);
    expect(result.explanation.toLowerCase()).toContain('paypal');
  });

  it('triggers when brand keyword appears in path of different domain', () => {
    const result = analyzeSuspiciousKeywords(
      makeNormalizedUrl('https://random-example.com/paypal/verify-account'),
      null
    );
    expect(result.triggered).toBe(true);
  });

  it('does NOT trigger for the actual brand domain', () => {
    // "paypal" on paypal.com is fine
    const result = analyzeSuspiciousKeywords(
      makeNormalizedUrl('https://www.paypal.com/login'),
      null
    );
    expect(result.triggered).toBe(false);
  });

  it('does NOT trigger for a normal URL with no brand keywords', () => {
    const result = analyzeSuspiciousKeywords(
      makeNormalizedUrl('https://myshop-example.com/products'),
      null
    );
    expect(result.triggered).toBe(false);
  });

  it('returns correct ruleId', () => {
    const result = analyzeSuspiciousKeywords(makeNormalizedUrl('https://example.com'), null);
    expect(result.ruleId).toBe('heuristic:suspicious_keywords');
  });
});

// ─── urlStructure ─────────────────────────────────────────────────────────────

describe('isRawIpAddress()', () => {
  it('returns true for valid IPv4', () => {
    expect(isRawIpAddress('192.168.1.1')).toBe(true);
    expect(isRawIpAddress('10.0.0.1')).toBe(true);
  });

  it('returns false for domain names', () => {
    expect(isRawIpAddress('example.com')).toBe(false);
    expect(isRawIpAddress('sub.example.co.uk')).toBe(false);
  });
});

describe('countSubdomainDepth()', () => {
  it('returns 0 when hostname equals registered domain', () => {
    expect(countSubdomainDepth('example.com', 'example.com')).toBe(0);
  });

  it('returns 1 for single subdomain', () => {
    expect(countSubdomainDepth('sub.example.com', 'example.com')).toBe(1);
  });

  it('returns 3 for deep nesting', () => {
    expect(countSubdomainDepth('a.b.c.example.com', 'example.com')).toBe(3);
  });
});

describe('detectBrandHyphenMimicry()', () => {
  it('detects paypal-secure.com as mimicking paypal', () => {
    expect(detectBrandHyphenMimicry('paypal-secure.com')).toBe('paypal');
  });

  it('detects secure-paypal.net as mimicking paypal', () => {
    expect(detectBrandHyphenMimicry('secure-paypal.net')).toBe('paypal');
  });

  it('does NOT flag paypal.com itself', () => {
    expect(detectBrandHyphenMimicry('paypal.com')).toBeNull();
  });

  it('does NOT flag unrelated hyphenated domains', () => {
    expect(detectBrandHyphenMimicry('my-shop.com')).toBeNull();
  });
});

describe('analyzeUrlStructure()', () => {
  it('triggers for raw IP address URL', () => {
    const result = analyzeUrlStructure(
      makeNormalizedUrl('http://192.168.1.100/phish'),
      null
    );
    expect(result.triggered).toBe(true);
    expect(result.explanation).toMatch(/ip address/i);
  });

  it('triggers for @ obfuscation in URL', () => {
    // URL: http://legitimate.com@192.168.1.1/path → browser goes to 192.168.1.1
    // Note: URL() parser will handle this correctly (hostname = 192.168.1.1)
    // but the original URL contains @ which we detect
    const normalized = makeNormalizedUrl('https://example.com/path');
    const result = analyzeUrlStructure(
      { ...normalized, original: 'http://legit.com@attacker-example.com/path' },
      null
    );
    expect(result.triggered).toBe(true);
    expect(result.explanation).toMatch(/@/);
  });

  it('triggers for excessive subdomain depth', () => {
    const result = analyzeUrlStructure(
      makeNormalizedUrl('https://a.b.c.d.e.phishing-example.com/'),
      null
    );
    expect(result.triggered).toBe(true);
    expect(result.explanation).toMatch(/subdomain/i);
  });

  it('does NOT trigger for normal HTTPS URL', () => {
    const result = analyzeUrlStructure(
      makeNormalizedUrl('https://secure.google.com/mail'),
      null
    );
    expect(result.triggered).toBe(false);
  });
});

// ─── loginFormSignal ──────────────────────────────────────────────────────────

describe('analyzeLoginFormSignal()', () => {
  it('does NOT trigger when no page signals available', () => {
    const trusted = new Set<string>(['example.com']);
    const result = analyzeLoginFormSignal(
      makeNormalizedUrl('https://random-example.com/'),
      null,  // no page signals
      trusted
    );
    expect(result.triggered).toBe(false);
  });

  it('does NOT trigger when no login form on page', () => {
    const trusted = new Set<string>();
    const result = analyzeLoginFormSignal(
      makeNormalizedUrl('https://random-example.com/'),
      makePageSignals(false),
      trusted
    );
    expect(result.triggered).toBe(false);
  });

  it('does NOT trigger for login form on trusted domain', () => {
    const trusted = new Set<string>(['google.com']);
    const result = analyzeLoginFormSignal(
      makeNormalizedUrl('https://accounts.google.com/signin'),
      makePageSignals(true),
      trusted
    );
    expect(result.triggered).toBe(false);
  });

  it('TRIGGERS for login form on unknown domain', () => {
    const trusted = new Set<string>();  // nothing trusted
    const result = analyzeLoginFormSignal(
      makeNormalizedUrl('https://unknown-phishing-example.com/login'),
      makePageSignals(true),
      trusted
    );
    expect(result.triggered).toBe(true);
    expect(result.explanation).toMatch(/login form/i);
  });

  it('returns correct ruleId', () => {
    const result = analyzeLoginFormSignal(
      makeNormalizedUrl('https://example.com'),
      null,
      new Set()
    );
    expect(result.ruleId).toBe('heuristic:login_form_signal');
  });
});
