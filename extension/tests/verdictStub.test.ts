/**
 * tests/verdictStub.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for background/verdictStub.ts.
 * Verifies: stub returns correct shape, handles non-applicable URLs,
 * and is explicitly marked as a stub (isStub: true) so Phase 2
 * test suites can verify the stub is no longer active.
 */

import { describe, it, expect } from 'vitest';
import { getVerdict } from '../background/verdictStub';

describe('verdictStub.ts — getVerdict', () => {
  it('returns a Verdict conforming to shared/types.ts Verdict interface', async () => {
    const verdict = await getVerdict('https://example.com');

    // Required fields per Verdict interface
    expect(typeof verdict.url).toBe('string');
    expect(typeof verdict.level).toBe('string');
    expect(typeof verdict.score).toBe('number');
    expect(Array.isArray(verdict.reasons)).toBe(true);
    expect(Array.isArray(verdict.ruleTriggers)).toBe(true);
    expect(typeof verdict.timestamp).toBe('string');
    expect(typeof verdict.isStub).toBe('boolean');
  });

  it('returns level: "safe" for a normal https URL', async () => {
    const verdict = await getVerdict('https://example.com');
    expect(verdict.level).toBe('safe');
  });

  it('returns level: "safe" for a normal http URL', async () => {
    const verdict = await getVerdict('http://example.com');
    expect(verdict.level).toBe('safe');
  });

  it('returns isStub: true — Phase 2 can check this to confirm replacement', async () => {
    const verdict = await getVerdict('https://example.com');
    expect(verdict.isStub).toBe(true);
  });

  it('always has at least one reason string (explainability constraint)', async () => {
    const verdict = await getVerdict('https://example.com');
    expect(verdict.reasons.length).toBeGreaterThan(0);
    expect(verdict.reasons[0].length).toBeGreaterThan(0);
  });

  it('returns a valid ISO timestamp', async () => {
    const verdict = await getVerdict('https://example.com');
    const date = new Date(verdict.timestamp);
    expect(date.getTime()).not.toBeNaN();
  });

  it('returns score 0 for the stub', async () => {
    const verdict = await getVerdict('https://example.com');
    expect(verdict.score).toBe(0);
  });

  it('returns empty ruleTriggers for the stub', async () => {
    const verdict = await getVerdict('https://example.com');
    expect(verdict.ruleTriggers).toHaveLength(0);
  });

  it('preserves the original URL in the verdict', async () => {
    const url = 'https://example.com/some/path?query=1';
    const verdict = await getVerdict(url);
    expect(verdict.url).toBe(url);
  });
});

describe('verdictStub.ts — non-applicable URLs', () => {
  const nonApplicable = [
    'chrome://newtab/',
    'chrome-extension://some-id/popup.html',
    'about:blank',
    'data:text/html,<h1>test</h1>',
    '',
  ];

  nonApplicable.forEach((url) => {
    it(`returns level: "not_applicable" for "${url || '(empty string)'}"`, async () => {
      const verdict = await getVerdict(url);
      expect(verdict.level).toBe('not_applicable');
    });
  });

  it('still returns isStub: true for non-applicable URLs', async () => {
    const verdict = await getVerdict('chrome://settings/');
    expect(verdict.isStub).toBe(true);
  });

  it('still has at least one reason for non-applicable URLs', async () => {
    const verdict = await getVerdict('about:blank');
    expect(verdict.reasons.length).toBeGreaterThan(0);
  });
});

describe('verdictStub.ts — function signature contract (Phase 2 compatibility)', () => {
  it('is an async function (returns a Promise)', () => {
    const result = getVerdict('https://example.com');
    expect(result).toBeInstanceOf(Promise);
  });

  it('accepts a URL string parameter', async () => {
    // This test documents the frozen function signature.
    // Phase 2 must keep: getVerdict(url: string): Promise<Verdict>
    const verdict = await getVerdict('https://example.com');
    expect(verdict).toBeDefined();
  });
});
