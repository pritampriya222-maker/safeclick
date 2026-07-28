/**
 * tests/riskScorer.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for background/riskScorer.ts.
 * Covers: safe/suspicious/dangerous score scenarios, reasons ordering,
 * reputation contribution, phishing pattern contribution, clipping.
 */

import { describe, it, expect } from 'vitest';
import { computeScore } from '../background/riskScorer';
import type { HeuristicResult, ReputationResult, PhishingPattern } from '../shared/types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeHeuristic(
  ruleId: string,
  triggered: boolean,
  weight: number,
  explanation = 'Test explanation.'
): HeuristicResult {
  return {
    ruleId,
    name: ruleId,
    triggered,
    weight,
    explanation,
  };
}

function makeReputation(knownMalicious: boolean, confidence = 0.9): ReputationResult {
  return {
    domain: 'test.com',
    knownMalicious,
    source: 'openphish',
    lastChecked: new Date().toISOString(),
    confidence,
    detail: knownMalicious ? 'Found in phishing feed.' : 'Clean.',
  };
}

function makePhishingPattern(patternId: string, weight: number): PhishingPattern {
  return {
    patternId,
    name: patternId,
    weight,
    explanation: `Pattern ${patternId} detected.`,
  };
}

// ─── Score levels ─────────────────────────────────────────────────────────────

describe('computeScore — verdict levels', () => {
  it('returns "safe" when no heuristics trigger and no reputation issues', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [makeHeuristic('h1', false, 20), makeHeuristic('h2', false, 15)],
      reputation: makeReputation(false),
      phishingPatterns: [],
    });
    expect(result.level).toBe('safe');
    expect(result.score).toBe(0);
  });

  it('returns "suspicious" when some heuristics trigger (score 30–69)', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [
        makeHeuristic('h1', true, 20),
        makeHeuristic('h2', true, 15),
        makeHeuristic('h3', false, 20),
      ],
      reputation: makeReputation(false),
      phishingPatterns: [],
    });
    expect(result.level).toBe('suspicious');
    expect(result.score).toBe(35);
  });

  it('returns "dangerous" when score ≥ 70', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [makeHeuristic('h1', true, 40)],
      reputation: makeReputation(true, 1.0),  // +40 from reputation
      phishingPatterns: [],
    });
    expect(result.level).toBe('dangerous');
    expect(result.score).toBeGreaterThanOrEqual(70);
  });
});

describe('computeScore — score arithmetic', () => {
  it('sums triggered heuristic weights', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [
        makeHeuristic('h1', true, 15),
        makeHeuristic('h2', true, 20),
        makeHeuristic('h3', false, 25), // not triggered
      ],
      reputation: null,
      phishingPatterns: [],
    });
    expect(result.score).toBe(35);
  });

  it('clips score to maximum 100', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [makeHeuristic('h1', true, 60), makeHeuristic('h2', true, 60)],
      reputation: makeReputation(true, 1.0),
      phishingPatterns: [makePhishingPattern('p1', 35)],
    });
    expect(result.score).toBe(100);
  });

  it('clips score to minimum 0', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [],
      reputation: makeReputation(false),
      phishingPatterns: [],
    });
    expect(result.score).toBe(0);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  it('adds phishing pattern weights', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [],
      reputation: null,
      phishingPatterns: [makePhishingPattern('p1', 35), makePhishingPattern('p2', 20)],
    });
    expect(result.score).toBe(55);
  });
});

describe('computeScore — reasons', () => {
  it('returns at least one reason string', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [],
      reputation: null,
      phishingPatterns: [],
    });
    expect(result.reasons.length).toBeGreaterThan(0);
    expect(result.reasons[0].length).toBeGreaterThan(0);
  });

  it('orders reasons by contribution descending', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [
        makeHeuristic('small', true, 10, 'Small heuristic triggered.'),
        makeHeuristic('large', true, 30, 'Large heuristic triggered.'),
      ],
      reputation: null,
      phishingPatterns: [],
    });
    // First reason should be the large one (weight 30 > weight 10)
    expect(result.reasons[0]).toContain('Large heuristic');
    expect(result.reasons[1]).toContain('Small heuristic');
  });

  it('includes reputation reason when known malicious', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [],
      reputation: makeReputation(true),
      phishingPatterns: [],
    });
    expect(result.reasons.some((r) => r.toLowerCase().includes('malicious'))).toBe(true);
  });

  it('includes phishing pattern explanation in reasons', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [],
      reputation: null,
      phishingPatterns: [makePhishingPattern('phishing:typosquatting', 35)],
    });
    expect(result.reasons.some((r) => r.includes('phishing:typosquatting'))).toBe(true);
  });
});

describe('computeScore — ruleTriggers', () => {
  it('includes triggered heuristics in ruleTriggers with triggered=true', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [makeHeuristic('h:test', true, 20)],
      reputation: null,
      phishingPatterns: [],
    });
    const trigger = result.ruleTriggers.find((t) => t.ruleId === 'h:test');
    expect(trigger).toBeDefined();
    expect(trigger?.triggered).toBe(true);
  });

  it('includes non-triggered heuristics in ruleTriggers with triggered=false', () => {
    const result = computeScore({
      url: 'https://example.com',
      heuristics: [makeHeuristic('h:notfired', false, 20)],
      reputation: null,
      phishingPatterns: [],
    });
    const trigger = result.ruleTriggers.find((t) => t.ruleId === 'h:notfired');
    expect(trigger).toBeDefined();
    expect(trigger?.triggered).toBe(false);
  });
});
