/**
 * tests/intelligenceClient.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Vitest tests for background/intelligenceClient.ts.
 * Covers: backend API call, seamless in-browser XGBoost ML fallback when offline,
 * confidence scoring, and explanation generation.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { callIntelligence } from '../background/intelligenceClient';

// ── Mock global fetch ──────────────────────────────────────────────────────────

const mockFetch = vi.fn();
global.fetch = mockFetch;

function makeSuccessResponse(overrides: Partial<Record<string, unknown>> = {}): Response {
  const body = JSON.stringify({
    ml_score: 0.04,
    ml_label: 'benign',
    model_version: '1.0.0',
    top_contributing_features: [
      { feature_name: 'has_https', label: 'Uses HTTPS', value: 1.0, contribution: -0.12 },
    ],
    source: 'model',
    latency_ms: 38.2,
    rule_score: 5,
    rule_reasons: ['No rule-based threat signals detected.'],
    rule_engine_version: '1.0.0',
    confidence: {
      level: 'high',
      agreement: true,
      combined_score: 0.045,
      note: 'Rule engine and ML model are in strong agreement.',
    },
    explanation: {
      summary: 'This URL appears safe based on rule analysis and ML model.',
      rule_reasons: ['No rule-based threat signals detected.'],
      ml_reasons: ['ML model found no strong phishing features.'],
    },
    ...overrides,
  });

  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function makeErrorResponse(status: number): Response {
  return new Response('{}', { status });
}

describe('callIntelligence — success path (backend online)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns MlVerdict fields from API response', async () => {
    mockFetch.mockResolvedValueOnce(makeSuccessResponse());
    const result = await callIntelligence('https://example.com', 5, ['Clean.']);
    expect(result.ml.score).toBe(0.04);
    expect(result.ml.label).toBe('benign');
    expect(result.ml.modelVersion).toBe('1.0.0');
    expect(result.ml.source).toBe('model');
  });

  it('maps top_contributing_features to FeatureContribution[]', async () => {
    mockFetch.mockResolvedValueOnce(makeSuccessResponse());
    const result = await callIntelligence('https://example.com', 5, []);
    expect(result.ml.topContributingFeatures).toHaveLength(1);
    expect(result.ml.topContributingFeatures[0].feature_name).toBe('has_https');
    expect(result.ml.topContributingFeatures[0].contribution).toBe(-0.12);
  });

  it('returns confidence fields correctly', async () => {
    mockFetch.mockResolvedValueOnce(makeSuccessResponse());
    const result = await callIntelligence('https://example.com', 5, []);
    expect(result.confidence.level).toBe('high');
    expect(result.confidence.agreement).toBe(true);
    expect(result.confidence.combinedScore).toBe(0.045);
  });

  it('returns explanation fields correctly', async () => {
    mockFetch.mockResolvedValueOnce(makeSuccessResponse());
    const result = await callIntelligence('https://example.com', 5, []);
    expect(result.explanation.summary).toContain('safe');
    expect(result.explanation.ruleReasons).toHaveLength(1);
    expect(result.explanation.mlReasons).toHaveLength(1);
  });
});

describe('callIntelligence — in-browser ML fallback (backend offline)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('evaluates URL with in-browser XGBoost model on network error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Connection refused'));
    const result = await callIntelligence('https://google.com', 0, ['Top domain.']);
    expect(result.ml.source).toBe('model');
    expect(result.ml.score).toBeLessThan(0.3);
    expect(result.ml.label).toBe('benign');
    expect(result.confidence.level).toBe('high');
    expect(result.explanation.summary).toContain('safe');
  });

  it('correctly scores suspicious phishing URL with in-browser ML model', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Backend offline'));
    const result = await callIntelligence('http://paypal-verification.security-account.tk/login', 80, ['Suspicious brand match']);
    expect(result.ml.source).toBe('model');
    expect(result.ml.score).toBeGreaterThan(0.5);
    expect(result.ml.label).toBe('phishing');
    expect(result.explanation.summary).toContain('high-risk');
  });

  it('falls back to in-browser ML on HTTP 500 error', async () => {
    mockFetch.mockResolvedValueOnce(makeErrorResponse(500));
    const result = await callIntelligence('https://github.com', 0, []);
    expect(result.ml.source).toBe('model');
    expect(result.ml.label).toBe('benign');
  });

  it('never rejects — always resolves on timeout (AbortError)', async () => {
    mockFetch.mockRejectedValueOnce(
      Object.assign(new Error('Aborted'), { name: 'AbortError' })
    );
    const result = await callIntelligence('https://example.com', 0, []);
    expect(result).toBeDefined();
    expect(result.ml.source).toBe('model');
  });
});
