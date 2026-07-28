/**
 * tests/intelligenceClient.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Vitest tests for background/intelligenceClient.ts.
 * Covers: successful merge, timeout fallback, network error fallback,
 * HTTP error fallback, response parsing, confidence fields.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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

describe('callIntelligence — success path', () => {
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
    expect(result.ml.topContributingFeatures[0].featureName).toBe('has_https');
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

  it('returns ruleEngineVersion from response', async () => {
    mockFetch.mockResolvedValueOnce(makeSuccessResponse());
    const result = await callIntelligence('https://example.com', 5, []);
    expect(result.ruleEngineVersion).toBe('1.0.0');
  });
});

describe('callIntelligence — graceful degradation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns unavailable fallback on network error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Connection refused'));
    const result = await callIntelligence('https://example.com', 10, ['Rule fired.']);
    expect(result.ml.source).toBe('unavailable');
    expect(result.ml.score).toBeNull();
    expect(result.ml.label).toBeNull();
  });

  it('returns unavailable fallback on HTTP 500', async () => {
    mockFetch.mockResolvedValueOnce(makeErrorResponse(500));
    const result = await callIntelligence('https://example.com', 10, ['Rule fired.']);
    expect(result.ml.source).toBe('unavailable');
  });

  it('returns unavailable fallback on HTTP 503', async () => {
    mockFetch.mockResolvedValueOnce(makeErrorResponse(503));
    const result = await callIntelligence('https://example.com', 10, []);
    expect(result.ml.source).toBe('unavailable');
  });

  it('fallback confidence is always low', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));
    const result = await callIntelligence('https://example.com', 90, []);
    expect(result.confidence.level).toBe('low');
    expect(result.confidence.agreement).toBe(false);
  });

  it('fallback preserves rule score in confidence', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));
    const result = await callIntelligence('https://example.com', 80, ['Rule fired.']);
    expect(result.confidence.combinedScore).toBeCloseTo(0.8, 1);
  });

  it('fallback explanation notes ML unavailability', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Offline'));
    const result = await callIntelligence('https://example.com', 0, []);
    expect(result.explanation.mlReasons[0]).toMatch(/unavailable/i);
  });

  it('never rejects — always resolves on timeout (AbortError)', async () => {
    mockFetch.mockRejectedValueOnce(
      Object.assign(new Error('Aborted'), { name: 'AbortError' })
    );
    await expect(
      callIntelligence('https://example.com', 0, [])
    ).resolves.toBeDefined();
  });
});
