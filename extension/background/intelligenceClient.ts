/**
 * extension/background/intelligenceClient.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 3: calls POST /api/v1/predict and returns a typed MlVerdict.
 *
 * Design decisions (documented in docs/architecture.md):
 * - Merge (confidence scoring) is done CLIENT-SIDE here, not as a separate
 *   backend endpoint, to avoid an extra round-trip and keep verdict latency low.
 * - Timeout: 1000ms (stricter than reputation client's 800ms since this
 *   endpoint also runs the rule engine server-side).
 * - Graceful degradation: any error → returns {source:'unavailable'} — the
 *   verdict is produced from Phase 2 rules alone with confidence='low'.
 */

import type { MlVerdict, ConfidenceInfo, ExplanationInfo, FeatureContribution } from '../shared/types';
import { API_BASE_URL } from '../shared/constants';

const INTELLIGENCE_TIMEOUT_MS = 1000;

// ── Response shape from /api/v1/predict ───────────────────────────────────────

interface PredictApiFeature {
  feature_name: string;
  label: string;
  value: number;
  contribution: number;
}

interface PredictApiConfidence {
  level: 'high' | 'medium' | 'low';
  agreement: boolean;
  combined_score: number;
  note: string;
}

interface PredictApiExplanation {
  summary: string;
  rule_reasons: string[];
  ml_reasons: string[];
}

interface PredictApiResponse {
  ml_score: number | null;
  ml_label: 'phishing' | 'benign' | null;
  model_version: string;
  top_contributing_features: PredictApiFeature[];
  source: 'model' | 'unavailable';
  latency_ms: number;
  rule_score: number;
  rule_reasons: string[];
  rule_engine_version: string;
  confidence: PredictApiConfidence;
  explanation: PredictApiExplanation;
}

// ── Returned structure ────────────────────────────────────────────────────────

export interface IntelligenceResult {
  ml: MlVerdict;
  ruleEngineVersion: string;
  ruleScore: number;
  ruleReasons: string[];
  confidence: ConfidenceInfo;
  explanation: ExplanationInfo;
}

// ── Unavailable fallback ──────────────────────────────────────────────────────

function unavailableFallback(ruleScore: number, ruleReasons: string[]): IntelligenceResult {
  return {
    ml: {
      score: null,
      label: null,
      modelVersion: '1.0.0',
      topContributingFeatures: [],
      source: 'unavailable',
    },
    ruleEngineVersion: 'unavailable',
    ruleScore,
    ruleReasons,
    confidence: {
      level: 'low',
      agreement: false,
      combinedScore: ruleScore / 100,
      note: 'ML backend unavailable — verdict based on local rules only.',
    },
    explanation: {
      summary: 'ML intelligence backend is unreachable. Using local rules only.',
      ruleReasons,
      mlReasons: ['ML model unavailable — rule engine only.'],
    },
  };
}

// ── Main call ─────────────────────────────────────────────────────────────────

/**
 * Call /api/v1/predict for a URL. Always resolves — never rejects.
 * On any error (timeout, network, parse), returns an unavailable fallback.
 *
 * @param url           The full URL to analyze.
 * @param ruleScore     The Phase 2 rule score (0–100) for fallback confidence.
 * @param ruleReasons   The Phase 2 rule reasons for fallback explanation.
 */
export async function callIntelligence(
  url: string,
  ruleScore: number,
  ruleReasons: string[],
): Promise<IntelligenceResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), INTELLIGENCE_TIMEOUT_MS);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      console.warn(`[SafeClick] Intelligence backend returned ${response.status}`);
      return unavailableFallback(ruleScore, ruleReasons);
    }

    const data: PredictApiResponse = await response.json();

    const features: FeatureContribution[] = (data.top_contributing_features ?? []).map((f) => ({
      featureName: f.feature_name,
      label: f.label,
      value: f.value,
      contribution: f.contribution,
    }));

    const ml: MlVerdict = {
      score: data.ml_score,
      label: data.ml_label,
      modelVersion: data.model_version,
      topContributingFeatures: features,
      source: data.source,
    };

    const confidence: ConfidenceInfo = {
      level: data.confidence.level,
      agreement: data.confidence.agreement,
      combinedScore: data.confidence.combined_score,
      note: data.confidence.note,
    };

    const explanation: ExplanationInfo = {
      summary: data.explanation.summary,
      ruleReasons: data.explanation.rule_reasons,
      mlReasons: data.explanation.ml_reasons,
    };

    return {
      ml,
      ruleEngineVersion: data.rule_engine_version,
      ruleScore: data.rule_score,
      ruleReasons: data.rule_reasons,
      confidence,
      explanation,
    };
  } catch (err) {
    clearTimeout(timer);
    if ((err as Error).name === 'AbortError') {
      console.warn('[SafeClick] Intelligence client timed out — falling back to local rules.');
    } else {
      console.warn('[SafeClick] Intelligence client error:', err);
    }
    return unavailableFallback(ruleScore, ruleReasons);
  }
}
