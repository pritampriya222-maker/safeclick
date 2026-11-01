/**
 * extension/background/intelligenceClient.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 3 + Hybrid ML: calls POST /api/v1/predict if backend is running,
 * and automatically falls back to the in-browser XGBoost model (localMlModel.ts)
 * if the backend is offline or unreachable.
 *
 * This ensures full ML classification and High Confidence even when running
 * completely offline with zero Python backend!
 */

import type { MlVerdict, ConfidenceInfo, ExplanationInfo, FeatureContribution } from '../shared/types';
import { API_BASE_URL } from '../shared/constants';
import { predictLocal, type LocalMlResult } from './ml/localMlModel';

const INTELLIGENCE_TIMEOUT_MS = 600;

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

// ── In-browser local ML fallback ──────────────────────────────────────────────

function localMlFallback(url: string, ruleScore: number, ruleReasons: string[]): IntelligenceResult {
  const localMl = predictLocal(url);

  if (!localMl) {
    return {
      ml: {
        score: null,
        label: null,
        modelVersion: '1.0.0',
        topContributingFeatures: [],
        source: 'unavailable',
      },
      ruleEngineVersion: '1.0.0',
      ruleScore,
      ruleReasons,
      confidence: {
        level: 'medium',
        agreement: true,
        combinedScore: ruleScore / 100,
        note: 'Verdict computed via built-in heuristic rules.',
      },
      explanation: {
        summary: 'Analyzed by built-in heuristic rule engine.',
        ruleReasons: ruleReasons.length ? ruleReasons : ['No suspicious patterns detected.'],
        mlReasons: [],
      },
    };
  }

  // Calculate agreement between rule score (0-100) and ML score (0.0-1.0)
  const ruleFraction = ruleScore / 100;
  const mlFraction = localMl.ml_score;
  const scoreDiff = Math.abs(ruleFraction - mlFraction);
  const agreement = scoreDiff < 0.35;

  const combinedScore = Math.round((0.5 * ruleFraction + 0.5 * mlFraction) * 1000) / 1000;
  let confidenceLevel: 'high' | 'medium' | 'low' = 'high';
  if (!agreement) {
    confidenceLevel = 'medium';
  }

  let summary = 'Analyzed by built-in ML classifier and heuristic rule engine.';
  if (ruleScore >= 70 || localMl.ml_score >= 0.7) {
    summary = 'Flagged as high-risk by built-in ML classifier and heuristic rules.';
  } else if (ruleScore <= 20 && localMl.ml_score <= 0.2) {
    summary = 'Verified safe by built-in ML classifier and heuristic rules.';
  }

  return {
    ml: {
      score: localMl.ml_score,
      label: localMl.ml_label,
      modelVersion: localMl.model_version,
      topContributingFeatures: localMl.top_contributing_features,
      source: 'model',
      latencyMs: localMl.latency_ms,
    },
    ruleEngineVersion: '1.0.0 (in-browser)',
    ruleScore,
    ruleReasons,
    confidence: {
      level: confidenceLevel,
      agreement,
      combinedScore,
      note: agreement
        ? 'In-browser ML model and heuristic rules are in strong agreement.'
        : 'Slight variance between ML probability and heuristic triggers.',
    },
    explanation: {
      summary,
      ruleReasons: ruleReasons.length ? ruleReasons : ['No heuristic threat rules triggered.'],
      mlReasons: [
        `In-browser XGBoost model evaluated 22 features (risk probability: ${Math.round(localMl.ml_score * 100)}%).`,
      ],
    },
  };
}

// ── Main call ─────────────────────────────────────────────────────────────────

/**
 * Call /api/v1/predict for a URL. If backend is offline or times out,
 * seamlessly evaluates using the in-browser XGBoost decision tree model.
 */
export async function callIntelligence(
  url: string,
  ruleScore: number = 0,
  ruleReasons: string[] = []
): Promise<IntelligenceResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), INTELLIGENCE_TIMEOUT_MS);

    const response = await fetch(`${API_BASE_URL}/api/v1/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return localMlFallback(url, ruleScore, ruleReasons);
    }

    const data = (await response.json()) as PredictApiResponse;

    if (data.source === 'unavailable' || data.ml_score === null) {
      return localMlFallback(url, ruleScore, ruleReasons);
    }

    return {
      ml: {
        score: data.ml_score,
        label: data.ml_label,
        modelVersion: data.model_version,
        topContributingFeatures: (data.top_contributing_features || []).map((f) => ({
          feature_name: f.feature_name,
          label: f.label,
          value: f.value,
          contribution: f.contribution,
        })),
        source: data.source,
        latencyMs: data.latency_ms,
      },
      ruleEngineVersion: data.rule_engine_version,
      ruleScore: data.rule_score,
      ruleReasons: data.rule_reasons,
      confidence: {
        level: data.confidence.level,
        agreement: data.confidence.agreement,
        combinedScore: data.confidence.combined_score,
        note: data.confidence.note,
      },
      explanation: {
        summary: data.explanation.summary,
        ruleReasons: data.explanation.rule_reasons,
        mlReasons: data.explanation.ml_reasons,
      },
    };
  } catch (err) {
    // Seamless in-browser fallback
    return localMlFallback(url, ruleScore, ruleReasons);
  }
}
