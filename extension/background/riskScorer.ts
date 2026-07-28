/**
 * background/riskScorer.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Transparent, weighted risk scoring function.
 *
 * NOT a black box: every contribution is documented, named, and exposed
 * in the Verdict's reasons array. Users and auditors can see exactly why
 * a score was assigned.
 *
 * Algorithm:
 *   score = Σ (triggered_heuristic.weight) + reputation_bonus + phishing_bonus
 *   score = clip(score, 0, 100)
 *   level = 'safe' if score ≤ 29
 *           'suspicious' if 30 ≤ score ≤ 69
 *           'dangerous' if score ≥ 70
 *
 * Reasons are ordered by contribution descending — most impactful first.
 */

import type { HeuristicResult, ReputationResult, PhishingPattern, Verdict, RuleTrigger, VerdictLevel } from '../shared/types';
import { RISK_THRESHOLDS, HEURISTIC_WEIGHTS } from '../shared/constants';

export interface ScorerInput {
  url: string;
  heuristics: HeuristicResult[];
  reputation: ReputationResult | null;
  phishingPatterns: PhishingPattern[];
}

export interface ScorerOutput {
  score: number;
  level: VerdictLevel;
  reasons: string[];
  ruleTriggers: RuleTrigger[];
}

/**
 * Compute the final risk score and verdict from all signals.
 * Always returns; never throws.
 */
export function computeScore(input: ScorerInput): ScorerOutput {
  const contributions: Array<{ weight: number; reason: string; ruleId: string; name: string }> = [];

  // ── 1. Heuristic contributions ────────────────────────────────────────────
  for (const h of input.heuristics) {
    if (h.triggered) {
      contributions.push({
        weight: h.weight,
        reason: h.explanation,
        ruleId: h.ruleId,
        name: h.name,
      });
    }
  }

  // ── 2. Reputation contribution ────────────────────────────────────────────
  if (input.reputation?.knownMalicious) {
    const reputationWeight = Math.round(
      HEURISTIC_WEIGHTS.REPUTATION_MALICIOUS * (input.reputation.confidence || 1)
    );
    contributions.push({
      weight: reputationWeight,
      reason: `Domain flagged as malicious by ${formatSource(input.reputation.source)}` +
        (input.reputation.detail ? ` (${input.reputation.detail})` : ''),
      ruleId: 'reputation:malicious',
      name: 'Reputation: Known Malicious Domain',
    });
  }

  // ── 3. Phishing pattern contributions ────────────────────────────────────
  for (const pattern of input.phishingPatterns) {
    contributions.push({
      weight: pattern.weight,
      reason: pattern.explanation,
      ruleId: pattern.patternId,
      name: pattern.name,
    });
  }

  // ── 4. Sort by weight descending (most impactful first) ───────────────────
  contributions.sort((a, b) => b.weight - a.weight);

  // ── 5. Sum and clip ───────────────────────────────────────────────────────
  const rawScore = contributions.reduce((sum, c) => sum + c.weight, 0);
  const score = Math.min(100, Math.max(0, rawScore));

  // ── 6. Determine level ────────────────────────────────────────────────────
  const level = scoreToLevel(score);

  // ── 7. Build reasons and rule triggers ───────────────────────────────────
  const reasons: string[] = contributions.length > 0
    ? contributions.map((c) => c.reason)
    : [score === 0 ? 'No threat signals detected.' : 'Unknown risk.'];

  const ruleTriggers: RuleTrigger[] = contributions.map((c) => ({
    ruleId: c.ruleId,
    name: c.name,
    triggered: true,
    weight: c.weight,
    explanation: c.reason,
  }));

  // Also include non-triggered heuristics in ruleTriggers for auditability
  for (const h of input.heuristics) {
    if (!h.triggered) {
      ruleTriggers.push({
        ruleId: h.ruleId,
        name: h.name,
        triggered: false,
        weight: h.weight,
        explanation: h.explanation,
      });
    }
  }

  return { score, level, reasons, ruleTriggers };
}

/**
 * Build a full Verdict from scorer input + output.
 * This is the function called by verdictEngine.ts.
 */
export function buildVerdict(
  url: string,
  input: ScorerInput,
  output: ScorerOutput,
  heuristics: HeuristicResult[],
  reputation: ReputationResult | null,
  phishingPatterns: PhishingPattern[]
): Verdict {
  return {
    url,
    level: output.level,
    score: output.score,
    reasons: output.reasons,
    ruleTriggers: output.ruleTriggers,
    timestamp: new Date().toISOString(),
    isStub: false,
    heuristics,
    reputation: reputation ?? undefined,
    phishingPatterns: phishingPatterns.length > 0 ? phishingPatterns : undefined,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreToLevel(score: number): VerdictLevel {
  if (score <= RISK_THRESHOLDS.SAFE_MAX) return 'safe';
  if (score <= RISK_THRESHOLDS.SUSPICIOUS_MAX) return 'suspicious';
  return 'dangerous';
}

function formatSource(source: ReputationResult['source']): string {
  const labels: Record<ReputationResult['source'], string> = {
    virustotal: 'VirusTotal',
    openphish: 'OpenPhish',
    local_blocklist: 'local blocklist',
    top_domain_list: 'trusted domain list',
    unavailable: 'reputation service (unavailable)',
    cache: 'reputation cache',
  };
  return labels[source] ?? source;
}
