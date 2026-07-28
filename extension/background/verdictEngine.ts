/**
 * background/verdictEngine.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 3: Intelligence Layer — wraps Phase 2's pipeline with ML + confidence.
 *
 * Keeps the IDENTICAL function signature:
 *   getVerdict(url: string): Promise<Verdict>
 *
 * Phase 3 Pipeline:
 *   URL → normalizer → heuristics → [reputation + intelligence in parallel]
 *       → phishing detector → risk scorer → confidence scorer → Verdict
 *
 * Phase 1/2 contract:
 * - Verdict.isStub = false ✓
 * - Verdict shape: additive only (all Phase 3 fields optional) ✓
 * - getVerdict() signature unchanged ✓
 * - popup/, options/, content/ — ZERO changes required ✓
 */

import type { Verdict, PageSignals, HeuristicResult } from '../shared/types';
import { NON_APPLICABLE_SCHEMES } from '../shared/constants';
import { normalizeUrl } from '../shared/urlNormalizer';
import { getSettings, isInAllowlist, isInDenylist } from '../shared/storage';
import { analyzeLengthAndEntropy } from './heuristics/lengthAndEntropy';
import { analyzeSuspiciousKeywords } from './heuristics/suspiciousKeywords';
import { analyzeUrlStructure } from './heuristics/urlStructure';
import { analyzeLoginFormSignal } from './heuristics/loginFormSignal';
import { checkReputation, getTopDomainsSet } from './reputationClient';
import { analyzePhishingPatterns } from './phishingDetector';
import { computeScore, buildVerdict } from './riskScorer';
import { callIntelligence } from './intelligenceClient';

/**
 * Compute a real, explainable Verdict for the given URL.
 *
 * @param url - Raw URL of the tab to analyze
 * @param pageSignals - Optional signals from the content script
 * @returns Always resolves (never rejects) with a Verdict
 */
export async function getVerdict(
  url: string,
  pageSignals: PageSignals | null = null
): Promise<Verdict> {
  // ── 1. Not-applicable URLs ────────────────────────────────────────────────
  if (!url || isNonApplicableUrl(url)) {
    return makeNotApplicableVerdict(url);
  }

  // ── 2. Normalize URL ──────────────────────────────────────────────────────
  const normalizedUrl = normalizeUrl(url);
  if (!normalizedUrl) {
    return makeErrorVerdict(url, 'URL could not be parsed.');
  }

  // ── 3. Load user settings ─────────────────────────────────────────────────
  const settings = await getSettings();

  // ── 4. Allowlist short-circuit ────────────────────────────────────────────
  if (isInAllowlist(normalizedUrl.registeredDomain, settings)) {
    return {
      url: normalizedUrl.normalized,
      level: 'safe',
      score: 0,
      reasons: [`Domain "${normalizedUrl.registeredDomain}" is in your trusted allowlist.`],
      ruleTriggers: [],
      timestamp: new Date().toISOString(),
      isStub: false,
      heuristics: [],
      reputation: undefined,
      phishingPatterns: [],
    };
  }

  // ── 5. Denylist short-circuit ────────────────────────────────────────────
  if (isInDenylist(normalizedUrl.registeredDomain, settings)) {
    return {
      url: normalizedUrl.normalized,
      level: 'dangerous',
      score: 100,
      reasons: [`Domain "${normalizedUrl.registeredDomain}" is in your blocked denylist.`],
      ruleTriggers: [],
      timestamp: new Date().toISOString(),
      isStub: false,
      heuristics: [],
      reputation: undefined,
      phishingPatterns: [],
    };
  }

  // ── 6. Build trusted domains set (top domains + user allowlist) ───────────
  const topDomains = getTopDomainsSet();
  const trustedDomains: Set<string> = new Set([
    ...topDomains,
    ...settings.allowlist,
  ]);

  // ── 7. Run heuristics (all independent, could run in parallel) ───────────
  const heuristics: HeuristicResult[] = [
    analyzeLengthAndEntropy(normalizedUrl, pageSignals),
    analyzeSuspiciousKeywords(normalizedUrl, pageSignals),
    analyzeUrlStructure(normalizedUrl, pageSignals),
    analyzeLoginFormSignal(normalizedUrl, pageSignals, trustedDomains),
  ];

  // ── 8. Parallel: reputation lookup + intelligence (ML + rule engine) ────────
  const scorerInputPrep = {
    url: normalizedUrl.normalized,
    heuristics,
    reputation: null as any,
    phishingPatterns: [] as any[],
  };
  // Pre-compute an initial rule score for the intelligence client fallback
  const preScore = computeScore({ ...scorerInputPrep, reputation: { domain: '', knownMalicious: false, source: 'unavailable' as const, lastChecked: new Date().toISOString(), confidence: 0 } });

  const [reputation, intelligence] = await Promise.all([
    checkReputation(normalizedUrl.registeredDomain),
    callIntelligence(url, preScore.score, preScore.reasons),
  ]);

  // ── 9. Phishing pattern analysis ─────────────────────────────────────────
  const phishingPatterns = analyzePhishingPatterns(
    normalizedUrl,
    heuristics,
    pageSignals,
    reputation
  );

  // ── 10. Risk scoring ──────────────────────────────────────────────────────
  const scorerInput = {
    url: normalizedUrl.normalized,
    heuristics,
    reputation,
    phishingPatterns,
  };
  const scorerOutput = computeScore(scorerInput);

  // ── 11. Build Phase 2 Verdict base ───────────────────────────────────────
  const baseVerdict = buildVerdict(
    normalizedUrl.normalized,
    scorerInput,
    scorerOutput,
    heuristics,
    reputation,
    phishingPatterns
  );

  // ── 12. Augment with Phase 3 intelligence fields ──────────────────────────
  return {
    ...baseVerdict,
    ml: intelligence.ml,
    ruleEngineVersion: intelligence.ruleEngineVersion,
    confidence: intelligence.confidence,
    explanation: intelligence.explanation,
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function isNonApplicableUrl(url: string): boolean {
  if (!url) return true;
  const lc = url.toLowerCase();
  return NON_APPLICABLE_SCHEMES.some((scheme) => lc.startsWith(scheme));
}

function makeNotApplicableVerdict(url: string): Verdict {
  return {
    url,
    level: 'not_applicable',
    score: 0,
    reasons: ['This type of page is not analyzed by SafeClick.'],
    ruleTriggers: [],
    timestamp: new Date().toISOString(),
    isStub: false,
  };
}

function makeErrorVerdict(url: string, detail: string): Verdict {
  return {
    url,
    level: 'unknown',
    score: 0,
    reasons: [`Analysis could not complete: ${detail}`],
    ruleTriggers: [],
    timestamp: new Date().toISOString(),
    isStub: false,
  };
}
