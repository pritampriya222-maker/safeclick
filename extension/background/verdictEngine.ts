/**
 * background/verdictEngine.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 2: Real threat detection engine.
 * Replaces verdictStub.ts internals while keeping the IDENTICAL function signature:
 *
 *   getVerdict(url: string): Promise<Verdict>
 *
 * Pipeline:
 *   URL → normalizer → heuristics (parallel) → reputation client → phishing detector → risk scorer → Verdict
 *
 * Consumers (tabTracker.ts) require ONE import change: verdictStub → verdictEngine.
 * popup/, options/, content/ — ZERO changes required.
 *
 * Phase 1 contract verification:
 * - Verdict.isStub is now false for all real verdicts ✓
 * - Verdict shape is identical to Phase 1 (additive fields only) ✓
 * - getVerdict() signature unchanged ✓
 */

import type { Verdict, PageSignals, HeuristicResult } from '../shared/types';
import { NON_APPLICABLE_SCHEMES, HEURISTIC_WEIGHTS } from '../shared/constants';
import { normalizeUrl } from '../shared/urlNormalizer';
import { getSettings, isInAllowlist, isInDenylist } from '../shared/storage';
import { analyzeLengthAndEntropy } from './heuristics/lengthAndEntropy';
import { analyzeSuspiciousKeywords } from './heuristics/suspiciousKeywords';
import { analyzeUrlStructure } from './heuristics/urlStructure';
import { analyzeLoginFormSignal } from './heuristics/loginFormSignal';
import { checkReputation, getTopDomainsSet, isTopDomain } from './reputationClient';
import { analyzePhishingPatterns } from './phishingDetector';
import { computeScore, buildVerdict } from './riskScorer';

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

  // ── 8. Reputation lookup (gracefully degrades) ────────────────────────────
  const reputation = await checkReputation(normalizedUrl.registeredDomain);

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

  // ── 11. Build final Verdict ───────────────────────────────────────────────
  return buildVerdict(
    normalizedUrl.normalized,
    scorerInput,
    scorerOutput,
    heuristics,
    reputation,
    phishingPatterns
  );
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
