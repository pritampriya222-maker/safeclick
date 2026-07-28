/**
 * background/phishingDetector.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Phishing-specific detection patterns beyond generic heuristics.
 *
 * Implements:
 * 1. Typosquatting — Damerau-Levenshtein distance ≤2 against known brand domains
 * 2. IDN homograph / confusable character detection
 * 3. Suspicious TLD combined with brand keyword
 *
 * All checks are pure functions — no network calls, no shared mutable state.
 */

import type { NormalizedUrl, ReputationResult, HeuristicResult, PhishingPattern, PageSignals } from '../shared/types';
import {
  HEURISTIC_WEIGHTS, KNOWN_BRAND_DOMAINS, SUSPICIOUS_TLDS,
  URL_ANALYSIS, SUSPICIOUS_BRAND_KEYWORDS,
} from '../shared/constants';

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Analyze a normalized URL for specific phishing patterns.
 * Returns an array of triggered PhishingPattern objects.
 *
 * @param normalizedUrl  - Output of urlNormalizer.ts
 * @param _heuristics    - Heuristic results (reserved for future cross-heuristic logic)
 * @param _pageSignals   - Page signals (reserved)
 * @param _reputation    - Reputation result (reserved for combined checks in Phase 3)
 */
export function analyzePhishingPatterns(
  normalizedUrl: NormalizedUrl,
  _heuristics: HeuristicResult[],
  _pageSignals: PageSignals | null,
  _reputation: ReputationResult | null
): PhishingPattern[] {
  const patterns: PhishingPattern[] = [];

  // 1. Typosquatting
  const typosquatPattern = checkTyposquatting(normalizedUrl);
  if (typosquatPattern) patterns.push(typosquatPattern);

  // 2. IDN homograph / confusable characters
  if (normalizedUrl.isIDN || normalizedUrl.isPunycode) {
    const homographPattern = checkHomograph(normalizedUrl);
    if (homographPattern) patterns.push(homographPattern);
  }

  // 3. Suspicious TLD + brand keyword
  const suspiciousTldPattern = checkSuspiciousTldWithBrand(normalizedUrl);
  if (suspiciousTldPattern) patterns.push(suspiciousTldPattern);

  return patterns;
}

// ─── Pattern 1: Typosquatting ─────────────────────────────────────────────────

/**
 * Check if the registered domain is within Levenshtein distance ≤2 of a
 * known brand domain BUT IS NOT that brand's domain.
 *
 * e.g. "paypall.com" vs "paypal.com" → distance 1 → typosquatting
 */
function checkTyposquatting(normalizedUrl: NormalizedUrl): PhishingPattern | null {
  const { registeredDomain } = normalizedUrl;

  for (const brandDomain of KNOWN_BRAND_DOMAINS) {
    // Skip if it IS the brand domain
    if (registeredDomain === brandDomain) continue;

    const distance = damerauLevenshtein(registeredDomain, brandDomain);
    if (distance <= URL_ANALYSIS.TYPOSQUAT_DISTANCE) {
      return {
        patternId: 'phishing:typosquatting',
        name: 'Typosquatting',
        weight: HEURISTIC_WEIGHTS.PHISHING_TYPOSQUAT,
        explanation: `Domain "${registeredDomain}" is suspiciously similar to the legitimate brand domain "${brandDomain}" (edit distance: ${distance}).`,
      };
    }
  }

  return null;
}

// ─── Pattern 2: IDN Homograph / Confusable Characters ────────────────────────

/**
 * Map of Unicode characters that are visually confusable with ASCII.
 * This is a carefully curated subset — Phase 3's ML can extend this.
 * Source: Unicode Consortium confusables.txt (key pairs only)
 */
const CONFUSABLES: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', // Cyrillic
  'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'ν': 'n',             // Greek
  'ì': 'i', 'í': 'i', 'ï': 'i', 'î': 'i',                       // Accented
  'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a',
  'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
  'ò': 'o', 'ó': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o',
  'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',             // Digit-letter
  'ℬ': 'b', 'ℭ': 'c', 'ℱ': 'f', 'ℊ': 'g',
};

/**
 * Check if the IDN hostname, when confusables are normalized, matches a
 * known brand domain — a homograph attack.
 */
function checkHomograph(normalizedUrl: NormalizedUrl): PhishingPattern | null {
  const { hostname, registeredDomain } = normalizedUrl;

  // Normalize confusables in the hostname
  const normalized = Array.from(hostname)
    .map((ch) => CONFUSABLES[ch] ?? ch)
    .join('');

  // Check if the confusable-normalized hostname matches a brand domain
  for (const brandDomain of KNOWN_BRAND_DOMAINS) {
    if (normalized.includes(brandDomain) && !hostname.includes(brandDomain)) {
      return {
        patternId: 'phishing:homograph',
        name: 'IDN Homograph Attack',
        weight: HEURISTIC_WEIGHTS.PHISHING_HOMOGRAPH,
        explanation: `Domain "${registeredDomain}" uses visually similar Unicode characters to impersonate "${brandDomain}".`,
      };
    }
  }

  return null;
}

// ─── Pattern 3: Suspicious TLD + Brand Keyword ───────────────────────────────

/**
 * Flag a URL where:
 * - The TLD is in the suspicious TLD list (cheap/free TLDs)
 * - AND the domain or path contains a brand keyword
 *
 * e.g. "paypal-login.tk" or "microsoft-verify.xyz"
 */
function checkSuspiciousTldWithBrand(normalizedUrl: NormalizedUrl): PhishingPattern | null {
  const { registeredDomain, path } = normalizedUrl;

  // Check if TLD is suspicious
  const hasSuspiciousTld = SUSPICIOUS_TLDS.some((tld) =>
    registeredDomain.endsWith(tld)
  );

  if (!hasSuspiciousTld) return null;

  // Check if domain or path contains a brand keyword
  const target = `${registeredDomain}${path}`.toLowerCase();
  const matchedBrand = SUSPICIOUS_BRAND_KEYWORDS.find((brand) => target.includes(brand));

  if (!matchedBrand) return null;

  const tld = '.' + registeredDomain.split('.').pop()!;

  return {
    patternId: 'phishing:suspicious_tld_brand',
    name: 'Suspicious TLD with Brand Keyword',
    weight: HEURISTIC_WEIGHTS.PHISHING_SUSPICIOUS_TLD,
    explanation: `Domain uses a cheap/free TLD ("${tld}") combined with the brand keyword "${matchedBrand}" — a common phishing tactic.`,
  };
}

// ─── Damerau-Levenshtein Distance ────────────────────────────────────────────

/**
 * Compute Damerau-Levenshtein distance between two strings.
 * More accurate than basic Levenshtein for typosquatting: handles transpositions
 * (e.g. "paplya" → "paypal" distance 2 vs basic Levenshtein distance 3).
 *
 * Restricted to strings ≤50 chars for performance (domain names are short).
 */
export function damerauLevenshtein(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;

  // Early exits
  if (a === b) return 0;
  if (la === 0) return lb;
  if (lb === 0) return la;
  if (Math.abs(la - lb) > 5) return Math.abs(la - lb); // Can't be ≤2 anyway

  // dp[i][j] = edit distance between a[0..i-1] and b[0..j-1]
  const dp: number[][] = Array.from({ length: la + 1 }, (_, i) =>
    Array.from({ length: lb + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );

  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,       // deletion
        dp[i][j - 1] + 1,       // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
      // Transposition
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost);
      }
    }
  }

  return dp[la][lb];
}
