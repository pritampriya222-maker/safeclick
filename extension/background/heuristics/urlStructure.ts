/**
 * background/heuristics/urlStructure.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Heuristic: URL structural anomaly detection.
 *
 * Detects:
 * 1. Raw IP addresses used instead of domain names
 * 2. "@" character obfuscation (browser navigates to part after @)
 * 3. Excessive subdomain depth (>3 labels before the registered domain)
 * 4. Suspicious hyphen patterns mimicking known brands
 *    (e.g. "paypal-secure.com" — legitimate PayPal never uses this)
 *
 * Pure function — no mutable state imports, fully testable.
 */

import type { HeuristicResult, NormalizedUrl, PageSignals } from '../../shared/types';
import { HEURISTIC_WEIGHTS, URL_ANALYSIS, KNOWN_BRAND_DOMAINS } from '../../shared/constants';

const RULE_ID = 'heuristic:url_structure';

/**
 * Analyze URL structural anomalies.
 */
export function analyzeUrlStructure(
  normalizedUrl: NormalizedUrl,
  _pageSignals: PageSignals | null
): HeuristicResult {
  const { original, hostname, registeredDomain } = normalizedUrl;

  const issues: string[] = [];

  // ── 1. Raw IP address ─────────────────────────────────────────────────────
  if (isRawIpAddress(hostname)) {
    issues.push(`URL uses a raw IP address (${hostname}) instead of a domain name`);
  }

  // ── 2. "@" obfuscation ────────────────────────────────────────────────────
  // e.g. "http://legitimate.com@phishing.com/path" — the browser goes to phishing.com
  if (original.includes('@')) {
    // URL class parses it correctly (hostname = part after @), but the @
    // itself in the URL is a strong phishing signal
    issues.push('URL contains "@" character — commonly used to disguise the real destination');
  }

  // ── 3. Excessive subdomain depth ─────────────────────────────────────────
  const subdomainDepth = countSubdomainDepth(hostname, registeredDomain);
  if (subdomainDepth > URL_ANALYSIS.MAX_SUBDOMAIN_DEPTH) {
    issues.push(`Unusually deep subdomain nesting (${subdomainDepth} levels — threshold: ${URL_ANALYSIS.MAX_SUBDOMAIN_DEPTH})`);
  }

  // ── 4. Brand hyphen mimicry ───────────────────────────────────────────────
  // "paypal-secure.com", "amazon-shipping.net", etc.
  const brandHyphen = detectBrandHyphenMimicry(registeredDomain);
  if (brandHyphen) {
    issues.push(`Registered domain "${registeredDomain}" uses hyphens to mimic the brand "${brandHyphen}"`);
  }

  const triggered = issues.length > 0;

  if (!triggered) {
    return {
      ruleId: RULE_ID,
      name: 'URL Structure Anomalies',
      triggered: false,
      weight: HEURISTIC_WEIGHTS.URL_STRUCTURE,
      explanation: 'URL structure appears normal.',
    };
  }

  return {
    ruleId: RULE_ID,
    name: 'URL Structure Anomalies',
    triggered: true,
    weight: HEURISTIC_WEIGHTS.URL_STRUCTURE,
    explanation: issues.join('; ') + '.',
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** Check if the hostname is a raw IPv4 or IPv6 address. */
export function isRawIpAddress(hostname: string): boolean {
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    const parts = hostname.split('.').map(Number);
    return parts.every((p) => p >= 0 && p <= 255);
  }
  // IPv6 (wrapped in brackets by URL parser or raw)
  if (hostname.startsWith('[') && hostname.endsWith(']')) return true;
  return false;
}

/** Count subdomain depth: number of labels before the registered domain. */
export function countSubdomainDepth(hostname: string, registeredDomain: string): number {
  if (hostname === registeredDomain) return 0;
  const subdomain = hostname.slice(0, hostname.length - registeredDomain.length - 1);
  if (!subdomain) return 0;
  return subdomain.split('.').length;
}

/**
 * Detect brand-hyphen mimicry: a registered domain that contains a known
 * brand name as a prefix/suffix with a hyphen.
 * e.g. "paypal-secure.com" → "paypal"
 * e.g. "amazon-support-center.net" → "amazon"
 */
export function detectBrandHyphenMimicry(registeredDomain: string): string | null {
  const domainWithoutTld = registeredDomain.split('.').slice(0, -1).join('.');

  for (const brandDomain of KNOWN_BRAND_DOMAINS) {
    const brandName = brandDomain.split('.')[0]; // e.g. "paypal" from "paypal.com"

    // Brand name must appear before or after a hyphen, but the registered domain
    // must NOT be the actual brand's domain (that's fine).
    if (registeredDomain === brandDomain) continue;

    const hyphenPatterns = [
      new RegExp(`^${brandName}-`, 'i'),  // paypal-secure.com
      new RegExp(`-${brandName}$`, 'i'),  // secure-paypal.com
      new RegExp(`-${brandName}-`, 'i'),  // support-paypal-help.com
    ];

    if (hyphenPatterns.some((re) => re.test(domainWithoutTld))) {
      return brandName;
    }
  }

  return null;
}
