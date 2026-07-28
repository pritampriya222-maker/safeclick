/**
 * background/heuristics/suspiciousKeywords.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Heuristic: Brand-impersonation keyword detection in URL subdomains and paths.
 *
 * Strategy (avoids naive false-positive-prone substring matching):
 * 1. Check if a brand keyword appears in the SUBDOMAIN or PATH (not the registered domain)
 *    — "paypal.com" is fine; "paypal-secure-login.attacker.com" is suspicious
 * 2. The registered domain must NOT be the brand's own domain
 * 3. Combine keyword match with suspicious action words for higher confidence
 *
 * Pure function — no imports of mutable state, fully testable.
 */

import type { HeuristicResult, NormalizedUrl, PageSignals } from '../../shared/types';
import { HEURISTIC_WEIGHTS, SUSPICIOUS_BRAND_KEYWORDS } from '../../shared/constants';

const RULE_ID = 'heuristic:suspicious_keywords';

/** Action words commonly combined with brand names in phishing URLs. */
const PHISHING_ACTION_WORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'logon',
  'secure', 'security', 'verify', 'verification',
  'account', 'accounts', 'update', 'confirm', 'confirmation',
  'billing', 'payment', 'invoice', 'checkout',
  'recover', 'recovery', 'reset', 'password',
  'support', 'help', 'service',
  'auth', 'authenticate', 'authorize',
  'wallet', 'withdraw', 'deposit',
] as const;

/**
 * Check for brand-impersonation keywords in subdomain and path.
 */
export function analyzeSuspiciousKeywords(
  normalizedUrl: NormalizedUrl,
  _pageSignals: PageSignals | null
): HeuristicResult {
  const { hostname, registeredDomain, path } = normalizedUrl;

  // Extract the part of the hostname that isn't the registered domain.
  const subdomainPart = hostname.slice(0, hostname.length - registeredDomain.length).replace(/\.$/, '');
  const analysisTarget = `${subdomainPart}${path}`.toLowerCase();

  // Find brand keywords present in subdomain/path (not in the registered domain itself)
  const matchedBrands: string[] = [];
  for (const brand of SUSPICIOUS_BRAND_KEYWORDS) {
    if (analysisTarget.includes(brand) && !registeredDomain.startsWith(brand)) {
      matchedBrands.push(brand);
    }
  }

  // Find phishing action words
  const matchedActions: string[] = [];
  for (const action of PHISHING_ACTION_WORDS) {
    if (analysisTarget.includes(action)) {
      matchedActions.push(action);
    }
  }

  // Only trigger if there's a brand match (action words alone aren't enough)
  const triggered = matchedBrands.length > 0;

  if (!triggered) {
    return {
      ruleId: RULE_ID,
      name: 'Suspicious Brand Keywords',
      triggered: false,
      weight: HEURISTIC_WEIGHTS.SUSPICIOUS_KEYWORDS,
      explanation: 'No suspicious brand-impersonation patterns detected.',
    };
  }

  const parts: string[] = [
    `Brand name(s) "${matchedBrands.join('", "')}" appear in subdomain/path of a different domain`,
  ];
  if (matchedActions.length > 0) {
    parts.push(`combined with phishing action word(s): "${matchedActions.slice(0, 3).join('", "')}"`);
  }

  return {
    ruleId: RULE_ID,
    name: 'Suspicious Brand Keywords',
    triggered: true,
    weight: HEURISTIC_WEIGHTS.SUSPICIOUS_KEYWORDS,
    explanation: parts.join(', ') + '.',
  };
}
