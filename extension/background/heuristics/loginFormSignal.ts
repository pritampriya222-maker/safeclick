/**
 * background/heuristics/loginFormSignal.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Heuristic: Login form on an untrusted/unknown domain.
 *
 * A login form on a well-known, allowlisted, or top-500 domain is normal.
 * A login form on an unknown or suspicious domain is a very strong phishing signal.
 *
 * Consumes: PageSignals.hasLoginForm (captured by Phase 1 content script)
 * Also checks: whether the domain is in the extension's allowlist or topDomains.
 *
 * Pure function — the top domain check uses the passed-in Set, not a module-level import.
 */

import type { HeuristicResult, NormalizedUrl, PageSignals } from '../../shared/types';
import { HEURISTIC_WEIGHTS } from '../../shared/constants';

const RULE_ID = 'heuristic:login_form_signal';

/**
 * Analyze whether a login form is present on an untrusted domain.
 *
 * @param normalizedUrl - The normalized URL
 * @param pageSignals - Signals from the content script (hasLoginForm)
 * @param trustedDomains - Set of domains considered trusted (allowlist + top domains)
 */
export function analyzeLoginFormSignal(
  normalizedUrl: NormalizedUrl,
  pageSignals: PageSignals | null,
  trustedDomains: ReadonlySet<string>
): HeuristicResult {
  // No page signals yet (content script hasn't reported in)
  if (!pageSignals) {
    return {
      ruleId: RULE_ID,
      name: 'Login Form on Untrusted Domain',
      triggered: false,
      weight: HEURISTIC_WEIGHTS.LOGIN_FORM_SIGNAL,
      explanation: 'Page signals not yet available.',
    };
  }

  // No login form — not suspicious regardless of domain trust level
  if (!pageSignals.hasLoginForm) {
    return {
      ruleId: RULE_ID,
      name: 'Login Form on Untrusted Domain',
      triggered: false,
      weight: HEURISTIC_WEIGHTS.LOGIN_FORM_SIGNAL,
      explanation: 'No login form detected on this page.',
    };
  }

  const { registeredDomain } = normalizedUrl;

  // Login form found — check domain trust
  const isTrusted = trustedDomains.has(registeredDomain);

  if (isTrusted) {
    return {
      ruleId: RULE_ID,
      name: 'Login Form on Untrusted Domain',
      triggered: false,
      weight: HEURISTIC_WEIGHTS.LOGIN_FORM_SIGNAL,
      explanation: `Login form detected, but domain "${registeredDomain}" is trusted.`,
    };
  }

  // Login form on an unknown/untrusted domain → HIGH RISK signal
  return {
    ruleId: RULE_ID,
    name: 'Login Form on Untrusted Domain',
    triggered: true,
    weight: HEURISTIC_WEIGHTS.LOGIN_FORM_SIGNAL,
    explanation: `Login form (password field) detected on an unrecognized domain "${registeredDomain}". This is a common phishing tactic.`,
  };
}
