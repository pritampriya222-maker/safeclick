/**
 * background/reputationClient.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Client for the Phase 2 backend reputation service.
 *
 * Priority order:
 * 1. LOCAL: Check bundled topDomains.json → instantly trusted (no network)
 * 2. BACKEND: GET /api/v1/reputation?domain=X with 800ms timeout
 * 3. GRACEFUL DEGRADATION: If backend is unreachable or times out, return
 *    { knownMalicious: false, confidence: 0, source: 'unavailable' }
 *    The extension MUST NOT hang or crash browsing due to backend downtime.
 *
 * The extension checks its own allowlist before calling this function —
 * allowlisted domains short-circuit in verdictEngine.ts, not here.
 */

import type { ReputationResult } from '../shared/types';
import { API_BASE_URL, REPUTATION_TIMEOUT_MS } from '../shared/constants';
import topDomainsData from '../shared/topDomains.json';

// ─── Top Domains Set (loaded once at module init) ────────────────────────────
const TOP_DOMAINS: ReadonlySet<string> = new Set<string>(topDomainsData.domains);

/**
 * Check if a domain is in our bundled top domains list.
 * Also normalizes www.example.com → example.com for comparison.
 */
export function isTopDomain(domain: string): boolean {
  const normalized = domain.replace(/^www\./, '');
  return TOP_DOMAINS.has(normalized) || TOP_DOMAINS.has(domain);
}

/** Expose the top domains set for use in heuristics (e.g. loginFormSignal). */
export function getTopDomainsSet(): ReadonlySet<string> {
  return TOP_DOMAINS;
}

/**
 * Look up the reputation of a domain.
 *
 * @param domain - The registered domain (eTLD+1) to check
 * @returns ReputationResult, always resolves (never throws)
 */
export async function checkReputation(domain: string): Promise<ReputationResult> {
  // ── 1. Top-domain short-circuit ───────────────────────────────────────────
  if (isTopDomain(domain)) {
    return {
      domain,
      knownMalicious: false,
      source: 'top_domain_list',
      lastChecked: new Date().toISOString(),
      confidence: 0.95,
      detail: 'Domain is in the bundled top-500 trusted domains list.',
    };
  }

  // ── 2. Backend reputation lookup with timeout ─────────────────────────────
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REPUTATION_TIMEOUT_MS);

    const encodedDomain = encodeURIComponent(domain);
    const response = await fetch(
      `${API_BASE_URL}/api/v1/reputation?domain=${encodedDomain}`,
      {
        method: 'GET',
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`[SafeClick] Reputation API returned ${response.status} for ${domain}`);
      return unavailableResult(domain);
    }

    const data = await response.json() as ReputationResult;
    return data;

  } catch (err) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    if (!isTimeout) {
      // Only log non-timeout errors (timeout is expected degradation)
      console.warn(`[SafeClick] Reputation lookup failed for ${domain}:`, err);
    }
    return unavailableResult(domain);
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function unavailableResult(domain: string): ReputationResult {
  return {
    domain,
    knownMalicious: false,
    source: 'unavailable',
    lastChecked: new Date().toISOString(),
    confidence: 0,
    detail: 'Reputation service unavailable — defaulting to unknown.',
  };
}
