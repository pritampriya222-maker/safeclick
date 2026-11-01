/**
 * background/reputationClient.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Client for the Phase 2 backend reputation service.
 * Phase 5: Also queries the shared threat intelligence endpoint, merging both
 * signals with clear provenance so they are never indistinguishable.
 *
 * Priority order:
 * 1. LOCAL: Check bundled topDomains.json → instantly trusted (no network)
 * 2. BACKEND: GET /api/v1/reputation?domain=X with 800ms timeout
 * 3. CROWD: GET /api/v1/threat-intel/lookup?domain=X (parallel, best-effort)
 *    — Crowd signal is merged into detail if threat found, never silently
 *      merged with automated signals. Label: "Flagged by N SafeClick users"
 * 4. GRACEFUL DEGRADATION: If backend is unreachable or times out, return
 *    { knownMalicious: false, confidence: 0, source: 'unavailable' }
 *    The extension MUST NOT hang or crash browsing due to backend downtime.
 *
 * The extension checks its own allowlist before calling this function —
 * allowlisted domains short-circuit in verdictEngine.ts, not here.
 */

import type { ReputationResult } from '../shared/types';
import { API_BASE_URL, REPUTATION_TIMEOUT_MS } from '../shared/constants';
import topDomainsData from '../shared/topDomains.json';
import threatData from '../shared/threatDatabase.json';

// ─── Top Domains & Threat Database Sets ──────────────────────────────────────
const TOP_DOMAINS: ReadonlySet<string> = new Set<string>(topDomainsData.domains);
const THREAT_DOMAINS: ReadonlySet<string> = new Set<string>(threatData.domains);

/**
 * Check if a domain is in our bundled top domains list.
 * Also normalizes www.example.com → example.com for comparison.
 */
export function isTopDomain(domain: string): boolean {
  const normalized = domain.replace(/^www\./, '').toLowerCase();
  return TOP_DOMAINS.has(normalized) || TOP_DOMAINS.has(domain.toLowerCase());
}

/**
 * Check if a domain is in the bundled URLhaus / Community Threat blocklist.
 */
export function isKnownThreatDomain(domain: string): boolean {
  const normalized = domain.replace(/^www\./, '').toLowerCase();
  return THREAT_DOMAINS.has(normalized) || THREAT_DOMAINS.has(domain.toLowerCase());
}

/** Expose the top domains set for use in heuristics (e.g. loginFormSignal). */
export function getTopDomainsSet(): ReadonlySet<string> {
  return TOP_DOMAINS;
}

// ─── Phase 5: Crowd sourced threat intel ─────────────────────────────────────

interface ThreatIntelResult {
  is_threat: boolean;
  report_count: number;
  label: string;   // e.g. "Flagged by 7 SafeClick users"
  confidence: string;
}

async function checkCrowdSourcedIntel(domain: string): Promise<ThreatIntelResult | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REPUTATION_TIMEOUT_MS);

    const res = await fetch(
      `${API_BASE_URL}/api/v1/threat-intel/lookup?domain=${encodeURIComponent(domain)}`,
      { signal: controller.signal, headers: { Accept: 'application/json' } },
    );
    clearTimeout(timeoutId);

    if (!res.ok) return null;
    return await res.json() as ThreatIntelResult;
  } catch {
    return null; // best-effort: crowd intel failing never blocks the verdict
  }
}

/**
 * Look up the reputation of a domain.
 * Phase 5: Merges automated reputation + crowd-sourced threat intel.
 * Crowd-sourced signals are explicitly labeled, never merged silently.
 *
 * @param domain - The registered domain (eTLD+1) to check
 * @returns ReputationResult, always resolves (never throws)
 */
export async function checkReputation(domain: string): Promise<ReputationResult> {
  // ── 1. Threat-database check (Instant Local URLhaus/Threat blocklist) ──────
  if (isKnownThreatDomain(domain)) {
    return {
      domain,
      knownMalicious: true,
      source: 'local_blocklist',
      lastChecked: new Date().toISOString(),
      confidence: 0.92,
      detail: 'Listed on URLhaus / Community Threat Intelligence blocklist as a high-risk piracy, warez, or malicious download domain.',
    };
  }

  // ── 2. Top-domain short-circuit ───────────────────────────────────────────
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

  // ── 2+3. Backend reputation + crowd intel (parallel) ─────────────────────
  const [reputationResult, crowdIntel] = await Promise.all([
    _fetchBackendReputation(domain),
    checkCrowdSourcedIntel(domain),
  ]);

  // ── Merge crowd signal into detail (provenance-labeled, never silent) ─────
  if (crowdIntel?.is_threat) {
    const crowdDetail = crowdIntel.label; // "Flagged by N SafeClick users"
    const existingDetail = reputationResult.detail ?? '';

    return {
      ...reputationResult,
      // If automated already flagged, keep it malicious; crowd adds context
      // If automated said safe, crowd overrides as malicious
      knownMalicious: reputationResult.knownMalicious || crowdIntel.is_threat,
      source: reputationResult.knownMalicious ? reputationResult.source : 'crowd_sourced',
      detail: existingDetail
        ? `${existingDetail} | ${crowdDetail}`
        : crowdDetail,
      // Boost confidence slightly if both signals agree
      confidence: reputationResult.knownMalicious
        ? Math.min(1, reputationResult.confidence + 0.05)
        : 0.7, // crowd-only confidence capped at 0.7
    };
  }

  return reputationResult;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function _fetchBackendReputation(domain: string): Promise<ReputationResult> {
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
      console.warn(`[SafeClick] Reputation lookup failed for ${domain}:`, err);
    }
    return unavailableResult(domain);
  }
}

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
