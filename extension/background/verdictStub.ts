/**
 * background/verdictStub.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * PHASE 1 STUB — REPLACE IN PHASE 2
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This file is the SEAM between the extension skeleton and the real detection
 * engine. Phase 2 replaces only the INTERNALS of getVerdict() — the function
 * signature below is FROZEN and must not change in any phase:
 *
 *   export async function getVerdict(url: string): Promise<Verdict>
 *
 * tabTracker.ts imports ONLY this signature. No other file in the extension
 * depends on this file's internal logic — only its type contract.
 *
 * WHAT TO DO IN PHASE 2:
 *   1. Rename this file to verdictEngine.ts (optional but recommended).
 *   2. Update the single import in tabTracker.ts to point to verdictEngine.ts.
 *   3. Replace the body of getVerdict() with the real pipeline:
 *      normalizer → heuristics → reputation client → phishing detector → risk scorer.
 *   4. Do NOT change the function signature or the Verdict interface.
 *   5. Do NOT modify popup/, options/, or content/ — those must work with zero changes.
 */

import type { Verdict } from '../shared/types';
import { NON_APPLICABLE_SCHEMES } from '../shared/constants';

/**
 * Returns a deterministic, clearly-labeled Phase 1 placeholder verdict.
 *
 * PHASE 1 BEHAVIOR: Always returns "safe" with a stub reason.
 * PHASE 2 BEHAVIOR: Replace this body with the real detection pipeline.
 *
 * @param url - The URL to analyze (may be empty string for non-applicable tabs)
 * @returns A Verdict conforming to shared/types.ts
 */
export async function getVerdict(url: string): Promise<Verdict> {
  const now = new Date().toISOString();

  // Handle non-applicable URL schemes (chrome://, extension://, etc.)
  if (!url || isNonApplicableUrl(url)) {
    return {
      url,
      level: 'not_applicable',
      score: 0,
      reasons: ['This URL scheme is not analyzed by SafeClick.'],
      ruleTriggers: [],
      timestamp: now,
      isStub: true,
    };
  }

  // ── STUB IMPLEMENTATION ──────────────────────────────────────────────────
  // This is intentionally minimal. The real engine goes here in Phase 2.
  // The stub returns "safe" for every http/https URL so the Phase 1 UI
  // can be fully tested without real threat detection logic.
  return {
    url,
    level: 'safe',
    score: 0,
    reasons: [
      'Phase 1 stub — real detection engine not yet implemented (Phase 2).',
    ],
    ruleTriggers: [],
    timestamp: now,
    isStub: true,
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function isNonApplicableUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return NON_APPLICABLE_SCHEMES.some((scheme) =>
      parsed.protocol.startsWith(scheme)
    );
  } catch {
    // Unparseable URL — treat as not applicable.
    return true;
  }
}
