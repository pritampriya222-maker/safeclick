/**
 * shared/urlNormalizer.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Pure URL normalization function. No side effects, fully unit-testable.
 *
 * Key behaviors:
 * 1. Lowercase scheme + hostname
 * 2. Strip default ports (80 for http, 443 for https)
 * 3. Strip tracking query params (list in constants.ts)
 * 4. Decode safe percent-encoding, flag suspicious encoding patterns
 * 5. Strip trailing slashes from path consistently
 * 6. Detect IDN domains (non-ASCII chars) and punycode (xn--)
 *    → These are PRESERVED as flags, not silently normalized away
 *
 * IMPORTANT: IDN/punycode flags are evidence of phishing intent.
 * Never strip or silently fix a homograph attempt — preserve it as a signal.
 */

import type { NormalizedUrl } from './types';
import { TRACKING_QUERY_PARAMS } from './constants';

/**
 * Normalize a URL and extract structured signals for the detection engine.
 *
 * @param rawUrl - The raw URL string to normalize
 * @returns NormalizedUrl or null if the URL is unparseable
 */
export function normalizeUrl(rawUrl: string): NormalizedUrl | null {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const path = normalizePath(parsed.pathname);
  const cleanQuery = stripTrackingParams(parsed.searchParams);

  // ── IDN / Punycode detection ──────────────────────────────────────────────
  // A punycode hostname starts with or contains "xn--" labels.
  const isPunycode = hostname.split('.').some((label) => label.startsWith('xn--'));

  // An IDN hostname contains non-ASCII characters after decoding.
  // Note: browsers may auto-display punycode as unicode — we check both forms.
  const isIDN = isPunycode || /[^\x00-\x7F]/.test(hostname);

  // ── Suspicious encoding detection ────────────────────────────────────────
  // Flags double-encoding (%25XX), null bytes (%00), non-printable chars.
  const hasSuspiciousEncoding = detectSuspiciousEncoding(rawUrl);

  // ── Non-standard port ─────────────────────────────────────────────────────
  const portIsNonStandard = isNonStandardPort(parsed);

  // ── Registered domain (eTLD+1 approximation) ─────────────────────────────
  const registeredDomain = extractRegisteredDomain(hostname);

  // ── Build normalized URL string ───────────────────────────────────────────
  const normalizedHostname = hostname; // already lowercased
  const normalizedPath = path || '/';
  const queryString = cleanQuery ? `?${cleanQuery}` : '';
  const portPart = portIsNonStandard && parsed.port ? `:${parsed.port}` : '';
  const normalized = `${scheme}://${normalizedHostname}${portPart}${normalizedPath}${queryString}`;

  return {
    original: rawUrl,
    normalized,
    hostname,
    registeredDomain,
    isIDN,
    isPunycode,
    hasSuspiciousEncoding,
    portIsNonStandard,
    scheme,
    path: normalizedPath,
    cleanQuery,
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Strip known tracking query parameters and return the remaining query string.
 */
function stripTrackingParams(searchParams: URLSearchParams): string {
  const trackingSet = new Set(TRACKING_QUERY_PARAMS);
  const clean = new URLSearchParams();

  for (const [key, value] of searchParams.entries()) {
    if (!trackingSet.has(key) && !key.startsWith('utm_')) {
      clean.append(key, value);
    }
  }

  return clean.toString();
}

/**
 * Normalize the path: strip trailing slash (unless root "/"), decode safe
 * percent-encoding, lowercase.
 */
function normalizePath(pathname: string): string {
  // Decode safe percent-encoding (letters, digits, common punctuation).
  let decoded = pathname;
  try {
    // Only decode sequences that produce printable ASCII — don't decode
    // sequences that produce control chars or non-ASCII (those are suspicious).
    decoded = pathname.replace(/%([0-9A-Fa-f]{2})/g, (match, hex) => {
      const code = parseInt(hex, 16);
      // Safe to decode: printable ASCII (0x20–0x7E), excluding special URL chars
      if (code >= 0x20 && code <= 0x7e && !'%?#&=+'.includes(String.fromCharCode(code))) {
        return String.fromCharCode(code);
      }
      return match; // Keep encoded
    });
  } catch {
    decoded = pathname;
  }

  // Strip trailing slash unless it's the root path.
  if (decoded.length > 1 && decoded.endsWith('/')) {
    decoded = decoded.slice(0, -1);
  }

  return decoded.toLowerCase();
}

/**
 * Detect suspicious percent-encoding patterns:
 * - Double-encoding (%25 followed by hex — encodes a % sign)
 * - Null bytes (%00)
 * - Non-printable character sequences
 */
function detectSuspiciousEncoding(url: string): boolean {
  // Double-encoded percent (%25XX)
  if (/%25[0-9A-Fa-f]{2}/i.test(url)) return true;
  // Null byte
  if (/%00/i.test(url)) return true;
  // Excessively high percent-encoding density (>25% of URL is encoded)
  const encodedCount = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  if (url.length > 20 && encodedCount / url.length > 0.25) return true;
  return false;
}

/**
 * Determine if the URL uses a non-standard port.
 */
function isNonStandardPort(parsed: URL): boolean {
  if (!parsed.port) return false; // No explicit port → using default
  const port = parseInt(parsed.port, 10);
  if (parsed.protocol === 'http:' && port === 80) return false;
  if (parsed.protocol === 'https:' && port === 443) return false;
  return true;
}

/**
 * Extract the registered domain (eTLD+1 approximation).
 * This is a best-effort implementation without a full Public Suffix List.
 * For Phase 3's ML feature extraction, a proper PSL library can replace this.
 *
 * Examples:
 *   "sub.example.com"    → "example.com"
 *   "sub.example.co.uk"  → "example.co.uk"
 *   "192.168.1.1"        → "192.168.1.1" (IP passthrough)
 */
export function extractRegisteredDomain(hostname: string): string {
  // Raw IP address → return as-is
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;

  const labels = hostname.split('.');
  if (labels.length <= 2) return hostname;

  // Common two-part TLDs (eTLD+2 → return last 3 labels)
  const lastTwo = labels.slice(-2).join('.');
  const twoPartTLDs = [
    'co.uk', 'co.in', 'co.jp', 'co.nz', 'co.za', 'co.au',
    'com.au', 'com.br', 'com.cn', 'com.mx', 'com.ar',
    'net.au', 'org.uk', 'ac.uk', 'gov.uk',
  ];

  if (twoPartTLDs.includes(lastTwo)) {
    return labels.slice(-3).join('.');
  }

  return labels.slice(-2).join('.');
}
