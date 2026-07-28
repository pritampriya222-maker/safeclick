/**
 * tests/urlNormalizer.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for shared/urlNormalizer.ts.
 * Covers: normalization, IDN/punycode detection, tracking param stripping,
 * suspicious encoding, non-standard ports, registered domain extraction.
 */

import { describe, it, expect } from 'vitest';
import { normalizeUrl, extractRegisteredDomain } from '../shared/urlNormalizer';

describe('normalizeUrl — basic normalization', () => {
  it('lowercases scheme and hostname', () => {
    const result = normalizeUrl('HTTPS://EXAMPLE.COM/Path');
    expect(result?.scheme).toBe('https');
    expect(result?.hostname).toBe('example.com');
  });

  it('strips trailing slash from path', () => {
    const result = normalizeUrl('https://example.com/page/');
    expect(result?.path).toBe('/page');
  });

  it('preserves root path slash', () => {
    const result = normalizeUrl('https://example.com/');
    expect(result?.path).toBe('/');
  });

  it('returns null for unparseable URLs', () => {
    expect(normalizeUrl('not-a-url')).toBeNull();
    expect(normalizeUrl('')).toBeNull();
  });

  it('returns the original URL in the output', () => {
    const url = 'https://example.com/test?q=1';
    const result = normalizeUrl(url);
    expect(result?.original).toBe(url);
  });
});

describe('normalizeUrl — tracking parameter stripping', () => {
  it('strips utm_source parameter', () => {
    const result = normalizeUrl('https://example.com/page?utm_source=email&id=42');
    expect(result?.cleanQuery).not.toContain('utm_source');
    expect(result?.cleanQuery).toContain('id=42');
  });

  it('strips utm_medium, utm_campaign, utm_content, utm_term', () => {
    const result = normalizeUrl(
      'https://example.com/?utm_medium=social&utm_campaign=launch&utm_content=btn&utm_term=kw'
    );
    expect(result?.cleanQuery).toBe('');
  });

  it('strips fbclid', () => {
    const result = normalizeUrl('https://example.com/?fbclid=AbC123');
    expect(result?.cleanQuery).not.toContain('fbclid');
  });

  it('strips gclid', () => {
    const result = normalizeUrl('https://example.com/?gclid=Cj0K');
    expect(result?.cleanQuery).not.toContain('gclid');
  });

  it('preserves non-tracking query params', () => {
    const result = normalizeUrl('https://example.com/?search=hello&page=2');
    expect(result?.cleanQuery).toContain('search=hello');
    expect(result?.cleanQuery).toContain('page=2');
  });
});

describe('normalizeUrl — IDN and punycode detection', () => {
  it('detects punycode domains (xn-- prefix)', () => {
    // xn--pypal-4ve.com is punycode for pạypal.com (homograph attack)
    const result = normalizeUrl('https://xn--pypal-4ve.com/login');
    expect(result?.isPunycode).toBe(true);
    expect(result?.isIDN).toBe(true);
  });

  it('does NOT flag regular ASCII domains as IDN', () => {
    const result = normalizeUrl('https://paypal.com/signin');
    expect(result?.isIDN).toBe(false);
    expect(result?.isPunycode).toBe(false);
  });

  it('flags mixed punycode subdomains', () => {
    const result = normalizeUrl('https://xn--pple-43d.apple.com/');
    expect(result?.isPunycode).toBe(true);
  });
});

describe('normalizeUrl — suspicious encoding detection', () => {
  it('flags double-encoded percent (%25XX)', () => {
    const result = normalizeUrl('https://example.com/path%252Ftraversal');
    expect(result?.hasSuspiciousEncoding).toBe(true);
  });

  it('flags null byte (%00)', () => {
    const result = normalizeUrl('https://example.com/file%00.txt');
    expect(result?.hasSuspiciousEncoding).toBe(true);
  });

  it('does NOT flag normal encoding', () => {
    const result = normalizeUrl('https://example.com/hello%20world');
    expect(result?.hasSuspiciousEncoding).toBe(false);
  });
});

describe('normalizeUrl — non-standard ports', () => {
  it('flags non-standard port for HTTPS', () => {
    const result = normalizeUrl('https://example.com:8443/page');
    expect(result?.portIsNonStandard).toBe(true);
  });

  it('does NOT flag standard HTTPS port 443', () => {
    const result = normalizeUrl('https://example.com:443/page');
    expect(result?.portIsNonStandard).toBe(false);
  });

  it('does NOT flag standard HTTP port 80', () => {
    const result = normalizeUrl('http://example.com:80/page');
    expect(result?.portIsNonStandard).toBe(false);
  });

  it('does NOT flag missing port (uses default)', () => {
    const result = normalizeUrl('https://example.com/page');
    expect(result?.portIsNonStandard).toBe(false);
  });
});

describe('extractRegisteredDomain', () => {
  it('extracts eTLD+1 for simple domain', () => {
    expect(extractRegisteredDomain('example.com')).toBe('example.com');
  });

  it('extracts eTLD+1 from subdomain', () => {
    expect(extractRegisteredDomain('sub.example.com')).toBe('example.com');
  });

  it('extracts eTLD+1 from deep subdomain', () => {
    expect(extractRegisteredDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('handles two-part TLDs (co.uk)', () => {
    expect(extractRegisteredDomain('sub.example.co.uk')).toBe('example.co.uk');
  });

  it('passes through raw IP addresses', () => {
    expect(extractRegisteredDomain('192.168.1.1')).toBe('192.168.1.1');
  });
});
