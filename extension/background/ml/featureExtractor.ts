/**
 * extension/background/ml/featureExtractor.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * TypeScript port of backend/ml/features.py.
 * Extracts the exact 22-feature vector for in-browser XGBoost ML inference.
 */

export const SUSPICIOUS_TLDS: ReadonlySet<string> = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq',
  '.xyz', '.top', '.club', '.work',
  '.loan', '.click', '.download', '.link',
  '.review', '.science', '.win', '.bid',
  '.trade', '.date', '.racing', '.party',
  '.stream', '.gdn', '.icu',
]);

export const BRAND_KEYWORDS: ReadonlySet<string> = new Set([
  'adobe', 'amazon', 'amex', 'apple', 'att',
  'bankofamerica', 'binance', 'bitcoin', 'blockchain',
  'capitalone', 'chase', 'citibank', 'coinbase', 'crypto',
  'docusign', 'dropbox', 'ebay', 'etsy',
  'facebook', 'fedex', 'gmail', 'google',
  'hotmail', 'hsbc', 'icloud', 'instagram',
  'linkedin', 'live', 'mastercard', 'microsoft',
  'netflix', 'office365', 'outlook',
  'paypal', 'pinterest', 'reddit',
  'samsung', 'snapchat', 'spotify', 'steam',
  'tiktok', 'twitter', 'uber', 'ups',
  'venmo', 'visa', 'wallet', 'walmart',
  'wellsfargo', 'whatsapp', 'yahoo', 'youtube', 'zoom',
]);

export const LOGIN_KEYWORDS: ReadonlySet<string> = new Set([
  'login', 'signin', 'sign-in', 'log-in', 'logon',
  'secure', 'security', 'verify', 'verification',
  'account', 'accounts', 'update', 'confirm', 'confirmation',
  'billing', 'payment', 'invoice', 'checkout',
  'recover', 'recovery', 'reset', 'password',
  'support', 'help', 'service', 'auth',
  'authenticate', 'authorize', 'wallet', 'withdraw',
]);

export const FEATURE_NAMES = [
  'url_length',
  'path_length',
  'domain_length',
  'tld_length',
  'num_dots',
  'num_hyphens',
  'num_digits_in_hostname',
  'num_query_params',
  'subdomain_entropy',
  'path_entropy',
  'is_ip_address',
  'has_at_symbol',
  'is_idn',
  'is_punycode',
  'has_suspicious_encoding',
  'port_is_nonstandard',
  'has_https',
  'has_suspicious_tld',
  'brand_keyword_count',
  'has_login_keyword',
  'has_suspicious_keyword',
  'subdomain_depth',
] as const;

export type FeatureMap = Record<typeof FEATURE_NAMES[number], number>;

function shannonEntropy(text: string): number {
  if (!text) return 0;
  const counts: Record<string, number> = {};
  for (const ch of text) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  const len = text.length;
  let entropy = 0;
  for (const count of Object.values(counts)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isIpAddress(hostname: string): boolean {
  const clean = hostname.replace(/[\[\]]/g, '');
  const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    return ipv4Match.slice(1).every((octet) => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }
  return clean.includes(':'); // IPv6
}

function extractRegisteredDomain(hostname: string): { registeredDomain: string; subdomain: string; tld: string } {
  if (isIpAddress(hostname)) {
    return { registeredDomain: hostname, subdomain: '', tld: '' };
  }

  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 1) {
    return { registeredDomain: hostname, subdomain: '', tld: '' };
  }

  const twoPartTlds = new Set(['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in', 'gov.uk', 'org.uk', 'ac.uk']);
  let tld = parts[parts.length - 1];
  let domainParts = 2;

  if (parts.length >= 3) {
    const candidate = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (twoPartTlds.has(candidate)) {
      tld = candidate;
      domainParts = 3;
    }
  }

  if (parts.length < domainParts) {
    return { registeredDomain: hostname, subdomain: '', tld };
  }

  const registeredDomain = parts.slice(parts.length - domainParts).join('.');
  const subdomain = parts.slice(0, parts.length - domainParts).join('.');
  return { registeredDomain, subdomain, tld: `.${tld}` };
}

export function extractFeatureMap(rawUrl: string): FeatureMap | null {
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    const path = parsed.pathname;
    const query = parsed.search;

    const { registeredDomain, subdomain, tld } = extractRegisteredDomain(hostname);
    const mainDomain = registeredDomain.split('.')[0] || '';

    // 1. Structural features
    const url_length = rawUrl.length;
    const path_length = path.length;
    const domain_length = hostname.length;
    const tld_length = tld.length;
    const num_dots = (hostname.match(/\./g) || []).length;
    const num_hyphens = (hostname.match(/-/g) || []).length;
    const num_digits_in_hostname = (hostname.match(/\d/g) || []).length;
    const num_query_params = query ? (query.match(/[?&]/g) || []).length : 0;

    // 2. Entropy
    const subdomain_entropy = shannonEntropy(subdomain);
    const path_entropy = shannonEntropy(path);

    // 3. Flags
    const is_ip = isIpAddress(hostname) ? 1 : 0;
    const has_at_symbol = rawUrl.includes('@') ? 1 : 0;
    const is_idn = /[^\u0000-\u007F]/.test(hostname) ? 1 : 0;
    const is_punycode = hostname.includes('xn--') ? 1 : 0;
    const has_suspicious_encoding = /%00|%2525|%2e%2e/i.test(rawUrl) ? 1 : 0;
    const port_is_nonstandard = parsed.port && !['80', '443', ''].includes(parsed.port) ? 1 : 0;
    const has_https = parsed.protocol === 'https:' ? 1 : 0;

    // 4. Heuristic & Keyword features
    const has_suspicious_tld = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;

    const fullUrlLower = rawUrl.toLowerCase();
    let brand_keyword_count = 0;
    let has_suspicious_keyword = 0;

    for (const brand of BRAND_KEYWORDS) {
      if (fullUrlLower.includes(brand)) {
        brand_keyword_count += 1;
        // Brand in subdomain or path, but NOT the registered domain
        if (!mainDomain.includes(brand) && (subdomain.includes(brand) || path.includes(brand))) {
          has_suspicious_keyword = 1;
        }
      }
    }

    let has_login_keyword = 0;
    for (const kw of LOGIN_KEYWORDS) {
      if (path.toLowerCase().includes(kw) || subdomain.includes(kw)) {
        has_login_keyword = 1;
        break;
      }
    }

    const subdomain_depth = subdomain ? subdomain.split('.').filter(Boolean).length : 0;

    return {
      url_length,
      path_length,
      domain_length,
      tld_length,
      num_dots,
      num_hyphens,
      num_digits_in_hostname,
      num_query_params,
      subdomain_entropy,
      path_entropy,
      is_ip_address: is_ip,
      has_at_symbol,
      is_idn,
      is_punycode,
      has_suspicious_encoding,
      port_is_nonstandard,
      has_https,
      has_suspicious_tld,
      brand_keyword_count,
      has_login_keyword,
      has_suspicious_keyword,
      subdomain_depth,
    };
  } catch {
    return null;
  }
}

export function extractFeatureVector(rawUrl: string): number[] | null {
  const map = extractFeatureMap(rawUrl);
  if (!map) return null;
  return FEATURE_NAMES.map((name) => map[name]);
}
