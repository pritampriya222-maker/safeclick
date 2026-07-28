"""
backend/ml/features.py
────────────────────────────────────────────────────────────────────────────
Feature extraction for the SafeClick ML model.

Mirrors Phase 2's TypeScript heuristic logic in Python so the same
feature definitions drive both the ML model (training + inference) and
the extension's rule engine — preventing feature-definition drift.

22 features, all numeric (binary flags = 0.0 or 1.0):
    Structural:  url_length, path_length, domain_length, tld_length,
                 num_dots, num_hyphens, num_digits_in_hostname, num_query_params
    Entropy:     subdomain_entropy, path_entropy
    Flags:       is_ip_address, has_at_symbol, is_idn, is_punycode,
                 has_suspicious_encoding, port_is_nonstandard, has_https
    Heuristic:   has_suspicious_tld, brand_keyword_count,
                 has_login_keyword, has_suspicious_keyword,
                 subdomain_depth

All feature names match the keys used in phishing_rules.json so the
rule engine and ML model reference the same schema.
"""

import math
import re
import urllib.parse
from typing import Optional


# ── Constants (mirrors extension/shared/constants.ts) ─────────────────────────

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.top', '.club', '.work',
    '.loan', '.click', '.download', '.link',
    '.review', '.science', '.win', '.bid',
    '.trade', '.date', '.racing', '.party',
    '.stream', '.gdn', '.icu',
}

BRAND_KEYWORDS = {
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
}

LOGIN_KEYWORDS = {
    'login', 'signin', 'sign-in', 'log-in', 'logon',
    'secure', 'security', 'verify', 'verification',
    'account', 'accounts', 'update', 'confirm', 'confirmation',
    'billing', 'payment', 'invoice', 'checkout',
    'recover', 'recovery', 'reset', 'password',
    'support', 'help', 'service', 'auth',
    'authenticate', 'authorize', 'wallet', 'withdraw',
}

# Feature schema: name → human-readable label
FEATURE_SCHEMA: dict[str, str] = {
    'url_length': 'URL Length',
    'path_length': 'Path Length',
    'domain_length': 'Domain Length',
    'tld_length': 'TLD Length',
    'num_dots': 'Number of Dots in Hostname',
    'num_hyphens': 'Number of Hyphens in Hostname',
    'num_digits_in_hostname': 'Digits in Hostname',
    'num_query_params': 'Number of Query Parameters',
    'subdomain_entropy': 'Subdomain Entropy',
    'path_entropy': 'Path Entropy',
    'is_ip_address': 'Is Raw IP Address',
    'has_at_symbol': 'Has @ Symbol',
    'is_idn': 'Is IDN Domain',
    'is_punycode': 'Is Punycode Domain',
    'has_suspicious_encoding': 'Has Suspicious Encoding',
    'port_is_nonstandard': 'Uses Non-Standard Port',
    'has_https': 'Uses HTTPS',
    'has_suspicious_tld': 'Suspicious TLD',
    'brand_keyword_count': 'Brand Keyword Count',
    'has_login_keyword': 'Has Login/Action Keyword',
    'has_suspicious_keyword': 'Has Brand in Wrong Domain',
    'subdomain_depth': 'Subdomain Depth',
}

FEATURE_NAMES = list(FEATURE_SCHEMA.keys())


# ── Public API ────────────────────────────────────────────────────────────────

def extract_features(url: str) -> Optional[dict[str, float]]:
    """
    Extract the 22-feature vector from a URL string.

    Returns a dict mapping feature name → float value, or None if the
    URL cannot be parsed.

    Feature values:
    - Binary flags: 0.0 (false) or 1.0 (true)
    - Numeric: actual measured value (length, count, entropy)
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
    except Exception:
        return None

    hostname = parsed.hostname or ''
    scheme = parsed.scheme.lower()
    path = parsed.path or ''
    query = parsed.query or ''
    port = parsed.port

    # Registered domain (eTLD+1 approximation)
    registered_domain = _extract_registered_domain(hostname)
    subdomain_part = hostname[: max(0, len(hostname) - len(registered_domain) - 1)]

    # ── Structural features ────────────────────────────────────────────────────
    url_length = float(len(url))
    path_length = float(len(path))
    domain_length = float(len(hostname))
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    tld_length = float(len(tld))
    num_dots = float(hostname.count('.'))
    num_hyphens = float(hostname.count('-'))
    num_digits_in_hostname = float(sum(c.isdigit() for c in hostname))
    num_query_params = float(len(urllib.parse.parse_qs(query)))

    # ── Entropy features ──────────────────────────────────────────────────────
    subdomain_entropy = _shannon_entropy(subdomain_part)
    path_entropy = _shannon_entropy(path)

    # ── Binary flags ──────────────────────────────────────────────────────────
    is_ip = 1.0 if _is_ip_address(hostname) else 0.0
    has_at = 1.0 if '@' in url else 0.0

    # IDN: contains non-ASCII or punycode labels
    is_punycode = 1.0 if any(label.startswith('xn--') for label in hostname.split('.')) else 0.0
    is_idn = 1.0 if (is_punycode or bool(re.search(r'[^\x00-\x7F]', hostname))) else 0.0

    # Suspicious encoding
    has_suspicious_encoding = 1.0 if _has_suspicious_encoding(url) else 0.0

    # Non-standard port
    if port:
        is_nonstandard = 0.0 if (scheme == 'http' and port == 80) or \
                                  (scheme == 'https' and port == 443) else 1.0
    else:
        is_nonstandard = 0.0

    has_https = 1.0 if scheme == 'https' else 0.0

    # Suspicious TLD
    has_suspicious_tld = 1.0 if tld.lower() in SUSPICIOUS_TLDS else 0.0

    # Brand keywords — count in subdomain+path but NOT in own registered domain
    analysis_target = f'{subdomain_part}{path}'.lower()
    brand_count = sum(
        1 for b in BRAND_KEYWORDS
        if b in analysis_target and not registered_domain.startswith(b)
    )
    brand_keyword_count = float(brand_count)

    # Login/action keyword
    combined = f'{subdomain_part}{path}{query}'.lower()
    has_login_keyword = 1.0 if any(kw in combined for kw in LOGIN_KEYWORDS) else 0.0

    # Brand keyword in wrong domain (suspicious_keywords heuristic)
    has_suspicious_keyword = 1.0 if brand_count > 0 else 0.0

    # Subdomain depth
    subdomain_depth = float(len(subdomain_part.split('.')) if subdomain_part else 0)

    return {
        'url_length': url_length,
        'path_length': path_length,
        'domain_length': domain_length,
        'tld_length': tld_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_digits_in_hostname': num_digits_in_hostname,
        'num_query_params': num_query_params,
        'subdomain_entropy': subdomain_entropy,
        'path_entropy': path_entropy,
        'is_ip_address': is_ip,
        'has_at_symbol': has_at,
        'is_idn': is_idn,
        'is_punycode': is_punycode,
        'has_suspicious_encoding': has_suspicious_encoding,
        'port_is_nonstandard': is_nonstandard,
        'has_https': has_https,
        'has_suspicious_tld': has_suspicious_tld,
        'brand_keyword_count': brand_keyword_count,
        'has_login_keyword': has_login_keyword,
        'has_suspicious_keyword': has_suspicious_keyword,
        'subdomain_depth': subdomain_depth,
    }


def extract_feature_vector(url: str) -> Optional[list[float]]:
    """Return features as an ordered list matching FEATURE_NAMES."""
    feats = extract_features(url)
    if feats is None:
        return None
    return [feats[name] for name in FEATURE_NAMES]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string. Range 0 (uniform) to log2(alphabet)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _is_ip_address(hostname: str) -> bool:
    """True if the hostname is a raw IPv4 or IPv6 address."""
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        parts = [int(p) for p in hostname.split('.')]
        return all(0 <= p <= 255 for p in parts)
    if hostname.startswith('[') and hostname.endswith(']'):
        return True
    return False


def _has_suspicious_encoding(url: str) -> bool:
    """Detect double-encoding or null bytes."""
    if re.search(r'%25[0-9A-Fa-f]{2}', url):
        return True
    if re.search(r'%00', url, re.I):
        return True
    encoded = re.findall(r'%[0-9A-Fa-f]{2}', url)
    if len(url) > 20 and len(encoded) / len(url) > 0.25:
        return True
    return False


def _extract_registered_domain(hostname: str) -> str:
    """eTLD+1 approximation (same logic as TypeScript urlNormalizer.ts)."""
    if _is_ip_address(hostname):
        return hostname
    labels = hostname.split('.')
    if len(labels) <= 2:
        return hostname
    two_part_tlds = {
        'co.uk', 'co.in', 'co.jp', 'co.nz', 'co.za', 'co.au',
        'com.au', 'com.br', 'com.cn', 'com.mx', 'com.ar',
        'net.au', 'org.uk', 'ac.uk', 'gov.uk',
    }
    last_two = '.'.join(labels[-2:])
    if last_two in two_part_tlds:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])
