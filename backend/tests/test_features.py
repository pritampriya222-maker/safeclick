"""
backend/tests/test_features.py
────────────────────────────────────────────────────────────────────────────
Pytest tests for ml/features.py — feature extraction correctness.
"""

import pytest
from ml.features import (
    extract_features, extract_feature_vector, FEATURE_NAMES,
    _shannon_entropy, _is_ip_address, _has_suspicious_encoding,
    _extract_registered_domain,
)


class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert _shannon_entropy('') == 0.0

    def test_uniform_string_returns_zero(self):
        assert _shannon_entropy('aaaaaaa') == 0.0

    def test_high_entropy_for_random_string(self):
        assert _shannon_entropy('xk4jq2ab9zf') > _shannon_entropy('aaabbbccc')


class TestIsIpAddress:
    def test_valid_ipv4(self):
        assert _is_ip_address('192.168.1.1') is True
        assert _is_ip_address('10.0.0.1') is True
        assert _is_ip_address('0.0.0.0') is True

    def test_domain_is_not_ip(self):
        assert _is_ip_address('example.com') is False
        assert _is_ip_address('paypal.com') is False

    def test_partial_ip_not_matched(self):
        assert _is_ip_address('192.168.1') is False

    def test_invalid_octet_not_matched(self):
        assert _is_ip_address('999.0.0.1') is False


class TestSuspiciousEncoding:
    def test_double_encoded_percent(self):
        assert _has_suspicious_encoding('https://example.com/path%252Ftraversal') is True

    def test_null_byte(self):
        assert _has_suspicious_encoding('https://example.com/file%00.txt') is True

    def test_normal_url_is_clean(self):
        assert _has_suspicious_encoding('https://example.com/hello%20world') is False


class TestExtractRegisteredDomain:
    def test_simple_domain(self):
        assert _extract_registered_domain('example.com') == 'example.com'

    def test_strips_subdomain(self):
        assert _extract_registered_domain('sub.example.com') == 'example.com'

    def test_two_part_tld(self):
        assert _extract_registered_domain('sub.example.co.uk') == 'example.co.uk'

    def test_ip_address_unchanged(self):
        assert _extract_registered_domain('192.168.1.1') == '192.168.1.1'


class TestExtractFeatures:
    def test_returns_dict_for_valid_url(self):
        feats = extract_features('https://example.com/page?q=1')
        assert feats is not None
        assert set(feats.keys()) == set(FEATURE_NAMES)

    def test_returns_none_for_invalid_url(self):
        assert extract_features('not-a-url') is None
        assert extract_features('') is None

    def test_safe_url_features(self):
        feats = extract_features('https://google.com')
        assert feats is not None
        assert feats['is_ip_address'] == 0.0
        assert feats['has_at_symbol'] == 0.0
        assert feats['has_https'] == 1.0
        assert feats['has_suspicious_tld'] == 0.0

    def test_ip_url_features(self):
        feats = extract_features('http://192.168.1.1/login')
        assert feats is not None
        assert feats['is_ip_address'] == 1.0
        assert feats['has_https'] == 0.0

    def test_at_symbol_detected(self):
        feats = extract_features('http://legit.com@attacker-example.com/path')
        assert feats is not None
        assert feats['has_at_symbol'] == 1.0

    def test_brand_keyword_in_wrong_domain(self):
        feats = extract_features('https://paypal-secure.attacker-example.tk/login')
        assert feats is not None
        assert feats['brand_keyword_count'] > 0
        assert feats['has_suspicious_keyword'] == 1.0
        assert feats['has_suspicious_tld'] == 1.0

    def test_login_keyword_detected(self):
        feats = extract_features('https://example.com/login/verify')
        assert feats is not None
        assert feats['has_login_keyword'] == 1.0

    def test_long_url_measured(self):
        long_url = 'https://example.com/' + 'a' * 200
        feats = extract_features(long_url)
        assert feats is not None
        assert feats['url_length'] > 100

    def test_subdomain_entropy_high_for_random(self):
        feats = extract_features('https://xk4jq2ab9zf.attacker-example.com/')
        assert feats is not None
        assert feats['subdomain_entropy'] > 3.0

    def test_nonstandard_port_detected(self):
        feats = extract_features('https://example.com:8443/page')
        assert feats is not None
        assert feats['port_is_nonstandard'] == 1.0

    def test_standard_port_not_flagged(self):
        feats = extract_features('https://example.com:443/page')
        assert feats is not None
        assert feats['port_is_nonstandard'] == 0.0

    def test_punycode_detected(self):
        feats = extract_features('https://xn--pypal-4ve.com/login')
        assert feats is not None
        assert feats['is_punycode'] == 1.0
        assert feats['is_idn'] == 1.0


class TestExtractFeatureVector:
    def test_returns_ordered_list(self):
        vec = extract_feature_vector('https://example.com')
        assert vec is not None
        assert len(vec) == len(FEATURE_NAMES)

    def test_returns_none_for_invalid(self):
        assert extract_feature_vector('not-a-url') is None
