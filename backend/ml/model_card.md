# SafeClick ML Model Card — v1.0.0

## Model Overview

| Field | Value |
|-------|-------|
| Model Type | XGBClassifier |
| Version | 1.0.0 |
| Task | Binary classification: phishing vs. benign URL |
| Features | 22 (see below) |
| Training Samples | 223 |
| Test Samples | 56 |
| Training Time | 0.18s |

## Validation Metrics (Held-Out Test Set)

| Metric | Value |
|--------|-------|
| Accuracy | 0.9821 |
| Precision | 0.9615 |
| Recall | 1.0 |
| F1 Score | 0.9804 |
| ROC AUC | 0.9974 |

## Dataset

- **Source**: C:\pritam\safeclick\backend\ml\data\sample_dataset.csv
- **Split**: 80% train / 20% test (stratified, seed=42)
- **Classes**: `phishing` (1) and `benign` (0)

See `backend/ml/data/README.md` for full dataset documentation and license information.

## Features Used (22 total)

All features are derived from URL structure — no page content, no cookies,
no network requests during feature extraction. The same feature definitions
are used in `backend/ml/features.py` (Python/ML) and `backend/rules/phishing_rules.json`
(rule engine), preventing feature-definition drift.

```
  url_length
  path_length
  domain_length
  tld_length
  num_dots
  num_hyphens
  num_digits_in_hostname
  num_query_params
  subdomain_entropy
  path_entropy
  is_ip_address
  has_at_symbol
  is_idn
  is_punycode
  has_suspicious_encoding
  port_is_nonstandard
  has_https
  has_suspicious_tld
  brand_keyword_count
  has_login_keyword
  has_suspicious_keyword
  subdomain_depth
```

## Top 10 Most Important Features

| Rank | Feature | Importance |
|------|---------|-----------|
| 1 | url_length | 0.1999 |
| 2 | num_hyphens | 0.1582 |
| 3 | num_digits_in_hostname | 0.1236 |
| 4 | path_length | 0.1065 |
| 5 | path_entropy | 0.1043 |
| 6 | has_suspicious_tld | 0.0744 |
| 7 | has_https | 0.0524 |
| 8 | subdomain_entropy | 0.0507 |
| 9 | num_dots | 0.0490 |
| 10 | has_login_keyword | 0.0446 |

## Known Limitations

- Trained on a synthetic/sample dataset by default — for production use, train on a
  larger real-world dataset (see `data/README.md`).
- URL-only features: cannot detect phishing pages that use legitimate domains
  (e.g. attacker-controlled subdomains on shared hosting). Phase 2's content
  script signals (login form detection) are not included in ML features.
- Non-English brand names may be underrepresented in the brand keyword list.
- IDN homograph attacks with unusual scripts may not be captured by the
  `is_idn` binary feature alone — Phase 2's confusables table provides additional coverage.

## Intended Use

Internal use only as part of SafeClick's Phase 3 intelligence layer.
The ML score is always combined with Phase 2's rule engine score via
the confidence scorer before a final verdict is produced. The ML model
alone should never override a confirmed reputation signal.
