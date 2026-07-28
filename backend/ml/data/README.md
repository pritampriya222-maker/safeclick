# SafeClick ML Data — Dataset Documentation

## Dataset Used

**Primary**: Synthetic labeled URL dataset generated from known heuristic patterns.

**Benign URLs**: Curated from the [Tranco top-1M list](https://tranco-list.eu/) (CC BY 4.0).

**Phishing URLs** for production training: Use any of the following freely-licensed sources:
- [PhishTank Community Feed](https://www.phishtank.com/developer_info.php) (creative commons, requires free account for API)
- [OpenPhish Community Feed](https://openphish.com/feed.txt) (free, no key required)
- [UCI ML Phishing Websites Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites) (CC BY 4.0)
- [Kaggle Phishing Site URLs](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) (CC0 Public Domain)

## Downloading a Production Dataset

```bash
# Option 1: UCI Phishing dataset (recommended, stable)
# Download from: https://archive.ics.uci.edu/dataset/327/phishing+websites
# Extract and place as: backend/ml/data/phishing_urls.csv

# Option 2: OpenPhish feed (latest live phishing)
curl -o backend/ml/data/openphish.txt https://openphish.com/feed.txt

# Option 3: Use the built-in synthetic sample (for testing/CI)
# File: backend/ml/data/sample_dataset.csv (included in repo)
```

## Sample Dataset (Included)

`sample_dataset.csv` contains ~300 clearly synthetic/fictional URLs:
- **Phishing**: Brand impersonation, raw IPs, suspicious TLDs, keyword stuffing
- **Benign**: Real top-domain URLs from the Tranco/Majestic lists

All phishing examples use **clearly fictional domains** (no real active phishing URLs).

## File Layout

```
backend/ml/data/
├── README.md          ← this file
├── sample_dataset.csv ← built-in ~300 rows (synthetic, safe for CI)
└── .gitkeep           ← keeps the directory tracked
```

## License

- Synthetic sample data: MIT (same as SafeClick project)
- UCI dataset (if downloaded): CC BY 4.0
- OpenPhish (if used): see https://openphish.com/terms_of_service.html
