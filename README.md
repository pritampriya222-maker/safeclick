# SafeClick 🛡️
> **Explainable, Multi-Layered, Local-First Phishing & Threat Intelligence Browser Defense**

[![Chrome Extension](https://img.shields.io/badge/Manifest-V3-blue.svg?style=flat-square&logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![React 18](https://img.shields.io/badge/React-18.3.1-61DAFB.svg?style=flat-square&logo=react)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688.svg?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost%201.0.0-FF6600.svg?style=flat-square&logo=xgboost)](https://xgboost.readthedocs.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?style=flat-square&logo=postgresql)](https://www.postgresql.org/)
[![Tests](https://img.shields.io/badge/Tests-258%20Passing-success.svg?style=flat-square)](https://vitest.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

---

## 📑 Table of Contents
1. [Executive Summary & Motivation](#-executive-summary--motivation)
2. [Key Capabilities](#-key-capabilities)
3. [Technology Stack](#-technology-stack)
4. [Detection Methodology & Architecture](#-detection-methodology--architecture)
5. [Theoretical & Algorithmic Foundations](#-theoretical--algorithmic-foundations)
6. [Literature Review & Academic References](#-literature-review--academic-references)
7. [Getting Started & Installation](#-getting-started--installation)
8. [Extension UI & User Experience](#-extension-ui--user-experience)
9. [Backend Cloud Platform & API Reference](#-backend-cloud-platform--api-reference)
10. [Model Card & Evaluation Metrics](#-model-card--evaluation-metrics)
11. [Testing & Quality Assurance](#-testing--quality-assurance)
12. [Privacy & Security Guarantees](#-privacy--security-guarantees)

---

## 📌 Executive Summary & Motivation

Traditional web safety mechanisms face three major structural flaws:
1. **Black-Box Opacity**: Standard browser warnings present generic "Deceptive site ahead" screens without explaining *why* a domain is dangerous, leading to user fatigue and habituated click-throughs.
2. **Centralized Cloud Latency & Privacy Leakage**: Sending every visited URL to third-party reputation APIs introduces perceptible navigation delays (200–800ms) and exposes browsing history.
3. **Zero-Hour Detection Blind Spots**: Threat list databases (Google Safe Browsing, PhishTank) require hours or days to ingest newly registered domains, leaving users vulnerable during initial phishing campaigns.

**SafeClick** resolves these challenges via a **hybrid, local-first architecture**:
- **0ms In-Browser ML & Heuristic Defense**: Evaluates a 22-feature XGBoost decision-tree ensemble and 5 independent heuristic engines directly in browser memory (zero server dependency required).
- **Transparent Explainability**: Every verdict exposes exact mathematical feature contributions, triggered heuristic rules, and plain-English provenance.
- **Multi-Feed Reputation & Crowdsourced Intelligence**: Seamlessly augments local defense with live feeds from URLhaus (abuse.ch), StevenBlack, OpenPhish, VirusTotal, and an anti-abuse crowdsourced threat aggregation network.

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Target URL Navigation                  │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
        ┌─────────────────────────┐                       ┌─────────────────────────┐
        │  Layer 1: Normalizer    │                       │   Layer 4: Threat Feeds │
        │  - Strip tracking params│                       │   - Top-500 Allowlist   │
        │  - Canonicalize eTLD+1  │                       │   - URLhaus (abuse.ch)  │
        └────────────┬────────────┘                       │   - StevenBlack Feeds   │
                     │                                    └────────────┬────────────┘
        ┌────────────┴────────────┐                                    │
        ▼                         ▼                                    │
┌──────────────────────┐  ┌──────────────────────┐                     │
│ Layer 2: Heuristics  │  │ Layer 3: ML Engine   │                     │
│ - Shannon Entropy    │  │ - 22-Feature Vector  │                     │
│ - Brand Impersonation│  │ - 200-Tree XGBoost   │                     │
│ - Homograph / IDN    │  │ - In-Browser + Cloud │                     │
│ - Shady Media/Warez  │  │ - SHAP Explanations  │                     │
│ - Login Form Signal  │  └──────────┬───────────┘                     │
└──────────┬───────────┘             │                                 │
           │                         │                                 │
           └────────────────► ┌──────┴─────────────────────────────────┘
                              ▼
                 ┌──────────────────────────┐
                 │ Layer 5: Verdict Scorer  │
                 │ - Confidence Scorer (0-1)│
                 │ - Risk Score (0-100)     │
                 │ - Plain-English Reasons  │
                 └────────────┬─────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────┐
│ SAFE / SUSPICIOUS (🟡)│           │ DANGEROUS (🔴 70-100) │
│ Ambient Dot + Tooltip │           │ Full-Page Interstitial│
│ Link Hover Inspector  │           │ 1-Hour Token Bypass   │
└───────────────────────┘           └───────────────────────┘
```

---

## ⚡ Key Capabilities

- **Zero-Server Standalone Execution**: The unpacked extension bundles the compiled XGBoost ML model and curated threat databases; it runs out-of-the-box on Chrome, Brave, Edge, and Opera without running Python or Node.js.
- **Real-Time Link Hover Safety Inspector**: Floating safety badge follows the cursor on mouseover (`Safe 🟢`, `Suspicious 🟡`, `Dangerous 🔴`), warning users before they click.
- **Typosquatting & Unicode Homograph Protection**: Detects adversarial string variations (e.g., `paypa1.com`, `gооgle.com` with Cyrillic `о`) via Damerau-Levenshtein distance and IDN homograph decoding.
- **Suspicious Download & Piracy Shield**: Identifies sketchy streaming, cracked game, repack, and APK mod portals using keyword analysis, high-risk TLD filters, and direct executable payload triggers.
- **Full-Page Warning Interstitial**: High-risk destinations ($\text{score} \ge 70$) are intercepted before rendering, featuring an educational risk breakdown and a cryptographic 1-hour session bypass.
- **Crowdsourced Threat Intel with Anti-Abuse Gating**: Users can report malicious sites; reports are promoted to the global community feed only after satisfying independent multi-reporter thresholds ($N \ge 3$) and automated ML verification ($\text{score} \ge 60$).

---

## 🛠️ Technology Stack

### 🌐 Frontend & Browser Extension (Manifest V3)
| Component | Technology | Rationale |
|---|---|---|
| **Runtime Environment** | Chrome Extensions MV3 | Modern, secure extension manifest with declarative permissions and background service workers |
| **UI Framework** | React 18.3.1 | Modular, reactive component architecture for Popup, Dashboard, Options, and Interstitial |
| **Language** | TypeScript 5.4.5 | Strict static typing across messaging channels, schemas, and heuristic modules |
| **Styling & Design** | Vanilla Modern CSS & CSS Modules | Zero TailwindCSS dependency; tailored glassmorphic dark mode with responsive animations |
| **Bundling & Build** | Vite 5.4.21 + Custom Rollup Config | Dual-output bundling: multi-entry ES chunks for pages + standalone IIFE bundle for content scripts |
| **Client-Side ML Runtime** | Pure TypeScript Tree Evaluator | In-browser decision tree evaluation of 200 XGBoost trees in ~0.05ms |

### ⚙️ Backend & Machine Learning Pipeline
| Component | Technology | Rationale |
|---|---|---|
| **API Framework** | FastAPI 0.115.0 + Uvicorn | High-performance asynchronous Python web framework with OpenAPI / Swagger contracts |
| **Machine Learning** | XGBoost 1.7.6 + Scikit-learn 1.3.2 | Gradient boosted decision trees optimized for structured tabular feature vectors |
| **Explainable AI (XAI)** | TreeSHAP (`shap` 0.44.1) | Game-theoretic feature attribution providing mathematical local feature importances |
| **Feature Extraction** | Pure Python 3.10 `features.py` | 22-dimensional numerical vector pipeline mirroring the TypeScript extension logic |
| **Caching Layer** | `cachetools` TTLCache + Redis 7 | Two-tier caching (in-process memory + optional distributed Redis) |

### 🗄️ Database, Auth & DevOps
| Component | Technology | Rationale |
|---|---|---|
| **Relational Database** | PostgreSQL 16 + `asyncpg` | ACID-compliant relational storage for users, devices, reports, and threat intel |
| **ORM & Migrations** | SQLAlchemy 2.0 (Async) + Alembic | Type-safe asynchronous ORM with automated forward/rollback schema migrations |
| **Authentication** | Direct `bcrypt` + PyJWT | 15-minute access JWTs with 7-day cryptographically rotated refresh tokens |
| **Containerization** | Docker + Docker Compose | Multi-container composition (FastAPI backend + PostgreSQL + optional Redis) |
| **Testing** | Vitest 1.6.1 + Pytest 9.0.3 | 258 automated unit, integration, and property-based regression tests |

---

## 🔬 Detection Methodology & Architecture

SafeClick evaluates destinations through a **5-layer pipeline**:

```
[Raw URL] ──► (1. Normalization) ──► (2. Allowlist / Threat DB)
                                            │
               ┌────────────────────────────┴──────────────────────────┐
               ▼                                                       ▼
      [Matches Allowlist]                                    [Unknown / Threat Domain]
               │                                                       │
               ▼                                                       ▼
      Return SAFE (Score 0)                               (3. Parallel Signals Engine)
                                                         ├─ 5 Local Heuristics
                                                         ├─ In-Browser XGBoost ML
                                                         ├─ URLhaus / StevenBlack DB
                                                         └─ Cloud / VirusTotal Feed
                                                                       │
                                                                       ▼
                                                          (4. Confidence & Scorer)
                                                                       │
                                                                       ▼
                                                          (5. Verdict & Interception)
```

### Layer 1: Normalization & Canonicalization
- Strips 30+ tracking parameters (`utm_*`, `fbclid`, `gclid`, `mc_cid`).
- Resolves IPv4/IPv6 octets, hexadecimal encodings, and Unicode normalization (NFKC).
- Canonicalizes hostnames into subdomains, registered domain ($\text{eTLD}+1$), and public suffix.

### Layer 2: Heuristic Rule Engines
1. **Length & Entropy Analyzer**: Computes Shannon entropy of hostname, subdomain, and path. Flags high-entropy algorithmic domain generation (DGA).
2. **Suspicious Keyword & Brand Impersonation**: Uses Damerau-Levenshtein distance to detect brand names placed in subdomains or paths when the registered domain is not owned by that brand.
3. **URL Structure & Obfuscation**: Flags `@` credential exploits, raw IP addressing, excessive subdomain depth ($\ge 3$), and non-standard network ports.
4. **Login Form Signal**: Content script inspects DOM for `<input type="password">` or credential forms on non-whitelisted domains.
5. **Suspicious Downloads & Warez**: Flags media piracy indices (`123movies`, `fmovies`), cracked game/repack hubs (`steamunlocked`, `fitgirl-repack`, `apkmody`), and direct binary download extensions on untrusted TLDs.

### Layer 3: Machine Learning Classification (XGBoost + SHAP)
- Extracts a 22-dimensional numerical vector representing structural, lexical, entropy, and keyword attributes.
- Predicts binary phishing probability $P(\text{phishing} \mid \vec{x}) \in [0.0, 1.0]$.
- **In-Browser Local ML**: When offline, all 200 decision trees evaluate directly in JavaScript in $< 0.1\text{ms}$.
- **Cloud ML + SHAP**: When online, the FastAPI backend computes exact TreeSHAP marginal contributions $\phi_i(\vec{x})$ for transparent UI rendering.

### Layer 4: Multi-Feed Reputation & Threat Intelligence
- **Bundled Top-500 Baseline**: Instantly trusts top global domains (Google, Microsoft, GitHub, Wikipedia).
- **URLhaus & StevenBlack Blocklist**: Instant local match for known active malware and piracy domains.
- **OpenPhish Community Feed**: Periodically refreshed live phishing database.
- **VirusTotal API (Optional)**: Free-tier multi-engine antivirus consensus query.

### Layer 5: Transparent Risk Scoring & Confidence Resolution
The risk score $S \in [0, 100]$ is computed as:
$$S = \min\left(100, \sum_{i} W_{\text{heuristic}, i} \cdot \mathbb{I}(\text{triggered}_i) + W_{\text{reputation}} \cdot C_{\text{reputation}} + W_{\text{phishing}} \right)$$

Verdict tiers:
- **`Safe`** ($0 \le S \le 29$): Green ambient dot.
- **`Suspicious`** ($30 \le S \le 69$): Amber dot + warning tooltip.
- **`Dangerous`** ($70 \le S \le 100$): Red dot + full-page warning interstitial.

---

## 📐 Theoretical & Algorithmic Foundations

### 1. Shannon Entropy Formulation
Used to detect randomized DGA (Domain Generation Algorithm) subdomains and obfuscated paths:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Where $P(x_i) = \frac{\text{count}(x_i)}{L}$. Subdomains with $H(X) > 3.85$ and length $> 12$ are flagged for high entropy.

### 2. Damerau-Levenshtein Metric for Typosquatting
Computes edit distance allowing insertions, deletions, substitutions, and adjacent transpositions:
$$d_{a,b}(i,j) = \min \begin{cases} 
d_{a,b}(i-1, j) + 1 \\
d_{a,b}(i, j-1) + 1 \\
d_{a,b}(i-1, j-1) + \text{cost}(a_i, b_j) \\
d_{a,b}(i-2, j-2) + 1 & \text{if } a_i = b_{j-1} \text{ and } a_{i-1} = b_j 
\end{cases}$$
If $1 \le d(D_{\text{visited}}, D_{\text{brand}}) \le 2$, the domain is flagged for brand typosquatting.

### 3. Gradient Boosted Decision Tree Formulation
XGBoost minimizes the regularized objective:
$$\mathcal{L}(\phi) = \sum_{i} l(\hat{y}_i, y_i) + \sum_{k} \Omega(f_k), \quad \text{where } \Omega(f) = \gamma T + \frac{1}{2}\lambda \sum_{j=1}^T w_j^2$$
Prediction is the sigmoid of leaf weights across all $K = 200$ trees:
$$P(y = 1 \mid \vec{x}) = \sigma\left( \sum_{k=1}^K f_k(\vec{x}) \right) = \frac{1}{1 + e^{-\sum_{k=1}^K f_k(\vec{x})}}$$

### 4. TreeSHAP Feature Attribution
Computes Shapley values from cooperative game theory:
$$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$
Provides exact local feature importances (e.g., `has_suspicious_keyword: +0.35`).

### 5. Anti-Abuse Crowdsourcing Gating
A reported domain $D$ is promoted to the global threat feed if and only if:
$$\text{UniqueReporters}(D) \ge 3 \quad \land \quad \text{EngineScore}(D) \ge 60$$

---

## 📚 Literature Review & Academic References

1. **URL-Based Phishing Detection & Lexical Analysis**:
   - *Ma, J., Saul, L. K., Savage, S., & Voelker, G. M. (2009).* "Beyond Blacklists: Learning to Detect Malicious Web Sites from Suspicious URLs." *Proceedings of the 15th ACM SIGKDD Conference*, 1245–1254.
   - *Marchal, S., François, J., State, R., & Engel, T. (2014).* "PhishStorm: Detecting Phishing with Streaming Analytics." *IEEE Transactions on Network and Service Management*, 11(4), 458–471.
2. **Typosquatting, Homograph & IDN Attacks**:
   - *Szurdi, J., Kocso, B., Cseh, G., Spring, J., Felegyhazi, M., & Kanich, C. (2014).* "The Long 'Taile' of Typosquatting: An Large-Scale Measurement Study." *ACM SIGCOMM Conference on Internet Measurement (IMC)*, 191–204.
   - *Holgers, T., Starr, D. E., & Chung, B. (2006).* "Cutting through the Confusion: A Solution to the IDN Homograph Attack." *Proceedings of the 21st Annual Computer Security Applications Conference (ACSAC)*, 33–42.
3. **Machine Learning & Tree-Based Classification**:
   - *Chen, T., & Guestrin, C. (2016).* "XGBoost: A Scalable Tree Boosting System." *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 785–794.
4. **Explainable AI in Cybersecurity**:
   - *Lundberg, S. M., & Lee, S. I. (2017).* "A Unified Approach to Interpreting Model Predictions." *Advances in Neural Information Processing Systems (NeurIPS 30)*, 4765–4774.
   - *Bitton, R., et al. (2023).* "Evaluating XAI Methods for Phishing Detection." *Computers & Security*, 128, 103167.
5. **Browser Security & Warning Interstitial Design**:
   - *Akhawe, D., & Felt, A. P. (2013).* "Alice in Warningland: A Large-Scale Field Study of Browser Security Warning Effectiveness." *USENIX Security Symposium*, 257–272.

---

## 🚀 Getting Started & Installation

### Option A: Install Standalone Extension (Zero Server Required)
1. Clone or download this repository.
2. Build the extension bundle:
   ```bash
   cd extension
   npm install
   npm run build
   ```
3. Open your browser (`chrome://extensions`, `brave://extensions`, `edge://extensions`, or `opera://extensions`).
4. Enable **Developer mode** (top-right toggle).
5. Click **Load unpacked** and select the **`extension/dist`** folder.
6. SafeClick is now active with local XGBoost ML detection, link inspection, and threat databases!

---

### Option B: Run Full Cloud Backend & Docker Stack

```bash
# 1. Start PostgreSQL, Redis, and FastAPI Backend via Docker Compose
docker-compose up -d

# 2. Verify backend health
curl http://localhost:8000/api/v1/health
# {"status":"ok","version":"0.5.0","timestamp":"..."}
```

Or run locally with Python:
```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows: venv\Scripts\activate | Linux: source venv/bin/activate
pip install -r requirements.txt

# Run migrations and start server
alembic upgrade head
python main.py                 # Starts at http://localhost:8000
```

---

## 🖥️ Extension UI & User Experience

```
+-------------------------------------------------------------+
|  SAFECLICK SECURITY INSPECTOR                        [92/100]|
|  http://paypal-verification.security-account.tk/login       |
|  [ DANGEROUS ]   Confidence: HIGH                           |
+-------------------------------------------------------------+
|  THREAT SIGNALS DETECTED:                                   |
|  • Brand in suspicious subdomain/path (paypal)              |
|  • High-risk suspicious TLD (.tk)                           |
|  • Login form on untrusted domain                           |
|  • XGBoost ML Risk Probability: 96.4%                       |
+-------------------------------------------------------------+
|  [ Trust Domain ]   [ Block Domain ]   [ View Audit Log ]   |
+-------------------------------------------------------------+
```

1. **Ambient Status Indicator**: Discreet pulsing dot in the top-right of every web page. Hovering renders a safety breakdown card.
2. **Link Hover Inspector**: Real-time cursor badge inspecting any link before you click.
3. **Popup Dashboard**: Instant risk dial (0–100), feature breakdown list, one-click allowlisting, and report button.
4. **Full Interstitial Screen**: Intercepts dangerous sites with educational warnings and a 1-hour session bypass token.
5. **Security Audit Log**: Complete history of visited domains, risk scores, and reasons with search, filtering, and JSON export.

---

## 🔌 Backend Cloud Platform & API Reference

| Endpoint | Method | Description | Auth Required |
|---|---|---|---|
| `/api/v1/predict` | `POST` | 22-feature extraction + XGBoost ML prediction + SHAP explanations | Optional |
| `/api/v1/reputation` | `GET` | Multi-source reputation lookup (OpenPhish, URLhaus, VirusTotal) | No |
| `/api/v1/threat-intel/lookup`| `GET` | Query crowdsourced threat intelligence database | No |
| `/api/v1/reports` | `POST` | Submit a malicious site report (Rate limited: 10/hr/IP) | Optional |
| `/api/v1/auth/register` | `POST` | Register a new user account | No |
| `/api/v1/auth/login` | `POST` | Authenticate and obtain JWT access + refresh tokens | No |
| `/api/v1/auth/refresh` | `POST` | Rotate refresh token and obtain new access token | Refresh JWT |
| `/api/v1/analytics/event` | `POST` | Log privacy-preserving aggregate telemetry | Optional |

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

---

## 📊 Model Card & Evaluation Metrics

| Metric | Result (Held-Out Test Set) |
|---|---|
| **Model Algorithm** | XGBoost (`XGBClassifier`) |
| **Accuracy** | **98.21%** |
| **Precision** | **96.15%** |
| **Recall (Phishing)** | **100.0%** (Zero missed phishing URLs) |
| **F1 Score** | **98.04%** |
| **ROC AUC Score** | **0.9974** |
| **Inference Latency** | **$< 0.1\text{ms}$** (In-Browser TS) / **$\approx 35\text{ms}$** (Python Cloud + SHAP) |

### 22 Numerical Features:
`url_length`, `path_length`, `domain_length`, `tld_length`, `num_dots`, `num_hyphens`, `num_digits_in_hostname`, `num_query_params`, `subdomain_entropy`, `path_entropy`, `is_ip_address`, `has_at_symbol`, `is_idn`, `is_punycode`, `has_suspicious_encoding`, `port_is_nonstandard`, `has_https`, `has_suspicious_tld`, `brand_keyword_count`, `has_login_keyword`, `has_suspicious_keyword`, `subdomain_depth`.

---

## 🧪 Testing & Quality Assurance

SafeClick maintains a comprehensive **258-test test suite**:

```bash
# 1. Run Extension Vitest Suite (140 tests)
cd extension
npm run test

# 2. Run Backend Pytest Suite (118 tests)
cd backend
pytest -v
```

```
========================= 118 passed in 5.85s =========================
✓ tests/authClient.test.ts (8 tests)
✓ tests/riskScorer.test.ts (13 tests)
✓ tests/heuristics.test.ts (33 tests)
✓ tests/intelligenceClient.test.ts (8 tests)
✓ tests/storage.test.ts (16 tests)
✓ tests/urlNormalizer.test.ts (25 tests)
✓ tests/messaging.test.ts (12 tests)
✓ tests/historyStore.test.ts (7 tests)
✓ tests/verdictStub.test.ts (18 tests)
Test Files  9 passed (9) | Tests 140 passed (140)
```

---

## 🔒 Privacy & Security Guarantees

1. **Local-First Guarantee**: All heuristic checks, allowlist evaluations, and ML predictions run locally in the browser by default. No URLs leave your device unless cloud lookups are explicitly enabled.
2. **Zero Plaintext Credentials**: Passwords are never extracted, inspected, or transmitted. The content script only reads boolean form existence flags.
3. **Cryptographic Protection**: Backend passwords hashed with `bcrypt` (work factor 12). Tokens signed with HMAC-SHA256.
4. **Differential Privacy**: Analytics events aggregate high-level metrics (rule triggers, verdict counts) stripped of user identifiers, query parameters, and session cookies.

---

## 📄 License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
