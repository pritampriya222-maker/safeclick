"""
backend/ml/train.py
────────────────────────────────────────────────────────────────────────────
Reproducible training script for the SafeClick phishing classifier.

Usage:
    python -m backend.ml.train                           # uses sample_dataset.csv
    python -m backend.ml.train --data path/to/urls.csv  # custom dataset
    python -m backend.ml.train --help

Output:
    backend/ml/model.joblib       — trained XGBoost (or GB) classifier
    backend/ml/eval_report.json   — validation metrics
    backend/ml/model_card.md      — human-readable model card

Dataset CSV format:
    url,label
    https://google.com,benign
    http://paypal-fake.tk/login,phishing
"""

import argparse
import json
import os
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings('ignore')

# Allow running as: python -m backend.ml.train OR python backend/ml/train.py
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / 'backend'))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_NAMES, extract_feature_vector

# Optional XGBoost (preferred if available)
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("[SafeClick] XGBoost not available, using GradientBoostingClassifier.")

MODEL_VERSION = "1.0.0"
RANDOM_SEED = 42
ML_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ML_DIR.parent


def load_dataset(csv_path: Path) -> tuple[list[str], list[int]]:
    """Load and validate a CSV dataset. Returns (urls, labels)."""
    df = pd.read_csv(csv_path)
    required = {'url', 'label'}
    if not required.issubset(df.columns):
        raise ValueError(f"CSV must have columns: {required}. Got: {set(df.columns)}")

    # Normalize labels
    df['label_int'] = df['label'].map({'phishing': 1, 'benign': 0})
    df = df.dropna(subset=['label_int'])
    df['label_int'] = df['label_int'].astype(int)

    print(f"[Train] Dataset: {len(df)} rows ({df['label_int'].sum()} phishing, {(df['label_int']==0).sum()} benign)")
    return df['url'].tolist(), df['label_int'].tolist()


def build_feature_matrix(urls: list[str], labels: list[int]) -> tuple[np.ndarray, np.ndarray]:
    """Extract features for all URLs, skipping unparseable ones."""
    X, y = [], []
    skipped = 0
    for url, label in zip(urls, labels):
        feats = extract_feature_vector(url)
        if feats is None:
            skipped += 1
            continue
        X.append(feats)
        y.append(label)
    if skipped:
        print(f"[Train] Skipped {skipped} unparseable URLs.")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def build_model() -> object:
    """Return the best available classifier."""
    if HAS_XGBOOST:
        print("[Train] Using XGBClassifier.")
        return XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric='logloss',
            random_state=RANDOM_SEED,
            verbosity=0,
        )
    else:
        print("[Train] Using GradientBoostingClassifier.")
        return GradientBoostingClassifier(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            random_state=RANDOM_SEED,
            verbose=0,
        )


def train(csv_path: Path) -> None:
    print(f"\n[SafeClick ML] Training pipeline started — model v{MODEL_VERSION}")
    print(f"[SafeClick ML] Dataset: {csv_path}")

    # ── Load data ──────────────────────────────────────────────────────────────
    urls, labels = load_dataset(csv_path)
    X, y = build_feature_matrix(urls, labels)
    print(f"[Train] Feature matrix: {X.shape[0]} rows × {X.shape[1]} features")

    # ── Train/test split ───────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_SEED
    )
    print(f"[Train] Split: {len(X_train)} train / {len(X_test)} test")

    # ── Train model ───────────────────────────────────────────────────────────
    model = build_model()
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"[Train] Training complete in {elapsed:.1f}s")

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n[Eval] Accuracy:  {accuracy:.4f}")
    print(f"[Eval] Precision: {precision:.4f}")
    print(f"[Eval] Recall:    {recall:.4f}")
    print(f"[Eval] F1 Score:  {f1:.4f}")
    print(f"[Eval] ROC AUC:   {roc_auc:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['benign', 'phishing'])}")

    # Feature importances
    importances = model.feature_importances_
    feat_imp = sorted(
        [(FEATURE_NAMES[i], float(importances[i])) for i in range(len(FEATURE_NAMES))],
        key=lambda x: x[1], reverse=True,
    )

    # ── Save model ────────────────────────────────────────────────────────────
    model_path = ML_DIR / 'model.joblib'
    meta = {
        'version': MODEL_VERSION,
        'feature_names': FEATURE_NAMES,
        'model_type': type(model).__name__,
        'train_size': len(X_train),
        'test_size': len(X_test),
        'dataset_source': str(csv_path),
    }
    joblib.dump({'model': model, 'meta': meta}, model_path)
    print(f"[SafeClick ML] Model saved -> {model_path}")

    # ── Save eval report ──────────────────────────────────────────────────────
    eval_report = {
        'model_version': MODEL_VERSION,
        'model_type': type(model).__name__,
        'dataset_path': str(csv_path),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'training_time_seconds': round(elapsed, 2),
        'metrics': {
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(roc_auc, 4),
        },
        'confusion_matrix': cm,
        'top_features': feat_imp[:10],
    }
    eval_path = ML_DIR / 'eval_report.json'
    with open(eval_path, 'w') as f:
        json.dump(eval_report, f, indent=2)
    print(f"[SafeClick ML] Eval report saved -> {eval_path}")

    _write_model_card(eval_report, feat_imp)
    print(f"[SafeClick ML] Training complete. Model version: {MODEL_VERSION}")

def _write_model_card(report: dict, feat_imp: list) -> None:
    card_path = ML_DIR / 'model_card.md'
    model_type = report['model_type']
    metrics = report['metrics']
    top_feats = feat_imp[:10]

    content = f"""# SafeClick ML Model Card — v{MODEL_VERSION}

## Model Overview

| Field | Value |
|-------|-------|
| Model Type | {model_type} |
| Version | {MODEL_VERSION} |
| Task | Binary classification: phishing vs. benign URL |
| Features | {len(FEATURE_NAMES)} (see below) |
| Training Samples | {report['train_samples']} |
| Test Samples | {report['test_samples']} |
| Training Time | {report['training_time_seconds']}s |

## Validation Metrics (Held-Out Test Set)

| Metric | Value |
|--------|-------|
| Accuracy | {metrics['accuracy']} |
| Precision | {metrics['precision']} |
| Recall | {metrics['recall']} |
| F1 Score | {metrics['f1_score']} |
| ROC AUC | {metrics['roc_auc']} |

## Dataset

- **Source**: {report['dataset_path']}
- **Split**: 80% train / 20% test (stratified, seed=42)
- **Classes**: `phishing` (1) and `benign` (0)

See `backend/ml/data/README.md` for full dataset documentation and license information.

## Features Used ({len(FEATURE_NAMES)} total)

All features are derived from URL structure — no page content, no cookies,
no network requests during feature extraction. The same feature definitions
are used in `backend/ml/features.py` (Python/ML) and `backend/rules/phishing_rules.json`
(rule engine), preventing feature-definition drift.

```
{chr(10).join(f'  {name}' for name in FEATURE_NAMES)}
```

## Top 10 Most Important Features

| Rank | Feature | Importance |
|------|---------|-----------|
{chr(10).join(f'| {i+1} | {name} | {imp:.4f} |' for i, (name, imp) in enumerate(top_feats))}

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
"""
    with open(card_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[SafeClick ML] Model card saved → {card_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SafeClick Phase 3 — Train phishing classifier')
    parser.add_argument(
        '--data',
        type=Path,
        default=Path(__file__).parent / 'data' / 'sample_dataset.csv',
        help='Path to labeled URL CSV (columns: url, label). Default: sample_dataset.csv',
    )
    args = parser.parse_args()

    if not args.data.exists():
        print(f"[Error] Dataset not found: {args.data}")
        sys.exit(1)

    train(args.data)
