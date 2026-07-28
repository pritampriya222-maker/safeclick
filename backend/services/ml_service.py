"""
backend/services/ml_service.py
────────────────────────────────────────────────────────────────────────────
Phase 3 ML prediction service.

- Loads the trained model ONCE at startup (not per-request).
- Exposes predict(url) -> MlPrediction dataclass.
- Uses SHAP TreeExplainer for per-request feature contributions.
  Falls back to global feature importances if SHAP is unavailable
  or per-request SHAP is too slow (>100ms).
- Latency budget: < 300ms per prediction (inference + SHAP).
- Gracefully handles missing model file — returns 'unavailable' result.
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from ml.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA,
    extract_feature_vector,
    extract_features,
)

MODEL_PATH = Path(__file__).resolve().parent.parent / 'ml' / 'model.joblib'
MODEL_VERSION = "1.0.0"

# Latency budget: 300ms for full prediction + SHAP
LATENCY_BUDGET_MS = 300

# Try imports at module load time (not per-request)
try:
    import joblib
    _JOBLIB_OK = True
except ImportError:
    _JOBLIB_OK = False

try:
    import shap
    _SHAP_OK = True
except ImportError:
    _SHAP_OK = False


@dataclass
class FeatureContribution:
    feature_name: str
    label: str
    value: float
    contribution: float  # positive = toward phishing


@dataclass
class MlPrediction:
    ml_score: Optional[float]          # 0–1 phishing probability
    ml_label: Optional[str]            # "phishing" or "benign"
    model_version: str
    top_contributing_features: list[FeatureContribution] = field(default_factory=list)
    source: str = 'unavailable'        # 'model' or 'unavailable'
    latency_ms: float = 0.0


class MlService:
    """
    Phishing URL classifier loaded once at startup.

    Usage:
        svc = MlService()
        svc.load()               # call once in FastAPI lifespan
        pred = svc.predict(url)
    """

    def __init__(self):
        self._model = None
        self._meta: dict = {}
        self._global_importances: list[FeatureContribution] = []
        self._shap_explainer = None
        self._loaded = False

    def load(self) -> None:
        """
        Load model from disk. Safe to call even if model file doesn't exist.
        If loading fails, predict() will always return 'unavailable'.
        """
        if not _JOBLIB_OK:
            print("[SafeClick ML] joblib not available — ML prediction disabled.")
            return

        if not MODEL_PATH.exists():
            print(f"[SafeClick ML] Model not found at {MODEL_PATH}. "
                  "Run 'python ml/train.py' to train. ML prediction disabled.")
            return

        try:
            bundle = joblib.load(MODEL_PATH)
            self._model = bundle['model']
            self._meta = bundle.get('meta', {})
            self._loaded = True

            # Pre-compute global feature importances (always available, zero cost at inference)
            importances = self._model.feature_importances_
            self._global_importances = [
                FeatureContribution(
                    feature_name=FEATURE_NAMES[i],
                    label=FEATURE_SCHEMA.get(FEATURE_NAMES[i], FEATURE_NAMES[i]),
                    value=0.0,
                    contribution=float(importances[i]),
                )
                for i in range(len(FEATURE_NAMES))
            ]
            self._global_importances.sort(key=lambda x: abs(x.contribution), reverse=True)

            # Try to build SHAP TreeExplainer
            if _SHAP_OK:
                try:
                    self._shap_explainer = shap.TreeExplainer(self._model)
                    print("[SafeClick ML] SHAP TreeExplainer ready.")
                except Exception as e:
                    print(f"[SafeClick ML] SHAP unavailable: {e} — using global feature importances.")

            print(f"[SafeClick ML] Model loaded (v{self._meta.get('version', MODEL_VERSION)}, "
                  f"{self._meta.get('model_type', 'unknown')}).")
        except Exception as e:
            print(f"[SafeClick ML] Failed to load model: {e}")
            self._loaded = False

    def predict(self, url: str) -> MlPrediction:
        """
        Predict phishing probability for a URL.
        Always returns — never raises. Uses graceful degradation.
        Respects LATENCY_BUDGET_MS; falls back to global importances if slow.
        """
        t0 = time.perf_counter()

        if not self._loaded or self._model is None:
            return MlPrediction(
                ml_score=None,
                ml_label=None,
                model_version=MODEL_VERSION,
                source='unavailable',
            )

        features_dict = extract_features(url)
        if features_dict is None:
            return MlPrediction(
                ml_score=None,
                ml_label=None,
                model_version=MODEL_VERSION,
                source='unavailable',
            )

        feature_vector = [features_dict[name] for name in FEATURE_NAMES]
        X = np.array([feature_vector], dtype=np.float32)

        try:
            proba = self._model.predict_proba(X)[0]
            ml_score = float(proba[1])  # probability of class 1 (phishing)
            ml_label = 'phishing' if ml_score >= 0.5 else 'benign'
        except Exception as e:
            print(f"[SafeClick ML] Prediction error: {e}")
            return MlPrediction(
                ml_score=None,
                ml_label=None,
                model_version=MODEL_VERSION,
                source='unavailable',
            )

        # ── Feature contributions ──────────────────────────────────────────────
        contributions = self._get_contributions(X, feature_vector, features_dict)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return MlPrediction(
            ml_score=round(ml_score, 4),
            ml_label=ml_label,
            model_version=self._meta.get('version', MODEL_VERSION),
            top_contributing_features=contributions[:5],
            source='model',
            latency_ms=round(elapsed_ms, 1),
        )

    def _get_contributions(
        self,
        X: np.ndarray,
        feature_vector: list[float],
        features_dict: dict[str, float],
    ) -> list[FeatureContribution]:
        """
        Get per-URL feature contributions using SHAP if available and fast,
        otherwise use global feature importances scaled by the feature values.
        """
        # Try SHAP first (only if within latency budget)
        if self._shap_explainer is not None:
            try:
                t_shap = time.perf_counter()
                shap_values = self._shap_explainer.shap_values(X)
                elapsed_shap = (time.perf_counter() - t_shap) * 1000

                if elapsed_shap < LATENCY_BUDGET_MS:
                    # SHAP returns shape (n_samples, n_features) for tree models
                    if isinstance(shap_values, list):
                        # Binary classification: list of 2 arrays [class0, class1]
                        vals = shap_values[1][0]
                    else:
                        vals = shap_values[0]

                    contributions = [
                        FeatureContribution(
                            feature_name=FEATURE_NAMES[i],
                            label=FEATURE_SCHEMA.get(FEATURE_NAMES[i], FEATURE_NAMES[i]),
                            value=round(float(feature_vector[i]), 4),
                            contribution=round(float(vals[i]), 4),
                        )
                        for i in range(len(FEATURE_NAMES))
                    ]
                    contributions.sort(key=lambda x: abs(x.contribution), reverse=True)
                    return contributions
            except Exception:
                pass  # Fall through to global importances

        # Global feature importances (zero latency, less precise)
        contributions = []
        for i, name in enumerate(FEATURE_NAMES):
            val = features_dict.get(name, 0.0)
            global_imp = self._global_importances[i].contribution if i < len(self._global_importances) else 0.0
            # Scale by feature value: non-zero features that are important get higher contribution
            effective_contribution = global_imp * (1.0 if val > 0 else -0.1)
            contributions.append(FeatureContribution(
                feature_name=name,
                label=FEATURE_SCHEMA.get(name, name),
                value=round(float(val), 4),
                contribution=round(effective_contribution, 4),
            ))
        contributions.sort(key=lambda x: abs(x.contribution), reverse=True)
        return contributions

    @property
    def is_loaded(self) -> bool:
        return self._loaded


# ── Module-level singleton ────────────────────────────────────────────────────
_default_ml_service: Optional[MlService] = None


def get_ml_service() -> MlService:
    """Return the shared ML service singleton (lazy init, not pre-loaded)."""
    global _default_ml_service
    if _default_ml_service is None:
        _default_ml_service = MlService()
    return _default_ml_service
