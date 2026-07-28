"""
backend/tests/test_ml_service.py
────────────────────────────────────────────────────────────────────────────
Pytest tests for services/ml_service.py.
Covers: prediction contract, latency budget, graceful degradation,
model not found handling, feature contribution types.
"""

import pytest
import time
from pathlib import Path


@pytest.fixture
def loaded_service():
    """MlService with model loaded from disk (requires model.joblib to exist)."""
    from services.ml_service import MlService
    svc = MlService()
    svc.load()
    return svc


@pytest.fixture
def unloaded_service():
    """MlService with no model loaded (simulates model missing)."""
    from services.ml_service import MlService
    svc = MlService()
    # Do NOT call load() — simulate missing model
    return svc


class TestMlServiceGracefulDegradation:
    def test_unloaded_service_returns_unavailable(self, unloaded_service):
        pred = unloaded_service.predict('https://example.com')
        assert pred.source == 'unavailable'
        assert pred.ml_score is None
        assert pred.ml_label is None

    def test_invalid_url_returns_unavailable(self, loaded_service):
        pred = loaded_service.predict('not-a-url')
        assert pred.source == 'unavailable'
        assert pred.ml_score is None


class TestMlServicePredictionContract:
    def test_safe_url_returns_low_score(self, loaded_service):
        pred = loaded_service.predict('https://google.com')
        assert pred.source == 'model'
        assert pred.ml_score is not None
        assert 0.0 <= pred.ml_score <= 1.0
        assert pred.ml_label in ('phishing', 'benign')
        assert pred.ml_score < 0.5  # google.com should be benign

    def test_phishing_url_returns_high_score(self, loaded_service):
        pred = loaded_service.predict('http://paypal-secure-login.attacker-example.tk/verify')
        assert pred.source == 'model'
        assert pred.ml_score is not None
        # The model was trained on synthetic data — phishing patterns should score high
        assert pred.ml_score >= 0.4

    def test_prediction_response_has_model_version(self, loaded_service):
        pred = loaded_service.predict('https://example.com')
        assert pred.model_version is not None
        assert len(pred.model_version) > 0

    def test_prediction_has_feature_contributions(self, loaded_service):
        pred = loaded_service.predict('https://example.com')
        assert pred.top_contributing_features is not None
        assert isinstance(pred.top_contributing_features, list)

    def test_feature_contributions_have_correct_shape(self, loaded_service):
        pred = loaded_service.predict('http://paypal-fake.tk/login')
        for fc in pred.top_contributing_features:
            assert hasattr(fc, 'feature_name')
            assert hasattr(fc, 'label')
            assert hasattr(fc, 'value')
            assert hasattr(fc, 'contribution')
            assert isinstance(fc.feature_name, str)
            assert isinstance(fc.contribution, float)


class TestMlServiceLatency:
    def test_prediction_within_300ms_budget(self, loaded_service):
        """Full prediction (inference + SHAP) must complete within 300ms budget."""
        url = 'http://paypal-secure-login.attacker-example.tk/verify'
        t0 = time.perf_counter()
        pred = loaded_service.predict(url)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 300, f"Prediction took {elapsed_ms:.1f}ms (budget: 300ms)"

    def test_prediction_latency_recorded(self, loaded_service):
        pred = loaded_service.predict('https://example.com')
        assert pred.latency_ms >= 0


class TestMlServiceEndpoint:
    """Tests for POST /api/v1/predict endpoint contract."""

    @pytest.fixture
    def app_with_ml(self, loaded_service):
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from main import app
        app.state.ml_service = loaded_service
        return app

    def test_predict_endpoint_returns_200(self, app_with_ml):
        from fastapi.testclient import TestClient
        with TestClient(app_with_ml) as client:
            response = client.post('/api/v1/predict', json={'url': 'https://google.com'})
        assert response.status_code == 200

    def test_predict_endpoint_schema(self, app_with_ml):
        from fastapi.testclient import TestClient
        with TestClient(app_with_ml) as client:
            response = client.post('/api/v1/predict', json={'url': 'https://google.com'})
        data = response.json()
        assert 'ml_score' in data
        assert 'ml_label' in data
        assert 'model_version' in data
        assert 'rule_score' in data
        assert 'rule_reasons' in data
        assert 'confidence' in data
        assert 'explanation' in data

    def test_predict_confidence_schema(self, app_with_ml):
        from fastapi.testclient import TestClient
        with TestClient(app_with_ml) as client:
            response = client.post('/api/v1/predict', json={'url': 'https://google.com'})
        data = response.json()
        conf = data['confidence']
        assert conf['level'] in ('high', 'medium', 'low')
        assert isinstance(conf['agreement'], bool)
        assert 0.0 <= conf['combined_score'] <= 1.0

    def test_predict_explanation_schema(self, app_with_ml):
        from fastapi.testclient import TestClient
        with TestClient(app_with_ml) as client:
            response = client.post('/api/v1/predict', json={'url': 'https://google.com'})
        data = response.json()
        exp = data['explanation']
        assert 'summary' in exp
        assert isinstance(exp['rule_reasons'], list)
        assert isinstance(exp['ml_reasons'], list)
        assert len(exp['summary']) > 0

    def test_predict_invalid_url_returns_400(self, app_with_ml):
        from fastapi.testclient import TestClient
        with TestClient(app_with_ml) as client:
            response = client.post('/api/v1/predict', json={'url': 'not-a-url'})
        assert response.status_code in (400, 422)

    def test_predict_missing_body_returns_422(self, app_with_ml):
        from fastapi.testclient import TestClient
        with TestClient(app_with_ml) as client:
            response = client.post('/api/v1/predict', json={})
        assert response.status_code == 422
