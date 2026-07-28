"""
backend/api/predict.py
────────────────────────────────────────────────────────────────────────────
POST /api/v1/predict — ML-powered phishing prediction endpoint.

Contract (also in docs/api-contracts.md):
  Request:  POST /api/v1/predict
            Content-Type: application/json
            { "url": "https://example.com/path" }

  Response: 200 OK
            {
              "ml_score": 0.04,
              "ml_label": "benign",
              "model_version": "1.0.0",
              "top_contributing_features": [
                { "feature_name": "has_suspicious_tld", "label": "Suspicious TLD",
                  "value": 0.0, "contribution": -0.12 }
              ],
              "source": "model",
              "latency_ms": 38.2,
              "rule_score": 0,
              "rule_reasons": ["No rule-based threat signals detected."],
              "rule_engine_version": "1.0.0",
              "confidence": {
                "level": "high",
                "agreement": true,
                "combined_score": 0.02,
                "note": "Rule engine and ML model are in strong agreement."
              },
              "explanation": {
                "summary": "This URL appears safe based on rule analysis and ML model.",
                "rule_reasons": ["No rule-based threat signals detected."],
                "ml_reasons": ["ML model found no strong phishing features."]
              }
            }
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, HttpUrl, field_validator

from ml.features import extract_features
from services.ml_service import MlService
from services.rule_engine import RuleEngine, get_rule_engine
from services.confidence_scorer import compute_confidence, build_explanation


router = APIRouter()


class PredictRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty.")
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError("URL must start with http:// or https://")
        if len(v) > 2000:
            raise ValueError("URL too long (max 2000 characters).")
        return v


class FeatureContributionResponse(BaseModel):
    feature_name: str
    label: str
    value: float
    contribution: float


class ConfidenceResponse(BaseModel):
    level: str
    agreement: bool
    combined_score: float
    note: str


class ExplanationResponse(BaseModel):
    summary: str
    rule_reasons: list[str]
    ml_reasons: list[str]


class PredictResponse(BaseModel):
    # ML
    ml_score: float | None
    ml_label: str | None
    model_version: str
    top_contributing_features: list[FeatureContributionResponse]
    source: str
    latency_ms: float
    # Rule engine
    rule_score: int
    rule_reasons: list[str]
    rule_engine_version: str
    # Confidence
    confidence: ConfidenceResponse
    # Explanation
    explanation: ExplanationResponse


@router.post(
    "/predict",
    response_model=PredictResponse,
    summary="ML Phishing Prediction",
    description=(
        "Run the Phase 3 intelligence pipeline on a URL: "
        "extracts 22 features, evaluates declarative rules, "
        "runs the XGBoost ML classifier, and combines both signals "
        "into a confidence-scored, explainable result. "
        "Latency budget: <300ms. Gracefully degrades if ML is unavailable."
    ),
)
async def predict(request: Request, body: PredictRequest) -> PredictResponse:
    """Phase 3 intelligence prediction endpoint."""
    url = body.url

    # ── Extract features ──────────────────────────────────────────────────────
    features = extract_features(url)
    if features is None:
        raise HTTPException(status_code=400, detail="Could not parse URL.")

    # ── Rule engine (synchronous, CPU-only, <5ms) ─────────────────────────────
    rule_engine: RuleEngine = get_rule_engine()
    rule_output = rule_engine.evaluate(features)

    # ── ML prediction (may be unavailable) ───────────────────────────────────
    ml_service: MlService = getattr(request.app.state, 'ml_service', None)
    if ml_service is not None:
        ml_pred = ml_service.predict(url)
    else:
        from services.ml_service import MlPrediction
        ml_pred = MlPrediction(
            ml_score=None,
            ml_label=None,
            model_version="1.0.0",
            source='unavailable',
        )

    # ── Confidence scoring ────────────────────────────────────────────────────
    confidence = compute_confidence(
        rule_score=rule_output.total_score,
        ml_score=ml_pred.ml_score,
    )

    # ── Determine final verdict label (for explanation) ───────────────────────
    if confidence.combined_score >= 0.65:
        final_verdict = 'dangerous'
    elif confidence.combined_score >= 0.35:
        final_verdict = 'suspicious'
    else:
        final_verdict = 'safe'

    # ── Build explanation ─────────────────────────────────────────────────────
    explanation = build_explanation(
        rule_reasons=rule_output.reasons,
        ml_contributions=ml_pred.top_contributing_features,
        confidence=confidence,
        final_verdict=final_verdict,
    )

    return PredictResponse(
        ml_score=ml_pred.ml_score,
        ml_label=ml_pred.ml_label,
        model_version=ml_pred.model_version,
        top_contributing_features=[
            FeatureContributionResponse(
                feature_name=c.feature_name,
                label=c.label,
                value=c.value,
                contribution=c.contribution,
            )
            for c in ml_pred.top_contributing_features
        ],
        source=ml_pred.source,
        latency_ms=ml_pred.latency_ms,
        rule_score=rule_output.total_score,
        rule_reasons=rule_output.reasons,
        rule_engine_version=rule_output.rule_engine_version,
        confidence=ConfidenceResponse(
            level=confidence.level,
            agreement=confidence.agreement,
            combined_score=confidence.combined_score,
            note=confidence.note,
        ),
        explanation=ExplanationResponse(
            summary=explanation['summary'],
            rule_reasons=explanation['ruleReasons'],
            ml_reasons=explanation['mlReasons'],
        ),
    )
