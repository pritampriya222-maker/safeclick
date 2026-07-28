"""
backend/services/confidence_scorer.py
────────────────────────────────────────────────────────────────────────────
Confidence scorer: combines the rule engine's weighted score and the
ML model's probability into a single, transparent confidence-scored verdict.

DOCUMENTED FORMULA (also in docs/architecture.md):
────────────────────────────────────────────────────
  rule_fraction  = rule_score / 100         (normalise to 0–1)
  ml_frac        = ml_score                 (already 0–1; use 0.5 if unavailable)
  agreement      = |rule_fraction - ml_frac| <= 0.30
  combined       = 0.5 * rule_fraction + 0.5 * ml_frac
  penalty        = 0.20 if not agreement else 0.0
  combined       = max(0.0, combined - penalty)   (clipped)

  level = 'high'   if combined >= 0.65 and agreement
        = 'medium' if 0.35 <= combined < 0.65
        = 'low'    otherwise   (or always when ml is unavailable)

RATIONALE:
  - Equal 50/50 weight between rule engine and ML model keeps neither
    dominant; future phases can tune the blend.
  - The agreement penalty (−0.20) intentionally reduces combined score
    when signals conflict, so the verdict reflects uncertainty rather
    than silently picking the higher-confidence signal.
  - When ML is unavailable: ml_frac defaults to 0.5 (maximum uncertainty)
    and level is capped at 'low' so the popup always surfaces the caveat.
────────────────────────────────────────────────────
"""

from dataclasses import dataclass
from typing import Optional


AGREEMENT_THRESHOLD = 0.30
DISAGREEMENT_PENALTY = 0.20

HIGH_CONFIDENCE_THRESHOLD = 0.65
LOW_CONFIDENCE_THRESHOLD = 0.35


@dataclass
class ConfidenceResult:
    level: str            # 'high' | 'medium' | 'low'
    agreement: bool
    combined_score: float  # 0–1 blended score
    note: str             # human-readable explanation
    ml_available: bool


def compute_confidence(
    rule_score: int,
    ml_score: Optional[float],
) -> ConfidenceResult:
    """
    Combine rule score (0–100) and ML score (0–1 or None) into a
    ConfidenceResult. Always returns, never raises.

    Args:
        rule_score:  0–100 weighted score from the rule engine.
        ml_score:    0–1 phishing probability from ML, or None if unavailable.

    Returns:
        ConfidenceResult with level, agreement, combined_score, and note.
    """
    ml_available = ml_score is not None

    rule_fraction = max(0.0, min(1.0, rule_score / 100.0))
    ml_frac = ml_score if ml_available else 0.5  # maximum uncertainty default

    # Agreement: both signals within 0.30 of each other
    agreement = abs(rule_fraction - ml_frac) <= AGREEMENT_THRESHOLD

    # Blended score
    combined = 0.5 * rule_fraction + 0.5 * ml_frac

    # Disagreement penalty
    if not agreement:
        combined = max(0.0, combined - DISAGREEMENT_PENALTY)

    combined = round(combined, 4)

    # Level — ML unavailable always capped at 'low'
    if not ml_available:
        level = 'low'
        note = (
            "ML model unavailable — verdict based on rule engine only. "
            "Confidence is reduced until ML backend is reachable."
        )
    elif agreement and combined >= HIGH_CONFIDENCE_THRESHOLD:
        level = 'high'
        note = (
            f"Rule engine (score {rule_score}/100) and ML model ({ml_frac:.0%} phishing) "
            "are in strong agreement."
        )
    elif not agreement:
        level = 'low'
        note = (
            f"Rule engine (score {rule_score}/100) and ML model ({ml_frac:.0%} phishing) "
            f"disagree by {abs(rule_fraction - ml_frac):.0%}. "
            "Both signals are shown — investigate further before blocking."
        )
    elif combined >= LOW_CONFIDENCE_THRESHOLD:
        level = 'medium'
        note = (
            f"Rule engine (score {rule_score}/100) and ML model ({ml_frac:.0%} phishing) "
            "broadly agree but with moderate certainty."
        )
    else:
        level = 'low'
        note = (
            f"Combined score {combined:.0%} is below the confidence threshold. "
            "Insufficient signal to make a high-confidence determination."
        )

    return ConfidenceResult(
        level=level,
        agreement=agreement,
        combined_score=combined,
        note=note,
        ml_available=ml_available,
    )


def build_explanation(
    rule_reasons: list[str],
    ml_contributions: list,
    confidence: ConfidenceResult,
    final_verdict: str,   # 'safe' | 'suspicious' | 'dangerous'
) -> dict:
    """
    Build the structured ExplanationInfo dict for the Verdict.

    Args:
        rule_reasons:      From rule engine / heuristics.
        ml_contributions:  FeatureContribution-like objects from MlPrediction.
        confidence:        ConfidenceResult.
        final_verdict:     'safe' | 'suspicious' | 'dangerous'.

    Returns:
        dict matching ExplanationInfo TypeScript interface.
    """
    # One-sentence summary
    if final_verdict == 'safe':
        summary = "This URL appears safe based on rule analysis and ML model."
    elif final_verdict == 'suspicious':
        summary = "This URL shows some suspicious patterns — proceed with caution."
    else:
        summary = "This URL shows strong phishing indicators — it is likely dangerous."

    if not confidence.ml_available:
        summary += " (ML model unavailable — rule engine only.)"
    elif not confidence.agreement:
        summary += f" Warning: rule engine and ML model disagree (confidence: {confidence.level})."

    # ML reasons: translate top feature contributions to plain English
    ml_reasons: list[str] = []
    positive_contribs = [c for c in ml_contributions if c.contribution > 0.01]
    for contrib in positive_contribs[:3]:
        label = contrib.label
        val = contrib.value
        if val > 0:
            ml_reasons.append(
                f"ML: '{label}' (value: {val:.2f}) contributed to the phishing prediction."
            )

    if not ml_reasons and not confidence.ml_available:
        ml_reasons = ["ML model unavailable — rule engine only."]
    elif not ml_reasons:
        ml_reasons = ["ML model found no strong phishing features."]

    return {
        'summary': summary,
        'ruleReasons': rule_reasons[:5],  # top 5 rule reasons
        'mlReasons': ml_reasons,
    }
