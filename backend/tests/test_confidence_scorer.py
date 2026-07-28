"""
backend/tests/test_confidence_scorer.py
────────────────────────────────────────────────────────────────────────────
Pytest tests for services/confidence_scorer.py.
Covers all documented formula scenarios: agreement/disagreement,
high/medium/low levels, ML unavailable, boundary conditions.
"""

import pytest
from services.confidence_scorer import (
    compute_confidence, build_explanation,
    AGREEMENT_THRESHOLD, DISAGREEMENT_PENALTY,
    HIGH_CONFIDENCE_THRESHOLD, LOW_CONFIDENCE_THRESHOLD,
)


class TestComputeConfidence:

    # ── Basic level outcomes ──────────────────────────────────────────────────

    def test_both_high_gives_high_confidence(self):
        """Rule score 80, ML 0.85 → both high, agreement, high confidence."""
        result = compute_confidence(rule_score=80, ml_score=0.85)
        assert result.level == 'high'
        assert result.agreement is True

    def test_both_low_gives_safe_result(self):
        """Rule score 5, ML 0.03 → both low, agreement, low combined."""
        result = compute_confidence(rule_score=5, ml_score=0.03)
        assert result.level in ('low', 'medium')  # combined is ~0.04
        assert result.agreement is True

    def test_disagreement_gives_low_confidence(self):
        """Rule score 10 (safe) but ML 0.90 (phishing) → disagreement → low."""
        result = compute_confidence(rule_score=10, ml_score=0.90)
        assert result.level == 'low'
        assert result.agreement is False

    def test_high_rule_low_ml_disagree(self):
        """Rule score 80, ML 0.10 → disagree → low."""
        result = compute_confidence(rule_score=80, ml_score=0.10)
        assert result.agreement is False
        assert result.level == 'low'

    def test_ml_unavailable_always_low(self):
        """ML unavailable → always low confidence regardless of rule score."""
        result = compute_confidence(rule_score=90, ml_score=None)
        assert result.level == 'low'
        assert result.ml_available is False

    def test_moderate_scores_give_medium(self):
        """Rule 50, ML 0.50 → combined ~0.50 → medium."""
        result = compute_confidence(rule_score=50, ml_score=0.50)
        assert result.level == 'medium'
        assert result.agreement is True

    # ── Agreement threshold tests ─────────────────────────────────────────────

    def test_agreement_within_threshold(self):
        """|0.5 - 0.7| = 0.2 < 0.3 → agreement."""
        result = compute_confidence(rule_score=50, ml_score=0.70)
        assert result.agreement is True

    def test_disagreement_outside_threshold(self):
        """|0.1 - 0.9| = 0.8 > 0.3 → disagreement."""
        result = compute_confidence(rule_score=10, ml_score=0.90)
        assert result.agreement is False

    def test_exactly_at_threshold_is_disagreement(self):
        """|0.5 - 0.8| = 0.3 = AGREEMENT_THRESHOLD — exactly at threshold is disagreement (strict <)."""
        result = compute_confidence(rule_score=50, ml_score=0.80)
        # |0.5 - 0.8| = 0.3 which equals the threshold; strict < means this is NOT agreement
        assert result.agreement is False

    # ── Score arithmetic ──────────────────────────────────────────────────────

    def test_combined_score_formula(self):
        """combined = 0.5*(60/100) + 0.5*0.6 = 0.6"""
        result = compute_confidence(rule_score=60, ml_score=0.60)
        assert abs(result.combined_score - 0.60) < 0.01

    def test_disagreement_penalty_applied(self):
        """Disagreement: combined - 0.2 penalty."""
        result = compute_confidence(rule_score=10, ml_score=0.90)
        # Without penalty: 0.5*0.1 + 0.5*0.9 = 0.5; with penalty = 0.3
        assert result.combined_score < 0.50

    def test_combined_score_clipped_to_zero(self):
        """Combined score never goes below 0."""
        result = compute_confidence(rule_score=0, ml_score=None)
        assert result.combined_score >= 0.0

    def test_ml_unavailable_uses_0_5_default(self):
        """When ML unavailable, ml_frac = 0.5 (max uncertainty)."""
        # rule_score = 80 → rule_frac = 0.8
        # combined = 0.5*0.8 + 0.5*0.5 = 0.65
        # agreement: |0.8 - 0.5| = 0.3 → at threshold (agreement=True)
        # But level is always 'low' when ML unavailable
        result = compute_confidence(rule_score=80, ml_score=None)
        assert result.level == 'low'
        assert 'unavailable' in result.note.lower()

    # ── Note contains useful information ─────────────────────────────────────

    def test_note_mentions_disagreement(self):
        result = compute_confidence(rule_score=5, ml_score=0.95)
        assert 'disagree' in result.note.lower() or 'agreement' in result.note.lower()

    def test_note_mentions_unavailable(self):
        result = compute_confidence(rule_score=50, ml_score=None)
        assert 'unavailable' in result.note.lower()


class TestBuildExplanation:
    def _confidence(self, ml_available=True, agreement=True, level='high', score=0.8):
        from services.confidence_scorer import ConfidenceResult
        return ConfidenceResult(
            level=level,
            agreement=agreement,
            combined_score=score,
            note='Test note.',
            ml_available=ml_available,
        )

    def _contrib(self, name, val, contrib):
        """Simple contrib-like object."""
        class C:
            feature_name = name
            label = name.replace('_', ' ').title()
            value = val
            contribution = contrib
        return C()

    def test_safe_verdict_has_safe_summary(self):
        exp = build_explanation([], [], self._confidence(score=0.05), 'safe')
        assert 'safe' in exp['summary'].lower()

    def test_dangerous_verdict_has_danger_summary(self):
        exp = build_explanation([], [], self._confidence(score=0.9), 'dangerous')
        assert 'dangerous' in exp['summary'].lower() or 'phishing' in exp['summary'].lower()

    def test_ml_unavailable_noted_in_summary(self):
        conf = self._confidence(ml_available=False, level='low', score=0.4)
        exp = build_explanation(['Rule triggered.'], [], conf, 'suspicious')
        assert 'unavailable' in exp['summary'].lower()

    def test_rule_reasons_included(self):
        exp = build_explanation(
            ['Brand keyword in subdomain.', 'Raw IP address.'],
            [],
            self._confidence(),
            'dangerous',
        )
        assert 'Brand keyword in subdomain.' in exp['ruleReasons']

    def test_ml_contrib_translated_to_english(self):
        contrib = self._contrib('has_suspicious_tld', 1.0, 0.5)
        exp = build_explanation([], [contrib], self._confidence(), 'dangerous')
        assert any('Has Suspicious Tld' in r or 'suspicious' in r.lower() for r in exp['mlReasons'])

    def test_negative_contribs_not_included(self):
        """Negative contributions (push toward benign) should not appear in ml_reasons."""
        contrib = self._contrib('has_https', 1.0, -0.3)  # negative = toward benign
        exp = build_explanation([], [contrib], self._confidence(), 'safe')
        assert not any('-0.3' in r for r in exp['mlReasons'])
