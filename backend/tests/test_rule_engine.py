"""
backend/tests/test_rule_engine.py
────────────────────────────────────────────────────────────────────────────
Pytest tests for services/rule_engine.py.
Covers:
  - Correct triggering/non-triggering
  - Score aggregation
  - SAFETY: malicious rule strings cannot execute arbitrary code
  - Backwards-compatibility with Phase 2 heuristic outputs
"""

import json
import pytest
import tempfile
import os
from pathlib import Path

from services.rule_engine import RuleEngine, _OPS


# ── Test rules factory ────────────────────────────────────────────────────────

def make_rules(*rules: dict) -> dict:
    return {"_version": "test", "rules": list(rules)}


def make_rule(
    rule_id="test:rule",
    name="Test Rule",
    description="Test description.",
    weight=10,
    conditions=None,
    category="test",
) -> dict:
    return {
        "id": rule_id,
        "name": name,
        "description": description,
        "weight": weight,
        "conditions": conditions or [],
        "category": category,
    }


def engine_with_rules(*rules: dict) -> RuleEngine:
    """Create a rule engine with custom in-memory rules."""
    data = make_rules(*rules)
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.json', delete=False, encoding='utf-8'
    ) as f:
        json.dump(data, f)
        tmp_path = f.name
    try:
        return RuleEngine(rules_path=Path(tmp_path))
    finally:
        os.unlink(tmp_path)


# ── Condition operator tests ──────────────────────────────────────────────────

class TestOperators:
    def test_gt_true(self):
        assert _OPS['gt'](5.0, 3.0) is True

    def test_gt_false(self):
        assert _OPS['gt'](3.0, 5.0) is False

    def test_lt_true(self):
        assert _OPS['lt'](2.0, 5.0) is True

    def test_eq_true(self):
        assert _OPS['eq'](1.0, 1.0) is True

    def test_eq_false(self):
        assert _OPS['eq'](1.0, 0.0) is False

    def test_gte(self):
        assert _OPS['gte'](5.0, 5.0) is True
        assert _OPS['gte'](4.0, 5.0) is False

    def test_lte(self):
        assert _OPS['lte'](5.0, 5.0) is True
        assert _OPS['lte'](6.0, 5.0) is False

    def test_neq(self):
        assert _OPS['neq'](1.0, 2.0) is True
        assert _OPS['neq'](1.0, 1.0) is False


# ── Basic triggering ──────────────────────────────────────────────────────────

class TestRuleTriggers:
    def test_rule_triggers_when_condition_met(self):
        engine = engine_with_rules(make_rule(
            conditions=[{"field": "url_length", "op": "gt", "value": 100}]
        ))
        output = engine.evaluate({'url_length': 200.0})
        assert output.triggered_results[0].triggered is True

    def test_rule_does_not_trigger_when_condition_not_met(self):
        engine = engine_with_rules(make_rule(
            conditions=[{"field": "url_length", "op": "gt", "value": 100}]
        ))
        output = engine.evaluate({'url_length': 50.0})
        assert len(output.triggered_results) == 0

    def test_and_logic_all_must_be_true(self):
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "url_length", "op": "gt", "value": 100},
            {"field": "is_ip_address", "op": "eq", "value": 1.0},
        ]))
        # Only url_length met — should NOT trigger
        output = engine.evaluate({'url_length': 200.0, 'is_ip_address': 0.0})
        assert len(output.triggered_results) == 0

    def test_and_logic_all_true_triggers(self):
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "url_length", "op": "gt", "value": 100},
            {"field": "is_ip_address", "op": "eq", "value": 1.0},
        ]))
        output = engine.evaluate({'url_length': 200.0, 'is_ip_address': 1.0})
        assert len(output.triggered_results) == 1

    def test_score_sums_triggered_weights(self):
        engine = engine_with_rules(
            make_rule("r1", weight=15, conditions=[{"field": "a", "op": "eq", "value": 1.0}]),
            make_rule("r2", weight=20, conditions=[{"field": "b", "op": "eq", "value": 1.0}]),
            make_rule("r3", weight=10, conditions=[{"field": "c", "op": "eq", "value": 1.0}]),
        )
        output = engine.evaluate({'a': 1.0, 'b': 1.0, 'c': 0.0})
        assert output.total_score == 35

    def test_score_clipped_to_100(self):
        engine = engine_with_rules(
            make_rule("r1", weight=70, conditions=[{"field": "x", "op": "eq", "value": 1.0}]),
            make_rule("r2", weight=70, conditions=[{"field": "x", "op": "eq", "value": 1.0}]),
        )
        output = engine.evaluate({'x': 1.0})
        assert output.total_score == 100

    def test_empty_features_returns_zero_score(self):
        engine = engine_with_rules(make_rule(
            conditions=[{"field": "url_length", "op": "gt", "value": 100}]
        ))
        output = engine.evaluate({})
        assert output.total_score == 0


# ── Safety: injection prevention ──────────────────────────────────────────────

class TestConditionEvaluatorSafety:
    """
    CRITICAL: verify that malicious rule strings cannot execute arbitrary code.
    The engine uses a whitelist of operators — unknown ops fail-safe (no trigger).
    """

    def test_unknown_operator_does_not_trigger(self):
        """An unknown op should silently skip the rule (fail safe)."""
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "url_length", "op": "exec('import os; os.system(\"calc\")')", "value": 1.0}
        ]))
        output = engine.evaluate({'url_length': 200.0})
        assert len(output.triggered_results) == 0
        assert output.total_score == 0

    def test_eval_as_operator_does_not_trigger(self):
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "url_length", "op": "eval", "value": 1.0}
        ]))
        output = engine.evaluate({'url_length': 200.0})
        assert len(output.triggered_results) == 0

    def test_missing_field_does_not_trigger(self):
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "nonexistent_feature", "op": "gt", "value": 0}
        ]))
        output = engine.evaluate({})
        assert len(output.triggered_results) == 0

    def test_missing_op_does_not_trigger(self):
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "url_length", "value": 100}  # no 'op' key
        ]))
        output = engine.evaluate({'url_length': 200.0})
        assert len(output.triggered_results) == 0

    def test_null_value_in_condition_does_not_trigger(self):
        engine = engine_with_rules(make_rule(conditions=[
            {"field": "url_length", "op": "gt", "value": None}
        ]))
        output = engine.evaluate({'url_length': 200.0})
        assert len(output.triggered_results) == 0


# ── Production rules file ─────────────────────────────────────────────────────

class TestProductionRules:
    def test_production_rules_load_without_error(self):
        """The actual phishing_rules.json must load correctly."""
        engine = RuleEngine()
        assert engine.rule_count > 0

    def test_known_phishing_url_scores_high(self):
        """A URL with many phishing signals should score high."""
        from ml.features import extract_features
        engine = RuleEngine()
        feats = extract_features('http://paypal-secure-login.attacker-example.tk/verify')
        assert feats is not None
        output = engine.evaluate(feats)
        assert output.total_score >= 30  # at least several rules fire

    def test_clean_url_scores_low(self):
        """A clean well-known URL should score very low."""
        from ml.features import extract_features
        engine = RuleEngine()
        feats = extract_features('https://google.com')
        assert feats is not None
        output = engine.evaluate(feats)
        assert output.total_score < 20  # almost no rules fire

    def test_ip_url_triggers_raw_ip_rule(self):
        from ml.features import extract_features
        engine = RuleEngine()
        feats = extract_features('http://192.168.1.100/login')
        assert feats is not None
        output = engine.evaluate(feats)
        triggered_ids = {r.rule_id for r in output.triggered_results}
        assert 'rule:url_structure:raw_ip' in triggered_ids
