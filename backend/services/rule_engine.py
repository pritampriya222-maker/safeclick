"""
backend/services/rule_engine.py
────────────────────────────────────────────────────────────────────────────
Safe, declarative rule engine for Phase 3.

Rules are defined in backend/rules/phishing_rules.json as structured
condition objects — this engine evaluates them WITHOUT using eval()/exec().

The condition schema is a whitelist of allowed operations:
    { "field": str, "op": "gt"|"lt"|"eq"|"gte"|"lte"|"neq", "value": float }

Multiple conditions in one rule use AND logic.
This design is safe even when Phase 6 lets org admins define custom rules
because the evaluator never interprets arbitrary code strings.

Backwards-compatible: same feature fields as Phase 2 heuristics use.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


RULES_PATH = Path(__file__).resolve().parent.parent / 'rules' / 'phishing_rules.json'
RULE_ENGINE_VERSION = "1.0.0"

# ── Allowed operators (whitelist — no arbitrary code) ─────────────────────────
_OPS = {
    'gt':  lambda a, b: a > b,
    'lt':  lambda a, b: a < b,
    'eq':  lambda a, b: abs(a - b) < 1e-9,
    'gte': lambda a, b: a >= b,
    'lte': lambda a, b: a <= b,
    'neq': lambda a, b: abs(a - b) >= 1e-9,
}

ALLOWED_FIELDS_TYPE = dict[str, float]


@dataclass
class RuleResult:
    rule_id: str
    name: str
    triggered: bool
    weight: int
    explanation: str
    category: str


@dataclass
class RuleEngineOutput:
    results: list[RuleResult]
    triggered_results: list[RuleResult]
    total_score: int          # clipped to 0–100
    rule_engine_version: str
    reasons: list[str]        # human-readable, ordered by weight desc


class RuleEngine:
    """
    Loads rules from phishing_rules.json and evaluates them against
    a feature dict produced by ml/features.py.

    Usage:
        engine = RuleEngine()
        features = extract_features("https://paypal-fake.tk/login")
        output = engine.evaluate(features)
        print(output.total_score, output.reasons)
    """

    def __init__(self, rules_path: Path = RULES_PATH):
        self._rules: list[dict[str, Any]] = []
        self._load_rules(rules_path)

    def _load_rules(self, rules_path: Path) -> None:
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_path}")
        with open(rules_path, encoding='utf-8') as f:
            data = json.load(f)
        self._rules = data.get('rules', [])

    def evaluate(self, features: dict[str, float]) -> RuleEngineOutput:
        """
        Evaluate all rules against the given feature dict.
        Returns a RuleEngineOutput with all results and aggregate score.
        """
        results: list[RuleResult] = []
        for rule in self._rules:
            result = self._evaluate_rule(rule, features)
            results.append(result)

        triggered = [r for r in results if r.triggered]
        triggered_sorted = sorted(triggered, key=lambda r: r.weight, reverse=True)

        raw_score = sum(r.weight for r in triggered)
        total_score = min(100, max(0, raw_score))

        reasons = [r.explanation for r in triggered_sorted]
        if not reasons:
            reasons = ["No rule-based threat signals detected."]

        return RuleEngineOutput(
            results=results,
            triggered_results=triggered_sorted,
            total_score=total_score,
            rule_engine_version=RULE_ENGINE_VERSION,
            reasons=reasons,
        )

    def _evaluate_rule(self, rule: dict[str, Any], features: dict[str, float]) -> RuleResult:
        """
        Evaluate a single rule. Returns RuleResult with triggered=True/False.
        Uses AND logic for multiple conditions.
        Silently skips rules with missing fields (graceful degradation).
        """
        rule_id = rule.get('id', 'unknown')
        name = rule.get('name', rule_id)
        weight = int(rule.get('weight', 0))
        description = rule.get('description', name)
        category = rule.get('category', 'unknown')
        conditions = rule.get('conditions', [])

        # AND logic: ALL conditions must be true for the rule to trigger
        triggered = True
        for cond in conditions:
            field = cond.get('field')
            op = cond.get('op')
            value = cond.get('value')

            # Safety: skip invalid conditions rather than raise
            if field is None or op is None or value is None:
                triggered = False
                break

            # Safety: only allow whitelisted fields and operators
            if op not in _OPS:
                # Unknown operator — fail safe (do not trigger)
                triggered = False
                break

            feature_val = features.get(field)
            if feature_val is None:
                # Feature not present — cannot evaluate, skip rule
                triggered = False
                break

            try:
                if not _OPS[op](float(feature_val), float(value)):
                    triggered = False
                    break
            except (TypeError, ValueError):
                triggered = False
                break

        return RuleResult(
            rule_id=rule_id,
            name=name,
            triggered=triggered,
            weight=weight if triggered else 0,
            explanation=description if triggered else f"{name}: not triggered.",
            category=category,
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def version(self) -> str:
        return RULE_ENGINE_VERSION


# ── Module-level singleton (loaded once at import) ────────────────────────────
_default_engine: Optional[RuleEngine] = None


def get_rule_engine() -> RuleEngine:
    """Return the shared rule engine singleton (lazy init)."""
    global _default_engine
    if _default_engine is None:
        _default_engine = RuleEngine()
    return _default_engine
