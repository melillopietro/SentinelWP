from core.models import Finding, Severity
from core.risk_engine import (
    CATEGORY_MULTIPLIERS,
    SEVERITY_WEIGHTS,
    compute_category_breakdown,
    compute_risk_score,
)


def test_severity_weights_documented_values():
    assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 40.0
    assert SEVERITY_WEIGHTS[Severity.HIGH] == 25.0
    assert CATEGORY_MULTIPLIERS["vulnerability_intelligence"] == 1.4


def test_score_is_deterministic_for_equal_findings_order():
    base = dict(category="exposure", severity=Severity.HIGH, confidence=0.9, title="Finding")
    f1 = Finding(id="aaa", **base)
    f2 = Finding(id="bbb", **base)
    s1, g1 = compute_risk_score([f1, f2])
    s2, g2 = compute_risk_score([f2, f1])
    assert (s1, g1) == (s2, g2)


def test_score_golden_single_critical():
    findings = [
        Finding(
            category="vulnerability_intelligence",
            title="CVE test",
            severity=Severity.CRITICAL,
            confidence=0.95,
        )
    ]
    score, grade = compute_risk_score(findings, confidence_threshold=0.3, normalization_factor=150.0)
    assert score == 29.9
    assert grade == "B+"


def test_breakdown_respects_confidence_threshold():
    findings = [
        Finding(category="headers", title="Low confidence", severity=Severity.HIGH, confidence=0.1),
        Finding(category="headers", title="High confidence", severity=Severity.MEDIUM, confidence=0.95),
    ]
    breakdown = compute_category_breakdown(findings, confidence_threshold=0.3)
    assert breakdown["headers"]["count"] == 1
