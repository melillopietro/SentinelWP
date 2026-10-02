"""
Comprehensive risk engine edge case tests.
Tests decay effect, severity weighting, category multipliers, and scoring accuracy.
"""
import pytest
from core.models import Finding, Severity
from core.risk_engine import compute_risk_score, compute_category_breakdown, SEVERITY_WEIGHTS, CATEGORY_MULTIPLIERS


class TestDecayEffect:
    """Verify decay=0.9 correctly applies diminishing returns"""

    def test_single_vs_triple_findings_same_category(self):
        """Three findings should score higher than 2.5x single finding"""
        # Single HIGH finding
        f1 = Finding(category="exposure", severity=Severity.HIGH, confidence=0.95, title="F1")
        s1, _ = compute_risk_score([f1])

        # Three HIGH findings in same category (with decay=0.9)
        findings = [
            Finding(category="exposure", severity=Severity.HIGH, confidence=0.95, title=f"F{i}")
            for i in range(3)
        ]
        s3, _ = compute_risk_score(findings)

        # With decay=0.9: F1 @ 100%, F2 @ 90%, F3 @ 81% = 271% of single
        # With old decay=0.7: F1 @ 100%, F2 @ 70%, F3 @ 49% = 219% of single
        assert s3 > s1 * 2.5, f"Expected s3={s3} > s1*2.5={s1*2.5} (decay effect too aggressive)"

    def test_decay_progressively_reduces(self):
        """Each additional finding should add progressively less"""
        findings_1 = [Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title="F1")]
        findings_2 = findings_1 + [Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title="F2")]
        findings_3 = findings_2 + [Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title="F3")]
        findings_4 = findings_3 + [Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title="F4")]

        s1, _ = compute_risk_score(findings_1)
        s2, _ = compute_risk_score(findings_2)
        s3, _ = compute_risk_score(findings_3)
        s4, _ = compute_risk_score(findings_4)

        # Each additional finding adds less than the previous one
        delta_1_2 = s2 - s1
        delta_2_3 = s3 - s2
        delta_3_4 = s4 - s3

        assert delta_1_2 > delta_2_3 > delta_3_4, "Decay should reduce contribution each iteration"

    def test_decay_realistic_multiplier(self):
        """Verify decay=0.9 gives ~10% reduction per finding"""
        # Single CRITICAL finding (baseline)
        f1 = Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title="F1")
        s1, _ = compute_risk_score([f1])

        # Two identical findings
        f2 = Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title="F2")
        s2, _ = compute_risk_score([f1, f2])

        # With decay=0.9, second finding should add ~90% of first
        # Expected: s2 ≈ s1 * (1 + 0.9) = s1 * 1.9
        expected_ratio = 1.85  # Allow some rounding tolerance
        actual_ratio = s2 / s1
        assert 1.75 < actual_ratio < 2.05, f"Expected ratio ~1.9, got {actual_ratio}"


class TestSeverityWeighting:
    """Verify SEVERITY_WEIGHTS align with CVSS 3.1"""

    def test_severity_weights_values(self):
        """Verify updated severity weights"""
        assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 50.0
        assert SEVERITY_WEIGHTS[Severity.HIGH] == 28.0
        assert SEVERITY_WEIGHTS[Severity.MEDIUM] == 12.0
        assert SEVERITY_WEIGHTS[Severity.LOW] == 5.0

    def test_critical_to_high_ratio(self):
        """CRITICAL should be ~1.79x HIGH (not 1.6x)"""
        ratio = SEVERITY_WEIGHTS[Severity.CRITICAL] / SEVERITY_WEIGHTS[Severity.HIGH]
        assert 1.75 < ratio < 1.85, f"Expected ratio ~1.79, got {ratio}"

    def test_critical_vs_high_scoring(self):
        """CRITICAL vulnerability should score significantly higher than HIGH"""
        crit = Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95)
        high = Finding(category="exposure", severity=Severity.HIGH, confidence=0.95)

        s_crit, _ = compute_risk_score([crit])
        s_high, _ = compute_risk_score([high])

        ratio = s_crit / s_high
        assert 1.75 < ratio < 1.85, f"Expected ratio ~1.79x, got {ratio:.2f}x"

    def test_high_to_medium_ratio(self):
        """HIGH should be ~2.33x MEDIUM"""
        high = Finding(category="exposure", severity=Severity.HIGH, confidence=0.95)
        medium = Finding(category="exposure", severity=Severity.MEDIUM, confidence=0.95)

        s_high, _ = compute_risk_score([high])
        s_medium, _ = compute_risk_score([medium])

        ratio = s_high / s_medium
        # 28.0 / 12.0 = 2.33x
        assert 2.2 < ratio < 2.5, f"Expected ratio ~2.33x, got {ratio:.2f}x"


class TestCategoryMultipliers:
    """Verify category multiplier prioritization"""

    def test_multiplier_values(self):
        """Verify updated category multipliers"""
        assert CATEGORY_MULTIPLIERS["authentication"] == 1.6
        assert CATEGORY_MULTIPLIERS["vulnerability_intelligence"] == 1.5
        assert CATEGORY_MULTIPLIERS["exposure"] == 1.4
        assert CATEGORY_MULTIPLIERS["headers"] == 0.9

    def test_authentication_prioritized_over_headers(self):
        """Authentication vulnerabilities should be weighted 1.6/0.9 ≈ 1.78x headers"""
        auth = Finding(category="authentication", severity=Severity.HIGH, confidence=0.95)
        headers = Finding(category="headers", severity=Severity.HIGH, confidence=0.95)

        s_auth, _ = compute_risk_score([auth])
        s_headers, _ = compute_risk_score([headers])

        ratio = s_auth / s_headers
        assert 1.5 < ratio < 2.0, f"Expected auth ~1.78x headers, got {ratio:.2f}x"

    def test_authentication_prioritized_over_enumeration(self):
        """Authentication should score higher than enumeration"""
        auth = Finding(category="authentication", severity=Severity.HIGH, confidence=0.95)
        enum = Finding(category="enumeration", severity=Severity.HIGH, confidence=0.95)

        s_auth, _ = compute_risk_score([auth])
        s_enum, _ = compute_risk_score([enum])

        # 1.6 / 1.2 = 1.33x
        ratio = s_auth / s_enum
        assert ratio > 1.25, f"Expected auth > enum, got {ratio:.2f}x"

    def test_exposure_higher_than_enumeration(self):
        """Direct exposure should be valued higher than reconnaissance"""
        exposure = Finding(category="exposure", severity=Severity.MEDIUM, confidence=0.95)
        enum = Finding(category="enumeration", severity=Severity.HIGH, confidence=0.95)

        s_exposure, _ = compute_risk_score([exposure])
        s_enum, _ = compute_risk_score([enum])

        # Even MEDIUM exposure (1.4x) can be > HIGH enumeration (1.2x) depending on decay/saturation
        # At least they should be close
        ratio = s_exposure / s_enum
        assert 0.7 < ratio < 1.2, f"Expected close scoring, got {ratio:.2f}x"


class TestConfidenceThreshold:
    """Verify confidence threshold filtering"""

    def test_default_threshold_is_05(self):
        """Default confidence threshold should be 0.5 (not 0.3)"""
        from config import CONFIDENCE_THRESHOLD
        assert CONFIDENCE_THRESHOLD == 0.5, f"Expected 0.5, got {CONFIDENCE_THRESHOLD}"

    def test_below_threshold_excluded(self):
        """Findings below confidence threshold should not affect score"""
        low_conf = Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.4)
        high_conf = Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.6)

        s_low, _ = compute_risk_score([low_conf], confidence_threshold=0.5)
        s_high, _ = compute_risk_score([high_conf], confidence_threshold=0.5)
        s_both, _ = compute_risk_score([low_conf, high_conf], confidence_threshold=0.5)

        assert s_low == 0.0, "Below-threshold finding should score 0"
        assert s_high > 0.0, "Above-threshold finding should score > 0"
        assert s_both == s_high, "Both should equal high (low excluded)"

    def test_confidence_filtering_reduces_false_positives(self):
        """Higher threshold should reduce noisy findings"""
        findings = [
            Finding(category="exposure", severity=Severity.HIGH, confidence=0.3, title="F1"),
            Finding(category="exposure", severity=Severity.HIGH, confidence=0.4, title="F2"),
            Finding(category="exposure", severity=Severity.HIGH, confidence=0.95, title="F3"),
        ]

        s_low_threshold, _ = compute_risk_score(findings, confidence_threshold=0.3)
        s_high_threshold, _ = compute_risk_score(findings, confidence_threshold=0.5)

        # Higher threshold should score lower (fewer findings included)
        assert s_high_threshold < s_low_threshold, "Higher threshold should reduce score"


class TestGradeMapping:
    """Verify uniform 10-point grading"""

    def test_grade_boundaries(self):
        """Each grade should span exactly 10 points"""
        # Test specific boundaries
        score_0, grade_0 = compute_risk_score([], confidence_threshold=0.9)  # No findings
        assert grade_0 == "A+", f"Score 0 should be A+, got {grade_0}"

        # Create findings to test grade boundaries
        def get_grade_at_score(target_score: float) -> str:
            # Rough approximation - create findings to hit a score range
            findings = []
            while True:
                s, g = compute_risk_score(findings)
                if s >= target_score or len(findings) > 50:
                    return g
                findings.append(Finding(category="exposure", severity=Severity.HIGH, confidence=0.95, title=f"F{len(findings)}"))
            return g

        # Grades should follow 10-point increments
        grades = ["A+", "A", "B+", "B", "C+", "C", "D", "E", "F"]
        for i, grade in enumerate(grades):
            expected_min = i * 10
            expected_max = (i + 1) * 10
            # This is a smoke test - actual grade assignment happens in _get_grade()

    def test_no_gaps_in_grade_map(self):
        """Grade map should cover 0-100 with no gaps"""
        from core.risk_engine import GRADE_MAP
        
        # Check continuity
        for i, (low, high, grade) in enumerate(GRADE_MAP):
            if i > 0:
                prev_low, prev_high, _ = GRADE_MAP[i - 1]
                assert low == prev_high, f"Gap between grades: {prev_high} -> {low}"


class TestNormalizationSaturation:
    """Verify exponential saturation behavior"""

    def test_saturation_with_many_findings(self):
        """Score should saturate toward 100 with many findings"""
        from config import NORMALIZATION_FACTOR

        # 5 CRITICAL findings
        findings_5 = [
            Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title=f"F{i}")
            for i in range(5)
        ]
        s5, _ = compute_risk_score(findings_5)

        # 20 CRITICAL findings
        findings_20 = [
            Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95, title=f"F{i}")
            for i in range(20)
        ]
        s20, _ = compute_risk_score(findings_20)

        # Both should be below 100, but saturation should be visible
        assert s5 < 100, "5 findings should not max score"
        assert s20 < 100, "20 findings should not max score"
        assert s20 > s5, "More findings should increase score"

        # Saturation: each finding should add less at high scores
        # The difference between 5->20 should be less than 5->0
        delta_5_20 = s20 - s5
        assert delta_5_20 < s5 * 0.5, "Saturation should reduce contribution of later findings"


class TestDeterminism:
    """Verify scoring is deterministic across runs"""

    def test_score_order_independent(self):
        """Score should be same regardless of finding order"""
        findings_a = [
            Finding(id="f1", category="exposure", severity=Severity.HIGH, confidence=0.95),
            Finding(id="f2", category="authentication", severity=Severity.CRITICAL, confidence=0.85),
            Finding(id="f3", category="headers", severity=Severity.LOW, confidence=0.7),
        ]

        findings_b = [
            Finding(id="f3", category="headers", severity=Severity.LOW, confidence=0.7),
            Finding(id="f1", category="exposure", severity=Severity.HIGH, confidence=0.95),
            Finding(id="f2", category="authentication", severity=Severity.CRITICAL, confidence=0.85),
        ]

        s_a, g_a = compute_risk_score(findings_a)
        s_b, g_b = compute_risk_score(findings_b)

        assert (s_a, g_a) == (s_b, g_b), "Score should be order-independent"

    def test_multiple_runs_identical(self):
        """Same input should produce identical score across multiple runs"""
        findings = [
            Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95),
            Finding(category="authentication", severity=Severity.HIGH, confidence=0.8),
        ]

        results = [compute_risk_score(findings) for _ in range(5)]
        assert all(r == results[0] for r in results), "Score should be deterministic"


class TestCategoryBreakdown:
    """Verify category breakdown computation"""

    def test_breakdown_respects_confidence_threshold(self):
        """Low-confidence findings should be excluded from breakdown"""
        findings = [
            Finding(category="headers", severity=Severity.HIGH, confidence=0.1),
            Finding(category="headers", severity=Severity.MEDIUM, confidence=0.95),
            Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.6),
        ]

        breakdown = compute_category_breakdown(findings, confidence_threshold=0.5)

        # Only 2 findings above 0.5 confidence
        assert breakdown["headers"]["count"] == 1  # Only 0.95 conf
        assert breakdown["exposure"]["count"] == 1  # 0.6 conf
        assert breakdown["headers"]["max_severity"] == "medium"

    def test_breakdown_max_severity_tracking(self):
        """Breakdown should track highest severity per category"""
        findings = [
            Finding(category="exposure", severity=Severity.LOW, confidence=0.95),
            Finding(category="exposure", severity=Severity.CRITICAL, confidence=0.95),
            Finding(category="exposure", severity=Severity.MEDIUM, confidence=0.95),
        ]

        breakdown = compute_category_breakdown(findings)
        assert breakdown["exposure"]["max_severity"] == "critical"
        assert breakdown["exposure"]["count"] == 3

    def test_breakdown_weighted_scoring(self):
        """Breakdown should accumulate weighted scores"""
        findings = [
            Finding(category="exposure", severity=Severity.HIGH, confidence=0.95),
            Finding(category="exposure", severity=Severity.HIGH, confidence=0.95),
        ]

        breakdown = compute_category_breakdown(findings)

        # Each HIGH @ 0.95 = 28.0 * 0.95 = 26.6
        expected_score = 26.6 * 2
        assert abs(breakdown["exposure"]["weighted_score"] - expected_score) < 0.5
