"""
Risk scoring engine - enterprise grade
- Severity weighting with category multipliers
- Confidence threshold filtering
- Diminishing returns per category
- Exponential saturation normalization (0-100 scale)
- Letter grade mapping
"""
import math
from typing import Optional
from core.models import Finding, Severity
from config import CONFIDENCE_THRESHOLD, NORMALIZATION_FACTOR

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 12.0,
    Severity.LOW: 5.0,
    Severity.INFO: 1.0,
}

CATEGORY_MULTIPLIERS = {
    "authentication": 1.4,
    "enumeration": 1.3,
    "exposure": 1.3,
    "encryption": 1.2,
    "headers": 1.0,
    "configuration": 1.1,
    "information_disclosure": 1.2,
    "plugins": 1.1,
}

GRADE_MAP = [
    (0, 15, "A+"),
    (15, 25, "A"),
    (25, 35, "B+"),
    (35, 45, "B"),
    (45, 55, "C+"),
    (55, 65, "C"),
    (65, 75, "D"),
    (75, 85, "E"),
    (85, 100, "F"),
]


def _get_grade(score: float) -> str:
    for low, high, grade in GRADE_MAP:
        if low <= score < high:
            return grade
    return "F"


def compute_risk_score(
    findings: list,
    confidence_threshold: Optional[float] = None,
    normalization_factor: Optional[float] = None,
) -> tuple:
    """
    Returns (score: float 0-100, grade: str)
    Higher score = worse security posture.
    """
    if confidence_threshold is None:
        confidence_threshold = CONFIDENCE_THRESHOLD
    if normalization_factor is None:
        normalization_factor = NORMALIZATION_FACTOR

    # Filter by confidence
    filtered = [f for f in findings if f.confidence >= confidence_threshold]
    if not filtered:
        return (0.0, "A+")

    # Group by category, apply diminishing returns within each
    category_scores = {}
    for f in filtered:
        cat = f.category or "general"
        if cat not in category_scores:
            category_scores[cat] = []
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        weight = SEVERITY_WEIGHTS.get(sev, 1.0)
        adjusted = weight * f.confidence
        category_scores[cat].append(adjusted)

    raw_total = 0.0
    for cat, scores in category_scores.items():
        scores.sort(reverse=True)
        multiplier = CATEGORY_MULTIPLIERS.get(cat, 1.0)
        cat_total = 0.0
        decay = 0.7
        for i, s in enumerate(scores):
            cat_total += s * (decay ** i)
        raw_total += cat_total * multiplier

    # Exponential saturation: score = 100 * (1 - e^(-raw/norm))
    score = 100.0 * (1.0 - math.exp(-raw_total / normalization_factor))
    score = round(min(100.0, max(0.0, score)), 1)
    grade = _get_grade(score)
    return (score, grade)


def compute_category_breakdown(findings: list) -> dict:
    """
    Returns {category: {count, max_severity, weighted_score}}
    """
    breakdown = {}
    for f in findings:
        cat = f.category or "general"
        if cat not in breakdown:
            breakdown[cat] = {"count": 0, "max_severity": "info", "weighted_score": 0.0}
        breakdown[cat]["count"] += 1
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        weight = SEVERITY_WEIGHTS.get(sev, 1.0)
        breakdown[cat]["weighted_score"] += weight * f.confidence
        sev_order = list(Severity)
        current_max = Severity(breakdown[cat]["max_severity"])
        if sev_order.index(sev) < sev_order.index(current_max):
            breakdown[cat]["max_severity"] = sev.value
    return breakdown
