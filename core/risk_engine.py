"""
Risk scoring engine - enterprise grade
- Severity weighting with category multipliers (aligned to CVSS 3.1)
- Confidence threshold filtering (excludes low-confidence findings)
- Diminishing returns per category (deterministic tie-breaking)
- Exponential saturation normalization (0-100 scale)
- Letter grade mapping (uniform 10-point grading)

SCORING FORMULA:
1. Filter findings by confidence >= CONFIDENCE_THRESHOLD
2. Per category: sort by (weight * confidence) descending, apply decay^i
3. Sum across categories with CATEGORY_MULTIPLIERS
4. Normalize via exponential saturation: score = 100 * (1 - exp(-raw_total / NORMALIZATION_FACTOR))
5. Map to letter grade (A+ to F)

NORMALIZATION_FACTOR:
- Controls saturation curve. Higher = slower saturation.
- With raw_total=150: score ≈ 63.2 (inflection point)
- With raw_total=300: score ≈ 95.0 (near-saturated)
- Default=150.0 empirically calibrated for ~50-100 typical findings per scan

DECAY (0.9):
- Diminishing returns for multiple findings in same category
- 10% reduction per additional finding (realistic stacking)
- Prevents single-category dominance from inflating scores

See docs/RISK_SCORING_MODEL.md for detailed analysis and calibration methodology.
"""
import math
from typing import Optional

from core.models import Finding, Severity
from config import CONFIDENCE_THRESHOLD, NORMALIZATION_FACTOR

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 50.0,  # 9.0-10.0 CVSS range (increased from 40.0)
    Severity.HIGH: 28.0,      # 7.0-8.9 CVSS range (increased from 25.0, ratio: 1.79x)
    Severity.MEDIUM: 12.0,    # 4.0-6.9 CVSS range
    Severity.LOW: 5.0,        # 0.1-3.9 CVSS range
    Severity.INFO: 1.0,
}

CATEGORY_MULTIPLIERS = {
    # Tier 1: Direct attack vectors (highest priority)
    "authentication": 1.6,              # Primary attack vector (increased from 1.4)
    
    # Tier 2: High-impact exposures and escalations
    "vulnerability_intelligence": 1.5,  # CVE/vulnerability matching (decreased from 1.4)
    "exposure": 1.4,                    # Direct exposure of sensitive info (increased from 1.3)
    "information_disclosure": 1.3,      # Indirect info leak (increased from 1.2)
    
    # Tier 3: Security mechanisms
    "encryption": 1.2,
    "enumeration": 1.2,                 # Decreased from 1.3 (reconnaissance, not direct exploit)
    
    # Tier 4: Configuration and management
    "configuration": 1.1,
    "plugins": 1.1,
    
    # Tier 5: Defense-in-depth (lowest priority)
    "headers": 0.9,                     # Reduced from 1.0 (defense in depth, not direct exploit)
    "http_disclosure": 1.1,             # Server/framework disclosure
    "wordpress_detection": 0.7,         # Reconnaissance-only (passive)
}

GRADE_MAP = [
    (0, 10, "A+"),      # 0-9.9 (Excellent security posture)
    (10, 20, "A"),      # 10-19.9 (Strong security posture)
    (20, 30, "B+"),     # 20-29.9 (Good security posture)
    (30, 40, "B"),      # 30-39.9 (Acceptable security posture)
    (40, 50, "C+"),     # 40-49.9 (Fair security posture)
    (50, 60, "C"),      # 50-59.9 (Moderate risk)
    (60, 70, "D"),      # 60-69.9 (High risk)
    (70, 80, "E"),      # 70-79.9 (Very high risk)
    (80, 101, "F"),     # 80-100 (Critical risk)
]


def _coerce_severity(value) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO


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

    filtered = [f for f in findings if f.confidence >= confidence_threshold]
    if not filtered:
        return (0.0, "A+")

    category_scores: dict[str, list[tuple[float, str]]] = {}
    for f in filtered:
        cat = f.category or "general"
        sev = _coerce_severity(f.severity)
        weight = SEVERITY_WEIGHTS.get(sev, 1.0)
        adjusted = weight * f.confidence
        tie_breaker = f.id or f.title or ""
        category_scores.setdefault(cat, []).append((adjusted, tie_breaker))

    raw_total = 0.0
    decay = 0.9  # 10% reduction per additional finding (was 0.7)
    for cat, scored in category_scores.items():
        scored.sort(key=lambda item: (-item[0], item[1]))
        multiplier = CATEGORY_MULTIPLIERS.get(cat, 1.0)
        cat_total = 0.0
        for i, (value, _) in enumerate(scored):
            cat_total += value * (decay ** i)
        raw_total += cat_total * multiplier

    score = 100.0 * (1.0 - math.exp(-raw_total / normalization_factor))
    score = round(min(100.0, max(0.0, score)), 1)
    grade = _get_grade(score)
    return (score, grade)


def compute_category_breakdown(
    findings: list,
    confidence_threshold: Optional[float] = None,
) -> dict:
    """
    Returns {category: {count, max_severity, weighted_score}}
    Uses the same confidence filter as compute_risk_score.
    """
    if confidence_threshold is None:
        confidence_threshold = CONFIDENCE_THRESHOLD

    breakdown = {}
    for f in findings:
        if f.confidence < confidence_threshold:
            continue
        cat = f.category or "general"
        if cat not in breakdown:
            breakdown[cat] = {"count": 0, "max_severity": "info", "weighted_score": 0.0}
        breakdown[cat]["count"] += 1
        sev = _coerce_severity(f.severity)
        weight = SEVERITY_WEIGHTS.get(sev, 1.0)
        breakdown[cat]["weighted_score"] += weight * f.confidence
        sev_order = list(Severity)
        current_max = Severity(breakdown[cat]["max_severity"])
        if sev_order.index(sev) < sev_order.index(current_max):
            breakdown[cat]["max_severity"] = sev.value
    return breakdown
