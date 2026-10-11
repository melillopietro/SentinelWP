"""
SentinelWP - Vulnerability Prioritization Engine
Calculates multi-factor composite priority score (0-100) and priority bands (P1-P4)
combining CVSS, EPSS, CISA KEV, Internet Exposure, Asset Criticality, and Ransomware relevance.
"""
from typing import Optional
from core.models import Severity


def calculate_priority_score(
    severity: Severity | str,
    cvss_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    kev: bool = False,
    asset_criticality: Optional[str] = None,
    asset_internet_facing: bool = True,
    ransomware_relevance: bool | str = False,
) -> tuple[float, str]:
    """
    Computes a composite risk priority score (0.0 to 100.0) and priority band ('P1', 'P2', 'P3', 'P4').

    Weights:
    - Base Severity / CVSS (max 35 pts):
      Uses cvss_score * 3.5 if available, else mapped from Severity enum (CRITICAL=35, HIGH=28, MEDIUM=18, LOW=8, INFO=2)
    - CISA KEV presence (25 pts):
      Actively exploited in the wild -> immediate high risk escalation
    - EPSS Exploit Probability (max 15 pts):
      epss_score * 15 (e.g. 0.80 * 15 = 12 pts)
    - Asset Criticality (max 15 pts):
      CRITICAL / TIER1 = 15, HIGH / TIER2 = 10, MEDIUM / TIER3 = 5, LOW = 2
    - Internet Exposure (5 pts):
      Publicly exposed asset = 5 pts
    - Ransomware Campaign Association (5 pts):
      Known ransomware weaponization = 5 pts
    """
    score = 0.0

    # 1. Base Severity / CVSS (0 - 35)
    if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
        base_pts = (cvss_score / 10.0) * 35.0
    else:
        sev_str = severity.value if isinstance(severity, Severity) else str(severity).lower()
        if sev_str == "critical":
            base_pts = 35.0
        elif sev_str == "high":
            base_pts = 28.0
        elif sev_str == "medium":
            base_pts = 18.0
        elif sev_str == "low":
            base_pts = 8.0
        else:
            base_pts = 2.0
    score += base_pts

    # 2. CISA KEV (Known Exploited Vulnerability) (0 or 25 pts)
    if kev:
        score += 25.0

    # 3. EPSS (0 - 15 pts)
    if epss_score is not None and 0.0 <= epss_score <= 1.0:
        score += epss_score * 15.0

    # 4. Asset Criticality (0 - 15 pts)
    crit = str(asset_criticality or "").lower()
    if crit in ("tier1", "critical", "tier-1"):
        score += 15.0
    elif crit in ("tier2", "high", "tier-2"):
        score += 10.0
    elif crit in ("tier3", "medium", "tier-3"):
        score += 5.0
    elif crit in ("tier4", "low", "tier-4"):
        score += 2.0

    # 5. Internet Exposure (0 or 5 pts)
    if asset_internet_facing:
        score += 5.0

    # 6. Ransomware association (0 or 5 pts)
    is_ransomware = False
    if isinstance(ransomware_relevance, bool):
        is_ransomware = ransomware_relevance
    elif isinstance(ransomware_relevance, str):
        is_ransomware = ransomware_relevance.lower() in ("high", "confirmed", "true", "active")
    if is_ransomware:
        score += 5.0

    # Cap at 100.0 and round
    score = min(100.0, max(0.0, round(score, 1)))

    # Priority Band classification
    # Any KEV finding with high severity or score >= 80 is P1
    if score >= 80.0 or (kev and score >= 65.0):
        band = "P1"
    elif score >= 60.0:
        band = "P2"
    elif score >= 35.0:
        band = "P3"
    else:
        band = "P4"

    return score, band
