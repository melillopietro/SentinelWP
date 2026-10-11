"""
SentinelWP - Service Level Agreement (SLA) Engine
Calculates finding remediation due dates based on multi-factor policies:
severity, priority, asset criticality, internet exposure, and CISA KEV.
Provides breach/warning evaluation and SLA pause/resume semantics.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from core.models import Finding, SLAPolicy
from core.lifecycle import FindingStatus, SLAStatus


# Default SLA windows in days based on priority band if no custom policy applies
DEFAULT_SLA_DAYS = {
    "P1": 2,    # 48 hours for critical/exploited issues
    "P2": 14,   # 14 days
    "P3": 30,   # 30 days
    "P4": 90,   # 90 days
}

DEFAULT_WARNING_DAYS = {
    "P1": 1,
    "P2": 3,
    "P3": 7,
    "P4": 15,
}

# Configurable default seed policy definitions per tenant
DEFAULT_SLA_SEEDS = [
    {
        "name": "Critical KEV Internet-Exposed",
        "severity": "critical",
        "criticality": None,
        "kev": True,
        "internet_exposed": True,
        "due_days": 1,
        "warning_days": 1,
    },
    {
        "name": "Critical Severity",
        "severity": "critical",
        "criticality": None,
        "kev": None,
        "internet_exposed": None,
        "due_days": 3,
        "warning_days": 1,
    },
    {
        "name": "High Severity",
        "severity": "high",
        "criticality": None,
        "kev": None,
        "internet_exposed": None,
        "due_days": 7,
        "warning_days": 3,
    },
    {
        "name": "Medium Severity",
        "severity": "medium",
        "criticality": None,
        "kev": None,
        "internet_exposed": None,
        "due_days": 30,
        "warning_days": 7,
    },
    {
        "name": "Low Severity",
        "severity": "low",
        "criticality": None,
        "kev": None,
        "internet_exposed": None,
        "due_days": 90,
        "warning_days": 15,
    },
]


def match_sla_policy(
    finding: Finding,
    policies: List[SLAPolicy],
    asset_criticality: Optional[str] = None,
    asset_internet_facing: bool = False,
) -> Optional[SLAPolicy]:
    """
    Finds the most specific matching SLA policy for a finding.
    Evaluates:
    - severity
    - asset criticality (tier1/tier2/etc or high/critical)
    - CISA KEV presence
    - internet exposure
    - priority band
    Returns the first matching policy, or None if no specific rule matches.
    """
    sev_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity).lower()
    crit_val = str(asset_criticality or "").lower()
    band_val = str(finding.priority_band or "").upper()

    # Sort policies: more specific criteria match first
    def policy_specificity(p: SLAPolicy) -> int:
        score = 0
        if p.kev is not None:
            score += 8
        if p.internet_exposed is not None:
            score += 4
        if getattr(p, "asset_criticality", None) or p.criticality:
            score += 4
        if getattr(p, "priority_band", None):
            score += 2
        if p.severity:
            score += 2
        return score

    sorted_policies = sorted(policies, key=policy_specificity, reverse=True)

    for p in sorted_policies:
        if not p.enabled:
            continue
        if p.severity and p.severity.lower() != sev_val:
            continue
        policy_crit = getattr(p, "asset_criticality", None) or p.criticality
        if policy_crit and policy_crit.lower() != crit_val:
            continue
        if getattr(p, "priority_band", None) and p.priority_band.upper() != band_val:
            continue
        if p.kev is not None and p.kev != finding.kev:
            continue
        if p.internet_exposed is not None and p.internet_exposed != asset_internet_facing:
            continue
        return p

    return None


def calculate_sla_due_date(
    created_at: str | datetime,
    priority_band: str = "P3",
    policy: Optional[SLAPolicy] = None,
) -> tuple[str, Optional[str]]:
    """
    Returns (sla_due_at_iso, policy_id_or_none) based on policy or default band.
    """
    if isinstance(created_at, str):
        try:
            start_dt = datetime.fromisoformat(created_at)
        except Exception:
            start_dt = datetime.now(timezone.utc)
    else:
        start_dt = created_at

    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)

    if policy and policy.enabled:
        due_days = policy.due_days
        policy_id = policy.id
    else:
        due_days = DEFAULT_SLA_DAYS.get(priority_band.upper(), 30)
        policy_id = None

    due_dt = start_dt + timedelta(days=due_days)
    return due_dt.isoformat(), policy_id


def evaluate_finding_sla_status(
    finding: Finding,
    policy: Optional[SLAPolicy] = None,
    now: Optional[datetime] = None,
) -> str:
    """
    Evaluates the SLAStatus for a finding:
    - If finding is in closed/remediated/verified/false_positive/risk_accepted status:
      returns SLAStatus.COMPLIED (or previous non-breached state / PAUSED).
    - If SLA is explicitly PAUSED: returns SLAStatus.PAUSED.
    - If no sla_due_at: returns SLAStatus.NOT_APPLICABLE.
    - If current time >= sla_due_at: returns SLAStatus.BREACHED.
    - If current time is within warning window: returns SLAStatus.WARNING.
    - Otherwise: returns SLAStatus.ON_TRACK.
    """
    current_status = finding.status.upper() if isinstance(finding.status, str) else finding.status.value

    if current_status == FindingStatus.RISK_ACCEPTED.value or finding.sla_paused_at or finding.sla_status == SLAStatus.PAUSED.value:
        return SLAStatus.PAUSED.value

    terminal_statuses = {
        FindingStatus.REMEDIATED.value,
        FindingStatus.VERIFIED.value,
        FindingStatus.CLOSED.value,
        FindingStatus.FALSE_POSITIVE.value,
    }

    if current_status in terminal_statuses:
        if finding.sla_status == SLAStatus.BREACHED.value:
            return SLAStatus.BREACHED.value
        return SLAStatus.COMPLIED.value

    if not finding.sla_due_at:
        return SLAStatus.NOT_APPLICABLE.value

    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        due_dt = datetime.fromisoformat(finding.sla_due_at)
        if due_dt.tzinfo is None:
            due_dt = due_dt.replace(tzinfo=timezone.utc)
    except Exception:
        return SLAStatus.NOT_APPLICABLE.value

    if now >= due_dt:
        return SLAStatus.BREACHED.value

    # Warning threshold
    warning_days = policy.warning_days if (policy and policy.enabled) else DEFAULT_WARNING_DAYS.get(finding.priority_band.upper(), 5)
    warning_dt = due_dt - timedelta(days=warning_days)

    if now >= warning_dt:
        return SLAStatus.WARNING.value

    return SLAStatus.ON_TRACK.value
