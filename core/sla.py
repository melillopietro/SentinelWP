"""
SentinelWP - Service Level Agreement (SLA) Engine
Compatibility wrapper re-exporting core/sla_engine.py.
"""
from core.sla_engine import (
    DEFAULT_SLA_DAYS,
    DEFAULT_WARNING_DAYS,
    DEFAULT_SLA_SEEDS,
    calculate_sla_due_date,
    evaluate_finding_sla_status,
    match_sla_policy,
)

__all__ = [
    "DEFAULT_SLA_DAYS",
    "DEFAULT_WARNING_DAYS",
    "DEFAULT_SLA_SEEDS",
    "calculate_sla_due_date",
    "evaluate_finding_sla_status",
    "match_sla_policy",
]
