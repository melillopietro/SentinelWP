"""
SentinelWP - Finding State Machine
Canonical module defining lifecycle states and transition validation.
"""
from core.lifecycle import (
    FindingStatus,
    RemediationStatus,
    RiskAcceptanceStatus,
    SLAStatus,
    InvalidStateTransitionError,
    OptimisticLockError,
    ALLOWED_FINDING_TRANSITIONS,
    can_transition,
    validate_transition,
)

__all__ = [
    "FindingStatus",
    "RemediationStatus",
    "RiskAcceptanceStatus",
    "SLAStatus",
    "InvalidStateTransitionError",
    "OptimisticLockError",
    "ALLOWED_FINDING_TRANSITIONS",
    "can_transition",
    "validate_transition",
    "get_allowed_transitions",
]

def get_allowed_transitions(status):
    if isinstance(status, str):
        try:
            status = FindingStatus(status)
        except ValueError:
            return set()
    return ALLOWED_FINDING_TRANSITIONS.get(status, set())
