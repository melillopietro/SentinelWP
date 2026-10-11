"""
Centralized Finding Lifecycle and State Machine for SentinelWP.
Enforces strict transitions, invalid transition rejection (HTTP 409 Conflict),
and optimistic locking.
"""
from enum import Enum
from typing import Set, Dict, Optional


class FindingStatus(str, Enum):
    NEW = "NEW"
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class RemediationStatus(str, Enum):
    OPEN = "OPEN"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    DONE = "DONE"
    CANCELLED = "CANCELLED"


class RiskAcceptanceStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class SLAStatus(str, Enum):
    ON_TRACK = "ON_TRACK"
    WARNING = "WARNING"
    BREACHED = "BREACHED"
    PAUSED = "PAUSED"
    COMPLIED = "COMPLIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class InvalidStateTransitionError(Exception):
    """Raised when an invalid finding status transition is attempted."""
    def __init__(self, current_status: str, target_status: str, message: Optional[str] = None):
        self.current_status = current_status
        self.target_status = target_status
        self.message = message or f"Invalid transition from '{current_status}' to '{target_status}'."
        super().__init__(self.message)


class OptimisticLockError(Exception):
    """Raised when concurrent modification is detected via version mismatch."""
    def __init__(self, finding_id_or_msg: str = "", expected_version: Optional[int] = None):
        self.finding_id = finding_id_or_msg
        self.expected_version = expected_version
        if expected_version is not None:
            msg = f"Conflict on finding '{finding_id_or_msg}': expected version {expected_version} has been modified concurrently."
        else:
            msg = str(finding_id_or_msg)
        super().__init__(msg)


# Explicit, strict transition graph
ALLOWED_FINDING_TRANSITIONS: Dict[FindingStatus, Set[FindingStatus]] = {
    FindingStatus.NEW: {
        FindingStatus.OPEN,
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.RISK_ACCEPTED,
    },
    FindingStatus.OPEN: {
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.REMEDIATED,
        FindingStatus.VERIFICATION_PENDING,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.ACKNOWLEDGED: {
        FindingStatus.IN_PROGRESS,
        FindingStatus.REMEDIATED,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.OPEN,
    },
    FindingStatus.IN_PROGRESS: {
        FindingStatus.REMEDIATED,
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.OPEN,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.BLOCKED if hasattr(FindingStatus, "BLOCKED") else FindingStatus.IN_PROGRESS,
    },
    FindingStatus.REMEDIATED: {
        FindingStatus.VERIFICATION_PENDING,
        FindingStatus.VERIFIED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.REOPENED,
    },
    FindingStatus.VERIFICATION_PENDING: {
        FindingStatus.VERIFIED,
        FindingStatus.REOPENED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.REMEDIATED,
    },
    FindingStatus.VERIFIED: {
        FindingStatus.CLOSED,
        FindingStatus.REOPENED,
    },
    FindingStatus.RISK_ACCEPTED: {
        FindingStatus.OPEN,
        FindingStatus.REOPENED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.CLOSED,
    },
    FindingStatus.FALSE_POSITIVE: {
        FindingStatus.OPEN,
        FindingStatus.REOPENED,
    },
    FindingStatus.CLOSED: {
        FindingStatus.REOPENED,
    },
    FindingStatus.REOPENED: {
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.REMEDIATED,
        FindingStatus.RISK_ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.OPEN,
    },
}


def can_transition(current: str, target: str) -> bool:
    """Check whether a transition between two finding statuses is permitted."""
    try:
        curr_enum = FindingStatus(current.upper())
        tgt_enum = FindingStatus(target.upper())
    except (ValueError, AttributeError):
        return False
    
    if curr_enum == tgt_enum:
        return True
    
    allowed = ALLOWED_FINDING_TRANSITIONS.get(curr_enum, set())
    return tgt_enum in allowed


def validate_transition(current: str, target: str) -> FindingStatus:
    """Validate transition and return validated target FindingStatus enum, or raise InvalidStateTransitionError."""
    try:
        curr_enum = FindingStatus(current.upper())
    except (ValueError, AttributeError):
        raise InvalidStateTransitionError(str(current), str(target), f"Unknown current status '{current}'")

    try:
        tgt_enum = FindingStatus(target.upper())
    except (ValueError, AttributeError):
        raise InvalidStateTransitionError(curr_enum.value, str(target), f"Unknown target status '{target}'")

    if curr_enum == tgt_enum:
        return tgt_enum

    if not can_transition(curr_enum.value, tgt_enum.value):
        raise InvalidStateTransitionError(
            curr_enum.value,
            tgt_enum.value,
            f"Cannot transition finding from '{curr_enum.value}' to '{tgt_enum.value}'."
        )

    return tgt_enum
