"""
core/differential.py — Sprint 3 Phase 3: Security Posture Differential Engine

Compares two consecutive scans on the same asset, producing a structured
ScanDifferential report with per-finding change states using stable fingerprints.

Change states (per OWASP classification):
  NEW        — fingerprint present in new_scan, absent in baseline
  PERSISTING — fingerprint present in both scans, status still open/active
  RESOLVED   — fingerprint absent in new_scan, was open in baseline
               (ONLY produced when new_scan completed successfully)
  REOPENED   — fingerprint was VERIFIED/CLOSED/REMEDIATED in baseline, reappeared
  UNKNOWN    — cannot determine change (insufficient data)

Critical safety invariant:
  RESOLVED change states are NEVER produced when new_scan.status != COMPLETED.
  A failed/incomplete scan cannot create false resolutions.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sentinelwp.differential")

# States mirroring FindingStatus where relevant, but expressed from a
# differential perspective (scanner-observed, not workflow-managed).
CHANGE_NEW = "NEW"
CHANGE_PERSISTING = "PERSISTING"
CHANGE_RESOLVED = "RESOLVED"
CHANGE_REOPENED = "REOPENED"
CHANGE_UNKNOWN = "UNKNOWN"

# Statuses that represent an "open" / active finding
_OPEN_STATUSES = {"OPEN", "REOPENED", "IN_PROGRESS"}

# Statuses that represent a previously resolved finding
_RESOLVED_STATUSES = {"VERIFIED", "CLOSED", "REMEDIATED"}


@dataclass
class FindingChange:
    """Describes how a single finding changed between two scans."""
    fingerprint: str
    change_state: str  # NEW / PERSISTING / RESOLVED / REOPENED / UNKNOWN
    finding_id: Optional[str] = None       # DB id from baseline or new scan
    title: str = ""
    category: str = ""
    severity: str = "info"
    baseline_status: Optional[str] = None  # status in baseline scan (if any)
    new_status: Optional[str] = None       # status in new scan (if any)
    # Component version changes (populated for plugin/theme/WP findings)
    baseline_version: Optional[str] = None
    new_version: Optional[str] = None


@dataclass
class ScanDifferential:
    """
    Full differential report between a baseline scan and a newer scan on the
    same asset.  Produced by compute_scan_differential().
    """
    baseline_scan_id: str
    new_scan_id: str
    asset_id: Optional[str]
    tenant_id: str
    # Is the differential trustworthy?  False when new_scan was not COMPLETED.
    is_complete: bool = True
    incomplete_reason: Optional[str] = None

    # Per-finding change records
    changes: list[FindingChange] = field(default_factory=list)

    # Aggregated counts (derived from changes list)
    new_count: int = 0
    persisting_count: int = 0
    resolved_count: int = 0
    reopened_count: int = 0

    # WP / component version changes detected via TechnologyObservation
    wp_version_changed: bool = False
    wp_version_baseline: Optional[str] = None
    wp_version_new: Optional[str] = None

    def _recompute_counts(self):
        self.new_count = sum(1 for c in self.changes if c.change_state == CHANGE_NEW)
        self.persisting_count = sum(1 for c in self.changes if c.change_state == CHANGE_PERSISTING)
        self.resolved_count = sum(1 for c in self.changes if c.change_state == CHANGE_RESOLVED)
        self.reopened_count = sum(1 for c in self.changes if c.change_state == CHANGE_REOPENED)


def compute_scan_differential(
    baseline_scan_id: str,
    new_scan_id: str,
    tenant_id: str,
    asset_id: Optional[str] = None,
) -> ScanDifferential:
    """
    Compute a ScanDifferential between two scans on the same asset.

    Args:
        baseline_scan_id: The older completed scan to compare against.
        new_scan_id:      The newer scan (should be COMPLETED for full fidelity).
        tenant_id:        Tenant scope.
        asset_id:         Asset scope (optional; used for resolution detection).

    Returns:
        ScanDifferential with all changes populated.

    Safety guarantee:
        If new_scan is not in COMPLETED status, is_complete=False is set and
        no RESOLVED changes are emitted.  This prevents false resolution events
        caused by a failed scan having zero findings.
    """
    # Import here to avoid circular imports at module load time
    from core.repository import get_scan, get_findings_for_scan

    diff = ScanDifferential(
        baseline_scan_id=baseline_scan_id,
        new_scan_id=new_scan_id,
        asset_id=asset_id,
        tenant_id=tenant_id,
    )

    # --- load scans ---
    baseline_scan = get_scan(baseline_scan_id, tenant_id=tenant_id)
    new_scan = get_scan(new_scan_id, tenant_id=tenant_id)

    if not baseline_scan:
        diff.is_complete = False
        diff.incomplete_reason = f"Baseline scan {baseline_scan_id} not found"
        logger.warning(diff.incomplete_reason)
        return diff

    if not new_scan:
        diff.is_complete = False
        diff.incomplete_reason = f"New scan {new_scan_id} not found"
        logger.warning(diff.incomplete_reason)
        return diff

    # --- Safety: block RESOLVED state for non-completed new scans ---
    from core.models import ScanStatus
    _new_status = getattr(new_scan, "status", None)
    new_scan_completed = (
        _new_status == ScanStatus.COMPLETED
        or (isinstance(_new_status, str) and _new_status.upper() == "COMPLETED")
        or (hasattr(_new_status, "value") and str(_new_status.value).upper() == "COMPLETED")
    )
    if not new_scan_completed:
        diff.is_complete = False
        diff.incomplete_reason = (
            f"New scan {new_scan_id} status is '{new_scan.status}' (not completed). "
            "RESOLVED changes suppressed to prevent false resolutions."
        )
        logger.warning(diff.incomplete_reason)

    # --- load findings indexed by fingerprint ---
    baseline_findings = get_findings_for_scan(baseline_scan_id, tenant_id=tenant_id)
    new_findings = get_findings_for_scan(new_scan_id, tenant_id=tenant_id)

    # Index by fingerprint; deduplicate by taking the most recent (highest obs_count)
    baseline_by_fp: dict[str, object] = {}
    for f in baseline_findings:
        fp = f.fingerprint or ""
        if not fp:
            continue
        existing = baseline_by_fp.get(fp)
        if existing is None or (f.observation_count or 0) > (existing.observation_count or 0):
            baseline_by_fp[fp] = f

    new_by_fp: dict[str, object] = {}
    for f in new_findings:
        fp = f.fingerprint or ""
        if not fp:
            continue
        existing = new_by_fp.get(fp)
        if existing is None or (f.observation_count or 0) > (existing.observation_count or 0):
            new_by_fp[fp] = f

    all_fingerprints = set(baseline_by_fp.keys()) | set(new_by_fp.keys())

    for fp in sorted(all_fingerprints):
        b = baseline_by_fp.get(fp)
        n = new_by_fp.get(fp)

        b_status = str(getattr(b, "status", "OPEN")).upper() if b else None
        n_status = str(getattr(n, "status", "OPEN")).upper() if n else None

        if n is not None and b is None:
            # Not in baseline → NEW
            change_state = CHANGE_NEW
        elif b is not None and n is None:
            # Was in baseline, not in new scan
            if not new_scan_completed:
                # Cannot trust absence; mark UNKNOWN
                change_state = CHANGE_UNKNOWN
            elif b_status in _OPEN_STATUSES or b_status in _RESOLVED_STATUSES:
                # Was actively tracked; not seen in new completed scan = RESOLVED
                change_state = CHANGE_RESOLVED
            else:
                # Was already in a terminal/workflow state; absence is expected
                change_state = CHANGE_RESOLVED
        elif b is not None and n is not None:
            # Present in both
            if b_status in _RESOLVED_STATUSES and n_status in _OPEN_STATUSES:
                change_state = CHANGE_REOPENED
            elif n_status in _OPEN_STATUSES or n_status == "REOPENED":
                change_state = CHANGE_PERSISTING
            else:
                change_state = CHANGE_PERSISTING
        else:
            change_state = CHANGE_UNKNOWN

        representative = n or b
        diff.changes.append(FindingChange(
            fingerprint=fp,
            change_state=change_state,
            finding_id=getattr(representative, "id", None),
            title=getattr(representative, "title", ""),
            category=getattr(representative, "category", ""),
            severity=str(getattr(representative, "severity", "info")),
            baseline_status=b_status,
            new_status=n_status,
        ))

    # --- WP version change detection ---
    b_wp = getattr(baseline_scan, "wordpress_version", None) or getattr(baseline_scan, "wp_version", None)
    n_wp = getattr(new_scan, "wordpress_version", None) or getattr(new_scan, "wp_version", None)
    if b_wp and n_wp and b_wp != n_wp:
        diff.wp_version_changed = True
        diff.wp_version_baseline = b_wp
        diff.wp_version_new = n_wp

    diff._recompute_counts()

    logger.info(
        "Differential %s→%s: NEW=%d PERSISTING=%d RESOLVED=%d REOPENED=%d (complete=%s)",
        baseline_scan_id[:8], new_scan_id[:8],
        diff.new_count, diff.persisting_count, diff.resolved_count, diff.reopened_count,
        diff.is_complete,
    )
    return diff


def get_latest_differential_for_asset(
    asset_id: str,
    tenant_id: str,
) -> Optional[ScanDifferential]:
    """
    Convenience: compute differential between the two most recent scans on an asset.
    Returns None if fewer than two completed scans exist.
    """
    from core.repository import list_scans
    from core.models import ScanStatus

    scans = list_scans(
        filters={"asset_id": asset_id, "tenant_id": tenant_id, "status": ScanStatus.COMPLETED.value},
        limit=2,
    )
    if len(scans) < 2:
        return None

    # list_scans returns newest first (ORDER BY created_at DESC)
    new_scan = scans[0]
    baseline_scan = scans[1]
    return compute_scan_differential(
        baseline_scan_id=baseline_scan.id,
        new_scan_id=new_scan.id,
        tenant_id=tenant_id,
        asset_id=asset_id,
    )
