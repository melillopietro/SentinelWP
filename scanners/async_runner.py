"""
Async Scan Runner with ThreadPoolExecutor and Live Progress tracking.
"""
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from core.models import ScanResult, ScanStatus
from core import repository
from scanners.base import BaseScanner
from scanners.orchestrator import SCAN_PROFILES

# Thread pool for asynchronous background scans (max 5 concurrent scans)
_executor = ThreadPoolExecutor(max_workers=5)

# In-memory progress tracking: scan_id -> dict(progress, current_step, total_steps, status)
_scan_progress: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def get_scan_progress(scan_id: str) -> Dict[str, Any]:
    """Retrieve current progress state for a scan."""
    with _lock:
        if scan_id in _scan_progress:
            return dict(_scan_progress[scan_id])
    
    # Fallback to DB check
    scan = repository.get_scan(scan_id)
    if scan:
        status_val = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        is_done = status_val in ("completed", "failed")
        return {
            "scan_id": scan_id,
            "status": status_val,
            "progress": 100 if is_done else 0,
            "current_step": "Complete" if is_done else "Pending",
            "total_steps": 1,
            "current_step_num": 1 if is_done else 0,
        }
    return {"scan_id": scan_id, "status": "unknown", "progress": 0, "current_step": "Not found"}


def _update_progress(scan_id: str, current_step: str, step_num: int, total_steps: int, status: str = "running"):
    """Update progress tracking dictionary and persist to ScanJob entity."""
    progress_pct = int((step_num / max(1, total_steps)) * 100)
    with _lock:
        _scan_progress[scan_id] = {
            "scan_id": scan_id,
            "status": status,
            "progress": min(100, progress_pct),
            "current_step": current_step,
            "step_num": step_num,
            "total_steps": total_steps,
        }
    try:
        job = repository.get_scan_job_by_scan_id(scan_id)
        if job:
            repository.update_scan_job_progress(job.id, min(100, progress_pct), current_step)
            if status == "completed":
                repository.mark_scan_job_status(job.id, "completed")
            elif status == "failed":
                repository.mark_scan_job_status(job.id, "failed")
    except Exception:
        pass


def _execute_async_scan(scan_id: str, target_url: str, initiated_by: str, scan_mode: str):
    """Background task function executed by ThreadPoolExecutor."""
    scanners = SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["passive"])
    total_steps = len(scanners)
    all_findings = []

    _update_progress(scan_id, "Initializing scan", 0, total_steps, status="running")

    for idx, scanner_cls in enumerate(scanners, 1):
        step_name = scanner_cls.__name__
        _update_progress(scan_id, f"Running {step_name}", idx, total_steps, status="running")
        try:
            scanner = scanner_cls(target_url)
            # Match orchestrator: active probes only for safe-active / full.
            if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_ACTIVE_PROBE"):
                scanner.ENABLE_ACTIVE_PROBE = True
            if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_SUBDIR_PROBE"):
                scanner.ENABLE_SUBDIR_PROBE = True
            findings = scanner.scan()
            for f in findings:
                f.scan_id = scan_id
            all_findings.extend(findings)
        except Exception as e:
            from core.models import Finding, Severity
            err_finding = Finding(
                scan_id=scan_id,
                category="error",
                title=f"Scanner Error: {step_name}",
                description=str(e)[:500],
                severity=Severity.INFO,
                confidence=0.5,
            )
            all_findings.append(err_finding)

    # Single authoritative post-process path (OSV gate + local intel + scoring).
    scan = repository.get_scan(scan_id)
    if scan:
        from core.scan_pipeline import finalize_and_score_scan, mark_scan_completed

        finalize_and_score_scan(all_findings, scan)
        for f in scan.findings:
            f.tenant_id = scan.tenant_id
            f.asset_id = scan.asset_id

        # Preserve dual wordpress_* / wp_* fields for UI/API compatibility.
        scan.wordpress_detected = bool(scan.is_wordpress)
        scan.wordpress_version = scan.wp_version
        scan.wordpress_version_source = getattr(scan, "wp_version_source", None)
        scan.wordpress_version_confidence = getattr(scan, "wp_version_confidence", None)

        mark_scan_completed(scan)
        repository.save_scan(scan)
        repository.save_findings_bulk(scan.findings)

        try:
            from core.notifications import dispatch_scan_notifications
            dispatch_scan_notifications(scan)
        except Exception:
            pass

    _update_progress(scan_id, "Completed", total_steps, total_steps, status="completed")


def start_async_scan(
    target_url: str,
    initiated_by: str = "",
    scan_mode: str = "passive",
    tenant_id: str = "default-tenant",
    asset_id: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> ScanResult:
    """
    Create a new scan record in DB and queue it for async background execution.
    Returns ScanResult immediately (in PENDING/RUNNING state).
    """
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    is_valid, error_msg = BaseScanner.validate_target(target_url)
    if not is_valid:
        raise ValueError(f"Target blocked: {error_msg}")

    if scan_mode not in SCAN_PROFILES:
        scan_mode = "passive"

    # Link to asset if not explicitly passed
    if not asset_id:
        try:
            asset = repository.ensure_asset_for_target(tenant_id, target_url)
            asset_id = asset.id
        except Exception:
            asset_id = None

    if scan_id:
        existing_scan = repository.get_scan(scan_id, tenant_id=tenant_id)
        if existing_scan:
            scan = existing_scan
            scan.status = ScanStatus.RUNNING
            repository.save_scan(scan)
        else:
            scan = ScanResult(
                id=scan_id,
                target_url=target_url,
                status=ScanStatus.RUNNING,
                scan_mode=scan_mode,
                initiated_by=initiated_by,
                tenant_id=tenant_id or "default-tenant",
                asset_id=asset_id,
            )
            repository.save_scan(scan)
    else:
        scan = ScanResult(
            target_url=target_url,
            status=ScanStatus.RUNNING,
            scan_mode=scan_mode,
            initiated_by=initiated_by,
            tenant_id=tenant_id or "default-tenant",
            asset_id=asset_id,
        )
        repository.save_scan(scan)

    # Ensure a ScanJob exists for persistent tracking
    from core.models import ScanJob, ScanJobStatus
    existing_job = repository.get_scan_job_by_scan_id(scan.id)
    if not existing_job:
        job = ScanJob(
            tenant_id=tenant_id or "default-tenant",
            asset_id=asset_id,
            scan_id=scan.id,
            status=ScanJobStatus.RUNNING.value,
            requested_by=initiated_by or "analyst",
            profile=scan_mode,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        repository.create_scan_job(job)

    # Initialize progress state
    _update_progress(scan.id, "Queued", 0, len(SCAN_PROFILES[scan_mode]), status="running")

    # Dispatch to background thread pool
    _executor.submit(_execute_async_scan, scan.id, target_url, initiated_by, scan_mode)

    return scan
