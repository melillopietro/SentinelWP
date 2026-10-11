"""
Celery Scan Tasks for SentinelWP.
Executed in dedicated worker processes. Enforces authorization re-validation,
persistent progress reporting, concurrency limits, retry/backoff, and audit logging.
"""
import logging
from datetime import datetime, timezone
import requests
from celery.exceptions import SoftTimeLimitExceeded

from config import (
    SCAN_MAX_RETRIES,
    MAX_CONCURRENT_SCANS_PER_ASSET,
    MAX_CONCURRENT_SCANS_PER_TENANT,
    MAX_CONCURRENT_SCANS_GLOBAL,
)
from core.tasks.celery_app import celery_app
from core.models import ScanStatus, ScanJobStatus, AuditEvent, Severity
from core.repository import (
    get_scan_job,
    try_claim_scan_job_for_execution,
    update_scan_job_progress,
    mark_scan_job_status,
    record_scan_job_heartbeat,
    get_scan,
    save_scan,
    get_asset,
    save_asset,
    update_asset,
    get_tenant,
    save_findings,
    process_scan_findings,
    log_audit_event,
    count_active_scan_jobs_for_asset,
    count_active_scan_jobs_for_tenant,
    count_active_scan_jobs_global,
)
from core.authorization import verify_scan_authorization
from scanners.orchestrator import ScanOrchestrator

logger = logging.getLogger("sentinelwp.tasks.scan")

# Structured worker outcome taxonomy (Celery return value remains bool for compatibility).
OUTCOME_EXECUTION_SUCCESS = "execution_success"
OUTCOME_IDEMPOTENT_SKIP = "idempotent_skip"
OUTCOME_JOB_NOT_FOUND = "job_not_found"
OUTCOME_AUTHORIZATION_REJECTION = "authorization_rejection"
OUTCOME_SSRF_REJECTION = "ssrf_rejection"
OUTCOME_EXECUTION_FAILURE = "execution_failure"
OUTCOME_USER_CANCELLED = "user_cancelled"
OUTCOME_TASK_TIMEOUT = "task_timeout"


def _log_scan_task_outcome(
    job_id: str,
    worker_id: str,
    outcome: str,
    *,
    detail: str = "",
    job_status: str | None = None,
    error_code: str | None = None,
) -> None:
    logger.info(
        "[scan_task_outcome] job_id=%s worker_id=%s outcome=%s job_status=%s error_code=%s detail=%s",
        job_id,
        worker_id,
        outcome,
        job_status or "",
        error_code or "",
        (detail[:500] if detail else ""),
    )


# Transient errors suitable for retry
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError,
    ConnectionResetError,
    TimeoutError,
)

RETRY_BACKOFF_STEPS = [30, 60, 120, 300]


@celery_app.task(
    bind=True,
    max_retries=SCAN_MAX_RETRIES,
    name="core.tasks.scan_tasks.run_scan_task",
)
def run_scan_task(self, scan_job_id: str):
    worker_id = (getattr(self.request, "hostname", None) if hasattr(self, "request") else None) or "worker-unknown"
    current_retries = (getattr(self.request, "retries", 0) if hasattr(self, "request") else 0) or 0
    logger.info(f"[{scan_job_id}] Worker {worker_id} picked up scan job (attempt {current_retries + 1})")

    job = get_scan_job(scan_job_id)
    if not job:
        logger.error(f"[{scan_job_id}] ScanJob not found in database. Aborting.")
        _log_scan_task_outcome(
            scan_job_id, worker_id, OUTCOME_JOB_NOT_FOUND, detail="scan_job_missing"
        )
        return False

    # Check if already cancelled
    if job.status == ScanJobStatus.CANCELLED.value:
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_IDEMPOTENT_SKIP,
            detail="cancelled_before_worker",
            job_status=job.status,
        )
        return False

    if job.status in (
        ScanJobStatus.COMPLETED.value,
        ScanJobStatus.FAILED.value,
        ScanJobStatus.TIMED_OUT.value,
    ):
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_IDEMPOTENT_SKIP,
            detail="terminal_duplicate_delivery",
            job_status=job.status,
        )
        return False

    # Concurrency Limits check: per-asset and per-tenant
    # Concurrency checks use >= MAX because count_active_scan_jobs_* counts jobs currently
    # in (queued, running, retrying) states. This job is still QUEUED and is included in
    # that count, so the comparison is: if others already at max, postpone.
    if job.asset_id:
        active_asset_jobs = count_active_scan_jobs_for_asset(job.asset_id)
        if active_asset_jobs >= MAX_CONCURRENT_SCANS_PER_ASSET + 1:  # +1: this job counts itself
            logger.info(f"[{scan_job_id}] Asset {job.asset_id} at max concurrent limit ({active_asset_jobs}/{MAX_CONCURRENT_SCANS_PER_ASSET}). Postponing.")
            raise self.retry(countdown=30)

    active_tenant_jobs = count_active_scan_jobs_for_tenant(job.tenant_id)
    if active_tenant_jobs >= MAX_CONCURRENT_SCANS_PER_TENANT + 1:
        logger.info(f"[{scan_job_id}] Tenant {job.tenant_id} at max concurrent limit ({active_tenant_jobs}/{MAX_CONCURRENT_SCANS_PER_TENANT}). Postponing.")
        raise self.retry(countdown=45)

    active_global_jobs = count_active_scan_jobs_global()
    if active_global_jobs >= MAX_CONCURRENT_SCANS_GLOBAL + 1:
        logger.info(f"[{scan_job_id}] Global scan concurrency at limit ({active_global_jobs}/{MAX_CONCURRENT_SCANS_GLOBAL}). Postponing.")
        raise self.retry(countdown=20)

    claimed_job = try_claim_scan_job_for_execution(scan_job_id, worker_id)
    if not claimed_job:
        fresh = get_scan_job(scan_job_id)
        if fresh and fresh.status == ScanJobStatus.RUNNING.value:
            if fresh.worker_id and fresh.worker_id != worker_id:
                _log_scan_task_outcome(
                    scan_job_id,
                    worker_id,
                    OUTCOME_IDEMPOTENT_SKIP,
                    detail=f"claimed_by_other_worker:{fresh.worker_id}",
                    job_status=fresh.status,
                )
                return False
            _log_scan_task_outcome(
                scan_job_id,
                worker_id,
                OUTCOME_IDEMPOTENT_SKIP,
                detail="reentrant_delivery_same_worker",
                job_status=fresh.status,
            )
            return False
        if fresh and fresh.status in (
            ScanJobStatus.COMPLETED.value,
            ScanJobStatus.CANCELLED.value,
            ScanJobStatus.FAILED.value,
            ScanJobStatus.TIMED_OUT.value,
        ):
            _log_scan_task_outcome(
                scan_job_id,
                worker_id,
                OUTCOME_IDEMPOTENT_SKIP,
                detail="claim_race_terminal_state",
                job_status=fresh.status,
            )
            return False
        logger.info(f"[{scan_job_id}] Could not claim job (status={getattr(fresh, 'status', 'unknown')}). Retrying.")
        raise self.retry(countdown=15)

    job = claimed_job

    scan = get_scan(job.scan_id, tenant_id=job.tenant_id)
    if not scan:
        logger.error(f"[{scan_job_id}] Linked Scan {job.scan_id} not found. Failing job.")
        mark_scan_job_status(
            scan_job_id,
            ScanJobStatus.FAILED.value,
            error_code="SCAN_NOT_FOUND",
            error_message="Scan entity not found",
            worker_id=worker_id,
        )
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_EXECUTION_FAILURE,
            detail="linked_scan_missing",
            job_status=ScanJobStatus.FAILED.value,
            error_code="SCAN_NOT_FOUND",
        )
        return False

    tenant = get_tenant(job.tenant_id)
    if not tenant or tenant.status != "active":
        logger.error(f"[{scan_job_id}] Tenant {job.tenant_id} is invalid or inactive. Failing closed.")
        mark_scan_job_status(
            scan_job_id,
            ScanJobStatus.FAILED.value,
            error_code="TENANT_INACTIVE",
            error_message="Tenant is inactive",
            worker_id=worker_id,
        )
        scan.status = ScanStatus.FAILED
        save_scan(scan)
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_EXECUTION_FAILURE,
            detail="tenant_inactive",
            job_status=ScanJobStatus.FAILED.value,
            error_code="TENANT_INACTIVE",
        )
        return False

    norm_mode = (scan.scan_mode or "passive").replace("-", "_").lower()
    if norm_mode in ("safe_active", "full"):
        is_auth, auth_err, _ = verify_scan_authorization(job.tenant_id, scan.target_url, scan.scan_mode)
        if not is_auth:
            logger.warning(
                f"[{scan_job_id}] PRE-FLIGHT GUARDRAIL TRIPPED in worker: {auth_err}. Failing closed."
            )
            mark_scan_job_status(
                scan_job_id,
                ScanJobStatus.FAILED.value,
                error_code="AUTHORIZATION_EXPIRED",
                error_message=f"Target scan authorization expired or invalid: {auth_err}",
                worker_id=worker_id,
            )
            scan.status = ScanStatus.FAILED
            scan.notes = f"Audit failed: {auth_err}"
            scan.completed_at = datetime.now(timezone.utc).isoformat()
            save_scan(scan)

            log_audit_event(AuditEvent(
                tenant_id=job.tenant_id,
                actor_user_id="worker",
                actor_username=worker_id,
                action="scan_job_failed",
                resource_type="scan_job",
                resource_id=scan_job_id,
                result="denied",
                metadata={"error": "authorization_expired", "scan_id": scan.id, "target": scan.target_url},
            ))
            _log_scan_task_outcome(
                scan_job_id,
                worker_id,
                OUTCOME_AUTHORIZATION_REJECTION,
                detail=auth_err or "authorization_expired",
                job_status=ScanJobStatus.FAILED.value,
                error_code="AUTHORIZATION_EXPIRED",
            )
            return False

    update_scan_job_progress(scan_job_id, 5, "Initializing Scanners", worker_id=worker_id)
    scan.status = ScanStatus.RUNNING
    save_scan(scan)

    log_audit_event(AuditEvent(
        tenant_id=job.tenant_id,
        actor_user_id="worker",
        actor_username=worker_id,
        action="scan_job_started",
        resource_type="scan_job",
        resource_id=scan_job_id,
        result="success",
        metadata={"scan_id": scan.id, "target": scan.target_url, "attempt": self.request.retries + 1},
    ))

    # Progress Callback
    def on_progress(pct: int, step_name: str):
        # Check cancellation midway
        fresh_job = get_scan_job(scan_job_id)
        if fresh_job and fresh_job.status == ScanJobStatus.CANCELLED.value:
            raise InterruptedError("Scan was cancelled by user request.")
        update_scan_job_progress(scan_job_id, pct, step_name, worker_id=worker_id)

    try:
        orchestrator = ScanOrchestrator(
            target_url=scan.target_url,
            scan_mode=scan.scan_mode,
            tenant_id=job.tenant_id,
            asset_id=job.asset_id,
        )

        # Run scanner stages with progress reporting
        update_scan_job_progress(scan_job_id, 15, "Target Recon & Fingerprinting", worker_id=worker_id)
        completed_scan = orchestrator.run()

        # Update and save scan results
        completed_scan.id = scan.id
        completed_scan.tenant_id = job.tenant_id
        completed_scan.asset_id = job.asset_id
        completed_scan.status = ScanStatus.COMPLETED
        completed_scan.completed_at = datetime.now(timezone.utc).isoformat()
        save_scan(completed_scan)

        # Update Asset metadata & Technology Inventory if WordPress detected
        if job.asset_id:
            try:
                asset = get_asset(job.asset_id, tenant_id=job.tenant_id)
                if asset:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    posture_updates: dict = {
                        "last_scan_id": scan.id,
                        "last_scan_at": now_iso,
                        "last_scan_status": "completed",
                        "last_successful_scan_at": now_iso,
                        "consecutive_scan_failures": 0,
                    }

                    if completed_scan.wordpress_detected or completed_scan.is_wordpress:
                        tags_set = set(t.strip() for t in (asset.tags or "").split(",") if t.strip())
                        tags_set.add("wordpress")
                        wp_v = completed_scan.wordpress_version or completed_scan.wp_version
                        if wp_v and wp_v not in ("Unknown", "Not WordPress"):
                            tags_set.add(f"wp-{wp_v}")
                            posture_updates["wp_version"] = wp_v
                        posture_updates["tags"] = ", ".join(sorted(tags_set))

                    # Capture score for posture summary
                    if completed_scan.score is not None:
                        posture_updates["risk_score"] = completed_scan.score

                    update_asset(asset.id, tenant_id=job.tenant_id, **posture_updates)

                if completed_scan.wordpress_detected or completed_scan.is_wordpress:
                    # Feed Phase 6 TechnologyObservation inventory
                    from core.models import TechnologyObservation
                    from core.repository import save_technology_observation
                    wp_ver = completed_scan.wordpress_version or completed_scan.wp_version
                    wp_src = completed_scan.wordpress_version_source or completed_scan.wp_version_source or "meta_generator"
                    wp_conf = completed_scan.wordpress_version_confidence or completed_scan.wp_version_confidence or "HIGH"
                    if wp_ver and wp_ver in ("Unknown", "Not WordPress"):
                        wp_ver = None

                    now_iso = datetime.now(timezone.utc).isoformat()
                    save_technology_observation(TechnologyObservation(
                        tenant_id=job.tenant_id,
                        asset_id=job.asset_id,
                        technology_type="CMS",
                        name="WordPress",
                        version=wp_ver,
                        source=wp_src,
                        confidence=str(wp_conf).upper(),
                        first_seen=now_iso,
                        last_seen=now_iso,
                        created_at=now_iso
                    ))
            except Exception as e:
                logger.warning(f"[{scan_job_id}] Could not update asset metadata or technology inventory: {e}")

        # Persist findings with lifecycle, fingerprinting, and observation tracking
        if completed_scan.findings:
            completed_scan.findings = process_scan_findings(
                scan_id=scan.id,
                tenant_id=job.tenant_id,
                asset_id=job.asset_id,
                raw_findings=completed_scan.findings
            )

        # S3-GAP-004: Automatic post-scan differential computation.
        # Triggered only when the scan reached COMPLETED status and there is a
        # prior completed scan on the same asset to compare against.
        # Failures are fully isolated — a differential error never corrupts scan data.
        _trigger_post_scan_differential(scan.id, job.tenant_id, job.asset_id, scan_job_id)

        # Mark job completed
        mark_scan_job_status(scan_job_id, ScanJobStatus.COMPLETED.value)
        update_scan_job_progress(scan_job_id, 100, "Completed", worker_id=worker_id)

        log_audit_event(AuditEvent(
            tenant_id=job.tenant_id,
            actor_user_id="worker",
            actor_username=worker_id,
            action="scan_job_completed",
            resource_type="scan_job",
            resource_id=scan_job_id,
            result="success",
            metadata={
                "scan_id": scan.id,
                "findings_count": len(completed_scan.findings),
                "grade": completed_scan.grade,
                "score": completed_scan.score,
            },
        ))
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_EXECUTION_SUCCESS,
            job_status=ScanJobStatus.COMPLETED.value,
        )
        logger.info(f"[{scan_job_id}] Scan completed successfully.")
        return True

    except InterruptedError:
        logger.info(f"[{scan_job_id}] Execution halted due to user cancellation.")
        scan.status = ScanStatus.FAILED
        scan.notes = "Scan cancelled by user."
        scan.completed_at = datetime.now(timezone.utc).isoformat()
        save_scan(scan)
        mark_scan_job_status(scan_job_id, ScanJobStatus.CANCELLED.value)
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_USER_CANCELLED,
            job_status=ScanJobStatus.CANCELLED.value,
        )
        return False

    except SoftTimeLimitExceeded:
        logger.error(f"[{scan_job_id}] Task soft time limit exceeded!")
        mark_scan_job_status(
            scan_job_id,
            ScanJobStatus.TIMED_OUT.value,
            error_code="TASK_TIMEOUT",
            error_message="Scan exceeded maximum execution time limit",
        )
        scan.status = ScanStatus.FAILED
        scan.notes = "Timed out"
        scan.completed_at = datetime.now(timezone.utc).isoformat()
        save_scan(scan)

        log_audit_event(AuditEvent(
            tenant_id=job.tenant_id,
            actor_user_id="worker",
            actor_username=worker_id,
            action="scan_job_timed_out",
            resource_type="scan_job",
            resource_id=scan_job_id,
            result="failure",
            metadata={"scan_id": scan.id, "error": "timeout"},
        ))
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            OUTCOME_TASK_TIMEOUT,
            job_status=ScanJobStatus.TIMED_OUT.value,
            error_code="TASK_TIMEOUT",
        )
        return False

    except RETRYABLE_EXCEPTIONS as exc:
        retry_idx = min(self.request.retries, len(RETRY_BACKOFF_STEPS) - 1)
        countdown = RETRY_BACKOFF_STEPS[retry_idx]
        logger.warning(
            f"[{scan_job_id}] Transient network/connection error: {exc}. Retrying in {countdown}s "
            f"(attempt {self.request.retries + 1}/{SCAN_MAX_RETRIES})"
        )
        mark_scan_job_status(
            scan_job_id,
            ScanJobStatus.RETRYING.value,
            error_code="TRANSIENT_NETWORK_ERROR",
            error_message=str(exc),
        )

        log_audit_event(AuditEvent(
            tenant_id=job.tenant_id,
            actor_user_id="worker",
            actor_username=worker_id,
            action="scan_job_retry",
            resource_type="scan_job",
            resource_id=scan_job_id,
            result="warning",
            metadata={"scan_id": scan.id, "error": str(exc), "countdown": countdown},
        ))
        raise self.retry(exc=exc, countdown=countdown)

    except Exception as exc:
        exc_msg = str(exc)
        if "Target blocked:" in exc_msg:
            error_code = "TARGET_BLOCKED"
            outcome = OUTCOME_SSRF_REJECTION
            logger.warning("[%s] Worker SSRF enforcement: %s", scan_job_id, exc_msg[:500])
        else:
            error_code = "SCAN_EXECUTION_ERROR"
            outcome = OUTCOME_EXECUTION_FAILURE
            logger.exception(f"[{scan_job_id}] Unhandled error executing scan: {exc}")
        mark_scan_job_status(
            scan_job_id,
            ScanJobStatus.FAILED.value,
            error_code=error_code,
            error_message=exc_msg[:500],
        )
        scan.status = ScanStatus.FAILED
        scan.notes = f"Execution error: {str(exc)[:200]}"
        scan.completed_at = datetime.now(timezone.utc).isoformat()
        save_scan(scan)

        # Update asset failure tracking (Sprint 3 Phase 2)
        if job.asset_id:
            try:
                asset = get_asset(job.asset_id, tenant_id=job.tenant_id)
                if asset:
                    new_failures = getattr(asset, "consecutive_scan_failures", 0) + 1
                    now_iso = datetime.now(timezone.utc).isoformat()
                    update_asset(job.asset_id, tenant_id=job.tenant_id,
                                 last_scan_id=scan.id,
                                 last_scan_at=now_iso,
                                 last_scan_status="failed",
                                 consecutive_scan_failures=new_failures)
            except Exception:
                pass

        log_audit_event(AuditEvent(
            tenant_id=job.tenant_id,
            actor_user_id="worker",
            actor_username=worker_id,
            action="scan_job_failed",
            resource_type="scan_job",
            resource_id=scan_job_id,
            result="failure",
            metadata={"scan_id": scan.id, "error": exc_msg[:200]},
        ))
        _log_scan_task_outcome(
            scan_job_id,
            worker_id,
            outcome,
            detail=exc_msg[:500],
            job_status=ScanJobStatus.FAILED.value,
            error_code=error_code,
        )
        return False


# ---------------------------------------------------------------------------
# S3-GAP-004: Post-scan differential helper
# ---------------------------------------------------------------------------

def _trigger_post_scan_differential(
    new_scan_id: str,
    tenant_id: str,
    asset_id: str | None,
    scan_job_id: str,
) -> None:
    """
    Compute a ScanDifferential between the just-completed scan and the most
    recent prior completed scan on the same asset.

    Safety invariants (enforced inside compute_scan_differential):
      - RESOLVED is only emitted when new_scan.status == COMPLETED.
      - If no prior scan exists, the differential has only NEW changes.
      - Any exception is caught here — scan completion state is never corrupted.

    Idempotency: if the same scan_id is re-processed (task retry after the
    worker crashed post-completion), compute_scan_differential will produce the
    same result.  There is no persistent store for differentials in the current
    schema so repeated calls are harmless.

    Args:
        new_scan_id: The just-completed scan.
        tenant_id:   Tenant scope.
        asset_id:    Asset scope (None for ad-hoc scans without an asset).
        scan_job_id: For log correlation only.
    """
    try:
        from core.differential import compute_scan_differential
        from core.repository import list_scans
        from core.models import ScanStatus

        if not asset_id:
            # Ad-hoc scans without an asset_id have no prior scan to compare
            logger.debug(
                "[%s] Skipping differential: no asset_id on scan %s",
                scan_job_id, new_scan_id[:8]
            )
            return

        # Find the most recent completed scan before this one on the same asset
        prior_scans = list_scans(
            limit=5,
            filters={
                "asset_id": asset_id,
                "tenant_id": tenant_id,
                "status": ScanStatus.COMPLETED.value,
            },
        )

        # Filter out the new scan itself (it is now COMPLETED so will appear)
        baseline_candidates = [s for s in prior_scans if s.id != new_scan_id]
        if not baseline_candidates:
            logger.info(
                "[%s] No prior completed scan for asset %s — differential skipped (first scan).",
                scan_job_id, asset_id[:8] if asset_id else "?"
            )
            return

        baseline_scan = baseline_candidates[0]
        diff = compute_scan_differential(
            baseline_scan_id=baseline_scan.id,
            new_scan_id=new_scan_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
        )
        logger.info(
            "[%s] Post-scan differential complete: NEW=%d PERSISTING=%d RESOLVED=%d REOPENED=%d "
            "(baseline=%s, new=%s, complete=%s)",
            scan_job_id,
            diff.new_count, diff.persisting_count, diff.resolved_count, diff.reopened_count,
            baseline_scan.id[:8], new_scan_id[:8], diff.is_complete,
        )

    except Exception as exc:
        # Differential errors must never propagate to the scan task caller.
        # A failure here is a non-critical observability gap, not a data corruption risk.
        logger.warning(
            "[%s] Post-scan differential failed for scan %s (non-fatal): %s",
            scan_job_id, new_scan_id[:8], exc,
        )
