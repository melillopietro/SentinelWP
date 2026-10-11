"""
Celery Maintenance and HA Scheduling Tasks for SentinelWP.
Includes duplicate-free scheduled scan dispatching and stale worker job recovery.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from core.tasks.celery_app import celery_app
from core.models import ScanResult, ScanJob, ScanStatus, ScanJobStatus, AuditEvent
from core.repository import (
    list_scheduled_scans,
    update_scheduled_scan,
    claim_scheduled_run,
    update_scheduled_run_status,
    ensure_asset,
    save_scan,
    create_scan_job,
    find_stale_scan_jobs,
    mark_scan_job_status,
    update_scan_job,
    get_scan,
    log_audit_event,
)

logger = logging.getLogger("sentinelwp.tasks.maintenance")


@celery_app.task(
    name="core.tasks.maintenance_tasks.dispatch_scheduled_scans_task",
    queue="maintenance",
)
def dispatch_scheduled_scans_task() -> Dict[str, Any]:
    """
    Centralized HA dispatcher triggered by Celery Beat every minute.
    Guarantees 0 duplicate scheduled jobs using DB unique constraints on ScheduledRun.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    schedules = list_scheduled_scans()

    dispatched_count = 0
    duplicate_blocked_count = 0

    for sched in schedules:
        if not sched.enabled:
            continue
        if not sched.next_run_at:
            continue

        # Sprint 3 Phase 2: skip paused schedules
        paused_until = getattr(sched, "paused_until", None)
        if paused_until:
            try:
                paused_dt = datetime.fromisoformat(paused_until)
                if paused_dt.tzinfo is None:
                    paused_dt = paused_dt.replace(tzinfo=timezone.utc)
                if paused_dt > now:
                    logger.debug(f"Schedule {sched.id} paused until {paused_until}, skipping.")
                    continue
                else:
                    # Pause period expired; clear it
                    sched.paused_until = None
                    update_scheduled_scan(sched)
            except Exception:
                pass

        try:
            next_run_dt = datetime.fromisoformat(sched.next_run_at)
            if next_run_dt.tzinfo is None:
                next_run_dt = next_run_dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        if next_run_dt <= now:
            planned_at = sched.next_run_at

            # Atomic claim with unique constraint protection
            run = claim_scheduled_run(
                schedule_id=sched.id,
                tenant_id=sched.tenant_id or "default-tenant",
                planned_at=planned_at,
            )

            if not run:
                duplicate_blocked_count += 1
                logger.warning(
                    f"Duplicate execution blocked for schedule {sched.id} ({sched.target_url}) at {planned_at}"
                )
                log_audit_event(AuditEvent(
                    tenant_id=sched.tenant_id or "default-tenant",
                    actor_user_id="celery_beat",
                    actor_username="scheduler",
                    action="scheduled_run_duplicate_blocked",
                    resource_type="scheduled_scan",
                    resource_id=sched.id,
                    result="denied",
                    metadata={"planned_at": planned_at, "target": sched.target_url},
                ))
                continue

            # Update schedule's next run time immediately to advance window
            sched.last_run_at = now_iso
            sched.next_run_at = (now + timedelta(hours=sched.interval_hours)).isoformat()
            update_scheduled_scan(sched)

            # Ensure asset entity
            asset = ensure_asset(sched.target_url, sched.tenant_id or "default-tenant")

            # Create ScanResult and ScanJob
            scan = ScanResult(
                tenant_id=sched.tenant_id or "default-tenant",
                asset_id=asset.id,
                target_url=sched.target_url,
                scan_mode=sched.scan_mode or "passive",
                status=ScanStatus.PENDING,
                initiated_by=f"schedule:{sched.id}",
                notes="Automated audit dispatched by Celery Beat scheduler",
            )
            save_scan(scan)

            job = ScanJob(
                tenant_id=sched.tenant_id or "default-tenant",
                asset_id=asset.id,
                scan_id=scan.id,
                status=ScanJobStatus.QUEUED.value,
                requested_by=sched.created_by or "scheduler",
                profile=sched.scan_mode or "passive",
            )
            create_scan_job(job)

            # Link ScheduledRun to ScanJob
            update_scheduled_run_status(run.id, status="dispatched", scan_job_id=job.id)

            # Dispatch worker task
            from core.tasks.scan_tasks import run_scan_task
            task_result = run_scan_task.delay(job.id)
            job.task_id = task_result.id

            log_audit_event(AuditEvent(
                tenant_id=sched.tenant_id or "default-tenant",
                actor_user_id="celery_beat",
                actor_username="scheduler",
                action="scheduled_run_dispatched",
                resource_type="scheduled_scan",
                resource_id=sched.id,
                result="success",
                metadata={
                    "scan_id": scan.id,
                    "scan_job_id": job.id,
                    "target": sched.target_url,
                    "planned_at": planned_at,
                },
            ))

            # Sprint 3 Phase 2: reset failure counter on successful dispatch
            sched.consecutive_failures = 0
            sched.last_success_at = now_iso
            update_scheduled_scan(sched)

            dispatched_count += 1
            logger.info(f"Dispatched scheduled scan job {job.id} for target {sched.target_url}")

    return {
        "status": "success",
        "dispatched": dispatched_count,
        "duplicate_blocked": duplicate_blocked_count,
    }


def reconcile_orphaned_scheduled_runs(stale_threshold_seconds: int = 600, limit: int = 50) -> Dict[str, Any]:
    """
    S4-GAP-003: Reconcile orphaned ScheduledRun records left in 'dispatched' state
    without corresponding ScanJobs or whose workers/schedulers crashed.
    """
    from config import is_postgres_configured
    from core.repository import _safe_commit, get_scan_job, get_scan_job_by_scan_id

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=stale_threshold_seconds)).isoformat()

    if is_postgres_configured():
        from core.db.session import session_scope
        from sqlalchemy import text
        with session_scope() as session:
            rows = session.execute(text("""
                SELECT id, schedule_id, tenant_id, planned_at, status, scan_job_id, created_at
                FROM scheduled_runs
                WHERE status = 'dispatched' AND created_at <= :cutoff
                ORDER BY created_at ASC
                LIMIT :limit
            """), {"cutoff": cutoff, "limit": limit}).mappings().all()

            reconciled_count = 0
            failed_count = 0
            completed_count = 0

            for r in rows:
                run_id = r["id"]
                sched_id = r["schedule_id"]
                tenant_id = r["tenant_id"]
                scan_job_id = r["scan_job_id"]

                if not scan_job_id:
                    scan_row = session.execute(text("""
                        SELECT id FROM scans
                        WHERE tenant_id = :tenant_id AND initiated_by = :initiated_by
                        ORDER BY started_at DESC LIMIT 1
                    """), {"tenant_id": tenant_id, "initiated_by": f"schedule:{sched_id}"}).mappings().first()

                    linked = False
                    if scan_row:
                        job = get_scan_job_by_scan_id(scan_row["id"], tenant_id=tenant_id)
                        if job:
                            session.execute(text(
                                "UPDATE scheduled_runs SET scan_job_id = :job_id WHERE id = :run_id"
                            ), {"job_id": job.id, "run_id": run_id})
                            linked = True
                            reconciled_count += 1

                    if not linked:
                        session.execute(text(
                            "UPDATE scheduled_runs SET status = 'failed' WHERE id = :run_id"
                        ), {"run_id": run_id})
                        failed_count += 1
                        log_audit_event(AuditEvent(
                            tenant_id=tenant_id,
                            actor_user_id="celery_beat",
                            actor_username="maintenance",
                            action="scheduled_run_orphaned_reconciled",
                            resource_type="scheduled_run",
                            resource_id=run_id,
                            result="warning",
                            metadata={
                                "reason": "scheduler_crash_missing_job",
                                "schedule_id": sched_id,
                                "planned_at": r["planned_at"]
                            }
                        ))
                else:
                    job = get_scan_job(scan_job_id, tenant_id=tenant_id)
                    if not job:
                        session.execute(text("UPDATE scheduled_runs SET status = 'failed' WHERE id = :run_id"), {"run_id": run_id})
                        failed_count += 1
                    elif job.status == ScanJobStatus.COMPLETED.value:
                        session.execute(text("UPDATE scheduled_runs SET status = 'completed' WHERE id = :run_id"), {"run_id": run_id})
                        completed_count += 1
                    elif job.status == ScanJobStatus.FAILED.value:
                        session.execute(text("UPDATE scheduled_runs SET status = 'failed' WHERE id = :run_id"), {"run_id": run_id})
                        failed_count += 1

            return {
                "orphans_found": len(rows),
                "reconciled": reconciled_count,
                "failed": failed_count,
                "completed": completed_count,
            }

    from core.repository import _get_conn
    conn = _get_conn()

    orphaned_runs = conn.execute("""
        SELECT id, schedule_id, tenant_id, planned_at, status, scan_job_id, created_at
        FROM scheduled_runs
        WHERE status = 'dispatched' AND created_at <= ?
        ORDER BY created_at ASC
        LIMIT ?
    """, (cutoff, limit)).fetchall()

    reconciled_count = 0
    failed_count = 0
    completed_count = 0

    for r in orphaned_runs:
        run_id = r["id"]
        sched_id = r["schedule_id"]
        tenant_id = r["tenant_id"]
        scan_job_id = r["scan_job_id"]

        if not scan_job_id:
            # Scheduler crashed before ScanJob was created or linked
            scan_row = conn.execute("""
                SELECT id FROM scans
                WHERE tenant_id = ? AND initiated_by = ?
                ORDER BY started_at DESC LIMIT 1
            """, (tenant_id, f"schedule:{sched_id}")).fetchone()

            linked = False
            if scan_row:
                job = get_scan_job_by_scan_id(scan_row["id"], tenant_id=tenant_id)
                if job:
                    conn.execute(
                        "UPDATE scheduled_runs SET scan_job_id = ? WHERE id = ?",
                        (job.id, run_id)
                    )
                    linked = True
                    reconciled_count += 1

            if not linked:
                # No job exists. Mark run as failed to unblock schedule tracking
                conn.execute(
                    "UPDATE scheduled_runs SET status = 'failed' WHERE id = ?",
                    (run_id,)
                )
                failed_count += 1
                log_audit_event(AuditEvent(
                    tenant_id=tenant_id,
                    actor_user_id="celery_beat",
                    actor_username="maintenance",
                    action="scheduled_run_orphaned_reconciled",
                    resource_type="scheduled_run",
                    resource_id=run_id,
                    result="warning",
                    metadata={
                        "reason": "scheduler_crash_missing_job",
                        "schedule_id": sched_id,
                        "planned_at": r["planned_at"]
                    }
                ))
        else:
            # scan_job_id is present: verify status
            job = get_scan_job(scan_job_id, tenant_id=tenant_id)
            if not job:
                conn.execute("UPDATE scheduled_runs SET status = 'failed' WHERE id = ?", (run_id,))
                failed_count += 1
            elif job.status == ScanJobStatus.COMPLETED.value:
                conn.execute("UPDATE scheduled_runs SET status = 'completed' WHERE id = ?", (run_id,))
                completed_count += 1
            elif job.status == ScanJobStatus.FAILED.value:
                conn.execute("UPDATE scheduled_runs SET status = 'failed' WHERE id = ?", (run_id,))
                failed_count += 1

        _safe_commit(conn)

    return {
        "orphans_found": len(orphaned_runs),
        "reconciled": reconciled_count,
        "failed": failed_count,
        "completed": completed_count,
    }


@celery_app.task(
    name="core.tasks.maintenance_tasks.recover_stale_jobs_task",
    queue="maintenance",
)
def recover_stale_jobs_task(stale_threshold_seconds: int = 600) -> Dict[str, Any]:
    """
    Recovers scan jobs left in 'running' state whose workers died or crashed,
    and reconciles orphaned ScheduledRun records left in 'dispatched' state.
    """
    stale_jobs = find_stale_scan_jobs(stale_threshold_seconds=stale_threshold_seconds)
    recovered_count = 0
    failed_count = 0

    for job in stale_jobs:
        logger.warning(
            f"Found stale scan job {job.id} (scan {job.scan_id}) last heartbeat at {job.heartbeat_at}"
        )

        scan = get_scan(job.scan_id, tenant_id=job.tenant_id)

        if job.attempt < job.max_attempts:
            from core.repository import try_reclaim_stale_scan_job_for_retry
            reclaimed = try_reclaim_stale_scan_job_for_retry(
                job.id, stale_threshold_seconds=stale_threshold_seconds
            )
            if not reclaimed:
                logger.info(
                    "Stale job %s was not reclaimed (worker recovered or already requeued). Skipping.",
                    job.id,
                )
                continue
            from core.tasks.scan_tasks import run_scan_task
            run_scan_task.delay(reclaimed.id)
            recovered_count += 1

            log_audit_event(AuditEvent(
                tenant_id=reclaimed.tenant_id,
                actor_user_id="celery_beat",
                actor_username="maintenance",
                action="scan_job_retry",
                resource_type="scan_job",
                resource_id=reclaimed.id,
                result="warning",
                metadata={"reason": "stale_recovery", "attempt": reclaimed.attempt},
            ))
        else:
            # Max attempts exhausted, mark failed
            mark_scan_job_status(
                job.id,
                ScanJobStatus.FAILED.value,
                error_code="STALE_WORKER_HEARTBEAT_EXHAUSTED",
                error_message="Worker terminated unexpectedly and max retry attempts exhausted",
            )
            if scan:
                scan.status = ScanStatus.FAILED
                scan.notes = "Failed: Worker terminated unexpectedly"
                scan.completed_at = datetime.now(timezone.utc).isoformat()
                save_scan(scan)

            failed_count += 1
            log_audit_event(AuditEvent(
                tenant_id=job.tenant_id,
                actor_user_id="celery_beat",
                actor_username="maintenance",
                action="scan_job_failed",
                resource_type="scan_job",
                resource_id=job.id,
                result="failure",
                metadata={"reason": "stale_heartbeat_exhausted", "scan_id": job.scan_id},
            ))

    orphaned_scheduled_res = reconcile_orphaned_scheduled_runs(
        stale_threshold_seconds=stale_threshold_seconds
    )

    return {
        "status": "success",
        "stale_found": len(stale_jobs),
        "recovered": recovered_count,
        "exhausted": failed_count,
        "orphaned_scheduled_runs": orphaned_scheduled_res,
    }


@celery_app.task(
    name="core.tasks.maintenance_tasks.purge_expired_records_task",
    queue="maintenance",
)
def purge_expired_records_task(batch_size: int = 500) -> Dict[str, Any]:
    """
    Purges expired operational records (scan_jobs) in bounded batches.

    Audit log retention policy (SEC-005):
    - audit_events are treated as immutable compliance records and are NOT deleted by this task.
    - Audit log purging is a separate, operator-initiated action requiring explicit configuration
      of AUDIT_LOG_PURGE_ENABLED=true AND a separate AUDIT_LOG_PURGE_RETENTION_DAYS value.
    - Default: audit_events are never purged automatically.
    - This separation satisfies the immutable-audit-log contract documented in
      docs/SECURITY_OPERATIONS.md and ENTERPRISE_VALIDATION_REPORT.md.
    """
    from config import SCAN_JOB_RETENTION_DAYS
    from config import is_postgres_configured
    from core.repository import _safe_commit
    import os

    now = datetime.now(timezone.utc)
    job_cutoff = (now - timedelta(days=SCAN_JOB_RETENTION_DAYS)).isoformat()

    if is_postgres_configured():
        from core.db.session import session_scope
        from sqlalchemy import text
        total_jobs_purged = 0
        total_audit_purged = 0
        with session_scope() as session:
            res = session.execute(text(
                "DELETE FROM scan_jobs WHERE status IN ('completed', 'failed', 'cancelled') AND created_at < :cutoff"
            ), {"cutoff": job_cutoff})
            total_jobs_purged = res.rowcount or 0

            audit_purge_enabled = os.getenv("AUDIT_LOG_PURGE_ENABLED", "false").lower() in ("true", "1", "yes")
            audit_purge_days_str = os.getenv("AUDIT_LOG_PURGE_RETENTION_DAYS", "")
            if audit_purge_enabled and audit_purge_days_str:
                try:
                    audit_purge_days = int(audit_purge_days_str)
                except ValueError:
                    audit_purge_days = 0
                if audit_purge_days > 0:
                    audit_cutoff = (now - timedelta(days=audit_purge_days)).isoformat()
                    res_audit = session.execute(text(
                        "DELETE FROM audit_events WHERE created_at < :cutoff"
                    ), {"cutoff": audit_cutoff})
                    total_audit_purged = res_audit.rowcount or 0

        return {
            "status": "success",
            "jobs_purged": total_jobs_purged,
            "audit_purged": total_audit_purged,
        }

    from core.repository import _get_conn
    conn = _get_conn()
    total_jobs_purged = 0
    total_audit_purged = 0

    # Purge old completed/failed scan jobs in batches
    while True:
        rows = conn.execute(
            "SELECT id FROM scan_jobs WHERE status IN ('completed', 'failed', 'cancelled') AND created_at < ? LIMIT ?",
            (job_cutoff, batch_size)
        ).fetchall()
        if not rows:
            break
        ids = [r[0] for r in rows]
        placeholders = ",".join(["?"] * len(ids))
        conn.execute(f"DELETE FROM scan_jobs WHERE id IN ({placeholders})", ids)
        _safe_commit(conn)
        total_jobs_purged += len(ids)
        if len(ids) < batch_size:
            break

    # Audit log purge: opt-in only via explicit operator configuration.
    # Requires AUDIT_LOG_PURGE_ENABLED=true AND AUDIT_LOG_PURGE_RETENTION_DAYS to be set.
    audit_purge_enabled = os.getenv("AUDIT_LOG_PURGE_ENABLED", "false").lower() in ("true", "1", "yes")
    audit_purge_days_str = os.getenv("AUDIT_LOG_PURGE_RETENTION_DAYS", "")

    if audit_purge_enabled and audit_purge_days_str:
        try:
            audit_purge_days = int(audit_purge_days_str)
        except ValueError:
            logger.error(
                "AUDIT_LOG_PURGE_RETENTION_DAYS is set but not a valid integer — "
                "skipping audit purge to preserve integrity."
            )
            audit_purge_days = 0

        if audit_purge_days > 0:
            audit_cutoff = (now - timedelta(days=audit_purge_days)).isoformat()
            logger.warning(
                f"Audit log purge ENABLED by operator (AUDIT_LOG_PURGE_ENABLED=true, "
                f"AUDIT_LOG_PURGE_RETENTION_DAYS={audit_purge_days}). "
                f"Purging audit_events older than {audit_cutoff}."
            )
            while True:
                rows = conn.execute(
                    "SELECT id FROM audit_events WHERE created_at < ? LIMIT ?",
                    (audit_cutoff, batch_size)
                ).fetchall()
                if not rows:
                    break
                ids = [r[0] for r in rows]
                placeholders = ",".join(["?"] * len(ids))
                conn.execute(f"DELETE FROM audit_events WHERE id IN ({placeholders})", ids)
                _safe_commit(conn)
                total_audit_purged += len(ids)
                if len(ids) < batch_size:
                    break
    else:
        logger.debug(
            "Audit log purge skipped (AUDIT_LOG_PURGE_ENABLED not set or AUDIT_LOG_PURGE_RETENTION_DAYS missing). "
            "Audit events are preserved as immutable compliance records."
        )

    logger.info(f"Purge completed: {total_jobs_purged} scan jobs, {total_audit_purged} audit events")
    return {
        "status": "success",
        "jobs_purged": total_jobs_purged,
        "audit_purged": total_audit_purged,
        "audit_purge_enabled": audit_purge_enabled,
    }


@celery_app.task(
    name="core.tasks.maintenance_tasks.process_intel_reassessment_queue_task",
    queue="maintenance",
    bind=True,
    max_retries=3,
)
def process_intel_reassessment_queue_task(self) -> Dict[str, Any]:
    """
    S3-GAP-002: Process pending intelligence-triggered reassessment events.

    Reads pending outbox events of type 'intel_triggered_reassessment', atomically
    claims them by transitioning to 'PROCESSING', and for each:
      1. Validates the asset still exists and monitoring is enabled.
      2. Verifies scan authorization (active scans require a current authorization).
      3. Dispatches a scan job via the existing run_scan_task pathway.
      4. Marks the event DELIVERED or FAILED according to outcome.

    Idempotency:
      - Events are claimed with an UPDATE ... WHERE status='PENDING' guard.
      - Dispatched events are marked DELIVERED immediately; duplicates are
        blocked by the unique event_key constraint on integration_outbox.
      - Task retries on transient errors retry unclaimed events only.

    Concurrency safety:
      - The status guard on the UPDATE ensures competing Celery workers cannot
        double-claim the same event.
      - External scans are NEVER dispatched; only internal scan jobs are created.

    Intelligence reassessment DOES NOT launch an external scan automatically.
    It creates an authorized scan recommendation stored in the outbox. An
    authorized scan job is created only when the asset has active authorization
    and monitoring is enabled.
    """
    from datetime import datetime, timezone, timedelta
    from core.repository import (
        get_pending_outbox_events,
        update_outbox_status,
        get_asset,
        ensure_asset,
        save_scan,
        create_scan_job,
        update_scheduled_run_status,
        log_audit_event,
        _get_conn,
        _safe_commit,
    )
    from core.models import (
        ScanResult, ScanJob, ScanStatus, ScanJobStatus, AuditEvent, IntegrationOutbox
    )
    from core.authorization import verify_scan_authorization

    now = datetime.now(timezone.utc)
    processed = 0
    dispatched = 0
    skipped_no_auth = 0
    skipped_no_asset = 0
    failed = 0

    from config import is_postgres_configured
    if is_postgres_configured():
        from core.repository import claim_outbox_events
        import os
        import uuid
        worker_id = f"worker-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        claimed_events = claim_outbox_events(limit=20, worker_id=worker_id, event_type="intel_triggered_reassessment")
        if not claimed_events:
            return {"status": "success", "processed": 0, "dispatched": 0}

    # Atomically claim PENDING events by setting them to PROCESSING
    # The UPDATE WHERE status=PENDING acts as optimistic lock for concurrent workers
    conn = _get_conn()
    pending_events = conn.execute("""
        SELECT id FROM integration_outbox
        WHERE event_type = 'intel_triggered_reassessment' AND status = 'PENDING'
        ORDER BY created_at ASC LIMIT 20
    """).fetchall()

    import os
    import uuid
    worker_id = f"worker-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    now_iso = now.isoformat()

    claimed_ids = []
    for row in pending_events:
        # Attempt atomic claim: only succeeds if still PENDING
        result = conn.execute("""
            UPDATE integration_outbox
            SET status = 'PROCESSING', claimed_at = ?, claimed_by = ?
            WHERE id = ? AND status = 'PENDING'
        """, (now_iso, worker_id, row["id"]))
        _safe_commit(conn)
        if result.rowcount == 1:
            claimed_ids.append(row["id"])

    if not claimed_ids:
        return {"status": "success", "processed": 0, "dispatched": 0}

    # Load full event objects for claimed IDs
    from core.repository import get_pending_outbox_events
    import json
    rows = conn.execute(
        f"SELECT * FROM integration_outbox WHERE id IN ({','.join('?' * len(claimed_ids))})",
        claimed_ids
    ).fetchall()

    events = [
        IntegrationOutbox(
            id=r["id"], tenant_id=r["tenant_id"], event_type=r["event_type"],
            event_key=r["event_key"], destination=r["destination"],
            payload_hash=r["payload_hash"],
            payload_json=json.loads(r["payload_json"] or "{}"),
            status=r["status"], attempt=r["attempt"],
            next_retry_at=r["next_retry_at"], last_error=r["last_error"],
            claimed_at=r["claimed_at"] if "claimed_at" in r.keys() else None,
            claimed_by=r["claimed_by"] if "claimed_by" in r.keys() else None,
            created_at=r["created_at"],
        )
        for r in rows
    ]

    for event in events:
        processed += 1
        payload = event.payload_json or {}
        asset_id = payload.get("asset_id")
        tenant_id = event.tenant_id
        target_url = payload.get("asset_url", "")

        try:
            # 1. Validate asset exists and monitoring is enabled
            asset = None
            if asset_id:
                asset = get_asset(asset_id, tenant_id=tenant_id)
            if not asset:
                logger.warning(
                    "Intel reassessment event %s: asset %s not found, marking failed.",
                    event.id[:8], asset_id
                )
                update_outbox_status(event.id, "FAILED", "Asset not found")
                skipped_no_asset += 1
                continue

            monitoring_enabled = getattr(asset, "monitoring_enabled", False)
            monitoring_paused = getattr(asset, "monitoring_paused_at", None)
            if not monitoring_enabled or monitoring_paused:
                logger.info(
                    "Intel reassessment event %s: asset %s monitoring disabled/paused, skipping.",
                    event.id[:8], asset_id[:8]
                )
                update_outbox_status(event.id, "SKIPPED", "Monitoring disabled or paused")
                skipped_no_auth += 1
                continue

            # 2. Verify scan authorization (safe-active requires active authorization)
            scan_mode = "safe-active"
            is_auth, auth_err, _ = verify_scan_authorization(tenant_id, target_url, scan_mode)
            if not is_auth:
                logger.info(
                    "Intel reassessment event %s: no active authorization for %s (%s).",
                    event.id[:8], target_url, auth_err
                )
                update_outbox_status(
                    event.id, "SKIPPED",
                    f"No active scan authorization: {auth_err}"
                )
                skipped_no_auth += 1
                continue

            # 3. Create scan job (no external HTTP requests here; task worker handles them)
            scan = ScanResult(
                tenant_id=tenant_id,
                asset_id=asset_id,
                target_url=target_url or asset.canonical_url,
                scan_mode=scan_mode,
                status=ScanStatus.PENDING,
                initiated_by=f"intel_reassessment:{event.id[:8]}",
                notes=(
                    f"Intel-triggered reassessment: vuln={payload.get('vuln_id', '?')} "
                    f"slug={payload.get('slug', '?')} "
                    f"cve={payload.get('cve_id', '?')}"
                ),
            )
            save_scan(scan)

            job = ScanJob(
                tenant_id=tenant_id,
                asset_id=asset_id,
                scan_id=scan.id,
                status=ScanJobStatus.QUEUED.value,
                requested_by=f"intel_reassessment:{event.event_key[:24] if event.event_key else '?'}",
                profile=scan_mode,
            )
            create_scan_job(job)

            # 4. Dispatch the scan worker task
            from core.tasks.scan_tasks import run_scan_task
            task_result = run_scan_task.delay(job.id)
            job.task_id = task_result.id

            # 5. Mark event delivered
            update_outbox_status(event.id, "DELIVERED")
            dispatched += 1

            log_audit_event(AuditEvent(
                tenant_id=tenant_id,
                actor_user_id="intel_monitor",
                actor_username="celery_intel_queue",
                action="intel_reassessment_scan_dispatched",
                resource_type="scan_job",
                resource_id=job.id,
                result="success",
                metadata={
                    "event_id": event.id,
                    "asset_id": asset_id,
                    "scan_id": scan.id,
                    "vuln_id": payload.get("vuln_id"),
                    "slug": payload.get("slug"),
                },
            ))

            logger.info(
                "Intel reassessment: dispatched scan job %s for asset %s (event %s)",
                job.id[:8], asset_id[:8], event.id[:8]
            )

        except Exception as exc:
            failed += 1
            err_str = str(exc)[:300]
            logger.exception(
                "Intel reassessment event %s failed: %s", event.id[:8], err_str
            )
            try:
                # Bounded retry: max 3 attempts, exponential backoff
                next_attempt = (event.attempt or 1) + 1
                if next_attempt <= 3:
                    backoff_seconds = min(60 * (2 ** (next_attempt - 1)), 300)
                    retry_at = (now + timedelta(seconds=backoff_seconds)).isoformat()
                    conn.execute(
                        """UPDATE integration_outbox
                           SET status='PENDING', attempt=?, next_retry_at=?, last_error=?,
                               claimed_at=NULL, claimed_by=NULL
                           WHERE id=?""",
                        (next_attempt, retry_at, err_str, event.id)
                    )
                else:
                    conn.execute(
                        """UPDATE integration_outbox
                           SET status='DEAD_LETTER', last_error=?,
                               claimed_at=NULL, claimed_by=NULL
                           WHERE id=?""",
                        (err_str, event.id)
                    )
                _safe_commit(conn)
            except Exception:
                pass

    return {
        "status": "success",
        "processed": processed,
        "dispatched": dispatched,
        "skipped_no_auth": skipped_no_auth,
        "skipped_no_asset": skipped_no_asset,
        "failed": failed,
    }


@celery_app.task(
    name="core.tasks.maintenance_tasks.recover_stale_outbox_events_task",
    queue="maintenance",
    bind=True,
    max_retries=3,
)
def recover_stale_outbox_events_task(
    self,
    stale_threshold_seconds: int = 600,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    S4-GAP-001: Recover intelligence reassessment outbox events stranded in
    'PROCESSING' state after Celery worker crashes or abrupt terminations.

    Requirements:
      1. Detects stale PROCESSING events exceeding stale_threshold_seconds based
         on claimed_at (falling back to created_at if claimed_at is NULL).
      2. Atomically claims recovery lease to prevent races between concurrent reapers.
      3. Idempotency guard: verifies if a ScanJob or ScanResult was already created
         prior to worker crash before redispatching. If found in queued/running/completed,
         marks event DELIVERED without duplicating external scans.
      4. Bounded retry backoff: re-queues to PENDING up to max_retries (3),
         transitioning to DEAD_LETTER upon exhaustion.
      5. Emits structured audit events for observability and metrics.
    """
    import os
    import json
    import uuid
    from datetime import datetime, timezone, timedelta
    from config import is_postgres_configured
    if is_postgres_configured():
        from core.repository import recover_stale_outbox_events
        recovered = recover_stale_outbox_events(timeout_seconds=stale_threshold_seconds)
        return {
            "status": "success",
            "stale_events_found": recovered,
            "reclaimed_for_retry": recovered,
            "routed_to_dead_letter": 0,
            "reconciled_existing_job": 0,
        }

    from core.repository import (
        _get_conn, _safe_commit, log_audit_event, update_outbox_status
    )
    from core.models import AuditEvent

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=stale_threshold_seconds)).isoformat()
    conn = _get_conn()

    stale_rows = conn.execute("""
        SELECT id, tenant_id, event_type, event_key, destination, payload_hash,
               payload_json, status, attempt, next_retry_at, last_error,
               claimed_at, claimed_by, created_at
        FROM integration_outbox
        WHERE event_type = 'intel_triggered_reassessment'
          AND status = 'PROCESSING'
          AND (
              (claimed_at IS NOT NULL AND claimed_at <= ?)
              OR (claimed_at IS NULL AND created_at <= ?)
          )
        ORDER BY created_at ASC
        LIMIT ?
    """, (cutoff, cutoff, limit)).fetchall()

    reaper_id = f"reaper-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    recovered_count = 0
    reconciled_existing_count = 0
    dead_letter_count = 0

    for r in stale_rows:
        event_id = r["id"]
        tenant_id = r["tenant_id"]
        event_key = r["event_key"]
        orig_claimed_at = r["claimed_at"]
        orig_claimed_by = r["claimed_by"]

        # 1. Atomic lease claim for recovery worker
        if orig_claimed_at is not None:
            res = conn.execute("""
                UPDATE integration_outbox
                SET claimed_by = ?
                WHERE id = ? AND status = 'PROCESSING' AND claimed_at = ?
            """, (reaper_id, event_id, orig_claimed_at))
        else:
            res = conn.execute("""
                UPDATE integration_outbox
                SET claimed_by = ?
                WHERE id = ? AND status = 'PROCESSING' AND claimed_at IS NULL
            """, (reaper_id, event_id))
        _safe_commit(conn)

        if res.rowcount != 1:
            # Another reaper claimed or state changed
            continue

        # 2. Idempotency Check: Did worker already create ScanJob/ScanResult before crash?
        existing_job = conn.execute("""
            SELECT id, status FROM scan_jobs
            WHERE tenant_id = ? AND requested_by = ?
            ORDER BY queued_at DESC LIMIT 1
        """, (tenant_id, f"intel_reassessment:{event_key[:24] if event_key else '?'}")).fetchone()

        existing_scan = conn.execute("""
            SELECT id, status FROM scans
            WHERE tenant_id = ? AND initiated_by = ?
            ORDER BY started_at DESC LIMIT 1
        """, (tenant_id, f"intel_reassessment:{event_id[:8]}")).fetchone()

        if existing_job or existing_scan:
            job_status = existing_job["status"] if existing_job else (existing_scan["status"] if existing_scan else "")
            if str(job_status).lower() in ("queued", "running", "completed"):
                # Job exists and is active or finished — resolve outbox without duplicate dispatch
                conn.execute("""
                    UPDATE integration_outbox
                    SET status = 'DELIVERED',
                        claimed_at = NULL,
                        claimed_by = NULL,
                        last_error = 'Reconciled: scan job was already created before worker termination'
                    WHERE id = ?
                """, (event_id,))
                _safe_commit(conn)

                log_audit_event(AuditEvent(
                    tenant_id=tenant_id,
                    actor_user_id="celery_beat",
                    actor_username="reaper",
                    action="outbox_event_reconciled",
                    resource_type="integration_outbox",
                    resource_id=event_id,
                    result="success",
                    metadata={
                        "event_key": event_key,
                        "scan_job_id": existing_job["id"] if existing_job else None,
                        "scan_id": existing_scan["id"] if existing_scan else None,
                        "job_status": str(job_status),
                    }
                ))
                reconciled_existing_count += 1
                logger.info("Reconciled outbox event %s: pre-existing scan job found in state %s",
                            event_id[:8], job_status)
                continue

        # 3. No active job found: crash occurred prior to scan dispatch. Check retry budget.
        current_attempt = r["attempt"] or 1
        if current_attempt < 3:
            next_attempt = current_attempt + 1
            backoff_seconds = min(60 * (2 ** (next_attempt - 1)), 300)
            retry_at = (now + timedelta(seconds=backoff_seconds)).isoformat()

            conn.execute("""
                UPDATE integration_outbox
                SET status = 'PENDING',
                    attempt = ?,
                    next_retry_at = ?,
                    claimed_at = NULL,
                    claimed_by = NULL,
                    last_error = 'Worker timeout during PROCESSING; reclaimed for retry'
                WHERE id = ?
            """, (next_attempt, retry_at, event_id))
            _safe_commit(conn)

            log_audit_event(AuditEvent(
                tenant_id=tenant_id,
                actor_user_id="celery_beat",
                actor_username="reaper",
                action="outbox_event_recovered",
                resource_type="integration_outbox",
                resource_id=event_id,
                result="warning",
                metadata={
                    "previous_attempt": current_attempt,
                    "next_attempt": next_attempt,
                    "retry_at": retry_at,
                    "orig_claimed_at": orig_claimed_at,
                    "orig_claimed_by": orig_claimed_by,
                }
            ))
            recovered_count += 1
            logger.warning("Reclaimed stale outbox event %s for retry (attempt %d/%d at %s)",
                           event_id[:8], next_attempt, 3, retry_at)
        else:
            # Retries exhausted -> DEAD_LETTER
            conn.execute("""
                UPDATE integration_outbox
                SET status = 'DEAD_LETTER',
                    claimed_at = NULL,
                    claimed_by = NULL,
                    last_error = 'Max retries exhausted after worker timeout during PROCESSING'
                WHERE id = ?
            """, (event_id,))
            _safe_commit(conn)

            log_audit_event(AuditEvent(
                tenant_id=tenant_id,
                actor_user_id="celery_beat",
                actor_username="reaper",
                action="outbox_event_dead_letter",
                resource_type="integration_outbox",
                resource_id=event_id,
                result="failure",
                metadata={
                    "exhausted_attempts": current_attempt,
                    "reason": "worker_crash_stale_processing",
                }
            ))
            dead_letter_count += 1
            logger.error("Stale outbox event %s exceeded max retries (%d); transitioned to DEAD_LETTER",
                         event_id[:8], current_attempt)

    return {
        "status": "success",
        "stale_found": len(stale_rows),
        "recovered": recovered_count,
        "reconciled_existing": reconciled_existing_count,
        "dead_letter": dead_letter_count,
    }
