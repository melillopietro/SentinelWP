"""
Celery Application and Celery Beat Schedule Configuration for SentinelWP.
Configured with dedicated queues: 'scan', 'intel', 'maintenance'.
"""
import os
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_init, beat_init

from config import (
    CELERY_BROKER_URL,
    CELERY_RESULT_BACKEND,
    SCAN_SOFT_TIME_LIMIT,
    SCAN_HARD_TIME_LIMIT,
    VULN_INTEL_SYNC_INTERVAL_MINUTES,
    is_postgres_configured,
)
from core.db.session import verify_operational_persistence_guard

celery_app = Celery(
    "sentinelwp",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=[
        "core.tasks.scan_tasks",
        "core.tasks.intel_tasks",
        "core.tasks.maintenance_tasks",
        "core.tasks.remediation_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=SCAN_SOFT_TIME_LIMIT,
    task_time_limit=SCAN_HARD_TIME_LIMIT,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_routes={
        "core.tasks.scan_tasks.*": {"queue": "scan"},
        "core.tasks.intel_tasks.*": {"queue": "intel"},
        "core.tasks.maintenance_tasks.*": {"queue": "maintenance"},
        "core.tasks.remediation_tasks.*": {"queue": "maintenance"},
        "core.tasks.evaluate_sla_breaches": {"queue": "maintenance"},
        "core.tasks.expire_risk_acceptances": {"queue": "maintenance"},
        "core.tasks.deliver_webhook": {"queue": "maintenance"},
        "core.tasks.sync_ticket_status": {"queue": "maintenance"},
        "core.tasks.generate_daily_risk_snapshot": {"queue": "maintenance"},
        "core.tasks.maintenance_tasks.purge_expired_records_task": {"queue": "maintenance"},
    },
    beat_schedule={
        "dispatch-scheduled-scans-every-minute": {
            "task": "core.tasks.maintenance_tasks.dispatch_scheduled_scans_task",
            "schedule": 60.0,
            "options": {"queue": "maintenance"},
        },
        "recover-stale-jobs-every-2-minutes": {
            "task": "core.tasks.maintenance_tasks.recover_stale_jobs_task",
            "schedule": 120.0,
            "options": {"queue": "maintenance"},
        },
        "sync-vulnerability-intelligence-periodic": {
            "task": "core.tasks.intel_tasks.sync_vulnerability_intelligence_task",
            "schedule": float(VULN_INTEL_SYNC_INTERVAL_MINUTES * 60),
            "options": {"queue": "intel"},
        },
        "evaluate-sla-breaches-every-5-minutes": {
            "task": "core.tasks.evaluate_sla_breaches",
            "schedule": 300.0,
            "options": {"queue": "maintenance"},
        },
        "expire-risk-acceptances-every-10-minutes": {
            "task": "core.tasks.expire_risk_acceptances",
            "schedule": 600.0,
            "options": {"queue": "maintenance"},
        },
        "generate-daily-risk-snapshot-every-hour": {
            "task": "core.tasks.generate_daily_risk_snapshot",
            "schedule": 3600.0,
            "options": {"queue": "maintenance"},
        },
        "purge-expired-records-daily": {
            "task": "core.tasks.maintenance_tasks.purge_expired_records_task",
            "schedule": 86400.0,
            "options": {"queue": "maintenance"},
        },
        # S3-GAP-002: Process intelligence reassessment queue every 5 minutes.
        # Picks up intel_triggered_reassessment outbox events and dispatches
        # authorized scan jobs. Events without active authorization are skipped.
        "process-intel-reassessment-queue-every-5-minutes": {
            "task": "core.tasks.maintenance_tasks.process_intel_reassessment_queue_task",
            "schedule": 300.0,
            "options": {"queue": "maintenance"},
        },
        # S4-GAP-001: Recover intelligence reassessment outbox events stranded
        # in PROCESSING state after worker crashes every 5 minutes.
        "recover-stale-outbox-events-every-5-minutes": {
            "task": "core.tasks.maintenance_tasks.recover_stale_outbox_events_task",
            "schedule": 300.0,
            "options": {"queue": "maintenance"},
        },
    },
)

@worker_init.connect
def on_worker_init(**kwargs):
    """Fail-closed startup connectivity guard for Celery workers."""
    if is_postgres_configured():
        verify_operational_persistence_guard()


@beat_init.connect
def on_beat_init(**kwargs):
    """Fail-closed startup connectivity guard for Celery Beat."""
    if is_postgres_configured():
        verify_operational_persistence_guard()


if __name__ == "__main__":
    celery_app.start()
