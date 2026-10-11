"""
Background Scheduler Daemon for Scheduled Scans.
Runs periodically to check if any scheduled scans are due.
Hardened with structured logging and resilient error recovery.
"""
import time
import logging
import threading
from datetime import datetime, timedelta, timezone
from core import repository
from scanners.async_runner import start_async_scan

logger = logging.getLogger("sentinelwp.scheduler")

_scheduler_thread: threading.Thread = None
_running = False


def _scheduler_loop():
    """Background thread loop that checks for due scheduled scans every 60 seconds."""
    logger.info("Background scan scheduler daemon started.")
    while _running:
        try:
            scheduled = repository.list_scheduled_scans()
            now = datetime.now(timezone.utc)

            for sched in scheduled:
                if not sched.enabled:
                    continue

                # Check if scan is due
                due = False
                if not sched.last_run_at:
                    due = True
                else:
                    try:
                        last_dt = datetime.fromisoformat(sched.last_run_at)
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=timezone.utc)
                        if now >= last_dt + timedelta(hours=sched.interval_hours):
                            due = True
                    except (ValueError, TypeError) as e:
                        logger.warning("Invalid last_run_at format for schedule ID %s (%s): %s", sched.id, sched.target_url, e)
                        due = True

                if due:
                    # Update timestamps
                    sched.last_run_at = now.isoformat()
                    sched.next_run_at = (now + timedelta(hours=sched.interval_hours)).isoformat()
                    repository.save_scheduled_scan(sched)

                    # Trigger background scan
                    try:
                        logger.info("Scheduler triggering scan for %s (mode=%s)", sched.target_url, sched.scan_mode)
                        start_async_scan(
                            target_url=sched.target_url,
                            initiated_by=f"Scheduler ({sched.created_by})",
                            scan_mode=sched.scan_mode,
                            tenant_id=sched.tenant_id or "default-tenant",
                            asset_id=sched.asset_id
                        )
                    except Exception as e:
                        logger.error("Failed to start scheduled scan for %s: %s", sched.target_url, e)
        except Exception as e:
            logger.error("Unexpected error in scheduler loop: %s", e)

        # Vulnerability Intelligence sync check
        try:
            from config import VULN_INTEL_ENABLED
            if VULN_INTEL_ENABLED:
                from core.vulnerability_intelligence.service import should_sync, sync_all
                if should_sync():
                    logger.info("Scheduler triggering automated Vulnerability Intelligence synchronization.")
                    sync_all()
        except Exception as e:
            logger.warning("Error during automated Threat Intel sync check: %s", e)

        time.sleep(60)


def start_scheduler():
    """Start the background scheduler daemon."""
    global _scheduler_thread, _running
    if not _running:
        _running = True
        _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
        _scheduler_thread.start()


def stop_scheduler():
    """Stop the background scheduler daemon."""
    global _running
    _running = False

