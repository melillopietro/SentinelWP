"""
Background Scheduler Daemon for Scheduled Scans.
Runs periodically to check if any scheduled scans are due.
"""
import time
import threading
from datetime import datetime, timedelta, timezone
from core import repository
from scanners.async_runner import start_async_scan

_scheduler_thread: threading.Thread = None
_running = False


def _scheduler_loop():
    """Background thread loop that checks for due scheduled scans every 60 seconds."""
    global _running
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
                    except Exception:
                        due = True

                if due:
                    # Update timestamps
                    sched.last_run_at = now.isoformat()
                    sched.next_run_at = (now + timedelta(hours=sched.interval_hours)).isoformat()
                    repository.save_scheduled_scan(sched)

                    # Trigger background scan
                    try:
                        start_async_scan(
                            target_url=sched.target_url,
                            initiated_by=f"Scheduler ({sched.created_by})",
                            scan_mode=sched.scan_mode
                        )
                    except Exception:
                        pass
        except Exception:
            pass

        # Vulnerability Intelligence sync check
        try:
            from config import VULN_INTEL_ENABLED
            if VULN_INTEL_ENABLED:
                from core.vulnerability_intelligence.service import should_sync, sync_all
                if should_sync():
                    sync_all()
        except Exception:
            pass

        time.sleep(60)


def start_scheduler():
    """Start the background scheduler daemon."""
    global _scheduler_thread, _running
    if not _running:
        _running = True
        _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
        _scheduler_thread.start()
