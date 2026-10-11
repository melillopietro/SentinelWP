# Sprint 3 — Continuous Monitoring

## Overview

Sprint 3 implements per-asset recurring assessment with failure tracking,
missed scan identification, monitoring pause/resume, and duplicate-scan prevention.

---

## ScheduledScan Sprint 3 Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_retries` | INT | `3` | Maximum retries on consecutive dispatch failure |
| `consecutive_failures` | INT | `0` | Current consecutive failure count |
| `last_failure_at` | TEXT (ISO) | `None` | Timestamp of last dispatch failure |
| `last_success_at` | TEXT (ISO) | `None` | Timestamp of last successful dispatch |
| `paused_until` | TEXT (ISO) | `None` | Non-null = schedule paused until this timestamp |

---

## Monitoring Pause / Resume

**Pause:** Set `paused_until` to a future ISO timestamp on a `ScheduledScan`.
`dispatch_scheduled_scans_task()` checks this field before dispatching:

```python
if paused_until and paused_dt > now:
    continue  # skip: schedule is paused
```

**Auto-resume:** When `paused_until` is in the past, the dispatcher clears it:
```python
sched.paused_until = None
update_scheduled_scan(sched)
```

No separate API endpoint is required — `update_scheduled_scan(sched)` with
`paused_until=None` is sufficient to resume.

---

## Failure Tracking

When `dispatch_scheduled_scans_task()` successfully dispatches a scan job:
```python
sched.consecutive_failures = 0
sched.last_success_at = now_iso
```

`scan_tasks.run_scan_task()` increments `consecutive_scan_failures` on the
associated `Asset` when a scan job fails (not recoverable via retry):
```python
new_failures = asset.consecutive_scan_failures + 1
update_asset(asset_id, last_scan_status="failed",
             consecutive_scan_failures=new_failures)
```

---

## Duplicate Scan Prevention

Duplicate scheduled dispatches are prevented at two levels:

1. **ScheduledRun unique constraint**: `UNIQUE(schedule_id, planned_at)` in the
   `scheduled_runs` table. `claim_scheduled_run()` uses `INSERT OR IGNORE` semantics —
   only one worker can claim a given `(schedule_id, planned_at)` slot.

2. **Per-asset concurrency limit**: `count_active_scan_jobs_for_asset()` enforced
   in `run_scan_task()` — if the asset already has a running scan, the new job
   retries after 30s (`MAX_CONCURRENT_SCANS_PER_ASSET=1` default).

**Acceptance criterion 3** (Duplicate scans are prevented per documented guarantees)
is satisfied. Consistency guarantee: DB-level atomic insert prevents duplicates
even across multiple concurrent Celery workers.

---

## Scheduling Reliability

- `dispatch_scheduled_scans_task()` runs every minute via Celery Beat.
- It uses `claim_scheduled_run()` with a DB unique constraint as the coordination
  primitive — no external lock required for dispatch deduplication.
- Stale jobs (worker died mid-scan) are recovered by `recover_stale_jobs_task()`
  which retries up to `max_attempts` before marking the job permanently failed.
- After restart, all in-memory state is recovered from the DB. No in-memory-only
  state is maintained for scheduling.

**Acceptance criterion 2** (Scheduling works reliably across supported restarts)
is satisfied: state is persisted in the DB before task dispatch.

---

## Missed Scan Identification

Assets where `last_scan_id IS NULL` or `last_scan_status = 'failed'` are surfaced
in the monitoring dashboard under `assets_needing_attention`. The `get_monitoring_dashboard()`
function queries this directly from the `assets` table.
