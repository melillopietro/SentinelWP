# Sprint 4 — Workflow Integration

## Architecture Diagram (Post Sprint 4)

```
Celery Beat (every 60s)
  └── dispatch_scheduled_scans_task()
        └── run_scan_task.delay(job_id)

Celery Beat (every 300s)
  └── process_intel_reassessment_queue_task()   ← NEW (S3-GAP-002)
        ├── SELECT/claim PENDING outbox events
        ├── verify monitoring enabled + authorized
        └── run_scan_task.delay(job_id)         ← only if authorized

run_scan_task(job_id)
  ├── Authorization re-validation
  ├── Concurrency limit checks
  ├── ScanOrchestrator.run()
  ├── save_scan() → status=COMPLETED
  ├── update_asset() (posture: wp_version, risk_score, last_scan_*)
  ├── process_scan_findings() (fingerprint, dedup, lifecycle)
  └── _trigger_post_scan_differential()         ← NEW (S3-GAP-004)
        ├── list_scans(asset, status=COMPLETED)
        ├── compute_scan_differential(baseline, new)
        └── (log result; failures isolated)

Intel Sync (every 30 min)
  └── sync_all()
        ├── _sync_wordfence_inner()
        ├── _sync_kev_inner()
        ├── _sync_plugin_metadata_inner()
        ├── _enrich_with_nvd_inner()
        └── check_intel_triggered_reassessment()  (failure-isolated)
              └── save_outbox_event(intel_triggered_reassessment)
                    └── consumed by process_intel_reassessment_queue_task
```

---

## Workflow 1: Scheduled Scan → Differential

```
Beat fires every 60s
  → dispatch_scheduled_scans_task()
     → claim_scheduled_run() [unique constraint: schedule_id + planned_at]
     → create ScanResult (PENDING) + ScanJob (QUEUED)
     → run_scan_task.delay(job_id)

Worker picks up run_scan_task(job_id)
  → re-validate authorization
  → ScanOrchestrator.run() [SSRF protected; passive/safe-active/full]
  → save_scan(status=COMPLETED)
  → update_asset() [wp_version, risk_score, last_scan_status=completed]
  → process_scan_findings() [fingerprint, dedup, lifecycle]
  → _trigger_post_scan_differential()
     → list_scans(asset_id, status=completed, limit=5)
     → filter out current scan
     → compute_scan_differential(baseline=prior[0], new=current)
        → ScanDifferential {NEW, PERSISTING, RESOLVED, REOPENED}
        → RESOLVED only if new scan status == COMPLETED (safety invariant)
     → log differential counts
```

**Key invariants:**
- Duplicate scheduled runs blocked by `UNIQUE(schedule_id, planned_at)` on `scheduled_runs` table.
- Differential never corrupts scan completion data (full try/except isolation).
- Failed scans never produce RESOLVED differential changes.

---

## Workflow 2: Intelligence Update → Reassessment

```
sync_all() runs (every 30 min or manual trigger)
  └── check_intel_triggered_reassessment()
       ├── list_assets(monitoring_enabled=True)
       ├── list_technology_observations(asset_id)
       ├── match_scan_findings(wp_version, plugins)
       └── for each match:
             event_key = "intel_match:{tenant}:{asset}:{vuln}:{slug}"
             if not already_staged:
               save_outbox_event(type=intel_triggered_reassessment, status=PENDING)

Beat fires process_intel_reassessment_queue_task() every 300s
  └── SELECT id WHERE type=intel_triggered_reassessment AND status=PENDING LIMIT 20
       for each candidate:
         UPDATE SET status=PROCESSING WHERE id=? AND status=PENDING  [atomic claim]
         if rowcount == 0: skip (claimed by another worker)

         load full event payload
         get_asset(asset_id) → must exist and monitoring_enabled=True
         verify_scan_authorization(tenant, url, safe-active) → must be active
         create ScanResult(PENDING) + ScanJob(QUEUED)
         run_scan_task.delay(job_id)
         update_outbox_status(DELIVERED)

         on exception:
           attempt < 3 → status=PENDING, attempt++, next_retry_at=now+backoff
           attempt >= 4 → status=DEAD_LETTER
```

**Idempotency guarantees:**
- Outbox `event_key` has a UNIQUE constraint — duplicate events from repeated syncs are silently swallowed.
- Status guard `WHERE status=PENDING` ensures only one worker processes each event.
- `DEAD_LETTER` events require manual inspection (operator action).

---

## Workflow 3: Pause / Resume

```
Admin/Analyst sends:
  POST /api/v1/schedules/<id>/pause  {"hours": 48}
    → get_scheduled_scan(id, tenant_id)  [object-level auth]
    → sched.paused_until = now + 48h
    → update_scheduled_scan(sched)
    → log_audit_event(schedule_paused)

Beat fires dispatch_scheduled_scans_task()
    → for sched in list_scheduled_scans():
         if paused_until and paused_until > now: continue  [skip]
         elif paused_until <= now: clear it, proceed  [auto-expire]

Admin sends:
  POST /api/v1/schedules/<id>/resume
    → sched.paused_until = None
    → update_scheduled_scan(sched)
    → log_audit_event(schedule_resumed)
    [Next Beat cycle will dispatch normally]
```

---

## Transaction Boundaries

| Operation | Atomicity Guarantee |
|-----------|-------------------|
| Scheduled run claim | `UNIQUE(schedule_id, planned_at)` constraint + `INSERT OR IGNORE` |
| Outbox event claim | `UPDATE WHERE status=PENDING` rowcount check |
| Outbox deduplication | `UNIQUE(event_key)` constraint on `integration_outbox` |
| Scan finding dedup | `fingerprint` + `scan_id` composite; `observation_count` increment |
| Asset posture update | Single `UPDATE assets` call; no cross-table transaction needed |
| Differential computation | Read-only; no DB writes; failures cannot corrupt data |

---

## Restart Recovery

| Failure Scenario | Recovery Mechanism |
|-----------------|-------------------|
| Worker crashes mid-scan | `recover_stale_jobs_task()` re-queues after 600s heartbeat timeout |
| Beat crashes after scheduling | Duplicate blocked by `UNIQUE(schedule_id, planned_at)` on resume |
| Worker crashes after PROCESSING claim | Event stays in PROCESSING — no automatic re-queue; will not be picked up again until the `PROCESSING` state is manually cleared or a cleanup job is added (see Sprint 5 gap) |
| Worker crashes after DELIVERED | Scan job was already queued; no duplicate dispatch |
| NVD backfill interrupted | Resume by re-running with `offset=previous_next_offset` |

**Note:** `PROCESSING` state stranded events are a Sprint 5 gap (see SPRINT_4_REMAINING_GAPS.md).
