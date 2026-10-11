# Sprint 4 — Distributed Reliability

## Overview

This document covers the distributed reliability properties implemented in Sprint 4,
including the distributed synchronization lock, outbox-based concurrency, and
restart recovery behaviors.

---

## Distributed Synchronization Lock (INTEL-OPEN-001, S3-GAP-001)

### Architecture

```
_sync_lock = _DistributedSyncLock()   # Module-level singleton

_DistributedSyncLock.acquire(blocking=False):
  if Redis reachable:
    redis.set(lock_name, uuid4_token, nx=True, ex=300)  # atomic SET NX EX
    if acquired: store token in self._token; return True
    if not acquired: return False
  else:
    if REQUIRE_DISTRIBUTED_LOCK=true: raise RuntimeError (fail-closed)
    return _process_lock.acquire(blocking=False)  # thread-local fallback

_DistributedSyncLock.release():
  if Redis reachable:
    eval(lua_script, key, self._token)  # atomic ownership-checked delete
  else:
    _process_lock.release()
```

### Properties

| Property | Implementation | Guarantee |
|----------|----------------|-----------|
| Atomic acquisition | `SET NX EX` (single Redis command) | Exactly one acquirer across all workers |
| Unique ownership token | `uuid4()` stored as lock value | Only the acquiring worker can release |
| Bounded lease | `EX 300` (300s TTL) | Lock auto-expires if worker crashes mid-sync |
| Ownership-checked release | Lua script: `GET` then `DEL` if matches token | Expired lock not released by different worker |
| Failure recovery | TTL expires automatically | Next sync cycle can proceed after ≤300s |
| Fallback safety | Thread lock when Redis unavailable (not required mode) | Process-local exclusion only |

### Consistency Guarantees by Deployment

| Deployment | Lock Type | Cross-Worker Safety |
|-----------|-----------|-------------------|
| Single process (dev) | Thread lock | ✅ Full process isolation |
| Single machine, multiple workers | Thread lock (same process is impossible; different processes → thread lock = no cross-process safety) | ⚠️ **Not safe without Redis** |
| Multi-machine Celery workers, Redis available | Redis distributed lock | ✅ Full cross-worker safety |
| Multi-machine, Redis unavailable, `REQUIRE_DISTRIBUTED_LOCK=false` | Thread lock (silently degraded) | ❌ No cross-machine safety |
| Multi-machine, Redis unavailable, `REQUIRE_DISTRIBUTED_LOCK=true` | **Fails closed** | ✅ No unsafe operation proceeds |

### Operational Recommendation

For production deployments with multiple Celery workers:
1. Set `REQUIRE_DISTRIBUTED_LOCK=true` in `.env`
2. Configure Redis Sentinel or Redis Cluster for HA
3. Monitor Redis availability via `/health` endpoint or external probe
4. Alert on `RuntimeError: REQUIRE_DISTRIBUTED_LOCK` in worker logs

---

## Outbox Concurrency Control

### Event Claiming Protocol

The `process_intel_reassessment_queue_task()` uses an optimistic-locking pattern
to prevent duplicate event processing by concurrent workers:

```sql
-- Step 1: SELECT candidates (read-only; no lock)
SELECT id FROM integration_outbox
WHERE event_type = 'intel_triggered_reassessment' AND status = 'PENDING'
ORDER BY created_at ASC LIMIT 20;

-- Step 2: Attempt atomic claim (one UPDATE per candidate)
UPDATE integration_outbox SET status = 'PROCESSING'
WHERE id = ? AND status = 'PENDING';

-- rowcount == 1 → claimed; rowcount == 0 → another worker already claimed it
```

**Why this works:**
- SQLite uses write-ahead logging (WAL); the `UPDATE WHERE status=PENDING` is atomic
  with respect to concurrent writers on the same connection.
- PostgreSQL's MVCC provides the same atomicity guarantee.
- Two workers racing on the same event: only one UPDATE succeeds (rowcount=1);
  the loser gets rowcount=0 and skips.

### Retry and Dead-Letter

| Attempt | Backoff | Next Status |
|---------|---------|-------------|
| 1 (initial) | — | PENDING → PROCESSING → DELIVERED or retry |
| 2 (retry 1) | 60s | PENDING (next_retry_at = now+60s) |
| 3 (retry 2) | 120s | PENDING (next_retry_at = now+120s) |
| 4 (retry 3) | 300s | PENDING (next_retry_at = now+300s) |
| ≥5 | — | DEAD_LETTER |

DEAD_LETTER events require manual operator inspection (query `status='DEAD_LETTER'`).

---

## Duplicate Scan Prevention

### Scheduled Scans
`claim_scheduled_run()` inserts into `scheduled_runs` with a `UNIQUE(schedule_id, planned_at)` constraint. If Beat fires twice before the scan runs (e.g., after a restart), the second `INSERT` is rejected by the constraint — the duplicate is logged and skipped.

### Intel Reassessment Scans
The outbox `event_key` has a UNIQUE constraint. `check_intel_triggered_reassessment()` checks `get_pending_outbox_events()` for existing events with the same key before inserting. If `sync_all()` runs twice in quick succession, the second call finds the existing PENDING event and skips insertion.

### Differential Computation
`compute_scan_differential()` is a pure computation (no DB writes). Running it twice for the same scan pair produces identical results (idempotent). No state is mutated.

---

## Restart Recovery Matrix

| Failure Point | State Left | Recovery |
|--------------|------------|---------|
| Beat crashes before `claim_scheduled_run` | No state | Beat restart dispatches normally |
| Beat crashes after `claim_scheduled_run`, before `run_scan_task.delay` | `ScheduledRun` in `dispatched` state but no ScanJob | `recover_stale_jobs_task` does not cover this; manual cleanup needed (Sprint 5 gap) |
| Worker crashes mid-scan (running) | ScanJob in `running`, Scan in `running` | `recover_stale_jobs_task` re-queues after 600s |
| Worker crashes after `save_scan(COMPLETED)`, before `_trigger_post_scan_differential` | Scan COMPLETED, no differential | Next manual or scheduled scan will produce differential from this scan as baseline |
| Worker crashes after PROCESSING claim, before DELIVERED | Event in `PROCESSING` state | **Stranded** — not automatically re-queued (Sprint 5 gap) |
| Redis restarts (lock held) | Lock TTL expires in ≤300s | Automatic recovery; next `sync_all()` call re-acquires |

### Sprint 5 Recovery Gaps
1. `ScheduledRun` in `dispatched` state with no linked ScanJob (Beat crashed mid-dispatch)
2. Outbox event stuck in `PROCESSING` (worker crashed after claim, before completion)

---

## NVD Backfill Reliability

The `backfill_nvd_enrichment_task()` supports checkpoint/resume via `offset` parameter:

```python
# First run
result = backfill_nvd_enrichment_task(max_total=100, offset=0)
next_offset = result["next_offset"]  # None if all done; integer if more remain

# Resume from checkpoint
result = backfill_nvd_enrichment_task(max_total=100, offset=next_offset)
```

**Idempotency:** The `WHERE cvss_score IS NULL OR cvss_score = 0` filter ensures
already-enriched records are never re-queried or overwritten.

**Rate limiting:** `time.sleep(6.5)` per record without NVD API key; `time.sleep(0.7)` with key.
At 6.5s per record and 100 records per invocation: approximately 10 minutes per batch.
For large deployments, operators should set `NVD_API_KEY` and increase batch size.
