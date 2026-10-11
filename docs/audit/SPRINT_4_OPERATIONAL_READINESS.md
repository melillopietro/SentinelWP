# Sprint 4 — Operational Readiness Assessment

**Branch:** `feat/sentinelwp-sprint4-integration`  
**Commit:** `cd5b162`  
**Status:** Verification Complete — Conditionally Production-Ready  

---

## 1. System Topology & Architecture

SentinelWP operates as a distributed multi-tier vulnerability management platform:

```
[ Web Clients / API Consumers ]
               │
               ▼
   [ Gunicorn / Flask API ] ───────────┐
   - REST Monitoring APIs              │
   - RBAC / Tenant Scope Enforcement   │
   - Audit Logging Engine              │
               │                       │
               ▼                       ▼
      [ PostgreSQL DB ]        [ Redis 7+ Broker / Cache ]
      - Asset Inventory        - Celery Task Queues
      - Findings & Lifecycle   - Distributed Lock: sentinelwp:vuln_intel_sync
      - Integration Outbox
               ▲                       ▲
               │                       │
               ├───────────────────────┤
               │                       │
    [ Celery Beat Scheduler ]   [ Celery Worker Pool ]
    - dispatch_scheduled_scans  - Queue: scans (Orchestrator, SSRF gate)
    - recover_stale_jobs        - Queue: maintenance (Outbox, Purge)
    - sync_vuln_intelligence    - Queue: intel (NVD Backfill, KEV sync)
    - process_intel_reassessment
```

---

## 2. Production Configuration Matrix

For horizontal multi-worker deployments, the following configuration parameters must be set in `.env`:

| Parameter | Recommended Prod Value | Security & Reliability Rationale |
|---|---|---|
| `ENVIRONMENT` | `production` | Enforces HTTPS cookies, production logging, and strict error sanitization. |
| `DATABASE_URL` | `postgresql://...` | Replaces single-writer SQLite with concurrent ACID transactions and row-level locking. |
| `REDIS_URL` | `redis://...` | Central message broker and distributed synchronization provider. |
| `REQUIRE_DISTRIBUTED_LOCK` | `true` | **CRITICAL:** Prevents silent degradation to process-local `threading.Lock`. Ensures concurrent workers cannot double-sync threat feeds. |
| `NVD_API_KEY` | `<registered_key>` | Elevates NIST NVD rate limit from 5 req/30s to 50 req/30s. Reduces NVD backfill delay from 6.5s to 0.7s per CVE. |
| `INTEL_REASSESSMENT_BATCH_SIZE`| `20` | Limits outbox batch size per cycle to prevent database lock contention. |
| `INTEL_REASSESSMENT_MAX_RETRIES`| `3` | Prevents infinite retry loops on non-recoverable asset errors. |
| `WSA_WP_SUBDIR_HINTS` | `wordpress,wp,blog` | Enables discovery of WordPress installations deployed in common nested subdirectories. |

---

## 3. Review of Critical Operational Risks

### A. Differential Persistence Analysis
* **Mechanism:**
  - `compute_scan_differential()` is an in-memory computation returning a `ScanDifferential` dataclass.
  - When a scan reaches `COMPLETED`, `_trigger_post_scan_differential()` executes in `core/tasks/scan_tasks.py`. It computes the delta between the new scan and the most recent prior completed scan on that asset, emitting log metrics (`NEW`, `PERSISTING`, `RESOLVED`, `REOPENED`).
  - The differential output itself is **not written to a persistent table**; there is no `scan_differentials` table in the database schema.
  - The API endpoint `GET /api/v1/assets/<asset_id>/differential` calculates the differential **on the fly** by retrieving the two most recent completed scans via `get_latest_differential_for_asset()`.
  - The monitoring dashboard (`GET /api/v1/monitoring/dashboard`) obtains 24-hour delta metrics by querying `findings` and `finding_history` directly (which are continuously updated by `process_scan_findings()`).
* **Operational Implication:**
  - **Zero Database Bloat:** Storing raw pairwise differentials for every historic scan combination would cause rapid table expansion without added analytical value.
  - **Missing Feature:** Historical pairwise audits between arbitrary older scans (e.g. Scan #2 vs Scan #10) cannot be retrieved from a saved cache and must be calculated on-demand.
  - **Verdict:** Compliant with Sprint 4 specifications. No database migration is required.

### B. Outbox Crash Recovery & Stranded Events
* **Mechanism:**
  - `process_intel_reassessment_queue_task()` uses optimistic locking:
    ```sql
    UPDATE integration_outbox SET status = 'PROCESSING'
    WHERE id = ? AND status = 'PENDING';
    ```
* **Failure Analysis:**
  - If a Celery worker encounters an abrupt crash (e.g., node termination, SIGKILL, out-of-memory killer) *after* updating status to `PROCESSING` but *before* marking `DELIVERED`, the event remains in `PROCESSING`.
  - On subsequent Beat runs (every 300s), the queue processor queries only `WHERE status = 'PENDING'`. As a result, stranded `PROCESSING` events are never retried automatically.
* **Root Cause:**
  - The outbox schema lacks a `heartbeat_at` or `claimed_at` timestamp, and there is no automated sweeper task for orphaned `PROCESSING` outbox records (unlike scan jobs, which are recovered by `recover_stale_jobs_task`).
* **Proposed Idempotent Recovery Mechanism:**
  - Create a lightweight reaper maintenance task (`recover_stale_outbox_events_task`) scheduled every 600s in Celery Beat:
    ```sql
    UPDATE integration_outbox
    SET status = 'PENDING',
        attempt = attempt + 1,
        last_error = 'Worker timeout during PROCESSING; reclaimed'
    WHERE status = 'PROCESSING'
      AND (created_at < :stale_cutoff OR next_retry_at < :stale_cutoff)
      AND attempt <= 3;
    ```
  - For events where `attempt > 3`, transition directly to `DEAD_LETTER`.
  - Before re-dispatching, verify whether a `ScanJob` with `requested_by = 'intel_reassessment:<event_id>'` already exists in the database. If it exists, set the event directly to `DELIVERED` without duplicating the scan.
  - **Action for Sprint 4:** Documented in `SPRINT_4_REMAINING_GAPS.md` as priority task for Sprint 5. No disruptive schema change introduced in Sprint 4.

### C. Redis Distributed Locking & Multi-Worker Safety
* **Mechanism:**
  - `_DistributedSyncLock` in `core/vulnerability_intelligence/service.py` provides mutual exclusion during threat feed ingestion (`sync_all()`).
  - In default single-process mode (`REQUIRE_DISTRIBUTED_LOCK=false`), if Redis is unreachable, the system silently falls back to a process-local `threading.Lock()`.
  - When `REQUIRE_DISTRIBUTED_LOCK=true`, `_get_redis_client()` checks connectivity via `client.ping()`. If Redis is offline or unreachable, it immediately raises:
    ```python
    RuntimeError("REQUIRE_DISTRIBUTED_LOCK=true but Redis is unavailable: ...")
    ```
* **Safe Production Configuration:**
  - Multi-worker deployments MUST set `REQUIRE_DISTRIBUTED_LOCK=true`.
  - In horizontal setups, process-local locks do not protect against race conditions across multiple nodes. The fail-closed design prevents concurrent NVD/Wordfence sync tasks from flooding external APIs and causing duplicate DB writes.
  - Redis Sentinel or Redis Cluster should be deployed to prevent sync disruption due to single-node Redis failovers.

### D. Policy Compliance of Intelligence-Triggered Scans
* **Verification:**
  - Automated threat feed matching triggers outbox events of type `intel_triggered_reassessment`.
  - `process_intel_reassessment_queue_task()` enforces a strict three-tier authorization gate before creating a scan job:
    1. **Asset Status Check:** Asset must exist in `assets` table and have `monitoring_enabled = True`.
    2. **Monitoring Pause Check:** If `monitoring_paused_at` is set, the event is set to `SKIPPED` (`Monitoring disabled or paused`).
    3. **Scan Authorization Gate:** Calls `verify_scan_authorization(tenant_id, target_url, "safe-active")`. If the active authorization token has expired, been revoked, or does not cover the asset domain, the event is marked `SKIPPED` (`No active scan authorization`).
  - **Network Boundary:** The queue task itself never performs external network requests. It creates a `ScanJob` that delegates execution to `run_scan_task()`, which applies existing SSRF IP range filtering, DNS rebinding guards, and rate limiting.

---

## 4. Operational Runbook

### Health & Readiness Probes
- **Liveness Probe:** `GET /health` — Returns HTTP 200 with application version and uptime.
- **Readiness Probe:** `GET /ready` — Validates database and cache connectivity.
- **Prometheus Metrics:** `GET /metrics` — Exposes Celery queue depths, scan completion counts, and threat feed freshness.

### Dead-Letter Triage Procedure
When an outbox event fails 3 consecutive execution attempts, it transitions to `status = 'DEAD_LETTER'`:
1. Query failed events:
   ```sql
   SELECT id, tenant_id, event_key, last_error, payload_json
   FROM integration_outbox
   WHERE status = 'DEAD_LETTER';
   ```
2. Diagnose error cause (e.g. malformed asset URL, database connectivity drop, foreign key mismatch).
3. If transient, reset to PENDING for re-processing:
   ```sql
   UPDATE integration_outbox
   SET status = 'PENDING', attempt = 1, next_retry_at = NULL
   WHERE id = '<event_id>';
   ```

### Scheduled Maintenance Tasks
| Task Name | Beat Schedule | Queue | Function |
|---|:---:|:---:|---|
| `dispatch_scheduled_scans_task` | Every 60s | `scans` | Claims and dispatches due scheduled scans |
| `process_intel_reassessment_queue_task` | Every 300s | `maintenance` | Processes intel-triggered reassessment events |
| `recover_stale_jobs_task` | Every 600s | `maintenance` | Resets or fails running jobs with dead worker heartbeats |
| `sync_vulnerability_intelligence_task` | Every 1800s | `intel` | Ingests NVD, CISA KEV, Wordfence, and WP plugins |
| `purge_expired_records_task` | Daily (03:00 UTC)| `maintenance` | Cleans up historical scan jobs and audit logs past retention |
