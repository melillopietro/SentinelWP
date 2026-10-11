# SENTINELWP — SPRINT 10 REAL CELERY DISTRIBUTED EXECUTION AUDIT
**Asynchronous Workflows, Broker Latency, Queue Segregation & Worker Idempotency**
**Audit Date:** October 11, 2026  
**Broker:** Redis 7 Alpine (`redis://127.0.0.1:6389/0`)  
**Backend:** Redis 7 Alpine (`redis://127.0.0.1:6389/1`)  
**Celery Version:** 5.6.3 (threads pool, concurrency 2)  
**Database:** PostgreSQL 16 (`sentinelwp_s10`)

---

## 1. DISTRIBUTED EXECUTION ARCHITECTURE

SentinelWP executes all long-running tasks asynchronously through dedicated background workers managed by Celery and Redis. The production configuration enforces strict queue segregation to prevent maintenance and intelligence workloads from starving critical vulnerability scans.

### Queue Topology
- `scan`: Dedicated exclusively to active vulnerability scans (`core.tasks.scan_tasks.run_scan_task`). Tasks in this queue interact with external WordPress targets subject to target allowlists and concurrency limits.
- `maintenance`: System health, scheduled run claiming (`dispatch_scheduled_scans_task`), stale job reapers (`recover_stale_jobs_task`), SLA evaluations (`evaluate_sla_breaches`), risk snapshots, and outbox distribution.
- `intel`: External vulnerability intelligence feeds (NVD, WPScan, CISA KEV) backfills and periodic sync tasks.

---

## 2. REAL SCAN EXECUTION AUDIT EVIDENCE

### Scan 1 Dispatch and Execution
- **Task ID:** `824b52ba-b00e-4012-a744-3a880726dfe1`
- **Job ID:** `job_559c75f2`
- **Scan Mode:** `passive`
- **Target URL:** `http://127.0.0.1:8099` (WordPress 6.4 Apache)
- **Assigned Worker Hostname:** `celery@MacBook-Air-di-Piero.local`
- **Dispatch Timestamp:** `10:07:15.184 UTC`
- **Completion Timestamp:** `10:07:22.419 UTC`
- **Total Duration:** `7.235 seconds`
- **Final Progress:** `100%`
- **Exit Status:** `completed`

#### Task Lifecycle Log Trace
```
[INFO/MainProcess] Connected to redis://127.0.0.1:6389/0
[INFO/MainProcess] celery@MacBook-Air-di-Piero.local ready.
[INFO/MainProcess] Task core.tasks.scan_tasks.run_scan_task[824b52ba-b00e-4012-a744-3a880726dfe1] received
[INFO/MainProcess] [job_559c75f2] Worker celery@MacBook-Air-di-Piero.local picked up scan job (attempt 1)
[INFO/MainProcess] [job_559c75f2] Scan authorization verified (auth_f6803647). Target http://127.0.0.1:8099 permitted.
[INFO/MainProcess] [job_559c75f2] Executing scan orchestrator with profile passive...
[INFO/MainProcess] [job_559c75f2] Progress updated to 25% (headers and configuration analysis)
[INFO/MainProcess] [job_559c75f2] Progress updated to 60% (vulnerability detection and version fingerprints)
[INFO/MainProcess] [job_559c75f2] Progress updated to 90% (fingerprint correlation and observation storage)
[INFO/MainProcess] [job_559c75f2] Scan completed. Persisting 35 verified findings to PostgreSQL.
[INFO/MainProcess] [job_559c75f2] Scan job marked COMPLETED. Total elapsed: 4.21s.
[INFO/MainProcess] Task core.tasks.scan_tasks.run_scan_task[824b52ba-b00e-4012-a744-3a880726dfe1] succeeded in 4.238s
```

---

## 3. IDEMPOTENCY & TERMINAL STATE PROTECTION

To prevent duplicate task execution when Celery workers crash or brokers re-deliver tasks, `run_scan_task` implements fail-fast idempotency guards.

### Verification Scenario: Duplicate Task Delivery
1. A completed scan job (`job_559c75f2`) was explicitly re-invoked through Celery's task executor (`run_scan_task.apply(args=[job_id])`).
2. The task entered `run_scan_task`, queried PostgreSQL for the current state of `job_559c75f2`, and observed `status = 'completed'`.
3. The task emitted a diagnostic log indicating the job was already in a terminal state:
   ```
   [INFO] [job_559c75f2] Scan job already in terminal state 'completed'. Skipping duplicate execution.
   ```
4. The task exited immediately without executing web requests, modifying scan results, or resetting timestamps.
5. The scan job status in PostgreSQL was verified: status remained `completed` with progress `100%`.

---

## 4. CONCURRENCY CONTROL & ACTIVE JOB RATE LIMITING

SentinelWP enforces three distinct concurrency limits in `core/tasks/scan_tasks.py`:
- `MAX_CONCURRENT_SCANS_PER_ASSET = 1`
- `MAX_CONCURRENT_SCANS_PER_TENANT = 5`
- `MAX_CONCURRENT_SCANS_GLOBAL = 10`

When a worker picks up a scan job for an asset that already has an active scan running, the worker records a postponement log and schedules an automatic backoff retry via Celery (`countdown=30s`). During the E2E validation, when concurrent jobs were queued for the same asset, the asset concurrency limiter successfully intervened, preventing denial-of-service against the target container.

---

## 5. CELERY BEAT PERIODIC SCHEDULING VERIFICATION

Celery Beat was configured to schedule periodic tasks directly into the Redis broker. The daemon operated without errors during the E2E validation, successfully executing:
1. `dispatch_scheduled_scans_task`: Evaluated enabled `scheduled_scans` records and claimed runnable time slots using PostgreSQL row locking.
2. `recover_stale_jobs_task`: Scanned PostgreSQL for scan jobs in `running` status whose `last_heartbeat_at` exceeded the timeout threshold (`600s`).
3. `recover_stale_outbox_events_task`: Scanned the outbox for events stuck in `PROCESSING` status for over 10 minutes and reclaimed them for retry.
4. `evaluate_sla_breaches`: Monitored active remediation SLAs against target resolution dates.

All beat executions logged structured JSON audit events and returned clean execution dictionaries without uncaught exceptions.
