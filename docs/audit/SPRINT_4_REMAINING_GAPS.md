# Sprint 4 — Remaining Gaps & Technical Debt

**Branch:** `feat/sentinelwp-sprint4-integration`  
**Commit:** `cd5b162`  
**Review Date:** 2026-10-10  

---

## 1. Gaps Successfully Closed in Sprint 4

The following items from the Sprint 3 audit were resolved and verified:

| Gap ID | Description | Resolution in Sprint 4 | Verification Status |
|---|---|---|:---:|
| **S3-GAP-001** | Redis lock fallback silent degradation | Introduced `REQUIRE_DISTRIBUTED_LOCK=true` env var which enforces fail-closed behavior (`RuntimeError`) if Redis is unavailable. | **CLOSED** (3 tests) |
| **S3-GAP-002** | Intel reassessment events not dispatched | Created `process_intel_reassessment_queue_task()` with atomic claim, auth check, backoff, and Celery Beat integration. | **CLOSED** (6 tests) |
| **S3-GAP-003** | Monitoring dashboard not exposed as API | Added `GET /api/v1/monitoring/dashboard` and `GET /api/v1/monitoring/assets`. | **CLOSED** (6 tests) |
| **S3-GAP-004** | Differential not computed automatically | Added `_trigger_post_scan_differential()` to `scan_tasks.py` and exposed `GET /api/v1/assets/<id>/differential`. | **CLOSED** (8 tests) |
| **S3-GAP-005** | Schedule pause/resume API missing | Added `POST /api/v1/schedules/<id>/pause` and `POST /api/v1/schedules/<id>/resume`. | **CLOSED** (5 tests) |
| **INFRA-OPEN-002**| NVD_API_KEY undocumented | Documented in `.env.example` with NIST registration instructions. | **CLOSED** |
| **DETECT-OPEN-002**| WSA_WP_SUBDIR_HINTS undocumented | Documented in `.env.example`. | **CLOSED** |
| **INTEL-OPEN-002**| Historical NVD enrichment backfill | Created `backfill_nvd_enrichment_task()` supporting dry-run, batches, and cursor resume. | **CLOSED** (3 tests) |
| **DETECT-OPEN-004**| Plugin readme.txt CDN stale caching | Added `Cache-Control: no-cache` and `Pragma: no-cache` to readme.txt requests. | **CLOSED** (3 tests) |

---

## 2. Gaps and Risks Identified in Sprint 4 Review

### S4-GAP-001: Stranded Outbox Events in `PROCESSING` State
* **Severity:** MEDIUM
* **Description:** When `process_intel_reassessment_queue_task()` claims an event, it executes `UPDATE integration_outbox SET status = 'PROCESSING'`. If the Celery worker process is terminated abruptly (SIGKILL, OOM, power cut) before completion, the event remains in `PROCESSING`. Since the query only fetches `WHERE status = 'PENDING'`, orphaned events remain stuck indefinitely.
* **Impact:** Affected intelligence-triggered scans are never re-evaluated unless manually edited in the database.
* **Recommended Sprint 5 Fix:** Implement `recover_stale_outbox_events_task()` in `maintenance_tasks.py` running every 600s, reclaiming events in `PROCESSING` whose `created_at` or `next_retry_at` exceeds a 600s threshold, checking for pre-existing `ScanJob` records before retry to ensure idempotency.

### S4-GAP-002: Pairwise Differential Historical Persistence
* **Severity:** LOW
* **Description:** `compute_scan_differential()` computes differences in-memory between two scans. The endpoint `/api/v1/assets/<asset_id>/differential` computes this dynamically between the two most recent completed scans. Older scan differentials are not persisted or cached.
* **Impact:** Pairwise historical diffs (e.g. between scan 1 and scan 5) require redundant on-demand re-computation.
* **Recommended Sprint 5 Fix:** Optionally introduce a lightweight table `scan_differentials` or store a differential summary JSON blob on `ScanResult` upon scan completion.

### S4-GAP-003: ScheduledRun Stranded on Beat Crash Mid-Dispatch
* **Severity:** LOW
* **Description:** `dispatch_scheduled_scans_task()` calls `claim_scheduled_run()` (marking `ScheduledRun` as `dispatched`), then invokes `run_scan_task.delay(job.id)`. If Beat or the host crashes in the microsecond between claiming and task enqueueing, the `ScheduledRun` record indicates dispatched, but no Celery task exists in Redis.
* **Impact:** A scheduled run may be skipped for that interval without a scan executing.
* **Recommended Sprint 5 Fix:** Extend `recover_stale_jobs_task()` to detect `ScheduledRun` rows older than 10 minutes that have no associated `ScanJob` or `ScanResult`.

### S4-GAP-004: Redis Reconnection Flapping in Distributed Lock
* **Severity:** LOW
* **Description:** `_get_redis_client()` evaluates `client.ping()` with a 1-second timeout. In high-latency networks, a single transient packet drop causes `REQUIRE_DISTRIBUTED_LOCK=true` to raise `RuntimeError` immediately rather than attempting 1–2 rapid retries.
* **Impact:** Vulnerability intelligence sync may abort on transient network blips.
* **Recommended Sprint 5 Fix:** Add a retry decorator (e.g. 3 attempts with 500ms backoff) before failing closed.

---

## 3. Carried-Forward Technical Debt from Prior Sprints

The following low-severity items remain open from earlier sprints:

| Identifier | Category | Description | Severity | Target |
|---|---|---|:---:|:---:|
| **DETECT-OPEN-001** | Detection | Soft-404 threshold tuning via `difflib.SequenceMatcher` or Levenshtein ratio. | LOW | Sprint 5 |
| **DETECT-OPEN-005** | Detection | User-Agent rotation pool. Current architecture intentionally uses a single configurable UA per enterprise policy. | LOW | Backlog |
| **INTEL-OPEN-003** | Intel | Schema fields for CISA KEV exploitation notes (`kev_notes`, `kev_ransomware_use`). | LOW | Sprint 5 |
| **INTEL-OPEN-004** | Intel | OSV ecosystem taxonomy empirical validation against live staging instances. | LOW | Sprint 5 |
| **INFRA-OPEN-001** | Infrastructure | Startup health check logging warning when Redis is absent in single-process mode. | LOW | Sprint 5 |
| **EVI-OPEN-001** | Evidence | Audit scanner `_add_finding()` calls to ensure complete reference field population. | LOW | Sprint 5 |
| **EVI-OPEN-002** | Evidence | Standardized remediation text templates across all scanner modules. | LOW | Sprint 5 |

---

## 4. Proposed Sprint 5 Priorities

1. **High-Availability Resilience & Outbox Sweeper:**
   - Implement `recover_stale_outbox_events_task` to resolve S4-GAP-001.
   - Implement Beat mid-dispatch orphan recovery to resolve S4-GAP-003.
2. **Threat Intelligence Refinement:**
   - Add CISA KEV exploitation fields (INTEL-OPEN-003).
   - Add Redis connection retry buffer in `_get_redis_client` (S4-GAP-004).
3. **Detection Accuracy & Evidence Quality:**
   - Tune soft-404 detection with structural text distance algorithms (DETECT-OPEN-001).
   - Standardize scanner remediation templates (EVI-OPEN-002).
