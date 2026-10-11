# Sprint 3 — Remaining Gaps

This document catalogs all known gaps that were **not closed** in Sprint 3, either
because they were out of scope, require infrastructure changes, or are lower priority.

---

## Carried Forward from Sprint 2 (unchanged)

### DETECT-OPEN-001 — Soft-404 Threshold Tuning
**Severity:** LOW  
**Status:** Not addressed in Sprint 3  
**Recommendation for Sprint 4:** Add Levenshtein-ratio or difflib.SequenceMatcher
comparison as an additional signal. Tune default threshold empirically.

### DETECT-OPEN-002 — WP_SUBDIR_HINTS Not Documented
**Severity:** LOW  
**Status:** Not addressed in Sprint 3 (documentation-only change)  
**Recommendation for Sprint 4:** Add entry to `.env.example`.

### DETECT-OPEN-004 — Plugin Version Cache-Busting
**Severity:** LOW  
**Status:** Not addressed in Sprint 3  
**Recommendation for Sprint 4:** Add `Cache-Control: no-cache` header to
readme.txt CDN requests.

### DETECT-OPEN-005 — UserAgent Fingerprinting Evasion
**Severity:** MEDIUM  
**Status:** Partially addressed — `WSA_USER_AGENT` env var is already configurable
and applied at session creation. UA rotation for WAF evasion was explicitly
**not** implemented (violates security policy). The operator can set any UA string.  
**Remaining gap:** No pool of UA strings. Single configurable UA is the supported model.

### INTEL-OPEN-002 — Historical NVD Enrichment Backfill
**Severity:** LOW  
**Status:** Not addressed in Sprint 3  
**Recommendation for Sprint 4:** Add `backfill_nvd_enrichment()` management command.

### INTEL-OPEN-003 — KEV Exploitation Evidence Fields
**Severity:** LOW  
**Status:** Not addressed in Sprint 3  
**Recommendation for Sprint 4:** Extend schema with `kev_notes`, `kev_ransomware_use`.

### INTEL-OPEN-004 — OSV Ecosystem Taxonomy Verification
**Severity:** LOW  
**Status:** Not empirically tested in Sprint 3  
**Recommendation for Sprint 4:** Test against `contact-form-7` 5.5.3 in staging.

### INFRA-OPEN-001 — Redis Unavailability During Sync
**Severity:** LOW  
**Status:** Partially addressed — `_DistributedSyncLock` falls back to thread lock
when Redis is unavailable. No startup health check added.  
**Remaining gap:** Add startup health check that logs WARNING if Redis unreachable.

### INFRA-OPEN-002 — NVD API Key Management
**Severity:** LOW  
**Status:** Not addressed in Sprint 3 (documentation-only change)  
**Recommendation for Sprint 4:** Add NVD_API_KEY entry to `.env.example`.

### EVI-OPEN-001 — Finding Reference Field Population
**Severity:** LOW  
**Status:** Not addressed in Sprint 3  
**Recommendation for Sprint 4:** Audit all scanner `_add_finding()` calls.

### EVI-OPEN-002 — Remediation Text Consistency
**Severity:** LOW  
**Status:** Not addressed in Sprint 3  
**Recommendation for Sprint 4:** Establish remediation text template.

---

## New Gaps Identified in Sprint 3

### S3-GAP-001 — Distributed Lock Fallback Documentation
**Severity:** LOW  
**Description:** The `_DistributedSyncLock` in `service.py` falls back to
`threading.Lock` when Redis is unreachable. This means two processes without
Redis access can still race (e.g. two Docker containers without Redis). The
fallback is safe for single-process / single-machine deployments but not for
horizontal scale without Redis.  
**Consistency guarantee:** When Redis is available, atomicity is guaranteed via
`SET NX EX`. When Redis is unavailable, only intra-process exclusion is provided.  
**Recommendation for Sprint 4:** Add a `REQUIRE_DISTRIBUTED_LOCK=true` env var
that causes startup failure if Redis is unavailable in production.

### S3-GAP-002 — Intel Reassessment Scan Queue Integration
**Severity:** MEDIUM  
**Description:** `check_intel_triggered_reassessment()` stages an outbox event
but does not automatically dispatch a new scan job. The reassessment requires a
human or automated consumer of the outbox to trigger a re-scan.  
**Recommendation for Sprint 4:** Add a Celery task `process_intel_reassessment_queue()`
that reads pending outbox events of type `intel_triggered_reassessment` and,
where authorization permits, dispatches a `run_scan_task`.

### S3-GAP-003 — Monitoring Dashboard API Endpoint
**Severity:** LOW  
**Description:** `get_monitoring_dashboard()` is implemented in the repository
layer but not yet exposed as a Flask API endpoint.  
**Recommendation for Sprint 4:** Add `GET /api/v1/monitoring/dashboard` endpoint.

### S3-GAP-004 — ScanDifferential Not Surfaced in API
**Severity:** LOW  
**Description:** `compute_scan_differential()` is implemented but not called
from the API layer or Celery tasks. It must be triggered manually.  
**Recommendation for Sprint 4:** Call `compute_scan_differential()` automatically
after each completed scan and store the result, or expose it via
`GET /api/v1/scans/{id}/differential`.

### S3-GAP-005 — Monitoring Pause API Endpoint Missing
**Severity:** LOW  
**Description:** The `paused_until` field on `ScheduledScan` is persisted and
respected by the dispatcher, but there is no API endpoint to set/clear it.  
**Recommendation for Sprint 4:** Add `POST /api/v1/schedules/{id}/pause` and
`POST /api/v1/schedules/{id}/resume` endpoints.
