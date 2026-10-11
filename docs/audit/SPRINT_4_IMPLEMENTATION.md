# Sprint 4 — Implementation Record
**Branch:** `feat/sentinelwp-sprint4-integration`
**Commit:** `cd5b162`
**Baseline (Sprint 3):** 438 passing
**Exit baseline:** 479 passing (+41, 0 regressions)

---

## Implementation Matrix

| Finding ID | Original Problem | Resolution | Primary Files | Tests | Residual Risk |
|------------|-----------------|------------|--------------|-------|---------------|
| S3-GAP-004 | `compute_scan_differential()` not called automatically | `_trigger_post_scan_differential()` added to `run_scan_task`; failure-isolated | `core/tasks/scan_tasks.py` | `TestPostScanDifferentialTrigger` (5 tests) | None — failure-isolated |
| S3-GAP-002 | Intel reassessment events not dispatched as scan jobs | `process_intel_reassessment_queue_task()` with atomic claim, auth gate, backoff | `core/tasks/maintenance_tasks.py`, `celery_app.py` | `TestIntelReassessmentQueue` (6 tests) | Dead-letter events require manual review |
| S3-GAP-003 | Monitoring dashboard not exposed as API | `GET /api/v1/monitoring/dashboard` + `/monitoring/assets` | `app.py` | `TestMonitoringAPIs` (12 tests) | None |
| S3-GAP-005 | No pause/resume API | `POST /api/v1/schedules/<id>/pause` and `/resume` | `app.py` | `TestMonitoringAPIs` (4 tests) | None |
| S3-GAP-001 | Redis fallback silent in multi-worker deployments | `REQUIRE_DISTRIBUTED_LOCK=true` → fail-closed | `service.py`, `.env.example` | `TestRequireDistributedLock` (3 tests) | Thread fallback still available for dev |
| INFRA-OPEN-002 | NVD_API_KEY undocumented | Documented in `.env.example` with registration URL | `.env.example` | — | None |
| DETECT-OPEN-002 | WSA_WP_SUBDIR_HINTS undocumented | Documented in `.env.example` with example | `.env.example` | — | None |
| INTEL-OPEN-002 | No historical NVD backfill mechanism | `backfill_nvd_enrichment_task()` with dry-run, batching, cursor resume | `core/tasks/intel_tasks.py` | `TestNvdBackfillTask` (3 tests) | Rate limiting; 6.5s/req without API key |
| DETECT-OPEN-004 | Plugin readme.txt may serve stale CDN version | `Cache-Control: no-cache` on readme.txt requests | `scanners/plugin_scanner.py` | `TestPluginMetadataCacheBusting` (3 tests) | Server may still return stale body |

---

## Detailed Change Log

### PHASE 1 — Automatic Post-Scan Differential (S3-GAP-004)

Added `_trigger_post_scan_differential(new_scan_id, tenant_id, asset_id, job_id)` to `scan_tasks.py`. Called immediately after `process_scan_findings()` inside the `COMPLETED` path of `run_scan_task()`.

**Logic:**
1. Skip if no `asset_id` (ad-hoc scans have no comparison baseline).
2. Query up to 5 prior completed scans for the same asset; filter out the current scan.
3. If no prior scan found: log INFO, return (first scan).
4. Call `compute_scan_differential(baseline=prior[0], new=current)`.
5. Log the result counts.
6. Any exception is caught and logged as WARNING — scan completion data is never affected.

**Safety invariants:**
- RESOLVED changes are only emitted when `new_scan.status == COMPLETED` (enforced inside `compute_scan_differential()`).
- The helper itself is wrapped in `try/except Exception` — differential failure = observability gap, not data corruption.
- Retried tasks produce the same differential (idempotent).

---

### PHASE 2 — Intelligence Reassessment Queue (S3-GAP-002)

`process_intel_reassessment_queue_task()` added to `maintenance_tasks.py`, registered in Beat at 300s.

**Processing sequence:**
1. `SELECT id FROM integration_outbox WHERE event_type='intel_triggered_reassessment' AND status='PENDING' LIMIT 20`
2. For each candidate: `UPDATE integration_outbox SET status='PROCESSING' WHERE id=? AND status='PENDING'` — `rowcount == 1` confirms exclusive claim.
3. Load full event payload.
4. Validate: asset exists → monitoring enabled → not paused → scan authorization active.
5. Create `ScanResult` + `ScanJob`, dispatch `run_scan_task.delay(job.id)`.
6. Mark event `DELIVERED`.
7. On exception: retry with exponential backoff (60s → 120s → 300s); `DEAD_LETTER` after attempt 4.

**No external scan launched by the task itself** — `run_scan_task` handles the actual scanning with all existing SSRF and authorization protections.

**Concurrency safety:** Two workers selecting the same `PENDING` event will race; only one `UPDATE WHERE status=PENDING` succeeds (rowcount=1 check). The loser gets rowcount=0 and skips that event.

---

### PHASE 3 — Flask Monitoring APIs (S3-GAP-003, S3-GAP-005)

Six new endpoints added to `app.py`:

| Endpoint | Scope | RBAC |
|----------|-------|------|
| `GET /api/v1/monitoring/dashboard` | `assets:read` | viewer+ |
| `GET /api/v1/monitoring/assets` | `assets:read` | viewer+ |
| `GET /api/v1/assets/<id>/differential` | `assets:read`, `findings:read` | viewer+ |
| `GET /api/v1/assets/<id>/lifecycle` | `assets:read`, `findings:read` | viewer+ |
| `POST /api/v1/schedules/<id>/pause` | `assets:write` | analyst+ |
| `POST /api/v1/schedules/<id>/resume` | `assets:write` | analyst+ |

All endpoints:
- Use `@require_scope()` for authentication + RBAC
- Use `@csrf.exempt` (API endpoints use Bearer/API-key auth, not sessions)
- Enforce tenant-scoped object-level authorization (`get_asset(id, tenant_id=g.tenant_id)`)
- Return 404 for cross-tenant resource access
- Pause/resume endpoints emit audit events

---

### PHASE 4 — Dashboard Template Integration

`templates/dashboard.html` extended with a `{% if monitoring %}` block that renders a 9-metric monitoring panel using the `monitoring` context variable passed from the `dashboard()` route. The route calls `repository.get_monitoring_dashboard(tenant_id)` in a try/except block so dashboard load never fails if monitoring data is unavailable.

Metrics displayed: Monitored Assets, Paused, Need Attention, Critical Findings, High Findings, New (24h), Resolved (24h), Scan Failures (24h), Intel Freshness (hours), 7-day risk trend.

---

### PHASE 5 — REQUIRE_DISTRIBUTED_LOCK (S3-GAP-001)

`_get_redis_client()` in `service.py` reads `REQUIRE_DISTRIBUTED_LOCK` env var. When `true`:
- If Redis is unreachable, raises `RuntimeError` with an actionable message
- Prevents silent degradation to process-local locking in multi-worker deployments

When `false` (default): existing silent fallback to `threading.Lock` is preserved for development and single-process deployments.

---

### PHASE 6 — Configuration & Backfill

**.env.example** additions:
- `NVD_API_KEY` with registration URL comment
- `REQUIRE_DISTRIBUTED_LOCK=false` with multi-worker guidance
- `INTEL_REASSESSMENT_BATCH_SIZE=20` and `INTEL_REASSESSMENT_MAX_RETRIES=3`
- `WSA_WP_SUBDIR_HINTS` commented example

**backfill_nvd_enrichment_task()**: uses `vuln_repo._get_vuln_conn()` (separate vuln intel DB). Queries `vulnerability_records WHERE cve IS NOT NULL AND cvss_score IS NULL ORDER BY id LIMIT ? OFFSET ?`. Supports `dry_run`, `max_total`, `offset` params for checkpoint/resume. Only overwrites records where `cvss_score IS NULL OR cvss_score = 0` (idempotent).

---

### PHASE 7 — Plugin Metadata Cache-Busting (DETECT-OPEN-004)

`PluginScanner._get_plugin_version_from_readme()` now passes `headers={"Cache-Control": "no-cache", "Pragma": "no-cache"}` to `_get()`. This is targeted specifically to the version-evidence request and does not affect enumeration probes or soft-404 sentinel requests.

---

### Migration 007

`migrations/versions/007_sprint4_workflow_integration.py`:
- `idx_outbox_event_type_status`: covers `WHERE event_type=? AND status=?`
- `idx_outbox_status_created`: covers `WHERE status IN (...) ORDER BY created_at`
- `idx_outbox_retry_at`: partial index on `next_retry_at IS NOT NULL`
- `idx_outbox_tenant_key`: deduplication key lookups
- `idx_scans_asset_status`: covers `list_scans(asset_id, status)` in differential
