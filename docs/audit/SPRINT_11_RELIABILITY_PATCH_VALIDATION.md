# SentinelWP — Reliability Patch Validation (SWP-REL-001/002/003)

**Date (UTC):** 2026-10-11  
**Parent baseline:** `e6ae64b9674b29a527065c775396ac3585337d48`  
**Patch scope:** Submission SSRF preflight, E2E assertion hardening, structured worker outcomes  
**Docker image (post-patch lab rebuild):** `sentinelwp:3.7.0` @ `sha256:e3e2b1fdb4cd362f9cc87a260f4d6188f12ee6d8588ce01d0a71ce671136a138`

---

## SWP-REL-001 — Scan submission SSRF preflight

| Item | Detail |
|------|--------|
| **Root cause** | `/scan/new` (and API enqueue paths) authorized targets but did not call `is_safe_target_url()` before persisting Scan/ScanJob or calling Celery. |
| **Files** | `core/scan_submission.py` (new), `app.py` |
| **Implementation** | `validate_scan_target_for_submission()` wraps canonical `is_safe_target_url(..., resolve_dns=True)`. `_reject_unsafe_scan_target_at_submission()` audits `scan_target_blocked` and returns HTTP **400** (HTML) or JSON `{code: TARGET_BLOCKED}`. Applied on `/scan/new`, `/api/scan` POST, and finding verification dispatch. **No** ScanJob/Celery when blocked. Worker orchestrator SSRF unchanged. |
| **Tests** | `tests/test_sprint11_reliability_patch.py` — unsafe metadata → 400, no job, `delay` not called; safe target still queues. |
| **E2E** | Phase 4 Section 5: HTTP **400**, zero new scans/jobs for metadata URL. |
| **Residual risk** | DNS rebinding / TOCTOU — submission check does not replace per-request worker and scanner enforcement. |
| **Status** | **RESOLVED** |

---

## SWP-REL-002 — E2E SSRF assertion correction

| Item | Detail |
|------|--------|
| **Root cause** | Test treated HTTP 200 or loose page heuristics as “blocked” while jobs were enqueued and failed asynchronously. |
| **Files** | `tests/e2e/sprint11_phase4_e2e_runner.py` |
| **Implementation** | Count scans/jobs before & after; require HTTP **400/403**; assert no new DB rows; inject lab-only job to verify worker returns `False` + `TARGET_BLOCKED`. |
| **Tests** | E2E runner (above); unit tests in `test_sprint11_reliability_patch.py`. |
| **E2E** | **PASS** — all four SSRF security checks in summary JSON. |
| **Residual risk** | None for test fidelity; production still depends on REL-001 + worker defense. |
| **Status** | **RESOLVED** |

---

## SWP-REL-003 — Celery result semantics

| Item | Detail |
|------|--------|
| **Root cause** | Celery log `succeeded: False` conflated idempotent skips, auth/SSRF failures, and execution errors. |
| **Files** | `core/tasks/scan_tasks.py` |
| **Implementation** | Added outcome constants and `_log_scan_task_outcome()` emitting `[scan_task_outcome] job_id=… outcome=… job_status=… error_code=…`. **Bool return unchanged** (`True` success, `False` skip/failure). SSRF worker failures use `error_code=TARGET_BLOCKED` and `outcome=ssrf_rejection`. |
| **Tests** | `test_worker_ssrf_still_enforced…`, `test_duplicate_delivery_logs_idempotent_skip` |
| **E2E** | Worker injection check: `False failed TARGET_BLOCKED` |
| **Residual risk** | External tools that only read Celery result bool must correlate with logs / `scan_jobs.error_code`. |
| **Status** | **RESOLVED** (observability; contract preserved) |

---

## Regression and laboratory validation

| Gate | Result |
|------|--------|
| `pytest tests/` | **640 passed**, 0 failed |
| Docker rebuild | `web`, `worker-scan`, `worker-intel`, `beat`, `gateway` recreated; **volumes not deleted** |
| Phase 4 E2E | **PASS** (`tests/e2e/logs/sprint11_phase4_e2e_summary.json`) |
| Log artifact | `tests/e2e/logs/reliability_patch_e2e_run.log` |

---

## Release recommendation

**GO** for reliability patch on Sprint 11 branch: unsafe submissions rejected at the edge; Beat/autonomous scans unaffected; worker semantics explicit in logs and `error_code`.
