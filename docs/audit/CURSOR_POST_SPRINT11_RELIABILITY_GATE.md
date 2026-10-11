# SentinelWP — Post-Sprint 11 Reliability Gate

**Date (UTC):** 2026-10-11  
**Role:** Principal Distributed Systems / Enterprise QA  
**Repository:** `/Users/piero/Downloads/SentinelWP`  
**Baseline commit:** `e6ae64b9674b29a527065c775396ac3585337d48`  
**Environment:** Docker project `sentinelwp-sprint11-validation` (disposable lab data only)  
**Evidence log (gitignored):** `tests/e2e/logs/reliability_gate_20261011_192652.log`

---

## 1. Release candidate preservation

| Check | Result |
|--------|--------|
| `git rev-parse HEAD` | `e6ae64b9674b29a527065c775396ac3585337d48` |
| Working tree during investigation | **Clean** (no source commits; only this audit doc added afterward) |
| Sprint 10 / unrelated stacks | **Not modified** |
| Docker volumes | **Not deleted** |

---

## 2. Investigation: Celery `run_scan_task` returning `False`

### 2.1 Occurrences (worker-scan container, full history)

| UTC (approx) | Celery task UUID | Scan job ID | Celery result | Classification |
|--------------|------------------|-------------|---------------|----------------|
| 16:56:19 | `45c54981-…` | `c97c79a1-8b18-4fed-b9a4-2776084bb853` | **False** | SSRF worker fail-closed |
| 17:01:01 | `41e61adb-…` | `76f18ab6-6970-4e95-ab9c-9fdc244cbd5e` | **False** | SSRF worker fail-closed |
| 17:27:14 | `c67ac6ce-…` | `jstale_fd2f83c4` (2nd delivery) | **False** | Expected duplicate delivery skip (job already **completed**) |

**Total `succeeded: False` in lab worker logs:** 3. **Zero** were autonomous Beat WordPress schedules failing silently.

### 2.2 End-to-end trace (SSRF cases — not Beat)

```
Celery Beat (dispatch_scheduled_scans_task)
  → NOT involved for c97c79a1 / 76f18ab6 (no scheduled_run row)

E2E Phase 4 runner — Section 5 (Security)
  → HTTPS POST /scan/new with target http://169.254.169.254/latest/meta-data/
  → Web creates Scan + ScanJob (queued) and enqueues run_scan_task

Redis (scan queue)
  → Task delivered to worker-scan

Worker run_scan_task
  → try_claim succeeds
  → orchestrator.run() → ValueError: Target blocked: private/reserved 169.254.169.254
  → mark_scan_job_status(FAILED, SCAN_EXECUTION_ERROR)
  → return False  (Celery marks task "succeeded" with return value False)

PostgreSQL
  → scan_jobs.status = failed, error_code = SCAN_EXECUTION_ERROR
  → scans.status = failed (6 metadata-target scans in DB, all failed)
```

**Worker log excerpt (17:01:01 case):**

```
[76f18ab6-…] Unhandled error executing scan: Target blocked: Target IP address is private or reserved: 169.254.169.254
  File "/app/core/tasks/scan_tasks.py", line 216, in run_scan_task
    completed_scan = orchestrator.run()
ValueError: Target blocked: Target IP address is private or reserved: 169.254.169.254
Task … succeeded in 0.25s: False
```

### 2.3 End-to-end trace (autonomous Beat — success)

| Scan job ID | scheduled_run | Target | Worker Celery result | DB job status |
|-------------|---------------|--------|----------------------|---------------|
| `60fcaa10-cab5-4d41-a11d-31189fdaea7d` | `9b9f1939-…` **completed** | `http://host.docker.internal:8099` | **True** | completed |
| `442acc56-543b-431c-b362-d331ef871c98` | `76e4fcf8-…` **completed** | lab WordPress | **True** | completed |

Beat continued dispatching after DR (`dispatch-scheduled-scans-every-minute` in beat logs). **No scheduling defect** tied to the DR drill.

### 2.4 What `False` means in code (`core/tasks/scan_tasks.py`)

| Return `False` | Meaning |
|--------------|---------|
| Early exit | Job missing, cancelled, or **already terminal** (idempotent duplicate delivery) |
| After claim lost | Another worker holds `running` (duplicate Celery message) |
| After execution error | Scan failed (SSRF block, auth, timeout, etc.) — job marked **failed** in PostgreSQL |
| Cancellation | User cancel path |

It does **not** mean Beat failed to dispatch or Redis lost the message. It is the task’s **boolean return value**, while Celery still records the task itself as **succeeded** (no unhandled exception).

### 2.5 Root cause statement

**Primary root cause of the reported “Beat / post-DR False” uncertainty:**  
Misattribution. The two material `False` results are from the **E2E SSRF negative test** enqueueing metadata URLs via `/scan/new`. The worker correctly enforces SSRF and fails the job. This is **valid authorization/SSRF rejection at execution time**, not a Beat or DR regression.

**Contributing gap (confirmed defect, medium):**  
`/scan/new` (`app.py`) validates scan **authorization** but does **not** call `is_safe_target_url()` before `save_scan` / `create_scan_job` / `run_scan_task.delay()`. The UI can accept a target (HTTP 200) while the worker fail-closes, producing confusing UX and noisy Celery `False` returns.

**Prior validation note correction:**  
The 17:01:01 `False` occurred during **Section 5 (Security)**, immediately **before** Section 6 (DR), not after restore.

---

## 3. Restart and recovery tests

Commands executed against `sentinelwp-sprint11-validation` (see evidence log).

| Test | Command / action | Outcome |
|------|------------------|---------|
| Terminal immutability | `mark_scan_job_status(completed → running)` on disposable job | **PASS** — update rejected (`False`), status stays `completed` |
| Stale heartbeat reclaim | Synthetic `running` job, heartbeat −900s; `recover_stale_jobs_task(600)` | **PASS** — `stale_found: 1`, `recovered: 1`, job → `retrying`, attempt 2, `STALE_HEARTBEAT_RETRY` |
| Redis restart | `docker restart sentinelwp-s11-val-redis` | **PASS** — `/health` OK after ~4s |
| Worker-scan restart | `docker restart sentinelwp-s11-val-worker-scan` | **PASS** — container up; queue consumption resumed |
| Beat restart | `docker restart sentinelwp-s11-val-beat` | **PASS** — scheduler resumed (`beat: Starting…`) |
| PostgreSQL restart | `docker restart sentinelwp-s11-val-postgres` | **PASS** — `pg_isready` OK; `/ready` database+redis connected |
| Scheduled slot dedup | `SELECT schedule_id, count(*) … HAVING count(*)>1` | **PASS** — no duplicate slots in DB |
| In-flight + restart | Stale job requeued during worker restart window | Job **completed** on retry; duplicate message returned **False** (terminal skip) — consistent with at-least-once semantics |

**Volumes:** unchanged.

---

## 4. Real concurrency testing

### 4.1 Two independent Celery worker **containers** (same Redis `scan` queue)

Ephemeral second worker:

```bash
docker run -d --name sentinelwp-s11-val-worker-scan-b \
  --network sentinelwp-s11-val-backend \
  --env-file .env.sprint11.validation \
  -v sentinelwp_s11_val_appdata:/app/data \
  sentinelwp:3.7.0 \
  celery -A core.tasks.celery_app worker -Q scan -c 1 --hostname worker-b@%h --loglevel=INFO
```

Duplicate delivery test: `run_scan_task.delay(job_id)` ×2 for `reljob_ea0246fc`.

| Worker | Log |
|--------|-----|
| `celery@3149db6f92c1` (primary) | Claimed job; scan **completed successfully** |
| `worker-b@…` (secondary) | `Job already claimed by worker celery@3149db6f92c1. Skipping duplicate delivery.` |

**Result:** One network scan execution; second worker **no orchestrator run**.

### 4.2 Automated regression (host, baseline tree)

```bash
python3 -m pytest \
  tests/test_sprint11_cursor_audit_remediation.py::TestScanJobAtomicClaimPostgres \
  tests/test_sprint11_cursor_audit_remediation.py::TestScanJobAtomicClaimSqlite -q
```

**3 passed** (including live PostgreSQL concurrent claim).

### 4.3 Remaining distributed scenarios (not fully exercised in lab)

| Scenario | Risk | Lab coverage |
|----------|------|----------------|
| Beat crash between `claim_scheduled_run` and `delay()` | Orphan `dispatched` run | Partial — dedup query clean; no injected crash |
| SIGKILL mid-orchestrator I/O | Stale `running` until reaper | Reaper validated synthetically, not kill -9 during HTTP |
| Split-brain two beats | Duplicate schedule dispatch | Single beat instance by design |
| Redis total data loss | In-flight Celery messages lost | Not tested (would need flush; out of scope) |
| Cross-tenant claim | Data leak | Prevented by job PK + tenant in repo layer; not chaos-tested |

---

## 5. Confirmed defects

| ID | Severity | Description | Beat/DR related? |
|----|----------|-------------|------------------|
| **SWP-REL-001** | **Medium** | Web `/scan/new` enqueues SSRF-blocked targets; worker fails correctly but UI/Celery surface misleading success/False | **No** |
| **SWP-REL-002** | **Low** | E2E SSRF check can **PASS** with HTTP **200** if page text matches heuristics; lab still creates real failed jobs | **No** |
| **SWP-REL-003** | **Low (ops)** | Celery log line `Task … succeeded: False` conflates idempotent skips with scan failures | **No** |

**Not confirmed:** Beat scheduling defect, DR-induced transaction inconsistency, or duplicate Beat WordPress scans.

---

## 6. Proposed focused patch (approval required — not applied)

**Scope:** Close SWP-REL-001 without weakening SSRF tests.

**File:** `app.py` — `new_scan()` POST handler, after authorization and before `save_scan`:

```python
from scanners.base import is_safe_target_url
safe, block_reason = is_safe_target_url(target, resolve_dns=True)
if not safe:
    flash(f"Target blocked: {block_reason}", "error")
    # audit scan_denied / target_blocked
    return render_template("new_scan.html"), 400
```

**Optional test:** assert `/scan/new` returns 400/403 for `169.254.169.254` without creating `scan_jobs`.

**E2E runner (SWP-REL-002):** tighten assertion to require status 400/403 and zero new queued jobs for metadata URL.

No commit made per gate instructions.

---

## 7. Release recommendation

### **CONDITIONAL GO** (reliability / scheduling)

**Rationale:**

- Autonomous Beat dispatch and WordPress lab scans **complete with Celery return `True`** and `scheduled_runs` / `scan_jobs` **completed** in PostgreSQL.
- Disaster recovery drill did **not** corrupt scheduling state; duplicate slot prevention holds.
- Multi-container duplicate delivery is safely deduplicated at claim layer; stale job reaper requeues and completes.
- All `False` returns are **explained** (SSRF enforcement + idempotent duplicate delivery), not silent Beat failure.

**Conditions:**

1. Accept **SWP-REL-001** for release **or** approve the web-layer SSRF preflight patch above.
2. Train operators: **`succeeded: False`** on `run_scan_task` requires inspecting `scan_jobs.error_code` and worker traceback — not Beat health.
3. Optional hardening: chaos tests for Beat crash window and SIGKILL mid-scan before production multi-beat HA.

---

## 8. Commands reference

```bash
# Baseline
git rev-parse HEAD

# Worker False inventory
docker logs sentinelwp-s11-val-worker-scan 2>&1 | grep 'succeeded.*False'

# PostgreSQL job forensics
docker exec sentinelwp-s11-val-postgres psql -U s11_admin -d sentinelwp_s11_val -c \
  "SELECT sj.id, sj.status, sj.error_code, s.target_url, sr.id AS scheduled_run
   FROM scan_jobs sj JOIN scans s ON s.id=sj.scan_id
   LEFT JOIN scheduled_runs sr ON sr.scan_job_id=sj.id
   WHERE sj.error_code IS NOT NULL OR s.target_url LIKE '%169.254%';"

# Dual-worker duplicate delivery (see Section 4.1)
# Service restarts: docker restart sentinelwp-s11-val-{redis,worker-scan,beat,postgres}

# Pytest atomic claim
python3 -m pytest tests/test_sprint11_cursor_audit_remediation.py::TestScanJobAtomicClaimPostgres \
  tests/test_sprint11_cursor_audit_remediation.py::TestScanJobAtomicClaimSqlite -q
```

---

## 9. Stop conditions

No push, merge, tag, deploy, image publish, volume deletion, or Sprint 12 work performed.

---

## 10. Patch resolution (2026-10-11)

Authorized patch **`fix(sprint11): reject unsafe scan submissions and clarify worker outcomes`** addresses SWP-REL-001/002/003.

| Finding | Post-patch status |
|---------|-------------------|
| SWP-REL-001 | **RESOLVED** — `core/scan_submission.py` + `/scan/new` / API preflight |
| SWP-REL-002 | **RESOLVED** — E2E counts DB rows + HTTP 400 |
| SWP-REL-003 | **RESOLVED** — `[scan_task_outcome]` structured logs; bool unchanged |

Full validation: [`CURSOR_RELIABILITY_PATCH_VALIDATION.md`](CURSOR_RELIABILITY_PATCH_VALIDATION.md)
