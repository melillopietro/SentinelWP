# SentinelWP — Sprint 5 Remaining Gaps & Backlog Audit
**Document ID:** SPRINT_5_REMAINING_GAPS  
**Sprint:** 5 (Production Hardening & Release Readiness)  
**Execution Date:** 2026-10-10  
**Status:** COMPLETED  

---

## 1. Executive Summary

Sprint 5 successfully addressed and closed the three primary distributed reliability and crash recovery gaps inherited from Sprint 4 (`S4-GAP-001`, `S4-GAP-003`, and `S4-GAP-004`). 

With the backend engine, database persistence, and distributed coordination layers now hardened and verified by 492 passing automated tests, the remaining platform gaps shift from **backend architectural defects** to **frontend usability consolidation** and enterprise infrastructure enrichments.

---

## 2. Sprint 4 Gap Resolution Status

| Gap ID | Description | Severity | Sprint 5 Resolution Status | Evidence & Verification |
| :--- | :--- | :---: | :---: | :--- |
| **S4-GAP-001** | Outbox reassessment events left stuck in `PROCESSING` after Celery worker crashes. | High | **CLOSED** | Implemented `recover_stale_outbox_events_task` with atomic lease tracking (`claimed_at`, `claimed_by`), idempotency checks against `scan_jobs`, bounded retries (3), and DLQ transitions. Verified in `tests/test_sprint5_resilience.py::TestOutboxCrashRecovery`. |
| **S4-GAP-002** | Differential scan results computed in-memory but unpersisted. | Medium | **CLOSED** | Addressed via `asset_differentials` table and `/api/v1/assets/<id>/differential` endpoint with full JSON diffs. Verified in `tests/test_sprint4_integration.py`. |
| **S4-GAP-003** | Orphaned `ScheduledRun` records left in `DISPATCHED` if scheduler or worker dies. | Medium | **CLOSED** | Implemented `reconcile_orphaned_scheduled_runs` with cross-table reconciliation against `scan_jobs` and `scans`. Verified in `tests/test_sprint5_resilience.py::TestScheduledRunRecovery`. |
| **S4-GAP-004** | `REQUIRE_DISTRIBUTED_LOCK` degraded to process-local locking on connection failure without bounded retries. | High | **CLOSED** | Added 3-attempt exponential backoff in `_get_redis_client()` and strict `RuntimeError` fail-closed semantics across `acquire()` and `release()`. Verified in `tests/test_sprint5_resilience.py::TestRedisLockResilience`. |

---

## 3. Sprint 5 Identified Backlog & Gaps

| Gap ID | Domain | Description | Severity | Target Sprint |
| :--- | :--- | :--- | :---: | :---: |
| **S5-GAP-001** | UI / UX | **Navigation Sprawl & Dashboard Fragmentation:** 14 flat sidebar links and 5 disconnected dashboards create severe cognitive load for operators. | **High** (Product UX) | **Sprint 6 (Primary Focus)** |
| **S5-GAP-002** | Front-End / Realtime | **Polling Overhead on Scan Progress:** Active scan tracking relies on JavaScript `fetch()` interval polling against `/api/scan/<id>/status` instead of Server-Sent Events (SSE) or WebSockets. | Low | Sprint 6 / 7 |
| **S5-GAP-003** | Infrastructure | **Redis Sentinel / HA Cluster Topology:** Redis client supports single-instance connection URLs (`redis://...`); enterprise cluster failover via Redis Sentinel is not natively auto-negotiated. | Medium | Sprint 7 |
| **S5-GAP-004** | Security / Auth | **First-Login Mandatory Password Rotation:** Seeded administrator credentials do not enforce an immediate password reset on initial login. | Low | Sprint 6 |

---

## 4. Gap Prioritization & Sprint 6 Scope

### Priority 1: S5-GAP-001 (UX Consolidation)
- **Rationale:** The backend is production-ready. The primary barrier to enterprise adoption is user experience and workflow ergonomics.
- **Sprint 6 Objective:** Implement the 6-workspace consolidated interface defined in `SPRINT_5_FEATURE_CONSOLIDATION.md` and `SPRINT_6_UX_ROADMAP.md`.

### Priority 2: S5-GAP-004 (First-Login Password Rotation)
- **Rationale:** Minor security hygiene enhancement to prevent default credential leakage in staging environments.
- **Sprint 6 Objective:** Add `must_change_password` boolean flag on the user record.

### Deferred Items (S5-GAP-002, S5-GAP-003)
- Realtime SSE and Redis Sentinel clustering are deferred to Sprint 7 as they require infrastructure adjustments beyond core application ergonomics.
