# SentinelWP — Sprint 10 Persistence Architecture Assessment & Migration Plan

## Executive Summary

SentinelWP currently possesses two persistence layers:
1. **Legacy SQLite Repository Layer** (`core/repository.py` and `core/vulnerability_intelligence/repository.py`): Contains 163 public functions using direct raw SQLite cursors and SQLite-specific SQL dialects (`PRAGMA`, `INSERT OR REPLACE`, `INSERT OR IGNORE`).
2. **Enterprise SQLAlchemy 2.x Declarative Layer** (`core/db/models.py` and `core/db/repositories/`): Contains 45 declarative ORM models and 9 repository classes (79 methods) designed for PostgreSQL 16 and SQLite.

To achieve genuine, production-grade PostgreSQL persistence **without split-brain operations or breaking SentinelWP's 538-test baseline**, this document outlines the complete database operation inventory, coverage gap analysis, fail-closed all-or-nothing enforcement strategy, and phased migration plan.

---

## 1. Complete Database Operation Inventory

A comprehensive AST code audit of `core/repository.py` and `core/vulnerability_intelligence/repository.py` identified **175 total persistence operations** categorized into 10 domains:

| Domain | Entity / Scope | Functions Count | Operations in `core/repository.py` & Intel Repo |
| :--- | :--- | :---: | :--- |
| **1. Multi-Tenancy** | Tenants & Workspaces | 6 | `save_tenant`, `get_tenant_by_id`, `get_tenant_by_slug`, `list_tenants`, `update_tenant`, `delete_tenant` |
| **2. Assets** | Asset Inventory & 360 | 11 | `_row_to_asset`, `save_asset`, `get_asset`, `get_asset_by_url`, `ensure_asset_for_target`, `ensure_asset`, `list_assets`, `update_asset`, `delete_asset`, `get_portfolio_metrics`, `get_monitoring_dashboard` |
| **3. Authorization** | Scan Guardrails | 5 | `save_scan_authorization`, `get_scan_authorization`, `get_active_authorization`, `list_scan_authorizations`, `revoke_scan_authorization` |
| **4. Identity & RBAC** | Users & Credentials | 7 | `save_user`, `get_user_by_username`, `get_user_by_id`, `list_users`, `count_users`, `update_user`, `delete_user` |
| **5. Core Scanning** | Scans, Findings, Lifecycle | 17 | `save_scan`, `get_scan`, `list_scans`, `delete_scan`, `update_scan`, `_row_to_finding`, `save_finding`, `save_findings_bulk`, `get_finding`, `get_finding_by_fingerprint`, `get_findings_for_scan`, `get_findings_for_asset`, `list_findings`, `delete_finding`, `update_finding`, `transition_finding_status`, `process_scan_findings`, `purge_all_scans_and_findings` |
| **6. Distributed Jobs** | Scan Jobs & Queues | 13 | `create_scan_job`, `update_scan_job`, `get_scan_job`, `get_scan_job_by_scan_id`, `update_scan_job_progress`, `record_scan_job_heartbeat`, `mark_scan_job_status`, `count_active_scan_jobs_for_tenant`, `count_active_scan_jobs_global`, `count_active_scan_jobs_for_asset`, `find_stale_scan_jobs`, `list_scan_jobs`, `get_queue_depth_metrics` |
| **7. Scheduling & Outbox** | Scheduled Scans & Beat | 9 | `_row_to_scheduled_scan`, `save_scheduled_scan`, `get_scheduled_scan`, `list_scheduled_scans`, `delete_scheduled_scan`, `claim_scheduled_run`, `update_scheduled_run_status`, `save_outbox_event`, `get_pending_outbox_events`, `update_outbox_status` |
| **8. Audit & Logging** | Audit Events | 3 | `log_audit_event`, `list_audit_events`, `_sanitize_metadata` |
| **9. Vulnerability Intel** | CVE, KEV, Feeds | 12 | `init_vuln_intel_db`, `get_intel_sync_status`, `list_intel_sync_statuses`, `update_intel_sync_status`, `evaluate_intel_freshness`, `save_vulnerability_record`, `get_vulnerability_record`, `get_vulnerability_by_cve`, `save_cisa_kev_record`, `get_cisa_kev_record`, `is_in_cisa_kev`, `get_intel_stats`, `record_sync_state`, `get_sync_state` |
| **10. Enterprise Ext.** | SLA, Remediation, EASM, Evidence, Policies | 92 | Finding observations (3), Finding history (2), Comments (2), Lifecycle (1), Remediation (8), SLA Policies (5), Risk Acceptance (5), Integrations (5), Ticket Refs (5), Webhook deliveries (4), API Keys (6), Risk Snapshots (2), Control Mappings (2), Discovery scopes (3), Discovered assets (3), Verifications (3), Evidence (4), Policy & Versions (6), Business Units & Services (6), Data Quality (3), Technology Obs (2), Saved Views (3) |

---

## 2. Existing SQLAlchemy Coverage & Gap Matrix

### 2.1 ORM Model Coverage: 100% (45 of 45 tables)
All 45 tables already have exact SQLAlchemy 2.x Declarative Models in `core/db/models.py`.

### 2.2 Repository Class Coverage: 48% (79 of 163 methods)
Existing repositories in `core/db/repositories/` cover the primary entities:
- `TenantRepository` (7 methods)
- `AssetRepository` (15 methods)
- `UserRepository` (8 methods)
- `ScanRepository` (7 methods)
- `FindingRepository` (8 methods)
- `ScanJobRepository` (13 methods)
- `SchedulerRepository` (11 methods)
- `AuditRepository` (4 methods)
- `IntelRepository` (6 methods)

### 2.3 Identified Implementation Gaps
The following 84 operations in `core/repository.py` currently lack an explicit method in `core/db/repositories/` and rely on raw SQLite queries:
1. **Finding Lifecycle & Differential Processing**:
   - `transition_finding_status()`: Requires optimistic concurrency check (`version_id`).
   - `process_scan_findings()`: Handles bulk fingerprint diffing and status transitions.
   - `get_finding_by_fingerprint()`.
2. **Enterprise Governance Operations**:
   - Remediation actions & SLA evaluation (`create_remediation`, `add_remediation_action`, `create_sla_policy`).
   - Risk acceptance records (`create_risk_acceptance`, `get_risk_acceptance_by_finding`).
   - External integrations (`IntegrationOutboxModel` event polling).
   - Evidence records (`EvidenceModel` SHA256 deduplication).
3. **Dialect Incompatibilities**:
   - **`INSERT OR REPLACE` / `INSERT OR IGNORE`**: Present in 21 places in `core/repository.py`. PostgreSQL rejects this syntax. Must be replaced with SQLAlchemy `session.merge()` or `ON CONFLICT (id) DO UPDATE`.

---

## 3. All-or-Nothing PostgreSQL Strategy (Anti-Split-Brain)

To guarantee that the application **never** silently writes operational data to SQLite when configured for PostgreSQL:

```
[ config.py: DATABASE_URL ]
        │
        ├── Starts with "postgresql" ──► PostgreSQL Operational Mode Active
        │                                 │
        │                                 ├── Startup Check: verify_db_connectivity()
        │                                 │    └─ FAILS FAST if PG is unreachable
        │                                 │
        │                                 ├── sqlite3.connect() in _get_conn()
        │                                 │    └─ STRICTLY DISABLED (Raises RuntimeError)
        │                                 │
        │                                 └── All Repository Calls Routed to SQLAlchemy
        │
        └── Starts with "sqlite"     ──► SQLite Fallback Mode Active (Dev/Unit Tests)
                                          │
                                          └── Standard SQLite Connection
```

### 3.1 Strict Fail-Closed Startup Guard
At application initialization (`app.py` and Celery worker startup):
```python
def verify_operational_persistence_guard():
    if config.IS_POSTGRES:
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1;"))
        except Exception as exc:
            raise RuntimeError(
                f"FATAL: PostgreSQL operational database required by DATABASE_URL but unreachable at "
                f"{config.DATABASE_URL.split('@')[-1]}. Silent SQLite fallback is strictly prohibited."
            ) from exc
```

### 3.2 Elimination of Silent SQLite Fallback
In `core/repository.py`:
```python
def _get_conn() -> sqlite3.Connection:
    if config.IS_POSTGRES:
        raise RuntimeError(
            "FATAL: Operational SQLite access was attempted while PostgreSQL mode is active. "
            "All persistence operations must route through SQLAlchemy session to prevent split-brain state."
        )
    ...
```

---

## 4. Recommended Migration Strategy

### The Unified Dual-Engine Bridge Architecture
Rather than rewriting thousands of lines of call sites across `app.py`, Celery tasks, and orchestrators, we implement a **Unified Dual-Engine Bridge** inside `core/repository.py`:

1. **Preserve Public Signatures**: All 163 public signatures (`get_asset`, `save_asset`, `get_scan`, `save_scan`, etc.) remain identical.
2. **Dynamic Backend Routing**:
   Each method checks `if config.IS_POSTGRES:`:
   - **PostgreSQL Path**: Uses `session_scope()` and either delegates to `core.db.repositories.*` or performs SQLAlchemy ORM operations against `core.db.models.*`.
   - **SQLite Path**: Retains existing verified SQLite queries for complete baseline backward-compatibility.
3. **Transaction & Isolation Boundaries**:
   - Each web request / task execution opens a managed SQLAlchemy `session_scope()`.
   - Flushes and commits are handled with automatic rollback on unhandled exceptions.
   - All queries enforce `tenant_id` filtering.

---

## 5. Main Architectural Risks & Mitigations

| Risk | Description | Mitigation |
| :--- | :--- | :--- |
| **Split-Brain State** | Partial routing causes some entities (e.g. assets) in PG and others (e.g. findings) in SQLite. | Enforce all-or-nothing guard: `_get_conn()` raises `RuntimeError` if invoked in PG mode. |
| **Session Leaks** | Unclosed SQLAlchemy sessions exhaust the PostgreSQL connection pool. | Use `session_scope()` context manager with deterministic finally-block closure and `pool_pre_ping=True`. |
| **Dialect Type Mismatch** | SQLite stores booleans/datetimes as integers/strings; PostgreSQL enforces native types. | `core.db.models.py` already specifies strict column types (`Boolean`, `String(64)`, `Integer`, `SafeJSON`). |
| **Concurrency & Locks** | Row-level locking behavior differences during scheduled scan claiming. | `SchedulerRepository.claim_scheduled_run()` already uses explicit atomic update matching SQLite semantics. |
| **Baseline Regression** | Changes break the 538 passing tests in SQLite mode. | Zero modifications to SQLite code branches; dual-engine routing preserves exact SQLite behavior when `DATABASE_URL` is SQLite. |

---

## 6. Phased Implementation Roadmap

1. **Phase 1: Core Entity Routing (Auth, Tenants, Assets, Scans, Findings, Jobs, Auditing)**:
   Implement PostgreSQL routing for the primary 79 operations using existing `core.db.repositories`.
2. **Phase 2: Enterprise Governance & Lifecycle Routing**:
   Implement PostgreSQL routing for finding transitions, observations, SLA, remediation, and outbox.
3. **Phase 3: Anti-Split-Brain Tests & Startup Guard**:
   Add test suite `tests/test_sprint10_postgres_persistence.py` verifying that in PostgreSQL mode:
   - Test asset and scan result persist to PG.
   - Any attempt to touch SQLite raises an immediate error.
   - App restart retains PG data.
4. **Phase 4: Live Container E2E Validation**:
   Connect Flask, Celery worker, and Celery Beat to the live `sentinelwp-sprint10` Docker stack and execute the full WordPress scan workflow.

---

## 7. Current Docker Environment Status

The isolated `sentinelwp-sprint10` Docker Compose environment is verified **healthy and ready**:
- **PostgreSQL 16**: `sentinelwp-sprint10-postgres` running on `127.0.0.1:5439` (Healthy, DB: `sentinelwp_s10`, User: `s10_user`).
- **Redis 7**: `sentinelwp-sprint10-redis` running on `127.0.0.1:6389` (Healthy, PONG verified).
- **MariaDB 10.5**: `sentinelwp-sprint10-mariadb` running on internal stack network (Healthy).
- **WordPress 6.4.3**: `sentinelwp-sprint10-wordpress` running on `127.0.0.1:8099` (Healthy, core installed, HTTP 200).
- **Host Workloads**: All host workloads (`ransomscope-*`, `seating_*`, `sonarqube`) remain 100% isolated and untouched.
