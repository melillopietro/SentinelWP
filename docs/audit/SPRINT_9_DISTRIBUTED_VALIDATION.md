# SentinelWP — Sprint 9 Distributed Architecture & Celery/Redis Validation Report

## 1. Executive Summary

SentinelWP features an enterprise dual-backend architecture:
1. **Local Async Runner**: SQLite + thread pool for standalone/air-gapped operations.
2. **Distributed Engine**: PostgreSQL 16 + Redis 7 + Celery for high-throughput enterprise deployments.

During Sprint 9, both deployment models and cross-component interfaces were tested against isolated containers.

---

## 2. Distributed Components Verification

### 2.1 Redis 7 Broker & Lock Manager (`127.0.0.1:6389`)
- **Connection Test**: Python `redis.from_url("redis://127.0.0.1:6389/0")` executed ping successfully.
- **Key Lifecycle & Expiry**: Synthetic key `pilot_test_key` written with 60s TTL and read back with exact byte equality (`sprint9_verified`).
- **Distributed Lock Guard**: Validated fail-closed behavior for distributed scan coordination.

### 2.2 PostgreSQL 16 Dialect & Enterprise Schema (`127.0.0.1:5439`)
- **PostgreSQL Version**: Verified PostgreSQL 16.15 on Alpine.
- **ORM / Driver**: Verified compatibility with modern SQLAlchemy 2.0 and `psycopg` (v3) driver (`postgresql+psycopg://...`).
- **Schema Initialization**: `init_db_schema()` successfully created all 45 enterprise tables in `sentinelwp_pilot` including:
  - `tenants`, `users`, `assets`, `findings`, `scan_jobs`, `scans`, `scan_authorizations`
  - `integration_outbox`, `vulnerability_records`, `cisa_kev_records`, `sla_policies`

### 2.3 Celery App & Task Queue
- **App Main**: Initialized under name `sentinelwp`.
- **Broker Connection**: Celery broker connection established to `redis://127.0.0.1:6389/0`.
- **Task Definitions**: `core.tasks.scan_tasks.run_scan_task` registered and operational.

---

## 3. Distributed Resilience & HA Test Results

The automated HA test suite (`tests/test_phase3_postgres_celery_ha.py`) was executed with 12 passed tests:
- `test_api_scan_status_reads_persistent_progress`: **PASS**
- `test_cancel_scan_job`: **PASS**
- `test_ha_scheduler_duplicate_prevention`: **PASS**
- `test_health_endpoint`: **PASS**
- `test_intel_sync_wordfence_failure_does_not_block_kev`: **PASS**
- `test_metrics_endpoint`: **PASS**
- `test_ready_endpoint`: **PASS**
- `test_retry_scan_job`: **PASS**
- `test_scan_task_successful_execution`: **PASS**
- `test_sqlite_to_postgres_migration`: **PASS**
- `test_stale_job_recovery`: **PASS**
- `test_worker_fails_closed_when_safe_active_authorization_expired`: **PASS**

---

## 4. Scope Classification (Live vs. Integration)

- **PostgreSQL 16 Schema Verification**: **CONFIRMED LIVE** (tables created via SQLAlchemy against container port 5439).
- **PostgreSQL Web App Persistence**: **PARTIAL / INTEGRATION TESTED** (validated via migration test harness; live web server ran on SQLite repository).
- **Celery Broker (Redis 7)**: **CONFIRMED LIVE** (broker connection, pool, and key lifecycle verified against container port 6389).
- **Celery Worker Execution**: **INTEGRATION TESTED** (verified via `test_scan_task_successful_execution`; standalone daemon container omitted from live pilot run).
