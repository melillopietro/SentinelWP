# Changelog

All notable changes to SentinelWP are documented in this file.

## [4.1.0] — 2026-10-11

### Added
- Enterprise Docker production stack (`Dockerfile.prod`, `docker-compose.prod.yml`, Nginx TLS gateway).
- PostgreSQL 16 operational persistence with Alembic migrations through `009_sprint11_schema_parity`.
- Celery distributed scan workers, maintenance/intel queues, and autonomous Beat scheduling.
- Multi-tenant login with optional organization slug disambiguation.
- Submission-time SSRF preflight (`core/scan_submission.py`) before ScanJob enqueue.
- Structured Celery worker outcomes (`[scan_task_outcome]`) and `TARGET_BLOCKED` error code.
- Production dependency lockfile `requirements-prod.txt` and `scripts/validate_prod_env.sh`.
- Disaster recovery scripts and Sprint 11 validation compose (`docker-compose.sprint11-validation.yml`).

### Security
- Session RBAC uses canonical `session["role"]` (`get_session_role`).
- Atomic scan job claiming (`try_claim_scan_job_for_execution`) with stale worker reclaim.
- Production strict DNS (`WSA_STRICT_DNS`) and HTTP response size limits in scanners.
- Fail-closed scan target validation at web/API submission and mandatory worker enforcement.

### Changed
- Official release version aligned to **4.1.0** across runtime, health API, UI, and reports.
- Enterprise packaging consolidates Sprints 8–11 pilot, Postgres HA, and remediation gates.

### Migration
- **Required for enterprise Postgres:** run `scripts/run_migrations.py --confirm` before web/workers start.
- Supported upgrade path: SQLite/dev → Postgres with Alembic chain `001` … `009_sprint11_schema_parity`.
- Review `docs/UPGRADE_ROLLBACK.md` before production cutover.

### Known limitations
- Celery delivery is at-least-once; duplicate messages rely on DB claim idempotency.
- Submission-time SSRF checks do not eliminate DNS rebinding (TOCTOU); worker checks remain mandatory.
- GitHub `main` at v4.0.0 shares **no common Git history** with this enterprise line; integrate via documented PR strategy, not blind merge.

## Prior releases

Historical version notes for v3.x remain in `templates/changelog.html` and `docs/audit/` sprint reports.
