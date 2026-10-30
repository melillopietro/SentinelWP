# Changelog

All notable changes to SentinelWP are documented in this file.

## [4.1.1] — 2026-10-30

### Fixed
- **SWP-01 & SWP-02 (Finding detail & Triage)**: Fixed Jinja2 template comparison syntax (`is not none`) preventing HTTP 500 errors when opening finding details or initiating triage (`templates/finding_detail.html`, `templates/sla.html`).
- **SWP-03 (Critical Findings drill-down)**: Synchronized continuous monitoring health counter with findings list tab to filter by `severity=critical` (`app.py`).
- **SWP-04 (CISA KEV Matches)**: Updated threat intel dashboard label to "CISA KEV Catalog Entries" and added real-time tenant asset match counter (`templates/vuln_intel_dashboard.html`, `app.py`).
- **SWP-05 (Executive report export)**: Added direct PDF export endpoint (`/reports/executive/export?format=pdf`) using ReportLab with Portfolio Metrics, Business Unit Distribution, and Top Active Exposures; preserved HTML download fallback (`app.py`, `templates/dashboard.html`).
- **SWP-06 (Executive summary metrics)**: Changed findings query join to `LEFT JOIN` in `core/repository.py` to ensure findings without asset IDs are included in portfolio metrics.
- **SWP-07 (Safe Active scan authorization)**: Supported both `auto_authorize` and `authorization_confirmed` parameters at scan submission, automatically creating a 90-day authorization window (`app.py`).
- **SWP-08 (Recurring schedule authorization guardrail)**: Enforced scan authorization checks on recurring schedule creation for Safe Active / Full profiles, failing closed unless authorized (`app.py`).
- **SWP-09 & Asset 360 (Live authorization status)**: Dynamically computed and synchronized `authorization_status` (`authorized`, `expired`, `unauthorized`) based on active windows in both Asset Inventory and Asset 360 profile (`app.py`, `templates/assets.html`, `templates/asset_detail.html`).
- **SWP-10 & Business Units (BU management & asset assignment)**: Added UI forms to create, edit, and safely delete Business Units (with guard against deleting BUs with assigned assets), plus Business Unit selector on asset registration/edit forms (`app.py`, `templates/assets.html`, `templates/asset_form.html`).
- **SWP-11 (Audit log navigation)**: Added return navigation button to Administration from the full Security Audit Trail (`templates/audit.html`).
- **SWP-12 & Admin Queue (Account access & password reset)**: Added `/forgot-password` and `/request-access` audit workflows with an administrative management queue in Settings with "Mark Handled" action (`app.py`, `templates/login.html`, `templates/settings.html`).
- **SWP-13 (SSO conditional rendering)**: Hid the Enterprise SSO / OIDC button on the login screen when OIDC is unconfigured (`app.py`, `templates/login.html`).
- **SWP-14 (Brand identity)**: Integrated SentinelWP SVG shield logo on login page and sidebar header (`templates/login.html`, `templates/base.html`).

### Added
- **Enterprise detection integrity & webshell heuristics**: Added PHP artifact signatures, soft-404 verification, and validation script (`scanners/php_artifact_scanner.py`, `scripts/enterprise_detection_validation.py`).
- **Regression test suite**: Added comprehensive test suite `tests/test_swp_functional_fixes.py` protecting against regressions on all audit findings.

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
