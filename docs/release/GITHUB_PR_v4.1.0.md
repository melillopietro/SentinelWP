# Pull Request — SentinelWP v4.1.0 (Draft — do not open until authorized)

## Title
**Release: SentinelWP v4.1.0 Enterprise (Sprint 11 packaging + security remediation)**

## Base / head (proposed)
- **Base:** `main` on `https://github.com/melillopietro/SentinelWP`
- **Head:** `release/sentinelwp-v4.1.0`

## Summary
This PR introduces **SentinelWP 4.1.0**, the enterprise production line built on Sprints 8–11:
- Docker/Nginx/Celery/PostgreSQL HA deployment
- Alembic migrations through `009_sprint11_schema_parity`
- Cursor audit remediation (session RBAC, atomic scan claims, SSRF preflight + worker enforcement)
- Reliability patch SWP-REL-001/002/003

## History note (critical)
`origin/main` (`ad1de5e`, single commit “v4.0.0”) and this branch **do not share a merge-base**. This is **not** a fast-forward. Merge requires an explicit **unrelated-histories** integration with human review, or a maintainer decision to **replace** `main` with the enterprise tree after validating feature parity.

## Test plan
- [ ] `pytest tests/` (640+ passed on release candidate)
- [ ] `docker compose -f docker-compose.sprint11-validation.yml` E2E PASS
- [ ] `pip-audit -r requirements-prod.txt` (Python 3.12) exit 0
- [ ] Fresh Postgres migrate + upgrade from prior schema in lab
- [ ] Manual smoke: login, scan, reports, six workspaces

## Upgrade / migration
See `CHANGELOG.md`, `docs/UPGRADE_ROLLBACK.md`, and `docs/DEPLOYMENT_UBUNTU.md`.

## Known limitations
- Celery at-least-once semantics; DB claim provides execution idempotency
- TOCTOU/DNS rebinding requires worker-side SSRF (documented)
- Laboratory E2E ≠ full production certification
