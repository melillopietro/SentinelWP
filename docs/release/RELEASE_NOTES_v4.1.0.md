# SentinelWP v4.1.0 — Release Notes (Draft)

**Release date (target):** 2026-10-11  
**Codename:** Enterprise  
**Git branch:** `release/sentinelwp-v4.1.0`

## Highlights
- First unified **enterprise production** release combining multi-tenant SaaS features, PostgreSQL persistence, Celery distributed scanning, and hardened container deployment.
- Independent security remediation integrated (session roles, login disambiguation, atomic job claims, SSRF depth).
- Operational tooling: backup/restore, production env validator, migration runner, isolated validation compose.

## Upgrade instructions
1. Back up PostgreSQL (`scripts/backup_postgres.sh`) and document Redis state.
2. Copy `.env.production.example` → `.env.production`; run `scripts/validate_prod_env.sh`.
3. Build/pull image `sentinelwp:4.1.0`; run `migrate` service once (`scripts/run_migrations.py --confirm`).
4. Rolling recreate: `web`, workers, `beat`, then verify `/ready`.
5. Run smoke tests (login, passive scan, report export).

## Migration requirements
- Alembic head: **`009_sprint11_schema_parity`**
- SQLite-only dev installs must migrate via documented Postgres cutover before enterprise compose.

## Rollback plan
1. Stop workers and Beat; stop web.
2. Restore PostgreSQL from last good backup (`scripts/restore_postgres.sh`).
3. Redeploy previous image tag (e.g. `sentinelwp:3.7.0` lab tag) **only** if schema compatible — prefer restore over down-migration.
4. See `docs/UPGRADE_ROLLBACK.md`.

## Known limitations
- Unrelated Git history vs public `main` v4.0.0 — see integration report before merging to GitHub.
- No multi-Beat leader election in default compose (single Beat instance by design).
- SSRF submission preflight does not replace worker enforcement.
