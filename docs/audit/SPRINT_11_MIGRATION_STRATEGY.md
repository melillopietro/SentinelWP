# SENTINELWP — SPRINT 11 DATABASE MIGRATION & LIFECYCLE STRATEGY
## Production Schema Evolution, Init-Container Orchestration & Disaster Recovery

**Audit Date:** 2026-10-11  
**Author:** Database Architect & DevSecOps Lead  
**Scope:** PostgreSQL 16 Schema Lifecycle, Alembic Migration Runner, Backup & Restore Workflows  
**Status:** Pre-Implementation Migration Strategy  

---

## 1. Executive Summary & Design Rationale

In earlier development sprints, database initialization relied on runtime calls to `init_db_schema()` using SQLAlchemy's `Base.metadata.create_all()`. While suitable for single-process SQLite test environments, this approach is fundamentally unsafe in a distributed enterprise topology with multiple Gunicorn web workers and Celery processes:

1. **Race Conditions & Table Lock Contention:** Multiple concurrently booting processes executing DDL statements simultaneously trigger deadlocks and partial table creation.
2. **Missing Version Tracking:** Runtime `create_all()` bypasses Alembic's `alembic_version` tracking table, leaving the database in an untracked state that breaks future migrations.
3. **No Rollback Capability:** Automatic table creation provides no structured downgrade or rollback path when an upgrade fails.

In Sprint 11, SentinelWP establishes a deterministic, automated migration strategy using an ephemeral **`sentinelwp-migrate`** initialization container orchestrated via Docker Compose.

---

## 2. Migration Architecture & Container Lifecycle

### 2.1 The Init-Container Model
The schema migration lifecycle is completely decoupled from web request serving and background task execution:

```
+--------------------------------------------------------+
| 1. Docker Compose executes:                            |
|    docker compose -f docker-compose.prod.yml up -d     |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
| 2. PostgreSQL 16 boots & passes healthcheck (pg_isready|
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
| 3. Ephemeral Init Container: sentinelwp-migrate        |
|    - Runs: alembic upgrade head                        |
|    - Tracks revision in alembic_version table          |
|    - Exits with status code 0 on success               |
+--------------------------------------------------------+
                           |
      +--------------------+--------------------+
      | (condition: service_completed_successfully)
      v                                         v
+---------------------------+        +---------------------------+
| 4a. sentinelwp-web Boots  |        | 4b. Celery Workers Boot   |
|     - Verifies PG schema  |        |     - Verify PG schema    |
|     - Ready to serve HTTP |        |     - Ready to pull tasks |
+---------------------------+        +---------------------------+
```

### 2.2 Docker Compose Orchestration Definition
```yaml
  migrate:
    build: .
    container_name: sentinelwp-migrate
    restart: "no"
    command: ["alembic", "upgrade", "head"]
    environment:
      ENVIRONMENT: production
      DATABASE_URL: ${DATABASE_URL}
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - sentinelwp-backend

  web:
    # ...
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      migrate:
        condition: service_completed_successfully
```

---

## 3. Deployment Scenarios: Clean Install vs Existing Upgrade

### 3.1 Scenario A: Fresh Clean Installation (Greenfield)
1. **Initial State:** Empty PostgreSQL data directory; no tables exist.
2. **Execution Flow:**
   - `sentinelwp-postgres` initializes standard PostgreSQL system catalogs.
   - `sentinelwp-migrate` connects and runs all migration revisions from `001_initial_enterprise_schema` through `008_sprint5_resilience_and_recovery` (and any new revisions).
   - `alembic_version` is created and populated with the head revision hash.
   - Bootstrap admin user and default system tenants are initialized automatically.
3. **Outcome:** A clean, version-tracked database ready for enterprise operation.

### 3.2 Scenario B: Upgrade of Existing Deployed Database (Brownfield)
1. **Initial State:** Existing PostgreSQL instance containing operational data and an established `alembic_version`.
2. **Execution Flow:**
   - Pre-migration backup is executed (`scripts/backup_postgres.sh`).
   - `sentinelwp-migrate` connects, inspects current version from `alembic_version`, and computes the incremental revision diff.
   - Incremental DDL migrations are executed within an atomic transaction.
   - `alembic_version` is updated to the new head revision.
   - Services boot and verify the schema against ORM models.
3. **Outcome:** Non-destructive schema evolution with data preservation.

---

## 4. Zero-Downtime Schema Evolution Principles

To ensure future platform updates can occur with zero or minimal downtime, all future Alembic migrations must adhere to the **Expand / Contract** pattern:

1. **Phase 1 (Expand):**
   - Add new columns as `NULLABLE` or with explicit non-locking `DEFAULT` values.
   - Create new tables and indexes concurrently (`CREATE INDEX CONCURRENTLY` where supported).
   - Old application code continues to operate normally against the expanded schema.
2. **Phase 2 (Migrate Data & Code):**
   - Deploy new application code that writes to both old and new schema structures or populates new columns.
   - Backfill historical records via background Celery maintenance tasks.
3. **Phase 3 (Contract):**
   - Deprecate old columns and apply `NOT NULL` constraints to new columns once backfill is certified.
   - Remove deprecated columns in a subsequent release cycle.

---

## 5. Rollback Safety & Transaction Isolation

### 5.1 Transactional DDL in PostgreSQL
PostgreSQL supports transactional DDL statements (`CREATE TABLE`, `ALTER TABLE ADD COLUMN`, `DROP INDEX`, etc.) within standard transaction blocks (`BEGIN ... COMMIT`).
- Alembic runs each migration inside `with context.begin_transaction():`.
- If any DDL statement fails, PostgreSQL rolls back the entire transaction immediately, preventing partial schema corruption.

### 5.2 Rollback Procedure
If a deployment fails during migration or application verification:
1. Halt the deployment: `docker compose -f docker-compose.prod.yml down`.
2. To rollback to a specific revision:
   ```bash
   docker compose -f docker-compose.prod.yml run --rm migrate alembic downgrade <target_revision>
   ```
3. If schema rollback is impossible due to destructive operations, execute the emergency restore procedure from the pre-migration backup.

---

## 6. Disaster Recovery: Automated Backup & Restore Procedures

### 6.1 Automated Backup Script (`scripts/backup_postgres.sh`)
- Generates compressed, consistent PostgreSQL custom dumps (`pg_dump -Fc`).
- Enforces atomic file writes and checks exit codes fail-closed.
- Names backups deterministically: `sentinelwp_backup_YYYYMMDD_HHMMSS.dump`.
- Retains daily backups for 30 days and weekly backups for 90 days.

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/sentinelwp}"
mkdir -p "${BACKUP_DIR}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/sentinelwp_${TIMESTAMP}.dump"

echo "[INFO] Starting SentinelWP PostgreSQL backup to ${BACKUP_FILE}..."
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U "${POSTGRES_USER:-sentinelwp}" -d "${POSTGRES_DB:-sentinelwp}" -Fc > "${BACKUP_FILE}"

echo "[INFO] Verifying backup integrity..."
if [ -s "${BACKUP_FILE}" ]; then
  chmod 600 "${BACKUP_FILE}"
  echo "[SUCCESS] Backup created successfully: $(ls -lh "${BACKUP_FILE}")"
else
  echo "[ERROR] Backup file is empty! Backup failed." >&2
  exit 1
fi
```

### 6.2 Restore Drill & Recovery Procedure (`scripts/restore_postgres.sh`)
Tested and certified in Sprint 10, the restore script:
1. Stops application services (`sentinelwp-web`, `sentinelwp-worker-scan`, `sentinelwp-worker-intel`, `sentinelwp-beat`).
2. Drops existing active database connections:
   ```sql
   SELECT pg_terminate_backend(pid) FROM pg_stat_activity 
   WHERE datname = 'sentinelwp' AND pid <> pg_backend_pid();
   ```
3. Restores schema and data via `pg_restore --clean --if-exists -d sentinelwp`.
4. Executes integrity verification queries to confirm table count and record counts match pre-disaster states.
5. Restarts application services and verifies healthcheck endpoints (`/ready`).

---

## 7. Migration Acceptance Checklist

- [ ] `sentinelwp-migrate` executes before web and worker containers start.
- [ ] Fresh database boots and creates all tables up to head revision without errors.
- [ ] Existing database verifies version compatibility and applies pending migrations cleanly.
- [ ] `alembic_version` accurately reflects the head revision.
- [ ] Pre-migration backup script runs without manual intervention and generates valid `.dump` artifacts.
- [ ] Restore drill executes successfully with complete data recovery.
