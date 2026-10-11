# SentinelWP — Upgrade & Rollback Procedures
## Database Schema Evolution & Safe Release Migration Runbook

This runbook describes the procedure to upgrade SentinelWP to a new release and roll back safely if an issue arises.

---

## 1. Pre-Upgrade Preparation

### Step 1: Create a Pre-Upgrade Atomic Backup
Before applying any software update or database migration, capture a consistent pre-upgrade backup:

```bash
cd /opt/sentinelwp
bash scripts/backup_postgres.sh
```

Confirm that the backup archive was created in `backups/` and verified with `pg_restore --list`.

### Step 2: Preview Schema Changes (Dry Run)
Inspect the generated SQL DDL statements before applying them to production:

```bash
docker compose -f docker-compose.prod.yml run --rm migrate python3 scripts/run_migrations.py --dry-run
```

Review the SQL statements to ensure no unintended destructive actions (e.g. unexpected table drops) are queued.

---

## 2. Upgrade Execution

### Step 1: Pull New Images or Checkout Tag
```bash
git fetch --tags
git checkout tags/v4.1.0  # Or target release tag
docker compose -f docker-compose.prod.yml build
```

### Step 2: Apply Database Migrations
Run the ephemeral `migrate` init container. The runner acquires PostgreSQL advisory lock `85504753` to prevent concurrent execution:

```bash
docker compose -f docker-compose.prod.yml run --rm migrate
```

Verify that the output displays:
```
[sentinelwp.migrate] Migration successful. Database is now at revision: <new_revision>
[sentinelwp.migrate] Advisory lock released.
```

### Step 3: Rolling Restart of Application Services
Update the application containers to the newly built image:

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps web worker-scan worker-intel beat
```

### Step 4: Verify Deployment
Run the verification smoke tests:

```bash
bash scripts/verify_deployment.sh --host 127.0.0.1
```

Confirm that health and readiness endpoints return HTTP 200 with all components `connected`.

---

## 3. Rollback Procedures

If an upgrade fails, errors occur during migration, or critical defects are identified post-deployment, follow these procedures.

### Scenario A: Rollback via Pre-Upgrade Backup (Recommended)
Because database migrations often include non-reversible structural changes or data transformations that cannot be cleanly undone with `downgrade`, the authoritative rollback mechanism is restoring the pre-upgrade snapshot.

1. **Stop Application Workers and Web Services:**
   ```bash
   docker compose -f docker-compose.prod.yml stop web worker-scan worker-intel beat
   ```

2. **Restore Database from Pre-Upgrade Backup:**
   ```bash
   LATEST_BACKUP=$(ls -t backups/sentinelwp_backup_*.dump | head -n 1)
   bash scripts/restore_postgres.sh "$LATEST_BACKUP" sentinelwp
   ```

3. **Revert Application Code & Rebuild/Restart:**
   ```bash
   git checkout <previous_release_tag_or_commit>
   docker compose -f docker-compose.prod.yml build web worker-scan worker-intel beat
   docker compose -f docker-compose.prod.yml up -d web worker-scan worker-intel beat
   ```

4. **Verify Rollback:**
   ```bash
   bash scripts/verify_deployment.sh --host 127.0.0.1
   ```

---

### Scenario B: Schema-Only Downgrade via Alembic (Advanced)
If code has not yet been restarted and a migration needs to be reversed without restoring the full database dump:

```bash
# Downgrade to a specific target revision
docker compose -f docker-compose.prod.yml run --rm migrate alembic downgrade <target_revision>
```

> [!WARNING]
> Schema downgrades may drop newly created columns or indexes, permanently discarding any data entered since the upgrade. Do not perform Alembic downgrades if new user data has been written to the database. Always prefer full backup restoration for disaster recovery.
