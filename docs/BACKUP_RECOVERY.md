# SentinelWP — Backup & Disaster Recovery Guide
## PostgreSQL Backup Automation, Integrity Verification & Restore Runbook

This guide covers automated backups, integrity validation, and disaster recovery restoration for the SentinelWP PostgreSQL datastore.

---

## 1. Backup Architecture & Tooling

SentinelWP utilizes atomic, compressed PostgreSQL custom-format archives (`pg_dump -Fc`) executed via [`scripts/backup_postgres.sh`](file:///Users/piero/Downloads/SentinelWP/scripts/backup_postgres.sh).

### Key Technical Characteristics:
- **Format:** PostgreSQL Custom Archive (`-Fc`), enabling parallel restoration, selective table restoration, and header verification.
- **Atomic Snapshots:** Uses PostgreSQL Multi-Version Concurrency Control (MVCC) to capture consistent point-in-time snapshots without locking tables or interrupting active scans.
- **Restricted Permissions:** Backup files are created with permissions `0600` (`chmod 600`) to prevent unauthorized access.
- **Automated Retention:** Retains the 14 most recent backups by default, automatically purging older snapshots.
- **Integrity Verification:** Each archive is validated immediately upon creation using `pg_restore --list`.

---

## 2. Automated Scheduled Backups (Cron)

To schedule daily automated backups on the Ubuntu Server host:

```bash
# Open crontab for operator user
crontab -e

# Add daily backup job at 02:30 AM UTC:
30 2 * * * /bin/bash /opt/sentinelwp/scripts/backup_postgres.sh >> /var/log/sentinelwp_backup.log 2>&1
```

Confirm that the output log is reviewed periodically.

---

## 3. Manual Backup Execution

To generate a manual backup on demand (e.g. before an upgrade or maintenance window):

```bash
cd /opt/sentinelwp
bash scripts/backup_postgres.sh
```

Example output:
```
[sentinelwp.backup] Starting atomic PostgreSQL backup...
[sentinelwp.backup] Target container: sentinelwp-postgres | Database: sentinelwp
[sentinelwp.backup] Dump archive generated: backups/sentinelwp_backup_20261011_174500.dump
[sentinelwp.backup] Archive integrity verified (46 tables found in TOC).
[sentinelwp.backup] Backup completed successfully in 0.10s.
```

---

## 4. Disaster Recovery Restoration Procedure

To restore a database from an existing backup archive, use [`scripts/restore_postgres.sh`](file:///Users/piero/Downloads/SentinelWP/scripts/restore_postgres.sh).

### Step 1: Pre-Restoration Inspection
Verify the contents and header of the chosen backup file:

```bash
pg_restore --list backups/sentinelwp_backup_20261011_174500.dump | head -n 30
```

### Step 2: Stop Active Application Services
To ensure consistent restoration without concurrent database writes, stop web and worker services:

```bash
docker compose -f docker-compose.prod.yml stop web worker-scan worker-intel beat
```

### Step 3: Execute Database Restore
Run the restore script specifying the backup archive and target database:

```bash
bash scripts/restore_postgres.sh backups/sentinelwp_backup_20261011_174500.dump sentinelwp
```

The script will:
1. Validate that the archive file exists and has a valid `pg_dump` header.
2. Require explicit confirmation if restoring over an existing populated database.
3. Terminate existing open database connections to `sentinelwp`.
4. Restore all schemas, tables, constraints, sequences, and indexes with `--clean --if-exists`.
5. Verify post-restore table count and data integrity.

### Step 4: Restart Application Stack
```bash
docker compose -f docker-compose.prod.yml start web worker-scan worker-intel beat
bash scripts/verify_deployment.sh --host 127.0.0.1
```

---

## 5. Recovery Objectives (RPO & RTO Expectations)

- **Recovery Point Objective (RPO):** With daily cron backups, maximum data loss window is 24 hours. For enterprise deployments requiring $\le 1$ hour RPO, configure WAL archiving (`archive_mode = on`, `archive_command = '...'`) or increase cron backup frequency to hourly.
- **Recovery Time Objective (RTO):** In controlled laboratory drills, restoration of small databases ($\approx 10$ MB) completed in **0.28 seconds**. Actual production RTO will scale with database volume, disk IOPS, and network throughput. Regular periodic restore drills into disposable test environments are recommended to benchmark RTO under realistic production data volumes.
