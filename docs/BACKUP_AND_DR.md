# SentinelWP Enterprise - Backup and Disaster Recovery (DR) Runbook

## 1. RPO & RTO Objectives

| Metric | Target | Description |
|---|---|---|
| **RPO (Recovery Point Objective)** | < 15 minutes | Maximum acceptable data loss window during a disaster. |
| **RTO (Recovery Time Objective)** | < 30 minutes | Maximum acceptable duration to restore service availability. |

---

## 2. Backup Architecture

SentinelWP provides automated, integrity-checked backup and restore capabilities supporting both PostgreSQL (Enterprise HA) and SQLite (Standalone/Airgapped) environments.

```
+-----------------------------------+
|      Live SentinelWP Database     |
+-----------------+-----------------+
                  |
                  | scripts/backup_db.py
                  v
+-----------------------------------+
|   GZIP-Compressed Backup Archive  |
|  - Raw SQL Dump / Online VACUUM   |
|  - SHA-256 Checksum Calculation   |
|  - JSON Manifest Metadata         |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|   Offsite Immutable Backup Store  |
|   (AWS S3 / GCP GCS / MinIO)      |
+-----------------------------------+
```

---

## 3. Automated Backup Execution

Use `scripts/backup_db.py` to produce a timestamped, gzip-compressed backup with SHA-256 verification and metadata manifest.

### Command Syntax:
```bash
python scripts/backup_db.py --out-dir /var/backups/sentinelwp
```

### Generated Files:
1. `sentinelwp_backup_<TIMESTAMP>.dump.gz`: Gzip-compressed binary backup.
2. `sentinelwp_backup_<TIMESTAMP>.manifest.json`: JSON manifest containing:
   - `sha256`: Cryptographic hash of the backup archive.
   - `created_at`: UTC ISO timestamp.
   - `backend`: `postgresql` or `sqlite`.
   - `size_bytes`: Compressed byte size.
   - `source`: Source connection URI / path.

---

## 4. Disaster Recovery & Restoration Procedure

To restore the SentinelWP database in a disaster scenario or test drill:

### Step 1: Verify Checksum Integrity
The restore script `scripts/restore_db.py` automatically validates the SHA-256 checksum against the manifest before initiating restoration:

```bash
python scripts/restore_db.py \
  --manifest /var/backups/sentinelwp/sentinelwp_backup_<TIMESTAMP>.manifest.json \
  --confirm
```

If the checksum does not match, the restore aborts immediately to prevent data corruption.

### Step 2: Validate Database State
Run Alembic check to ensure schema consistency:
```bash
alembic current
```

### Step 3: Run Smoke Verification
Run SentinelWP regression tests against the restored database:
```bash
pytest tests/test_wordpress_version_regression.py -q
```

---

## 5. PostgreSQL Point-In-Time Recovery (PITR)

For mission-critical production deployments, enable continuous WAL (Write-Ahead Logging) archiving:

1. Configure `archive_mode = on` and `archive_command` in `postgresql.conf`.
2. Push WAL segments to S3/GCS bucket via `wal-g` or `pgBackRest`.
3. In case of catastrophic event, replay WAL logs to any point in time within the RPO window.

---

## 6. Regular DR Drill Schedule

- **Automated Backup**: Executed every 6 hours via cron or Kubernetes CronJob.
- **Integrity Validation Drill**: Executed weekly in staging (automated restore and test run).
- **Full DR Simulation**: Conducted quarterly by the SecOps team.
