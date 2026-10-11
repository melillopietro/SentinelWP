# SentinelWP Enterprise Operations Runbook (Phase 3)

**Version:** 3.8.0-enterprise  
**Audience:** Platform Engineers, SREs, DevSecOps, Enterprise Administrators  
**Classification:** Operational Procedure Document  

---

## 1. Architecture Overview & Components

SentinelWP Phase 3 is composed of five decoupled enterprise services:

1. **`web`**: Stateless Flask application served via Gunicorn. Handles HTTP traffic, authentication, tenant isolation, scan authorization guardrails, and enqueues jobs to Redis.
2. **`worker-scan`**: Celery worker consuming the `scan` queue with concurrency limits. Executes passive and authorized safe-active vulnerability scans.
3. **`worker-intel`**: Celery worker consuming the `intel` queue. Ingests Wordfence, CISA KEV, and WordPress.org vulnerability data.
4. **`beat`**: Centralized Celery Beat scheduler. Fires scheduled scans and triggers stale job recovery sweeps on the `maintenance` queue.
5. **`db` / `redis`**: PostgreSQL 16+ persistence layer and Redis 7+ message broker.

---

## 2. Environment Variables & Configuration

Configure the following variables in `/etc/sentinelwp/sentinelwp.env` or `.env`:

```bash
# Core Environment
ENVIRONMENT=production
WSA_SECRET_KEY="<generate-with-openssl-rand-hex-32>"
BASE_URL="https://sentinel.company.internal"

# Database Configuration (PostgreSQL 16+)
DATABASE_URL="postgresql+psycopg://sentinel:secure_db_pass@postgres:5432/sentinelwp"
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=30

# Redis & Celery Message Broker
REDIS_URL="redis://:secure_redis_pass@redis:6379/0"
CELERY_BROKER_URL="redis://:secure_redis_pass@redis:6379/0"
CELERY_RESULT_BACKEND="redis://:secure_redis_pass@redis:6379/1"

# Execution Mode
SCAN_EXECUTION_BACKEND=celery   # Use 'local' ONLY for offline development/testing

# Scan Guardrails & Concurrency
SCAN_MAX_RETRIES=3
SCAN_SOFT_TIME_LIMIT=1200       # 20 minutes warning/interruption
SCAN_HARD_TIME_LIMIT=1500       # 25 minutes hard kill
MAX_CONCURRENT_SCANS_PER_TENANT=5
MAX_CONCURRENT_SCANS_PER_ASSET=2
INTEL_FRESHNESS_SLA_HOURS=24.0

# Audit & Log Retention
SCAN_JOB_RETENTION_DAYS=90
AUDIT_RETENTION_DAYS=365
```

---

## 3. Deployment & Lifecycle Management

### 3.1 Docker Compose (Recommended for Container Orchestration)

To start the full enterprise stack with health checks and dependencies:

```bash
# 1. Build images and start all services
docker compose up -d --build

# 2. Check service status
docker compose ps

# 3. View real-time logs of the scan workers
docker compose logs -f worker-scan
```

### 3.2 Manual Systemd / Bare-Metal Process Control

#### Web Application:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 --access-logfile - --error-logfile - app:app
```

#### Scan Queue Worker (Dedicated pool of 4 concurrent workers):
```bash
celery -A core.tasks.celery_app.celery_app worker -Q scan -c 4 -n worker-scan@%h --loglevel=INFO
```

#### Intelligence Queue Worker (Single concurrency to respect upstream rate limits):
```bash
celery -A core.tasks.celery_app.celery_app worker -Q intel -c 1 -n worker-intel@%h --loglevel=INFO
```

#### Maintenance & Centralized Scheduler (Celery Beat):
```bash
celery -A core.tasks.celery_app.celery_app beat -s /var/run/sentinelwp/celerybeat-schedule --loglevel=INFO
```

---

## 4. Database Migrations & Data Pipeline

### 4.1 Schema Migration via Alembic

To initialize or upgrade database schemas to the latest enterprise revision:

```bash
# Apply pending schema migrations
alembic upgrade head

# Inspect current schema version
alembic current

# Rollback one migration step (if needed)
alembic downgrade -1
```

### 4.2 SQLite to PostgreSQL Data Migration Tool

To migrate historical scans, users, assets, and threat intelligence from existing SQLite databases to PostgreSQL:

```bash
# 1. Test migration with dry-run mode (verifies connection and schema)
python scripts/migrate_sqlite_to_postgres.py --sqlite data/wsa.db --postgres "postgresql+psycopg://sentinel:pass@localhost:5432/sentinelwp" --dry-run

# 2. Execute full transactional migration with row verification
python scripts/migrate_sqlite_to_postgres.py --sqlite data/wsa.db --postgres "postgresql+psycopg://sentinel:pass@localhost:5432/sentinelwp" --batch-size 2000
```

---

## 5. High-Availability Scheduler Operations

- **Zero Duplicates Guarantee:** Scheduled scans are orchestrated by `dispatch_scheduled_scans_task` running on the `maintenance` queue.
- **Run Tracking:** Each planned slot writes a `ScheduledRun` record. The unique constraint `(schedule_id, planned_at)` ensures that if multiple workers attempt to dispatch the same run during a network partition or failover, secondary attempts are discarded (`duplicate_blocked`).

---

## 6. Stale Job Recovery & Failure Handling

If a worker node crashes or loses connectivity while executing a scan:

1. **Automatic Heartbeat Detection:**
   - Active workers emit heartbeats into `scan_jobs.heartbeat_at` at every progress step.
   - The maintenance sweeper (`recover_stale_jobs_task`) executes every 5 minutes and flags any scan in `running` status whose last heartbeat is older than 10 minutes (`stale_threshold_seconds=600`).
2. **Automatic Retry:**
   - If `attempt < max_attempts`, the job status is set to `retrying`, attempt counter is incremented, and it is re-enqueued to the `scan` queue.
   - If `attempt >= max_attempts`, the job status is marked `failed` (`error_code="STALE_WORKER_TIMEOUT"`).
3. **Manual Job Replay:**
   - Analysts or Administrators can click **Retry** on the scan detail page or execute:
     ```bash
     curl -X POST https://sentinel.company.internal/scan-job/<job_id>/retry \
          -H "Cookie: session=..."
     ```
4. **Emergency Scan Cancellation:**
   - Analysts can cancel hung or errant scans via UI or API:
     ```bash
     curl -X POST https://sentinel.company.internal/scan-job/<job_id>/cancel \
          -H "Cookie: session=..."
     ```

---

## 7. Monitoring, Probes & Observability

### 7.1 Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 5000
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 5000
  initialDelaySeconds: 10
  periodSeconds: 5
```

### 7.2 Prometheus Telemetry (`/metrics`)

The following metrics are exposed in standard Prometheus text format:
- `sentinel_scan_jobs_queued`: Current count of jobs in `queued` state.
- `sentinel_scan_jobs_running`: Current count of jobs being processed by workers.
- `sentinel_scan_jobs_failed_total`: Cumulative counter of failed scan executions.
- `sentinel_intel_freshness_seconds{source="cisa_kev"}`: Age in seconds since last successful threat intelligence ingestion.

Alerting thresholds:
- Trigger **WARNING** if `sentinel_scan_jobs_queued > 50` for > 15 minutes (Worker saturation).
- Trigger **ALERT** if `sentinel_intel_freshness_seconds > 86400` (Threat intelligence SLA breach).

---

## 8. Backup & Disaster Recovery

### 8.1 PostgreSQL Backup
```bash
pg_dump -h postgres -U sentinel -d sentinelwp -Fc -f /backups/sentinelwp_$(date +%Y%m%d_%H%M%S).dump
```

### 8.2 PostgreSQL Restore
```bash
pg_restore -h postgres -U sentinel -d sentinelwp --clean /backups/sentinelwp_YYYYMMDD_HHMMSS.dump
```
