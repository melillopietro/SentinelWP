# SentinelWP — Operations Runbook
## Daily Maintenance, Monitoring, Worker Management & Incident Response

This runbook outlines operational procedures for system administrators and DevSecOps engineers maintaining SentinelWP in production.

---

## 1. Routine Health & Metrics Monitoring

### 1.1 Probes & Endpoints
SentinelWP exposes standardized HTTP probes over the internal and reverse proxy interfaces:

| Endpoint | Path | Expected Output | Purpose |
| :--- | :--- | :--- | :--- |
| **Liveness Probe** | `/health` | `HTTP 200` (`status: ok`) | Verifies that the Gunicorn WSGI process is alive and responding. |
| **Readiness Probe** | `/ready` | `HTTP 200` (`status: ready`) | Verifies active connections to PostgreSQL and Redis. Returns `HTTP 503` if any core dependency fails. |
| **Prometheus Metrics**| `/metrics`| `HTTP 200` (text/plain) | Exposes Prometheus application metrics, scan counters, finding gauges, and intelligence sync status. |

### 1.2 Automated Container Healthchecks
Docker Compose automatically polls service health every 10–20 seconds:
- `gateway`: Polls `curl -f http://127.0.0.1/health`
- `postgres`: Polls `pg_isready -U sentinelwp -d sentinelwp`
- `redis`: Polls `redis-cli ping`
- `web`: Polls `curl -f http://localhost:8080/ready`

View real-time container health:
```bash
docker compose -f docker-compose.prod.yml ps
```

---

## 2. Celery Worker Management & Scaling

### 2.1 Concurrency & Queues
SentinelWP segments background workloads into distinct Celery queues:
- **`scan` Queue (`sentinelwp-worker-scan`):** Dedicated to active and passive WordPress vulnerability scans.
  - Recommended concurrency: 2–4 workers per 4 CPU cores (`WORKER_SCAN_CONCURRENCY`).
  - Worker recycling: `--max-tasks-per-child=50` to release memory allocated by network sockets and parsing libraries.
  - Memory limit: `--max-memory-per-child=250000` (250 MB).
- **`intel,maintenance` Queue (`sentinelwp-worker-intel`):** Handles periodic CVE/KEV data feed synchronization and outbox event dispatch.
  - Recommended concurrency: 2 workers (`WORKER_INTEL_CONCURRENCY`).
  - Worker recycling: `--max-tasks-per-child=100`.

### 2.2 Scaling Workers Horizontally
To scale scan worker containers on a multi-core server:

```bash
# Scale scan worker to 2 container replicas
docker compose -f docker-compose.prod.yml up -d --scale worker-scan=2
```

---

## 3. Autonomous Scheduling & Celery Beat

Celery Beat autonomously evaluates cron schedules defined in the `scheduled_scans` table and dispatches due jobs into Redis.

### 3.1 Verification of Beat Operation
Inspect Beat logs to verify execution ticks:
```bash
docker compose -f docker-compose.prod.yml logs --tail=50 beat
```
Expected output:
```
[INFO] Scheduler: Sending due task core.tasks.scan_scheduler_tick
[INFO] Task core.tasks.scan_scheduler_tick[...] sent to queue
```

### 3.2 Duplicate Execution Prevention
A double-lock mechanism prevents duplicate job execution:
1. **Advisory / State Lock:** Scan scheduler evaluates whether an existing `ScheduledRun` is already `in_progress` or `dispatched` for the active time window.
2. **Scan Job Idempotency:** If two workers attempt to claim the same scan job slot concurrently, PostgreSQL unique constraints reject the secondary attempt.

---

## 4. Incident Response & Failure Scenarios

### 4.1 Redis Outage (Broker Unavailability)
- **Symptoms:**
  - `/ready` returns `HTTP 503` with `redis: error: connection_failed`.
  - Web UI fails to queue new scans (returns HTTP 500 or error notification).
  - Celery Beat logs display connection refusal errors.
- **Impact:**
  - Read-only features (viewing existing dashboards, findings, assets) remain functional.
  - Active scans in progress may fail or freeze.
- **Recovery:**
  - Restart Redis: `docker compose -f docker-compose.prod.yml restart redis`.
  - Once Redis recovers, workers reconnect automatically without restarting.

### 4.2 PostgreSQL Outage (Database Unavailability)
- **Symptoms:**
  - Both `/ready` and core UI endpoints fail closed with HTTP 500 / 503.
  - Workers back off and pause execution.
- **Impact:**
  - Entire platform unavailable until database restores connectivity.
- **Recovery:**
  - Check database logs: `docker compose -f docker-compose.prod.yml logs postgres`.
  - Verify disk space on host: `df -h`.
  - Restart PostgreSQL container: `docker compose -f docker-compose.prod.yml restart db`.

### 4.3 Stuck or Orphaned Scan Jobs
If a worker process was abruptly terminated (e.g. host OOM killer):
- The background reconciliation task (`core.tasks.reconcile_orphaned_scans`) automatically runs every 5 minutes.
- Scans whose heartbeat timestamp has not updated in $> 300$ seconds are transitioned to `failed` with error code `WORKER_HEARTBEAT_TIMEOUT`.
