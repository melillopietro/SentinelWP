# SENTINELWP — SPRINT 11 DEPLOYMENT TOPOLOGY SPECIFICATION
## Enterprise Multi-Container Architecture on Ubuntu Server LTS

**Audit Date:** 2026-10-11  
**Author:** Principal DevSecOps Engineer & Security Architect  
**Target Environment:** Ubuntu Server 22.04 / 24.04 LTS with Docker Compose v2.27+  
**Architecture Status:** Proposed Enterprise Architecture (Phase 1 Approved for Planning)  

---

## 1. Architectural Overview & Design Principles

The SentinelWP Enterprise Deployment Topology establishes a defense-in-depth, zero-trust network perimeter for running SentinelWP in production on Ubuntu Server LTS.

### Core Architecture Tenets
1. **Single Authorized Ingress:** Only the hardened Reverse Proxy (`sentinelwp-gateway`) listens on host interfaces (ports 80 and 443).
2. **Zero Host Exposure for Internal Stores:** PostgreSQL (`5432`) and Redis (`6379`) are NEVER bound to host ports. They exist solely within an isolated Docker network.
3. **No Target Lab Infrastructure in Production:** WordPress, MariaDB, and synthetic lab targets are strictly omitted from the production compose definition.
4. **Deterministic Initialization Pipeline:** Database schema migrations (`sentinelwp-migrate`) run as an isolated one-shot init container before the web server or workers are permitted to boot.
5. **Specialized Worker Segregation:** Scanning tasks are decoupled from intelligence and maintenance tasks into dedicated worker pools with strict memory limits and recycled child processes.
6. **Immutable Root Filesystems & Least Privilege:** All application containers execute as non-root user `appuser` (UID 1000:GID 1000) with `read_only: true`, `cap_drop: ALL`, and `no-new-privileges: true`.

---

## 2. Container Topology Specification

The complete enterprise stack comprises seven long-running services and one ephemeral initialization container:

```
[ Internet / Enterprise LAN ]
             |
             v (Host Ports 80, 443)
+-----------------------------------------------------------------------------------+
| 1. sentinelwp-gateway (Nginx Alpine)                                              |
|    - TLS 1.3 / Modern Ciphers, HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
|    - Rate Limiting (10 req/s on /api/v1/auth/login), Request Body Limit (25MB)     |
|    - Forwarding: X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host             |
+-----------------------------------------------------------------------------------+
             |
             | (Internal Bridge Network: sentinelwp-net)
             v
+-----------------------------------------------------------------------------------+
| 2. sentinelwp-web (Flask + Gunicorn 4 Workers)                                    |
|    - Port: 8080 (Internal only)                                                   |
|    - Middleware: Werkzeug ProxyFix                                                |
|    - Read-only rootfs + tmpfs [/tmp] + named volume [/app/data]                   |
+-----------------------------------------------------------------------------------+
       |                                                            |
       | (PostgreSQL Protocol: 5432)                                | (Redis Protocol: 6379)
       v                                                            v
+-----------------------------+                           +-------------------------+
| 3. sentinelwp-postgres      |                           | 4. sentinelwp-redis     |
|    - Image: postgres:16-alpi|                           |    - Image: redis:7-alpi|
|    - Port: 5432 (Internal)  |                           |    - Port: 6379 (Intern)|
|    - Volume: sentinelwp_pgda|                           |    - requirepass <token>|
|    - Healthcheck: pg_isready|                           |    - Volume: redis_data |
+-----------------------------+                           +-------------------------+
       ^                                                            ^
       |                                                            |
+-----------------------------------------------------------------------------------+
| Background Worker & Scheduling Tier                                               |
|                                                                                   |
| 5. sentinelwp-worker-scan   (Celery, Queue: 'scan', Concurrency: 4)               |
|    - Limits: --max-tasks-per-child=50 --max-memory-per-child=250000              |
|                                                                                   |
| 6. sentinelwp-worker-intel  (Celery, Queue: 'intel,maintenance', Concurrency: 2) |
|    - Limits: --max-tasks-per-child=100                                            |
|                                                                                   |
| 7. sentinelwp-beat          (Celery Beat Scheduler, Concurrency: 1)              |
|    - Schedule file: /app/data/celerybeat-schedule                                 |
+-----------------------------------------------------------------------------------+

[ Ephemeral Init Container ]
+-----------------------------------------------------------------------------------+
| 8. sentinelwp-migrate (Alembic Migration Runner)                                  |
|    - Command: alembic upgrade head                                                |
|    - Runs to completion before web/workers start (depends_on condition: service_co|
+-----------------------------------------------------------------------------------+
```

---

## 3. Detailed Service Specifications

### 3.1 Gateway Service (`sentinelwp-gateway`)
- **Image:** `nginx:1.25-alpine`
- **Host Ports:** `80:80`, `443:443`
- **Configuration Highlights:**
  - Automated HTTP to HTTPS 301 redirection.
  - TLS 1.3 preferred, TLS 1.2 minimum. Strict cipher suites (`ECDHE-ECDSA-AES256-GCM-SHA384:...`).
  - HSTS enabled: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.
  - Security headers: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.
  - Content Security Policy (CSP) tailored for the 6 workspace interfaces.
  - Rate limiting zones: `limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;`.
  - Upstream proxy pass: `http://sentinelwp-web:8080`.

### 3.2 Web Application Service (`sentinelwp-web`)
- **Image:** `sentinelwp:3.7.0` (built via production multi-stage Dockerfile).
- **Runtime Command:** `gunicorn --bind 0.0.0.0:8080 --workers 4 --threads 2 --timeout 120 --access-logfile - --error-logfile - app:app`
- **Security Context:** `user: 1000:1000`, `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`.
- **Mounts:**
  - `/app/data` (named volume `sentinelwp_appdata`, read-write for temporary report generation).
  - `/tmp` (`tmpfs: size=128M`).
- **Dependencies:** `sentinelwp-migrate` (completed successfully), `sentinelwp-postgres` (healthy), `sentinelwp-redis` (healthy).
- **Healthcheck:** `curl -f http://localhost:8080/ready || exit 1` (interval: 15s, timeout: 5s, retries: 3).

### 3.3 Database Service (`sentinelwp-postgres`)
- **Image:** `postgres:16-alpine`
- **Exposed Ports:** `5432` (on internal network only; **no host port binding**).
- **Environment:**
  - `POSTGRES_DB: sentinelwp`
  - `POSTGRES_USER: sentinelwp`
  - `POSTGRES_PASSWORD_FILE: /run/secrets/pg_password` (Docker secret / environment file).
- **Storage:** Named volume `sentinelwp_pgdata` mounted at `/var/lib/postgresql/data`.
- **Healthcheck:** `pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB` (interval: 10s, timeout: 5s, retries: 5).

### 3.4 Task Broker & Cache Service (`sentinelwp-redis`)
- **Image:** `redis:7-alpine`
- **Exposed Ports:** `6379` (on internal network only; **no host port binding**).
- **Runtime Command:** `redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes --appendfsync everysec`
- **Storage:** Named volume `sentinelwp_redisdata` mounted at `/data`.
- **Healthcheck:** `redis-cli -a $$REDIS_PASSWORD ping` (interval: 10s, timeout: 5s, retries: 5).

### 3.5 Dedicated Scan Worker (`sentinelwp-worker-scan`)
- **Command:** `celery -A core.tasks.celery_app worker -Q scan -c 4 --max-tasks-per-child=50 --max-memory-per-child=250000 --loglevel=INFO`
- **Purpose:** Executes CPU/network intensive scanner modules (DNS, TLS, HTTP, WP Core, Plugins, REST API).
- **Memory Hygiene:** Child worker processes are automatically recycled after 50 tasks or 250MB memory utilization, eliminating cumulative leaks in long-running BeautifulSoup/ReportLab processing.
- **Healthcheck:** Script-based healthcheck verifying Celery heartbeat via Redis ping.

### 3.6 Dedicated Intelligence Worker (`sentinelwp-worker-intel`)
- **Command:** `celery -A core.tasks.celery_app worker -Q intel,maintenance -c 2 --max-tasks-per-child=100 --loglevel=INFO`
- **Purpose:** Handles vulnerability database syncing (Wordfence, NVD), SLA monitoring, outbox webhook delivery, and stale job cleanup.
- **Resource Limits:** Concurrency 2 (lower overhead).

### 3.7 Beat Scheduler (`sentinelwp-beat`)
- **Command:** `celery -A core.tasks.celery_app beat --schedule=/app/data/celerybeat-schedule --loglevel=INFO`
- **Storage:** Mounted to `sentinelwp_appdata` to preserve the periodic clock file across restarts.
- **Concurrency:** Strictly 1 process; must never be scaled horizontally.

### 3.8 Database Migration Runner (`sentinelwp-migrate`)
- **Command:** `alembic upgrade head`
- **Execution Model:** One-shot ephemeral container (`restart: "no"`).
- **Orchestration:** Using Docker Compose `depends_on` with `condition: service_completed_successfully`. `sentinelwp-web`, `worker-scan`, and `worker-intel` depend on this container completing successfully before starting their processes.

---

## 4. Network Isolation & Docker Bridge Configuration

```yaml
networks:
  sentinelwp-frontend:
    driver: bridge
    internal: false
  sentinelwp-backend:
    driver: bridge
    internal: true
```

### Network Membership Table
| Service | `sentinelwp-frontend` | `sentinelwp-backend` (internal: true) | Reason |
| :--- | :---: | :---: | :--- |
| `sentinelwp-gateway` | **YES** | **YES** | Bridges incoming external HTTP traffic to internal Gunicorn |
| `sentinelwp-web` | NO | **YES** | Isolated; receives requests only from gateway; talks to DB/Redis |
| `sentinelwp-postgres` | NO | **YES** | Isolated; unreachable from host or external networks |
| `sentinelwp-redis` | NO | **YES** | Isolated; unreachable from host or external networks |
| `sentinelwp-worker-scan`| NO | **YES** | Isolated; talks to DB/Redis; makes outbound requests to targets |
| `sentinelwp-worker-intel`| NO | **YES** | Isolated; talks to DB/Redis; makes outbound requests to feeds |
| `sentinelwp-beat` | NO | **YES** | Isolated; pushes tasks into Redis broker only |
| `sentinelwp-migrate` | NO | **YES** | Isolated; applies migrations directly to PostgreSQL |

*Note: For worker containers making outbound scan and intelligence requests, `sentinelwp-backend` provides default outbound NAT while preventing any inbound connection from the host.*

---

## 5. Storage & Volume Mapping

```yaml
volumes:
  sentinelwp_pgdata:
    name: sentinelwp_pgdata
    driver: local
  sentinelwp_redisdata:
    name: sentinelwp_redisdata
    driver: local
  sentinelwp_appdata:
    name: sentinelwp_appdata
    driver: local
  sentinelwp_nginx_logs:
    name: sentinelwp_nginx_logs
    driver: local
```

---

## 6. Centralized Logging & Container Observability

1. **Standardized Logging Format:**
   - All services output JSON structured logs to `stdout` and `stderr`.
   - Python applications utilize `core.logging_config` to inject `service_name`, `request_id`, `tenant_id`, and `timestamp`.
2. **Docker Daemon Log Driver:**
   - Configure local JSON file rotation in `docker-compose.prod.yml`:
     ```yaml
     logging:
       driver: "json-file"
       options:
         max-size: "20m"
         max-file: "5"
     ```
   - Prevents disk exhaustion on Ubuntu Server host partitions.

---

## 7. Topology Acceptance Criteria

- [ ] All 7 persistent containers start up reliably via `docker compose -f docker-compose.prod.yml up -d`.
- [ ] Ingress to SentinelWP is achievable exclusively through port 80/443.
- [ ] Direct connection attempts to host ports 5432, 5433, 6379, 8080, and 8085 are rejected or refused.
- [ ] Schema migration executes automatically before web workers boot.
- [ ] Scan worker and intel worker operate concurrently without resource starvation.
- [ ] Graceful shutdown (`docker compose down`) terminates workers cleanly without data corruption.
