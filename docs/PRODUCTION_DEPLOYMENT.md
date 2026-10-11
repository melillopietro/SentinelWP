# SentinelWP Enterprise - Production Deployment Guide

## 1. Architecture Overview

SentinelWP Enterprise is architected as a distributed, multi-tenant security assessment and posture management platform.

```
                    +---------------------------+
                    |    Reverse Proxy / WAF    |
                    | (NGINX / Envoy / Cloudflare)
                    +-------------+-------------+
                                  | TLS / HTTPS
                                  v
                    +---------------------------+
                    |      sentinelwp-web       |
                    | (Flask WSGI / Gunicorn)   |
                    +-------------+-------------+
                                  |
            +---------------------+---------------------+
            |                                           |
            v                                           v
+-----------------------+                   +-----------------------+
|   PostgreSQL 15+ HA   |                   |    Redis 7+ Sentinel  |
| (Primary / Replicas)  |                   | (Broker, Cache, Locks)|
+-----------------------+                   +-----------------------+
            ^                                           ^
            |                                           |
    +-------+-------------------------------------------+-------+
    |                                                           |
    v                                                           v
+-------------------------------+               +-------------------------------+
|    sentinelwp-worker-scan     |               |    sentinelwp-worker-intel    |
| (Celery Scan Workers, Queues: |               | (Celery Intel Workers, Queues:|
|  scans, batch_scans)          |               |  vulnerability_intel)         |
+-------------------------------+               +-------------------------------+
                                                ^
                                                |
                                +---------------+---------------+
                                |       sentinelwp-beat         |
                                | (Celery Beat Scheduler)       |
                                +-------------------------------+
```

---

## 2. Infrastructure Sizing Guidelines

| Component | Minimum (Staging / <100 assets) | Recommended Production (100 - 2,500 assets) | Large Enterprise (>2,500 assets) |
|---|---|---|---|
| **Web Service (`sentinelwp-web`)** | 2 vCPU, 2 GB RAM (2 instances) | 4 vCPU, 4 GB RAM (3-5 instances behind ALB) | 8 vCPU, 8 GB RAM (Auto-scaling 5-15) |
| **Scan Workers (`worker-scan`)** | 2 vCPU, 4 GB RAM (2 workers) | 4 vCPU, 8 GB RAM (4-8 workers) | 8 vCPU, 16 GB RAM (Dedicated pool, 10-30 workers) |
| **Intel Workers (`worker-intel`)** | 1 vCPU, 2 GB RAM (1 worker) | 2 vCPU, 4 GB RAM (2 workers) | 4 vCPU, 8 GB RAM (2-4 workers) |
| **PostgreSQL Database** | 2 vCPU, 4 GB RAM, 50 GB SSD | 4 vCPU, 16 GB RAM, 250 GB NVMe (Primary + Standby) | 8+ vCPU, 32+ GB RAM, Multi-AZ RDS/Aurora |
| **Redis** | 1 vCPU, 1 GB RAM | 2 vCPU, 4 GB RAM (Cluster / Sentinel HA) | 4 vCPU, 8 GB RAM (ElastiCache / MemoryDB) |

---

## 3. Database Hardening & Least-Privilege Setup

In production, database access must follow the principle of least privilege. Do **not** run the application using a PostgreSQL `superuser`.

Execute the least-privilege setup script located at `scripts/init_least_privilege_users.sql`:

```bash
# Connect as postgres superuser
psql -h <db-host> -U postgres -d sentinelwp -f scripts/init_least_privilege_users.sql
```

This establishes three distinct roles:
1. `sentinelwp_migration`: Used exclusively by CI/CD or deployment jobs running `alembic upgrade head`. Holds `CREATE`, `ALTER`, `DROP`, `REFERENCES`.
2. `sentinelwp_app`: Used by `sentinelwp-web` and Celery workers for runtime operations. Restricted to `SELECT`, `INSERT`, `UPDATE`, `DELETE` on application tables. Cannot alter schemas.
3. `sentinelwp_readonly`: Used for reporting, analytics, read replicas, and disaster recovery verification. Restricted strictly to `SELECT`.

---

## 4. Environment Configuration & Production Enforcement

SentinelWP enforces production safety checks via `validate_production_config(enforce=True)` in `config.py`.

### Required Production Environment Variables:

```env
# Application Core
ENVIRONMENT=production
SECRET_KEY=<cryptographically-secure-random-key-min-32-chars>
LOG_FORMAT=json
LOG_LEVEL=INFO

# Database Connection (PostgreSQL required in production)
DATABASE_URL=postgresql://sentinelwp_app:<secure-password>@postgres.internal:5432/sentinelwp

# Asynchronous Task Execution (Celery required in production)
SCAN_EXECUTION_BACKEND=celery
REDIS_URL=redis://:redis_auth_token@redis.internal:6379/0
CELERY_BROKER_URL=redis://:redis_auth_token@redis.internal:6379/0
CELERY_RESULT_BACKEND=redis://:redis_auth_token@redis.internal:6379/1

# Security & Session Settings
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax

# Secrets Provider (vault, file, or composite)
SECRETS_PROVIDER=composite
SECRETS_FILE_PATH=/run/secrets
VAULT_ADDR=https://vault.internal:8200
VAULT_ROLE_ID=<approle-role-id>
VAULT_SECRET_ID=<approle-secret-id>

# SSO / OIDC (Optional, if enabled)
OIDC_ENABLED=True
OIDC_ISSUER_URL=https://sso.organization.com
OIDC_CLIENT_ID=sentinelwp-production
OIDC_CLIENT_SECRET=<oidc-client-secret>
OIDC_REDIRECT_URI=https://sentinelwp.organization.com/auth/oidc/callback
```

---

## 5. Deployment Procedure

### Step 1: Execute Database Migrations
Always run Alembic migrations prior to rolling out new application containers:
```bash
DATABASE_URL=postgresql://sentinelwp_migration:<migration-password>@postgres.internal:5432/sentinelwp \
alembic upgrade head
```

### Step 2: Verify Single Alembic Head
```bash
alembic heads
# Expected output: a single clean revision hash (e.g. 0004_...)
```

### Step 3: Launch Web & Worker Services
Using Docker Compose or Kubernetes manifests:
```bash
docker compose -f docker-compose.yml up -d --remove-orphans
```

### Step 4: Health and Readiness Checks
Verify the deployment via HTTP endpoints:
- `GET /health`: Basic liveness probe (returns `{"status": "ok", "service": "sentinelwp"}`)
- `GET /ready`: Readiness probe verifying PostgreSQL connection and Redis connectivity.
- `GET /metrics`: Operational metrics (total scans, active jobs, findings counts).
