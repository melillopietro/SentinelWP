# SENTINELWP — SPRINT 11 BASELINE AUDIT
## Enterprise Packaging & Deployment Baseline Inventory

**Audit Date:** 2026-10-11  
**Author:** DevSecOps & Security Architecture Team  
**Git Branch:** `feat/sentinelwp-sprint11-enterprise-packaging`  
**Base Commit:** `707edff` (`feat(sprint10): distributed e2e validation, postgres restore & release hardening`)  
**Release Candidate Baseline:** `v3.7.0-rc1`  
**Regression Test Count:** 594 passing tests (0 failures, 13 warnings)  
**Target Host Operating System:** Ubuntu Server 22.04 / 24.04 LTS (x86_64 / arm64)  
**Deployment Engine:** Docker Engine 26+ with Docker Compose v2.27+  

---

## 1. Executive Summary

SentinelWP has completed Sprints 0 through 10, evolving from a monolithic SQLite prototype into an enterprise-grade WordPress Security Assessment and Posture Management (ASPM) platform. Sprint 10 successfully certified fail-closed PostgreSQL 16 persistence, distributed Celery task orchestration, Redis caching/brokerage, outbox delivery, SLA management, and dual-scanner execution.

Sprint 11 transitions SentinelWP from an ephemeral test/laboratory environment to a reproducible, hardened, and observable enterprise deployment tailored for Ubuntu Server LTS.

This document establishes the authoritative operational baseline across runtime environments, dependencies, system daemons, persistence storage, and configuration interfaces.

---

## 2. Runtime Environment & Target OS Compatibility

### 2.1 Target Operating System: Ubuntu Server LTS
| Component | Specification | Compatibility Notes |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu Server 22.04.4 LTS (Jammy) / 24.04 LTS (Noble) | Standard enterprise deployment base; LTS support through 2027/2029 |
| **Kernel Architecture** | Linux kernel 5.15+ (Jammy) / 6.8+ (Noble); x86_64 / arm64 | Container cgroups v2 supported out-of-the-box |
| **Container Engine** | Docker Engine CE 26.0+ (via official Docker APT repository) | Requires `containerd.io`, rootless or protected docker daemon socket |
| **Compose Specification** | Docker Compose Plugin v2.27+ | Native `docker compose` syntax (Compose V2 specification) |
| **System Prerequisites** | `curl`, `openssl`, `ca-certificates`, `gnupg`, `ufw`, `fail2ban` | Minimal host footprint; all application binaries reside in containers |

### 2.2 Python Runtime & Base Container Image
- **Base Image:** `python:3.12-slim-bookworm` (Debian 12 Bookworm base)
- **Host vs Container Runtime:** Host does not require Python or virtualenv installed; all execution occurs inside containerized environments.
- **Python Version:** Python 3.12.x
- **Build Requirements:** `build-essential`, `libpq-dev`, `curl` installed during multi-stage or slim build to support C-extensions (`psycopg[binary]`, `bcrypt`, `reportlab`).

---

## 3. Dependency Inventory & Packaging Review

The current `requirements.txt` contains 12 core runtime dependencies:

| Dependency | Current Specification | Target Production Pin | Purpose & Criticality |
| :--- | :--- | :--- | :--- |
| `flask` | `>=3.0.0` | `3.0.3` | Core web framework, routing, request lifecycle |
| `requests` | `>=2.31.0` | `2.31.0` | HTTP scanner probe engine, CVE intelligence fetcher |
| `openpyxl` | `>=3.1.2` | `3.1.2` | Excel (.xlsx) security report generation & full DB export |
| `reportlab` | `>=4.0.0` | `4.1.0` | Enterprise executive PDF report generation |
| `bcrypt` | `>=4.0.0` | `4.1.2` | Password hashing for local users (Blowfish crypt) |
| `python-dotenv` | `>=1.0.0` | `1.0.1` | Environment variable file loading |
| `gunicorn` | `>=21.2.0` | `21.2.0` | Production WSGI application server (Prefork worker model) |
| `sqlalchemy` | `>=2.0.0` | `2.0.29` | Enterprise ORM and PostgreSQL SQL abstraction |
| `alembic` | `>=1.13.0` | `1.13.1` | Schema migration framework and version tracking |
| `psycopg[binary]` | `>=3.1.0` | `3.1.18` | High-performance PostgreSQL 16 driver (DB-API / libpq) |
| `redis` | `>=5.0.0` | `5.0.3` | Redis client for Celery broker, result backend, sliding rate limiter |
| `celery` | `>=5.3.0` | `5.3.6` | Distributed task queue and scheduler framework |

### 3.1 Packaging Audit Findings
1. **Unpinned Versions Risk:** The repository currently specifies minimum versions (`>=`) without exact pins (`==`). In enterprise CI/CD and deployment pipelines, unpinned dependencies introduce non-deterministic builds and supply-chain vulnerability exposure.
2. **Missing Production Lockfile:** A deterministic `requirements-prod.lock` or pinned `requirements.txt` must be maintained for production releases.
3. **Missing Proxy Middleware:** Flask requires `werkzeug.middleware.proxy_fix.ProxyFix` to be explicitly imported and mounted on `app.wsgi_app` to consume reverse-proxy forwarded headers securely.

---

## 4. Current Daemon & Workload Architecture

In Sprint 10, the platform was verified with 4 core application services plus isolated supporting stores:

```
[ Ingress / Client ]
         |
         v (HTTP 8085 / 8080)
+-------------------------------------------------------------+
| sentinelwp-web (Flask + Gunicorn 4 workers)                |
+-------------------------------------------------------------+
         |                                           |
         v (SQL 5432)                                v (Redis 6379)
+-----------------------------+             +-----------------------+
| sentinelwp-postgres (PG 16) |             | sentinelwp-redis (R7) |
+-----------------------------+             +-----------------------+
         ^                                           ^
         |                                           |
+------------------------------------+      +-----------------------+
| sentinelwp-worker-scan (Celery -Q) |<-----+ sentinelwp-beat (Beat)|
| - Concurrency 4 (scan tasks)       |      +-----------------------+
+------------------------------------+                  |
         ^                                              |
         | (SQL 5432)                                   |
+------------------------------------+                  |
| sentinelwp-worker-intel (Celery)   |<-----------------+
| - Concurrency 2 (intel/maintenance)|
+------------------------------------+
```

### 4.1 Workload Roles & Queues
1. **`sentinelwp-web`**:
   - Handles HTTP/REST requests, session management, CSRF validation, user authentication, report downloads, and UI rendering across 6 workspaces.
   - Enforces PostgreSQL operational persistence guard at startup.
2. **`sentinelwp-worker-scan`**:
   - Subscribes strictly to queue: `scan`.
   - Executes multi-phase WordPress scans (DNS, SSL, Headers, Core, Plugins, Themes, Users, REST API).
   - Enforces scan authorizations, target allowlists, and finding differential reconciliation.
3. **`sentinelwp-worker-intel`**:
   - Subscribes strictly to queues: `intel`, `maintenance`.
   - Executes vulnerability feed synchronization (Wordfence, NVD), SLA evaluation, stale job recovery, risk snapshot generation, and webhook outbox deliveries.
4. **`sentinelwp-beat`**:
   - Dispatches scheduled scans every 60 seconds.
   - Triggers stale job recovery sweeps every 120 seconds.
   - Triggers periodic vulnerability intelligence feed syncs.
   - Dispatches daily risk snapshots at midnight UTC.

---

## 5. Storage & Persistence Inventory

| Storage Artifact | Storage Engine | Path / Volume | Retention Policy | Backup Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Operational Database** | PostgreSQL 16 (Alpine) | Named volume: `sentinelwp_pgdata` (`/var/lib/postgresql/data`) | Permanent / append-only audit trail | `pg_dump` compressed SQL backups |
| **Task Broker & Cache** | Redis 7 (Alpine) | Named volume: `sentinelwp_redisdata` (`/data`) | Ephemeral (AOF / RDB enabled) | Recreatable on restart |
| **Export / Report Cache** | Local filesystem | Named volume: `sentinelwp_appdata` (`/app/data`) | 7 days retention for temporary PDFs/XLSXs | Ephemeral volume mount |
| **Celery Beat Schedule** | Persistent file | Mounted volume: `sentinelwp_appdata` (`/app/data/celerybeat-schedule`) | Permanent (persists job dispatch clock) | Preserved in app volume |
| **Application Logs** | Container stdout/stderr | Docker log driver (`/var/lib/docker/containers/...`) | Rotated (10MB x 5 files max) | Host journald / rsyslog |

---

## 6. Port & Network Surface Inventory (Current vs Target)

| Service | Legacy Sprint 10 Port | Legacy Binding | Target Enterprise Binding | Exposure Justification |
| :--- | :--- | :--- | :--- | :--- |
| **Reverse Proxy (Nginx)** | N/A | None | `0.0.0.0:80`, `0.0.0.0:443` | **PUBLIC**: Only authorized ingress point |
| **Web Server (Gunicorn)** | `8085` / `8080` | `0.0.0.0:8085` | Internal Docker Network only (`8080`) | **INTERNAL ONLY**: Reverse proxy forwards traffic |
| **PostgreSQL 16** | `5433` / `5439` | `0.0.0.0:5433` (or loopback) | Internal Docker Network only (`5432`) | **INTERNAL ONLY**: No external port published |
| **Redis 7** | `6379` / `6389` | `0.0.0.0:6379` (or loopback) | Internal Docker Network only (`6379`) | **INTERNAL ONLY**: No external port published |
| **WordPress (Lab)** | `8086` | Loopback / host | **REMOVED**: Disposable lab service excluded from prod | **NONE**: Never deployed in enterprise prod |

---

## 7. Baseline Verification Status

The regression test suite was executed and confirmed prior to initiating Sprint 11 planning:
- **Test Command:** `pytest -q`
- **Results:** `594 passed, 13 warnings in 34.16s`
- **Coverage Areas Verified:**
  - Multi-tenant data segregation
  - RBAC permission guards (Admin, Analyst, Auditor, Viewer)
  - PostgreSQL adapter session scopes and transaction rollback
  - Finding lifecycle state machine and optimistic locking
  - Outbox retry and backoff mechanisms
  - Celery scan execution and differential deduplication
  - Fail-closed PostgreSQL persistence guards

**Baseline Audit Conclusion:** SentinelWP is architecturally mature and regression-free. The enterprise packaging effort will focus entirely on infrastructure containerization, network perimeter protection, secret governance, and migration orchestration without altering domain business logic.
