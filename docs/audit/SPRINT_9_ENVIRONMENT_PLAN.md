# SentinelWP — Sprint 9 Environment & Infrastructure Plan

## 1. Executive Summary

This document outlines the architecture, port allocation, isolation boundaries, and lifecycle management for the **Sprint 9 Real-World Pilot Validation Environment**.

The environment provisions a dedicated, self-contained pilot laboratory with zero disruption to existing host containers, volumes, networks, or SentinelWP's production SQLite operational database.

---

## 2. Docker Topology & Service Inventory

The pilot topology is declared in `docker-compose.pilot.yml` using the dedicated Compose project name `sentinelwp-pilot` and isolated bridge network `sentinelwp-pilot-net`.

| Service Name | Container Name | Image / Base | Host Binding | Network Role | Credentials / Env |
|--------------|----------------|--------------|--------------|--------------|-------------------|
| **pilot-postgres** | `sentinelwp-pilot-postgres` | `postgres:16-alpine` | `127.0.0.1:5439:5432` | PostgreSQL 16 Enterprise DB | User: `pilot_user`, DB: `sentinelwp_pilot` |
| **pilot-redis** | `sentinelwp-pilot-redis` | `redis:7-alpine` | `127.0.0.1:6389:6379` | Celery Broker & Lock Manager | Synthetic loopback-only |
| **pilot-mariadb** | `sentinelwp-pilot-mariadb` | `mariadb:10.5` | Internal only | WordPress Lab Backend DB | User: `pilot_wp`, DB: `wordpress_pilot` |
| **pilot-wordpress**| `sentinelwp-pilot-wordpress`| `wordpress:6.4.3-php8.1-apache` | `127.0.0.1:8099:80` | WordPress 6.4.3 Target Lab | Site: `http://127.0.0.1:8099` |
| **sentinelwp-web** | Host Virtualenv / Process | Python 3.14 / Flask | `127.0.0.1:8089` | SentinelWP Unified Platform | Tenant: `pilot-enterprise-tenant` |

---

## 3. Isolation & Non-Interference Verification

### 3.1 Host Port Allocation Strategy
To avoid conflicts with active host workloads (`ransomscope-*` on 8080/8081/5433, `seating_*` on 8083, `sonarqube` on 9000), Sprint 9 strictly bound all services to dedicated, unallocated loopback ports:
- **Web App**: `127.0.0.1:8089`
- **PostgreSQL**: `127.0.0.1:5439`
- **Redis**: `127.0.0.1:6389`
- **WordPress Lab**: `127.0.0.1:8099`

All port allocations were checked prior to startup via `lsof -i` and confirmed exclusively loopback bound (`127.0.0.1`).

### 3.2 Database & Data Isolation
- **Operational Data Protection**: `data/wsa.db` was preserved unmodified.
- **Pilot Test Database**: Configured via `WSA_DATABASE_PATH=/tmp/sentinelwp_pilot_test.db`.
- **PostgreSQL Schema Isolation**: Dedicated project database `sentinelwp_pilot` verified on PostgreSQL 16 with 45 tables created via SQLAlchemy `Base.metadata.create_all()`.

---

## 4. Playwright & Browser E2E Prerequisites

- **Playwright Engine**: Installed version `1.63.0` in the local Python `.venv`.
- **Browser Binary**: Chromium headless driver installed via `playwright install chromium`.
- **Screen Resolution**: Tested at Desktop 1440x900 and Mobile Viewport 375x812 (iPhone).
- **Artifacts Output**: Full-page PNG screenshots stored in `docs/audit/screenshots/`.

---

## 5. Teardown & Decommissioning Runbook

To safely shut down the pilot laboratory without affecting other containers:
```bash
docker compose -p sentinelwp-pilot -f docker-compose.pilot.yml down -v
kill <sentinelwp_web_pid>
rm -f /tmp/sentinelwp_pilot_*.db
```
