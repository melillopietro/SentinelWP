# SentinelWP — Sprint 7 Release Readiness & Deployment Checklist
## Release Candidate Verification, Configuration Hardening & Production Checklist

**Sprint:** Sprint 7 — Enterprise QA, Stability & Release Candidate  
**Target Branch:** `feat/sentinelwp-sprint7-release-candidate`  
**Candidate Version:** `v3.7.0-rc1`  
**Release Verdict:** **RECOMMENDED FOR CONTROLLED ENTERPRISE PILOT**  
**Test Baseline:** 520 passed, 0 failed, 13 warnings in 30.1s  

---

### 1. Release Candidate Scope & Stability Status

SentinelWP has successfully achieved stability across all functional, security, distributed, and user experience domains:
- **Workspaces:** All 6 unified workspaces operational with full RBAC and backward compatibility.
- **Scanning Pipeline:** Multi-signal detection, soft-404 suppression, and version range correlation verified.
- **Distributed Engine:** Celery task routing, Redis distributed locking, and outbox crash recovery hardened.
- **Regression Suite:** 520 automated tests passing with zero failures. Warnings reduced to 13.
- **Security:** Strict multi-tenant isolation, SSRF defenses, and tamper-evident audit logging confirmed.

---

### 2. Pre-Deployment Configuration & Security Checklist

Prior to launching in a production enterprise environment, the following configuration checklist must be satisfied:

| Check | Environment Variable / Setting | Production Requirement | Validation Status |
|---|---|---|:---:|
| **Secret Key** | `WSA_SECRET_KEY` | Must be configured to a cryptographically secure 32+ character random secret (e.g. `openssl rand -hex 32`). Never use default keys. | **Enforced by startup check** |
| **Distributed Locking** | `REQUIRE_DISTRIBUTED_LOCK` | Set to `true` to guarantee cluster-wide locking for intelligence sync. | **Enforced in RC** |
| **Redis Broker** | `REDIS_URL` | Configured to TLS-enabled Redis cluster (e.g. `rediss://...`) with auth password. | **Configurable** |
| **Database Engine** | `DATABASE_URL` | PostgreSQL 15+ with connection pooling (e.g. PgBouncer) for multi-worker scaling; SQLite for single-node pilots. | **Verified dual-mode** |
| **Session Security** | `SESSION_COOKIE_SECURE` | Set to `true` (requires HTTPS termination at load balancer or ingress). | **Default in Prod** |
| **CSRF Protection** | `WTF_CSRF_ENABLED` | Set to `true` across all UI routes. | **Enabled by default** |
| **Celery Concurrency** | `CELERY_WORKER_CONCURRENCY` | Tune based on CPU/RAM allocation (e.g., 4–8 worker processes per node). | **Documented** |

---

### 3. Production Deployment Architecture

```
                       [ Enterprise Ingress / TLS Termination ]
                                         │
                                         ▼
                      [ Gunicorn WSGI Tier (2-4 Workers) ]
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
         [ Redis Broker ]                             [ PostgreSQL / SQLite ]
                 │                                               │
         ┌───────┴───────┐                                       │
         ▼               ▼                                       │
[ Celery Worker ] [ Celery Beat ]                                │
  (Queue: scans)    (Dispatcher)                                 │
  (Queue: maint)         │                                       │
         └───────────────┴───────────────────────────────────────┘
```

---

### 4. Rollback & Disaster Recovery Procedures

1. **Database Snapshot:**
   - Execute backup before deployment: `cp data/wsa.db data/wsa.db.bak_$(date +%Y%m%d%H%M%S)`.
   - In PostgreSQL environments: run `pg_dump -Fc sentinelwp > backup.dump`.
2. **Binary & Code Rollback:**
   - Deployment rollback target: Git commit `04b33f0` (`feat/sentinelwp-sprint6-unified-ui`).
3. **Queue Drainage:**
   - In the event of emergency worker rollback: issue `celery -A core.tasks.celery_app purge` to clear transient unacknowledged scan tasks.

---

### 5. Final Release Candidate Verdict

> [!TIP] Release Candidate Status: **APPROVED FOR ENTERPRISE PILOT**  
> SentinelWP meets all operational, architectural, and security acceptance criteria for release as `v3.7.0-rc1`.  
> Codebase is hardened, test coverage is comprehensive (520 tests), and zero critical regressions exist.
