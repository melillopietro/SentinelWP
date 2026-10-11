# SENTINELWP — SPRINT 11 IMPLEMENTATION PLAN & EXECUTION ROADMAP
## Enterprise Packaging & Secure Deployment on Ubuntu Server LTS

**Planning Date:** 2026-10-11  
**Author:** DevSecOps Lead, Security Architect & Release Manager  
**Branch:** `feat/sentinelwp-sprint11-enterprise-packaging`  
**Base Commit:** `707edff` (594 passing tests)  
**Target Release Candidate:** `v3.7.0` (Production General Availability)  
**Scope:** Architecture Audit, Containerization, Ingress Security, Migration Orchestration, E2E Verification  

---

## 1. Executive Roadmap Overview

Sprint 11 packages SentinelWP into an enterprise-ready, reproducible, and hardened deployment for Ubuntu Server LTS using Docker Compose.

The implementation is structured into five distinct, gated phases:

```
+-------------------------------------------------------------------------------+
| Phase 1: Baseline & Architecture Audit (COMPLETE - Pending User Approval)    |
| - 594 regression tests verified                                              |
| - Baseline inventory, topology, security gaps, and migration plan drafted    |
+-------------------------------------------------------------------------------+
                                      |
                                      v [GATE: User Review & Phase 2 Approval]
+-------------------------------------------------------------------------------+
| Phase 2: Enterprise Containerization & Topology Implementation                |
| - Dockerfile.prod & docker-compose.prod.yml                                   |
| - Nginx reverse proxy configuration (TLS 1.3, CSP, HSTS, Rate Limits)        |
| - Werkzeug ProxyFix integration in app.py                                     |
| - Dedicated Celery workers (scan vs intel/maintenance)                        |
+-------------------------------------------------------------------------------+
                                      |
                                      v [GATE: Pre-Hardening Verification]
+-------------------------------------------------------------------------------+
| Phase 3: Security Hardening, SSRF Protection & Secrets Governance             |
| - Fail-closed production SSRF validation in scanners/base.py                  |
| - Non-root execution (UID 1000), read-only rootfs, cap_drop ALL               |
| - Zero published host ports for DB & Redis                                    |
| - scripts/validate_prod_env.sh (secret entropy & default credential detector) |
+-------------------------------------------------------------------------------+
                                      |
                                      v [GATE: Database Orchestration]
+-------------------------------------------------------------------------------+
| Phase 4: Database Migration Automation & Disaster Recovery                    |
| - One-shot init container: sentinelwp-migrate (alembic upgrade head)          |
| - scripts/backup_postgres.sh & scripts/restore_postgres.sh                    |
| - Disaster recovery drill verification                                        |
+-------------------------------------------------------------------------------+
                                      |
                                      v [GATE: Final Release Acceptance]
+-------------------------------------------------------------------------------+
| Phase 5: Verification, Smoke Testing & Release Certification                  |
| - End-to-end deployment verification script (scripts/verify_deployment.sh)    |
| - Regression suite execution (594+ passing tests)                            |
| - Healthcheck and metrics endpoint verification (/health, /ready, /metrics)   |
| - Tag and certify Release Candidate v3.7.0                                   |
+-------------------------------------------------------------------------------+
```

---

## 2. Detailed Phase Specifications

### Phase 1: Baseline & Architecture Audit (Current Phase)
- **Status:** Complete with the delivery of the 5 audit documents.
- **Deliverables:**
  - `docs/audit/SPRINT_11_BASELINE.md`
  - `docs/audit/SPRINT_11_DEPLOYMENT_TOPOLOGY.md`
  - `docs/audit/SPRINT_11_SECURITY_GAPS.md`
  - `docs/audit/SPRINT_11_MIGRATION_STRATEGY.md`
  - `docs/audit/SPRINT_11_IMPLEMENTATION_PLAN.md`
- **Exit Criteria:** Stop point reached. Present findings and plan to the user for formal approval before modifying application code or creating deployment configurations.

---

### Phase 2: Enterprise Containerization & Topology Implementation
- **Objective:** Create the hardened multi-container architecture for Ubuntu Server LTS.
- **Files to Create / Modify:**
  - `Dockerfile.prod`: Multi-stage build with minimal runtime footprint, non-root user `appuser` (UID 1000), and C-libraries for PostgreSQL and report generation.
  - `docker-compose.prod.yml`: 7-service topology plus migration init container, internal bridge network (`sentinelwp-backend`), named volumes, and resource limits.
  - `nginx/nginx.conf` & `nginx/conf.d/sentinelwp.conf`: Nginx gateway reverse proxy configuration with TLS termination, HSTS, secure headers, rate limits, and client request buffering.
  - `app.py`: Mount `werkzeug.middleware.proxy_fix.ProxyFix` conditionally when behind proxy or in production.
  - `core/tasks/celery_app.py`: Worker split optimization (queues `scan` vs `intel,maintenance`), `--schedule` volume configuration for beat.
- **Verification Gate:**
  - Build images successfully without cache errors.
  - Validate compose configuration syntax (`docker compose -f docker-compose.prod.yml config`).

---

### Phase 3: Security Hardening, SSRF Protection & Secrets Governance
- **Objective:** Close all vulnerabilities identified in `SPRINT_11_SECURITY_GAPS.md`.
- **Files to Create / Modify:**
  - `scanners/base.py`: Enforce fail-closed private target blocking in production mode; ignore or reject test allowlists in production.
  - `config.py`: Enforce `SESSION_COOKIE_SECURE=True` fail-closed when `ENVIRONMENT == "production"`.
  - `.env.production.example`: Fully documented enterprise environment configuration template with zero exposed default passwords.
  - `scripts/validate_prod_env.sh`: Automated preflight script checking:
    - Minimum secret entropy (32+ chars for secret key).
    - Rejection of default development credentials (`sentinelwp_dev_password`, `admin123`).
    - File permissions (`chmod 600 .env.production`).
- **Verification Gate:**
  - Unit tests verifying SSRF rejection under `ENVIRONMENT=production`.
  - Validation script correctly fails on dev secrets and passes on secure secrets.

---

### Phase 4: Database Migration Automation & Disaster Recovery
- **Objective:** Eliminate runtime DDL race conditions and operationalize disaster recovery.
- **Files to Create / Modify:**
  - `docker-compose.prod.yml`: Add `sentinelwp-migrate` service with `depends_on` conditions.
  - `scripts/backup_postgres.sh`: Atomic, compressed `pg_dump` backup script with retention rotation.
  - `scripts/restore_postgres.sh`: Verified PostgreSQL database restore drill script.
- **Verification Gate:**
  - Clean initialization test on empty volume.
  - Incremental upgrade test on existing database.
  - Backup and restore drill execution.

---

### Phase 5: Verification, Smoke Testing & Release Certification
- **Objective:** Execute full operational acceptance test and certify `v3.7.0`.
- **Files to Create / Modify:**
  - `scripts/verify_deployment.sh`: Comprehensive automated smoke test suite checking:
    1. Container healthcheck states (`docker compose ps`).
    2. Zero host port exposure for PostgreSQL and Redis.
    3. HTTPS / HTTP ingress via Nginx (port 80 -> 443 redirect, TLS handshake).
    4. Healthcheck endpoints (`/health`, `/ready`, `/metrics`).
    5. Celery worker inspection ping (`celery -A core.tasks.celery_app inspect ping`).
    6. Non-root user execution in all running containers (`ps aux` UID 1000).
    7. Read-only root filesystem enforcement.
  - Full regression test run (`pytest` - 594+ tests).
  - `docs/audit/SPRINT_11_RELEASE_READINESS.md`: Final certification report.
- **Verification Gate:**
  - 100% passing tests.
  - All automated checks pass.
  - Clean git status.

---

## 3. Inventory of Files to Create & Modify

| Phase | File Path | Action | Description |
| :---: | :--- | :---: | :--- |
| **1** | `docs/audit/SPRINT_11_BASELINE.md` | Create | Baseline environment & dependency audit |
| **1** | `docs/audit/SPRINT_11_DEPLOYMENT_TOPOLOGY.md` | Create | Enterprise container topology specification |
| **1** | `docs/audit/SPRINT_11_SECURITY_GAPS.md` | Create | Security gaps and remediation specifications |
| **1** | `docs/audit/SPRINT_11_MIGRATION_STRATEGY.md` | Create | Database lifecycle and migration plan |
| **1** | `docs/audit/SPRINT_11_IMPLEMENTATION_PLAN.md` | Create | Phase-by-phase implementation roadmap |
| **2** | `Dockerfile.prod` | Create | Hardened production multi-stage Dockerfile |
| **2** | `docker-compose.prod.yml` | Create | 7-service enterprise production compose |
| **2** | `nginx/nginx.conf` | Create | Gateway main configuration (worker processes, events) |
| **2** | `nginx/conf.d/sentinelwp.conf` | Create | Upstream proxy, TLS, headers, rate limits |
| **2** | `app.py` | Modify | Werkzeug ProxyFix middleware mounting |
| **3** | `scanners/base.py` | Modify | Production SSRF guard fail-closed |
| **3** | `config.py` | Modify | Secure session cookie validation fail-closed |
| **3** | `.env.production.example` | Create | Enterprise environment configuration template |
| **3** | `scripts/validate_prod_env.sh` | Create | Secret entropy and default credential preflight |
| **4** | `scripts/backup_postgres.sh` | Create | Production backup automation |
| **4** | `scripts/restore_postgres.sh` | Modify/Verify | Production restore drill script |
| **5** | `scripts/verify_deployment.sh` | Create | Automated deployment verification script |
| **5** | `docs/audit/SPRINT_11_RELEASE_READINESS.md` | Create | Sprint 11 release certification report |

---

## 4. Rollback & Contingency Plan

1. **Git Isolation:** All work is strictly isolated in branch `feat/sentinelwp-sprint11-enterprise-packaging`. The working tree can be reverted to commit `707edff` at any point with zero risk to main or prior sprint branches.
2. **Backward Compatibility:** All existing development and testing configurations (`Dockerfile`, `docker-compose.yml`, `docker-compose.sprint10.yml`) remain intact for local testing. The production deployment configuration uses dedicated artifacts (`Dockerfile.prod`, `docker-compose.prod.yml`).
3. **Zero Impact on Regression Baseline:** None of the 594 existing tests will be broken or bypassed. New unit and integration tests will be added specifically to cover `ProxyFix`, production SSRF guards, and secret validators.

---

## 5. Phase 1 Stop Point Confirmation

As mandated by Sprint 11 directives:
- Phase 1 is **strictly planning and architecture assessment**.
- Zero source code or deployment files have been modified.
- No new containers or infrastructure have been provisioned.
- No git commits, pushes, merges, or tags have been executed.
- All five planning artifacts have been authored and placed in `docs/audit/`.

**Awaiting user authorization to proceed to Phase 2.**
