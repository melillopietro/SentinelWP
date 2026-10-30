# Enterprise Release Gate

**Product:** SentinelWP v3.7.0 (codename Pilot-Readiness)  
**Assessment date:** 2026-10-11  
**Evidence basis:** Source review, automated tests, disposable DB migration drill, running validation stack (pre-rebuild)

**Legend:** PASS | PARTIAL | FAIL | NOT VERIFIED

---

## A. Repository & process

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Sprint 11 committed as immutable SHA | **FAIL** | HEAD still `707edff`; large uncommitted tree |
| Independent audit claims verified | **PARTIAL** | P0 fixes verified in source + tests; agent markdown not trusted |
| Secrets not in Git | **PASS** | `.env*` gitignored; audit docs omit values |
| Six-workspace UI preserved | **PASS** | Only `login.html` optional slug field; `dashboard.html` minimal diff |

---

## B. Security — authentication & authorization

| Criterion | Status | Evidence |
|-----------|--------|----------|
| SWP-AUTH-001 session/API RBAC | **PASS** | `get_session_role()` + tests |
| SWP-AUTH-002 multi-tenant login | **PASS** | `authenticate_login_user()` + SQLite migration + tests |
| Bearer API key semantics unchanged | **PASS** | `verify_api_key` path untouched |
| Cross-tenant IDOR exhaustive tests | **PARTIAL** | Tenant-scoped repo patterns; limited negative API matrix |
| CSRF on browser mutations | **PASS** | Existing `tests/test_p0_security.py` |

---

## C. Security — distributed scans

| Criterion | Status | Evidence |
|-----------|--------|----------|
| SWP-DIST-001 atomic job claim | **PASS** | PG/SQLite concurrency tests |
| Terminal job state immutability | **PASS** | Unit test + repo logic |
| Stale worker recovery | **PARTIAL** | Atomic reclaim; full crash E2E not run |
| Celery acks late / redelivery | **PASS** | Config unchanged; skip-on-duplicate in worker |
| Exactly-once scan network I/O | **FAIL** (by design) | At-least-once; not claimed |

---

## D. Security — SSRF & scanner

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Production private IP block | **PASS** | `is_safe_target_url` + sprint11 packaging tests |
| Production test allowlist disabled | **PASS** | Fail-closed in prod |
| Strict DNS in production | **PASS** | Default + compose env |
| DNS rebinding TOCTOU | **NOT VERIFIED** | Dynamic lab not run |
| Response size limits | **PASS** | `WSA_MAX_HTTP_RESPONSE_BYTES` |
| Scanner TLS verification | **PARTIAL** | Opt-in; default off by design |

---

## E. PostgreSQL & migrations

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Alembic single head 009 | **PASS** | `alembic heads` + validation DB |
| Fresh install 001→009 | **PASS** | `verify_migration_upgrade_lifecycle.py` Part 1 |
| Upgrade 008→009 data preserved | **PASS** | Lifecycle script Part 2 |
| Migration prod confirmation gate | **PASS** | Lifecycle script Part 3 |
| SQLite fallback in production | **PASS** | `validate_production_config` + startup guard |
| Live prod DB upgrade | **NOT VERIFIED** | Only disposable drill DBs |

---

## F. Docker & deployment

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Non-root containers | **PASS** | Dockerfile.prod UID 1000 |
| DB/Redis not host-published (prod compose) | **PASS** | Network design |
| Nginx TLS ingress | **PASS** | Config present; validation gateway healthy |
| Resource limits | **PARTIAL** | Added to prod compose; validation compose unchanged |
| Single Celery Beat | **PARTIAL** | Documented; operator must enforce scale=1 |
| Image rebuild with remediation | **FAIL** | Running s11-val images pre-remediation |
| Image digest pinning | **NOT VERIFIED** | Tags still floating |

---

## G. Testing

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Full regression suite | **PASS** | 636 tests |
| Sprint 11 packaging tests | **PASS** | 27 tests |
| PostgreSQL integration tests | **PARTIAL** | When `:5439` / `:5432` labs available |
| Playwright user journeys | **NOT VERIFIED** | Not executed this takeover |
| Real Celery E2E scan (post-fix image) | **NOT VERIFIED** | Pending rebuild |

---

## H. Supply chain

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Pinned prod requirements | **PASS** | `requirements-prod.txt` |
| pip-audit clean | **NOT VERIFIED** | Host 3.14 could not resolve psycopg 3.1.19 |
| Python 3.12 prod runtime | **PASS** | Dockerfile.prod |

---

## I. Operational readiness

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Backup/restore scripts | **PARTIAL** | Present untracked; not re-run |
| Runbooks / deployment docs | **PARTIAL** | Present untracked; content not re-audited line-by-line |
| Monitoring endpoints | **PASS** | `/health`, `/ready` on validation web |

---

## J. Gate summary

| Area | Worst status |
|------|----------------|
| Security remediations (source) | PASS |
| Runtime deployment (containers) | FAIL (stale images) |
| Git release discipline | FAIL |
| End-user E2E | NOT VERIFIED |

---

## K. Overall gate decision

### **PARTIAL PASS → CONDITIONAL GO**

**May proceed to controlled pilot only after:**

1. Git checkpoint of all Sprint 11 + remediation work.  
2. Rebuild and redeploy application/worker images.  
3. Playwright + one authorized lab scan through Celery.  
4. `pip-audit` inside Python 3.12 prod image.

**Do not treat as general availability (GA)** until E2E and supply-chain checks complete.

---

## L. Sign-off checklist (for human operator)

- [ ] Review uncommitted diff (`git diff 707edff`)
- [ ] Approve commit message & branch strategy
- [ ] Rebuild validation stack: `docker compose -f docker-compose.sprint11-validation.yml build --no-cache`
- [ ] Redeploy without deleting volumes (or with explicit DR approval)
- [ ] Run Playwright runner
- [ ] Record pilot go-live date and rollback owner
