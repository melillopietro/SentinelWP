# Sprint 11 — Independent Security Audit Remediation

**Date:** 2026-10-11  
**Branch:** `feat/sentinelwp-sprint11-enterprise-packaging`  
**Baseline HEAD (unchanged):** `707edff3ef088d6ab52a1235f4fcc03bb7167557`  
**Regression (post-remediation):** **636 passed**, 14 warnings (~39s, full `tests/` suite)

---

## Summary

| Finding ID | Status | Release blocker cleared |
|------------|--------|-------------------------|
| SWP-AUTH-001 | **Confirmed — Fixed** | Yes |
| SWP-DIST-001 | **Confirmed — Fixed** | Yes |
| SWP-AUTH-002 | **Confirmed — Fixed** (SQLite schema + login resolver) | Yes |
| SWP-SSRF-001 | **Partially confirmed — Hardened** | Mitigated (strict DNS default in prod) |
| SWP-SSRF-002 | **Needs dynamic testing** | Residual TOCTOU (industry-standard) |
| Terminal `mark_scan_job_status` | **Confirmed — Fixed** | Yes |
| Stale recovery race | **Partially confirmed — Fixed** (atomic reclaim) | Yes |
| Env admin variable names | **Confirmed — Fixed** (`.env.production.example`) | No (docs) |
| Scanner TLS verify | **Hardening** (`WSA_SCANNER_TLS_VERIFY`) | Documented |
| Adapter docstring drift | **Confirmed — Fixed** | No |
| Docker resource limits / Beat HA | **Hardening — Documented** | No |

**Updated release recommendation:** **CONDITIONAL GO** for controlled pilot after committing this remediation set and running production compose smoke on a disposable lab (not executed in this session).

---

## SWP-AUTH-001 — REST API session role mismatch

| Field | Detail |
|-------|--------|
| **Status** | Confirmed |
| **Root cause** | Login stored `session["role"]`; `require_scope` read `session["user_role"]`, defaulting all session API callers to viewer. |
| **Files changed** | `core/api_auth.py`, `core/auth/session_roles.py`, `tests/test_sprint11_security_remediation.py`, `tests/test_p0_security.py` |
| **Fix** | Canonical `get_session_role()` reads `role` then legacy `user_role`; sets `g.role` on session auth. API-key path unchanged. |
| **Tests** | API matrix: admin/analyst/viewer, 401/403, API key scopes, tenant binding |
| **Evidence** | `636 passed` including `TestApiSessionAuthorizationMatrix` |
| **Residual risk** | Low — API keys remain separate trust path |
| **Release blocker** | Cleared |

---

## SWP-DIST-001 — Duplicate scan job execution

| Field | Detail |
|-------|--------|
| **Status** | Confirmed |
| **Root cause** | Unconditional `mark_scan_job_status(RUNNING)` before scanner work; no compare-and-swap on job state. |
| **Files changed** | `core/db/repositories/scan_job_repo.py`, `core/db/adapter.py`, `core/repository.py`, `core/tasks/scan_tasks.py`, `core/tasks/maintenance_tasks.py` |
| **Fix** | `try_claim_scan_job_for_execution()` — conditional `UPDATE … WHERE status IN ('queued','retrying')` with `RETURNING` (PostgreSQL) / rowcount (SQLite). Scanner starts only after successful claim. Duplicate Celery delivery skips if another worker holds `RUNNING`. |
| **Tests** | SQLite + live PostgreSQL concurrent claim (`TestScanJobAtomicClaimSqlite`, `TestScanJobAtomicClaimPostgres`) |
| **Evidence** | Exactly one winner in 2- and 4-thread claim tests |
| **Residual risk** | **At-least-once** Celery delivery remains; network scan is **not** exactly-once, but duplicate **job execution** is prevented when claim semantics hold. |
| **Release blocker** | Cleared |

### Terminal status immutability

| Field | Detail |
|-------|--------|
| **Status** | Confirmed |
| **Fix** | `mark_status` / SQLite `mark_scan_job_status` refuse transitions from terminal states (idempotent same-status only). |
| **Tests** | `TestScanJobAtomicClaimSqlite::test_terminal_status_immutable` |

### Stale recovery

| Field | Detail |
|-------|--------|
| **Status** | Partially confirmed |
| **Fix** | `try_reclaim_stale_scan_job_for_retry()` atomically moves stale `running` → `retrying`; maintenance task skips if reclaim fails (healthy worker recovered). |
| **Tests** | Covered indirectly via reclaim implementation; full worker crash E2E not run |

---

## SWP-AUTH-002 — Multi-tenant login ambiguity

| Field | Detail |
|-------|--------|
| **Status** | Confirmed |
| **Root cause** | Login used global `get_user_by_username`; legacy SQLite had `username UNIQUE` preventing per-tenant duplicates. |
| **Files changed** | `core/auth/login.py`, `app.py`, `templates/login.html`, `core/repository.py` (SQLite migration), `core/db/repositories/user_repo.py`, `core/db/adapter.py` |
| **Fix** | `authenticate_login_user()` with optional `tenant_slug`; ambiguous multi-match without slug returns `None` (generic failure at UI). SQLite migrated to `UNIQUE(tenant_id, username)`. |
| **Tests** | `TestMultiTenantLoginResolution` |
| **Evidence** | Slug disambiguation + ambiguous same-password rejection |
| **Residual risk** | Low for PostgreSQL (already composite unique); SQLite dev DBs auto-migrate on `init_db()` |
| **Release blocker** | Cleared |

---

## SWP-SSRF-001 / SWP-SSRF-002 — DNS fail-open

| Field | Detail |
|-------|--------|
| **Status** | SWP-SSRF-001 partially confirmed; SWP-SSRF-002 needs dynamic testing |
| **Root cause** | Non-strict DNS allowed hostname approval when resolution failed. |
| **Files changed** | `config.py` (`strict_dns_resolution_required()`), `scanners/base.py` |
| **Fix** | Production defaults to strict DNS (`WSA_STRICT_DNS=true` in `.env.production.example`); unresolved hostnames fail closed when strict. Hop-by-hop redirect validation unchanged. |
| **Tests** | `TestStrictDnsProduction`, existing SSRF suites still pass |
| **Residual risk** | DNS rebinding TOCTOU between validate and connect (mitigated industry-wide via strict DNS + per-hop checks, not eliminated) |
| **Release blocker** | Mitigated for pilot with `WSA_STRICT_DNS=true` |

---

## Secondary items

### Scanner TLS (`WSA_SCANNER_TLS_VERIFY`)

- **Default:** `false` — preserves ability to assess targets with broken/self-signed TLS (findings still describe TLS issues).
- **Production option:** set `WSA_SCANNER_TLS_VERIFY=true` when all targets have valid public certificates.
- **Limitation:** Verification enabled may reduce visibility into certificate misconfiguration on intentionally invalid certs.

### Environment template

- `.env.production.example` now uses `WSA_ADMIN_USERNAME` / `WSA_ADMIN_PASSWORD` aligned with `config.py`.

### Adapter documentation

- Stale “Phase 5 NotImplementedError” header replaced in `core/db/adapter.py`.

### Docker / Beat (hardening — not implemented in compose)

- **Celery Beat:** run **single** beat instance per deployment (`celerybeat-schedule` on shared volume).
- **Resource limits:** recommend `mem_limit` / CPU caps in production orchestration (Kubernetes/systemd) — not added to compose to avoid breaking dev compose compatibility.

---

## Validation performed

| # | Activity | Result |
|---|----------|--------|
| 1 | Targeted API authorization tests | Pass |
| 2 | Tenant-aware authentication tests | Pass |
| 3 | PostgreSQL atomic claim concurrency | Pass (live PG on `:5439`) |
| 4 | Celery duplicate delivery | Logic covered via claim + scan_tasks skip path (unit via integration tests) |
| 5 | Worker recovery | Atomic reclaim implemented; full crash E2E not run |
| 6 | SSRF strict DNS tests | Pass |
| 7 | Full repository regression | **636 passed** |
| 8 | Docker laboratory scan | **Not run** (preserves existing Docker environments) |
| 9 | Playwright login/RBAC | **Not run** (no Playwright execution in this session) |

---

## Commands to reproduce

```bash
cd /Users/piero/Downloads/SentinelWP
python3 -m pytest tests/ -q
python3 -m pytest tests/test_sprint11_security_remediation.py -v
```

Optional (live PostgreSQL claim test):

```bash
# Requires Sprint 10 lab Postgres on 127.0.0.1:5439
python3 -m pytest tests/test_sprint11_security_remediation.py::TestScanJobAtomicClaimPostgres -v
```

---

## Outstanding before final Sprint 11 tag

1. Commit remediation changes (explicitly **not** done per instructions).
2. Disposable `docker-compose.prod.yml` smoke + migration 008→009.
3. Playwright RBAC journey verification.
4. Dynamic SSRF lab (controlled DNS/HTTP) for SWP-SSRF-002 residual.
