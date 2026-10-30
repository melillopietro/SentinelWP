# SentinelWP Enterprise — Phase 2 Architecture & Security Report
**Multi-Tenancy, Asset Inventory, Scan Authorization & Immutable Audit Logging**

**Author:** Principal Security Architect & Lead Python Engineer  
**Repository:** `melillopietro/SentinelWP`  
**Branch:** `enterprise-phase2-tenant-asset-authorization`  
**Date:** 2026-09-29  
**Status:** Successfully Implemented & Fully Validated  

---

## 1. Executive Summary

SentinelWP Enterprise has completed **Phase 2**, achieving enterprise multi-tenant partitioning, centralized asset inventory management with Asset 360 posture tracking, scan authorization guardrails, object-level authorization (IDOR prevention returning HTTP 404), and an immutable administrative audit log.

All implementations strictly respect the enterprise mandate:
1. **Zero New Offensive Capabilities**: No aggressive fuzzers or offensive probes were added.
2. **Safe Active Scan Guardrails**: Safe Active scans strictly require an unexpired, active authorization window on the canonical target asset; unauthorized attempts fail closed (HTTP 403) and log an audit denial.
3. **100% Backward Compatibility**: Existing SQLite databases (`data/wsa.db`) migrate automatically and idempotently on startup with a seeded Default Workspace (`default-tenant`).
4. **Complete Test Suite Parity**: All 152 pre-existing tests continue to pass without modification, complemented by 20 new comprehensive enterprise validation tests (172/172 total tests passing).

---

## 2. Core Architecture & New Capabilities

```
+---------------------------------------------------------------------------------------+
|                                     SentinelWP UI                                     |
|  +--------------------+  +--------------------+  +------------------+  +-----------+  |
|  |    Dashboard       |  |  Asset Inventory   |  |    Asset 360     |  | Audit Log |  |
|  |  (Tenant-Scoped)   |  | (Categorization)   |  | (Authorizations) |  |  (Admin)  |  |
|  +--------------------+  +--------------------+  +------------------+  +-----------+  |
+-------------------------------------------|-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                     core/authorization.py (Central Authorization)                     |
|  * Tenant Scope Extraction (from Authenticated Session, never from client input)      |
|  * IDOR Prevention Guardrail: enforce_tenant_object() -> HTTP 404 (Zero Disclosure)  |
|  * Role Capabilities: Viewer (Read-only) | Analyst (Triage/Scan) | Admin (Governance) |
|  * Scan Authorization Guardrail: verify_scan_authorization() -> Fail-Closed Check     |
+-------------------------------------------|-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                       core/repository.py (SQLite Data Access Layer)                   |
|  * Idempotent ALTER TABLE & Index Migrations on Startup                               |
|  * Default Workspace Backfill (tenant_id = 'default-tenant')                          |
|  * CRUD & Scoped Queries: tenants, assets, scan_authorizations, audit_events           |
|  * Immutable Append-Only Audit Logging with Credential Redaction                      |
+---------------------------------------------------------------------------------------+
```

### 2.1 Multi-Tenant / Workspace Partitioning
- **Domain Model**: `Tenant` (`id`, `name`, `slug`, `status`, `created_at`, `updated_at`).
- **Default Workspace Migration**: On initialization, `init_db()` seeds `id="default-tenant"`, `name="Default Workspace"`, `slug="default"`, and migrates legacy rows where `tenant_id IS NULL OR tenant_id = ''`.
- **Session Boundary**: `tenant_id` is extracted strictly from the authenticated user record in server session (`session["tenant_id"]`). No endpoint or client parameter can override the tenant scope.

### 2.2 Enterprise Asset Inventory & Asset 360 View
- **Domain Model**: `Asset` (`id`, `tenant_id`, `canonical_url`, `hostname`, `display_name`, `business_owner`, `technical_owner`, `environment`, `internet_exposure`, `criticality`, `data_classification`, `authorization_status`, `authorization_review_date`, `tags`, `status`, `created_at`, `updated_at`).
- **URL Canonicalization (`core/canonical.py`)**:
  - Automatically lowercases hostname.
  - Strips standard ports (`80` for HTTP, `443` for HTTPS) while preserving non-standard ports (e.g. `8443`).
  - Strips query parameters and URL fragments that do not belong to asset identity.
  - Normalizes trailing slashes while preserving WordPress subdirectories (e.g. `https://example.com/blog`).
  - Distinguishes `canonical_url` from `hostname`.
- **Asset 360 Profile (`/asset/<id>`)**:
  - Governance metadata (Environment, Exposure, Criticality, Classification, Owners).
  - Scan Authorization Guardrail card (active authorization window, allowed profiles, budget, revoke action).
  - Historical scans executed against this asset.
  - Active aggregated findings discovered on this asset.
- **Inventory Management**:
  - `GET /assets`: Searchable and filterable registry by environment, criticality, authorization status, and search terms.
  - `GET /asset/new` & `POST /asset/create`: Asset registration with optional immediate authorization.
  - `GET /asset/<id>/edit` & `POST /asset/<id>/edit`: Asset metadata modification (Analyst+).
  - `POST /asset/<id>/delete`: Decommissioning via soft delete (`status="disabled"`).

### 2.3 Scan Authorization Guardrail (Safe Active)
- **Domain Model**: `ScanAuthorization` (`id`, `tenant_id`, `asset_id`, `status`, `allowed_profiles`, `request_budget`, `valid_from`, `valid_until`, `approved_by`, `notes`, `created_at`, `updated_at`).
- **Guardrail Rule**: Safe Active scans (`scan_mode="safe-active"`) cannot execute unless a valid `ScanAuthorization` record exists for the target asset satisfying:
  - `status == "active"`
  - `valid_from <= now <= valid_until`
  - `safe_active` profile permitted in `allowed_profiles`
- **Fail-Closed Behavior**: If missing, expired, or revoked, active scan execution is strictly blocked (HTTP 403), displaying an explicit refusal message without downgrading to passive. A `scan_denied` audit event is logged.

### 2.4 Centralized Object-Level Authorization & IDOR Policy
- **Central Module**: `core/authorization.py`.
- **Zero Resource Disclosure Policy**: Any cross-tenant access attempt (viewing, editing, deleting another tenant's scan, finding, asset, schedule, report, or user) immediately aborts with **HTTP 404 (Not Found)** rather than HTTP 403 (Forbidden). This prevents external or internal adversaries from probing for the existence of foreign tenant identifiers.
- **RBAC Matrix**:
  - **Viewer**: Read-only access to tenant assets, scans, findings, and schedules. Strictly blocked (HTTP 403) from mutations.
  - **Analyst**: Can create assets, edit metadata, grant scan authorizations, triage findings, run authorized scans, and manage schedules. Blocked from user management and asset decommissioning.
  - **Admin**: Full control within their tenant, including user management, asset decommissioning, database purging, and access to `/audit`.

### 2.5 Immutable Audit Logging
- **Domain Model**: `AuditEvent` (`id`, `tenant_id`, `actor_user_id`, `actor_username`, `action`, `resource_type`, `resource_id`, `result`, `metadata`, `created_at`).
- **Append-Only Store**: Only `INSERT` operations are exposed. No `DELETE` or `UPDATE` routes exist.
- **Sensitive Credential Sanitization**: `_sanitize_metadata()` redacts passwords, tokens, session cookies, API keys, and authorization headers to `[REDACTED]`.
- **Administrative UI (`/audit`)**: Admin-only audit inspection table with filters by actor, action, and result (success, denied, failure).

---

## 3. Files Created and Modified

| File | Type | Description |
| :--- | :--- | :--- |
| `core/models.py` | Modified | Added `Tenant`, `Asset`, `ScanAuthorization`, `AuditEvent` dataclasses; added `tenant_id` and `asset_id` to existing domain models. |
| `core/canonical.py` | New | Target URL canonicalization and hostname normalization utility. |
| `core/authorization.py` | New | Centralized enterprise authorization service (RBAC, IDOR enforcement, scan authorization guardrails). |
| `core/repository.py` | Modified | Database schema migrations, tenant default backfill, full CRUD for tenants, assets, authorizations, audit events, and tenant-scoped queries. |
| `app.py` | Modified | Integrated workspace context processor, asset inventory routes, scan authorization enforcement, immutable audit logging, and tenant isolation. |
| `scanners/orchestrator.py` | Modified | Updated `run_scan` to support `tenant_id` and `asset_id` propagation to scan and finding records. |
| `scanners/async_runner.py` | Modified | Updated `start_async_scan` and background execution thread to link scans and findings to tenant and asset. |
| `scanners/batch_runner.py` | Modified | Propagated `tenant_id` across concurrent batch scan jobs. |
| `core/scheduler.py` | Modified | Propagated `tenant_id` and `asset_id` into async scan invocations from scheduler loop. |
| `templates/base.html` | Modified | Added sidebar navigation links for "Asset Inventory" and "Audit Log" (Admin only), plus active Workspace badge. |
| `templates/assets.html` | New | Asset Inventory listing with environment, criticality, authorization status filters and "+ Add Asset" button. |
| `templates/asset_form.html` | New | Registration and editing form for enterprise assets with optional initial authorization grant. |
| `templates/asset_detail.html` | New | Comprehensive Asset 360 view with governance metadata, authorization guardrail management, scan history, and findings. |
| `templates/audit.html` | New | Immutable Security Audit Log dashboard for administrators with search and filtering. |
| `docs/POSTGRESQL_MIGRATION_PLAN.md` | New | Architectural plan for PostgreSQL, Alembic, Row-Level Security (RLS), and schema mapping. |
| `ENTERPRISE_VALIDATION_REPORT.md` | Modified | Updated control statuses for M-04, M-08, M-09, M-11. |
| `tests/test_phase2_tenant_asset_auth.py` | New | 20 automated regression tests covering tenant isolation (HTTP 404), scan authorization guardrails, canonicalization, audit sanitization, and RBAC. |

---

## 4. Automated Verification & Test Results

```bash
$ PYTHONPATH=. .venv/bin/pytest -v
============================= test session starts ==============================
platform darwin -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /Users/piero/Downloads/SentinelWP
collecting ... collected 172 items

tests/test_p0_security.py .........................                      [ 14%]
tests/test_phase2_tenant_asset_auth.py ....................              [ 26%]
tests/test_scheduled_scans_batch.py ............                         [ 33%]
tests/test_sentinel.py ..............................                    [ 50%]
tests/vulnerability_intelligence/test_cisa_kev_client.py ....            [ 52%]
tests/vulnerability_intelligence/test_normalizer.py .......              [ 56%]
tests/vulnerability_intelligence/test_nvd_client.py ....                 [ 59%]
tests/vulnerability_intelligence/test_reports.py ........                [ 63%]
tests/vulnerability_intelligence/test_repository.py ............         [ 70%]
tests/vulnerability_intelligence/test_routes.py ......                   [ 74%]
tests/vulnerability_intelligence/test_scanner_integration.py .........   [ 79%]
tests/vulnerability_intelligence/test_scheduler_integration.py ...       [ 81%]
tests/vulnerability_intelligence/test_service.py ...........             [ 87%]
tests/vulnerability_intelligence/test_version_matcher.py ..........      [ 93%]
tests/vulnerability_intelligence/test_wordfence_client.py .......        [ 97%]
tests/vulnerability_intelligence/test_wordpress_plugins_client.py ....   [100%]

======================= 172 passed, 8 warnings in 0.60s ========================

$ .venv/bin/python -m unittest discover -s tests
Ran 87 tests in 0.248s
OK

$ .venv/bin/python -m compileall .
Listing '.'...
(clean compilation across all modules, exit code 0)
```

---

## 5. Control Matrix Evolution (Current Status)

| Control ID | Control Name | Status | Current Reality in Repository |
| :--- | :--- | :---: | :--- |
| **M-01** | CSRF Protection | **PASS** | Centralized `CSRFProtect` on all forms, headers, and mutating routes. |
| **M-02** | Secret & Session Hardening | **PASS** | Strong key validation, cookie flags (`HttpOnly`, `SameSite`), fixation defense. |
| **M-03** | SSRF & Network Safety | **PASS** | CIDRs, cloud metadata blocks, local domain suffix blocks, hop-by-hop redirect inspection. |
| **M-04** | Scan Authorization Guardrail | **PARTIAL** | `ScanAuthorization` baseline implemented; Safe Active fails closed without active authorization window. Cryptographic domain token proof remains open. |
| **M-05** | Credential Safety | **PASS** | `BruteForceScanner` removed from standard profile; zero plaintext password storage; irreversible hashes. |
| **M-06** | PII Minimization | **PASS** | Username hashing, pseudonymized identifiers, author name disclosure mitigation. |
| **M-07** | Scan Profiles | **PASS** | `full` profile sanitized to safe non-offensive checks; marked as legacy in UI and code. |
| **M-08** | Asset Inventory & Scope | **PARTIAL** | `Asset` model, Asset 360 view, canonicalization, environment/criticality metadata implemented. Dynamic asset graph and EASM continuous discovery open. |
| **M-09** | Multi-Tenancy & Authorization | **PARTIAL** | `Tenant` model, default workspace migration, and object-level IDOR prevention (HTTP 404) implemented. PostgreSQL, RLS, and Celery/Redis open (documented in `POSTGRESQL_MIGRATION_PLAN.md`). |
| **M-10** | Risk Engine & Monotonicity | **PASS** | Monotonic risk scoring and narrative evaluation enforced. |
| **M-11** | Immutable Audit Logging | **PARTIAL** | Append-only `AuditEvent` store in SQLite, sanitized metadata, Admin `/audit` dashboard. Remote SIEM streaming remains open. |
| **M-12** | Remediation Lifecycle | **PARTIAL** | Finding status triage restricted to Analyst+; edits logged to audit trail. Multi-stage approval flow open. |

---

## 6. What Remains Open for Future Phases

While SentinelWP now exhibits solid multi-tenant boundaries and governance controls, it is **not yet fully enterprise-ready** in the following areas:
1. **Runtime Database**: SQLite remains the active runtime database (`data/wsa.db`). The migration to PostgreSQL with Alembic and database-level Row-Level Security (RLS) is fully specified in `docs/POSTGRESQL_MIGRATION_PLAN.md` but pending infrastructure provisioning.
2. **Asynchronous Worker Tier**: Background scans and scheduled recurring jobs currently run in an in-process thread pool daemon. Production enterprise scaling requires decoupling into Celery/Redis workers.
3. **Advanced Domain Ownership Verification**: Domain ownership currently relies on administrative manual registration and authorization windows; cryptographic verification (DNS TXT record tokens or well-known challenge files) will be added in Phase 3.
4. **External SIEM Ingestion**: Audit events are retained locally in SQLite; streaming log shippers (Syslog/CEF/Webhook to Splunk/Elastic) remain for Phase 3.
