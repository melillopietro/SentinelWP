# Sprint 4 — API Security Validation

## Scope

This document records the security review of all Sprint 4 API additions and
changes, covering commit `cd5b162` on branch `feat/sentinelwp-sprint4-integration`.

---

## New Endpoints Security Assessment

### `GET /api/v1/monitoring/dashboard`

| Property | Assessment |
|----------|-----------|
| Authentication | `@require_scope("assets:read")` — requires Bearer token or session |
| RBAC | Viewer, Analyst, Admin (assets:read scope) |
| Tenant isolation | `g.tenant_id` set by `require_scope()` from validated session/API key |
| Data exposure | Only aggregated counts (integers). No asset URLs, credentials, CVE details, or evidence |
| Cross-tenant | Not possible — all queries filtered by `tenant_id` |
| CSRF | `@csrf.exempt` — API endpoints use token auth, not session cookies for writes |
| Input | None (GET, no query params with security impact) |
| **Verdict** | **PASS** |

### `GET /api/v1/monitoring/assets`

| Property | Assessment |
|----------|-----------|
| Authentication | `@require_scope("assets:read")` |
| Object-level auth | All assets filtered by `tenant_id` — no cross-tenant data leakage |
| Pagination | `page_size` capped at 200; prevents unbounded response |
| Data exposure | Monitoring state fields only; no raw evidence, secrets, or scan findings |
| Input validation | `page` and `page_size` cast to int with `max()`/`min()` bounds |
| **Verdict** | **PASS** |

### `GET /api/v1/assets/<asset_id>/differential`

| Property | Assessment |
|----------|-----------|
| Authentication | `@require_scope("assets:read", "findings:read")` |
| Object-level auth | `get_asset(asset_id, tenant_id=g.tenant_id)` — returns 404 for wrong tenant |
| Cross-tenant | Asset lookup enforces tenant scope; differential uses asset_id + tenant_id filters |
| Data exposure | Finding titles, categories, severities, fingerprints. No raw evidence or credential data |
| Failed scan safety | `is_complete=False` when new scan not COMPLETED; no RESOLVED changes in that case |
| **Verdict** | **PASS** |

### `GET /api/v1/assets/<asset_id>/lifecycle`

| Property | Assessment |
|----------|-----------|
| Authentication | `@require_scope("assets:read", "findings:read")` |
| Object-level auth | Asset lookup with tenant scope; 404 for cross-tenant |
| Pagination | `page_size` capped at 100 |
| Data exposure | Finding metadata only (title, severity, status, CVE ID, dates). No raw HTTP response data |
| **Verdict** | **PASS** |

### `POST /api/v1/schedules/<id>/pause` and `/resume`

| Property | Assessment |
|----------|-----------|
| Authentication | `@require_scope("assets:write")` — analyst or admin only |
| Object-level auth | `get_scheduled_scan(id, tenant_id=g.tenant_id)` — 404 for wrong tenant |
| Input validation | `hours` cast to int, bounded `max(1, min(720, hours))` — integer overflow and out-of-range inputs handled |
| Audit logging | Both operations emit `log_audit_event()` with actor, resource, result |
| CSRF | `@csrf.exempt` — these are REST API endpoints using Bearer/API-key auth |
| Viewer blocked | `assets:write` scope excludes viewer role (403) |
| **Verdict** | **PASS** |

---

## REQUIRE_DISTRIBUTED_LOCK Security Analysis

### Change
`_get_redis_client()` now raises `RuntimeError` when `REQUIRE_DISTRIBUTED_LOCK=true` and Redis is unreachable.

### Threat Model

| Threat | Assessment |
|--------|-----------|
| Silent lock degradation in multi-worker | **Eliminated.** With `REQUIRE_DISTRIBUTED_LOCK=true`, sync operations fail loudly rather than running without cross-process exclusion. |
| Denial of service via Redis outage | **Accepted risk.** If `REQUIRE_DISTRIBUTED_LOCK=true` and Redis goes down, `sync_all()` will raise rather than run. This is the intended fail-closed behavior. Operators should configure Redis HA (Redis Sentinel or Cluster) in production. |
| Secret leak via error message | **Not present.** The RuntimeError message contains only the Redis URL (from env var, not a secret) and a guidance string. |
| False positive fail-closed (flap) | **Mitigated.** The Redis client caches the connection object once established (`_redis_client`). Brief transient Redis latency only affects the first connection attempt per worker process. |

### Consistency Guarantees

| Mode | Process Isolation | Cross-process Isolation |
|------|------------------|------------------------|
| `REQUIRE_DISTRIBUTED_LOCK=false` + Redis available | ✅ | ✅ (Redis SET NX EX) |
| `REQUIRE_DISTRIBUTED_LOCK=false` + Redis unavailable | ✅ (thread lock) | ❌ (thread-local only) |
| `REQUIRE_DISTRIBUTED_LOCK=true` + Redis available | ✅ | ✅ |
| `REQUIRE_DISTRIBUTED_LOCK=true` + Redis unavailable | N/A | **Fails closed (RuntimeError)** |

---

## Intel Reassessment Queue Security

### No Unauthorized Scanning
The `process_intel_reassessment_queue_task()` calls `verify_scan_authorization()` before creating any scan job. This is the same authorization check used in `run_scan_task()`. If authorization is expired, revoked, or missing, the event is marked `SKIPPED` — no scan job is created.

### No External HTTP in Queue Processor
The queue processor itself makes no outbound HTTP requests. It only reads from the database and dispatches a Celery task. The actual HTTP scanning happens inside `run_scan_task()` which enforces all SSRF protections.

### Payload Contents
Outbox event payloads contain only:
- `asset_id` (UUID — no secrets)
- `asset_url` (canonical URL — no credentials)
- `vuln_id`, `slug`, `cve_id` (intel identifiers — public information)
- `severity`, `triggered_at`

No scan credentials, API keys, finding raw evidence, or user session data.

---

## No New Attack Surface

| Category | Assessment |
|----------|-----------|
| New HTTP endpoints | 6 new Flask routes — all authenticated, tenant-scoped |
| New external HTTP calls | None (queue processor dispatches tasks; does not call external APIs) |
| New file writes | None |
| New subprocess execution | None |
| New deserialization | Outbox payload is JSON (existing `json.loads`); no pickle |
| New env var parsing | `REQUIRE_DISTRIBUTED_LOCK` (boolean, string comparison, no eval) |
| New DB schema | 5 indices added (migration 007); no new tables; no schema relaxation |
| Template injection | Jinja2 autoescaping enabled; monitoring data is numeric/ISO strings only |

---

## Summary

| Component | Finding | Status |
|-----------|---------|--------|
| Monitoring dashboard API | No data exposure, tenant-scoped, viewer-accessible | ✅ PASS |
| Asset differential API | Object-level auth, 404 on cross-tenant, failed-scan safety | ✅ PASS |
| Schedule pause/resume API | Analyst+ only, audit-logged, input-bounded | ✅ PASS |
| REQUIRE_DISTRIBUTED_LOCK | Fail-closed with explicit operator opt-in | ✅ PASS |
| Intel queue processor | No unauthorized scanning, payload-safe, concurrent-safe | ✅ PASS |
| Plugin cache-busting | Targeted Cache-Control; no fingerprinting evasion | ✅ PASS |
