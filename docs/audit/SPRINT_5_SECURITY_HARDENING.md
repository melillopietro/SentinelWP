# SentinelWP — Sprint 5 Security Hardening Report
**Document ID:** SPRINT_5_SECURITY_HARDENING  
**Sprint:** 5 (Production Hardening & Release Readiness)  
**Security Standard:** OWASP ASVS v4.0 / CIS Benchmark Alignment  
**Execution Date:** 2026-10-10  
**Status:** COMPLETED & AUDITED  

---

## 1. Executive Summary

As part of the Sprint 5 production readiness evaluation, a comprehensive security posture review was performed covering authentication, session handling, API authorization, tenant boundary enforcement, Server-Side Request Forgery (SSRF) mitigations, secrets hygiene, and audit logging.

SentinelWP demonstrates robust multi-layered defenses established in prior sprints:
- Strictly scoped API Key authorization with constant-time SHA-256 token hashing.
- Role-Based Access Control (`admin`, `analyst`, `viewer`) with granular endpoint enforcement.
- Strict SSRF protection rejecting internal IP ranges (RFC 1918, RFC 3927, loopbacks) across scanning and webhook pipelines.
- CSRF token validation on all mutating HTML browser forms (`Flask-WTF` / `CSRFProtect`).
- Tenant isolation enforced in SQLite and PostgreSQL repository queries.

This report details the current security controls, validates compliance, and identifies operational hardening actions for enterprise deployment.

---

## 2. Authentication & Session Security

### 2.1 Password Hashing & Policy
- **Algorithm:** PBKDF2 with SHA-256 (`werkzeug.security.generate_password_hash` / `check_password_hash`).
- **Policy Enforcement:** Minimum 8 characters, requiring mixed alphanumeric characters on setup.
- **Session Configuration:**
  - `SESSION_COOKIE_HTTPONLY = True`: Blocks JavaScript access to session cookies, mitigating XSS session hijacking.
  - `SESSION_COOKIE_SAMESITE = 'Lax'`: Mitigates cross-site request forgery attacks.
  - `SESSION_COOKIE_SECURE`: Configured to `True` when `ENV == 'production'` or `PREFERRED_URL_SCHEME == 'https'`.
  - Session expiration enforced via server-side session timestamps.

### 2.2 OIDC / SSO Integration
- SentinelWP supports OpenID Connect (OIDC) authentication (`/auth/oidc/login`, `/auth/oidc/callback`) alongside local credentials.
- Multi-factor authentication readiness: Delegated to upstream Identity Provider (IdP) via OIDC.

### 2.3 Administrative Credential Policy & Rotation
- Default credentials are created during platform initialization (`/setup` or startup seed).
- **Finding:** In development and test environments, seeded admin/analyst passwords (`SentinelWP@Admin2026!`, `SentinelWP@Analyst2026!`) are used.
- **Production Hardening Requirement:** Production deployment scripts must mandate custom passwords via environment variables (`ADMIN_PASSWORD`, `ANALYST_PASSWORD`) or immediately prompt for password change upon first administrative login.
- **Recommendation:** Implement `must_change_password` flag for newly provisioned user accounts.

---

## 3. API Authorization & RBAC Boundaries

### 3.1 Dual-Mode Authentication
SentinelWP supports two distinct authentication contexts:
1. **Interactive Session Authentication:** Cookie-backed session for web UI users, verified via `@login_required` and role gates (`@admin_required`, `@analyst_required`).
2. **Programmatic API Authentication:** Bearer token or `X-API-Key` header, validated against `api_keys` table using constant-time hash comparison (`hmac.compare_digest`).

### 3.2 Role Permissions Matrix

| Endpoint Group | Viewer | Analyst | Admin |
| :--- | :---: | :---: | :---: |
| Dashboard, Portfolio, Findings, Assets (Read) | Read-Only | Read-Only | Read-Only |
| Launch Ad-hoc Scan (`/scan/new`, `/api/scan`) | Blocked (403) | Permitted | Permitted |
| Batch Scan (`/scan/batch`) | Blocked (403) | Permitted | Permitted |
| Asset Create / Edit / Delete | Blocked (403) | Permitted | Permitted |
| Finding Status / Triage / Remediation | Blocked (403) | Permitted | Permitted |
| Risk Acceptance Request | Blocked (403) | Permitted | Permitted |
| Risk Acceptance Approval / Revocation | Blocked (403) | Blocked (403) | Permitted |
| Scheduled Scan Management | Blocked (403) | Permitted | Permitted |
| Tenant Offboarding / Management | Blocked (403) | Blocked (403) | Permitted |
| User Management (`/users`) | Blocked (403) | Blocked (403) | Permitted |
| Audit Log Access (`/audit`) | Blocked (403) | Blocked (403) | Permitted |
| Database Maintenance / Purge | Blocked (403) | Blocked (403) | Permitted |

Unit test `tests/test_phase2_tenant_asset_auth.py` and `tests/test_sprint4_integration.py` independently verify these RBAC gates.

---

## 4. Tenant Isolation

- SentinelWP enforces multi-tenancy at the data layer.
- Every asset, scan, finding, remediation, and outbox record contains a foreign key `tenant_id`.
- Repositories (`core/repository.py` and `core/vulnerability_intelligence/repository.py`) inject `tenant_id = ?` into query filters.
- API endpoints resolve `current_tenant_id` from the authenticated user's session or API key context.
- Tenant switching requires administrative privileges.
- Cross-tenant data leakage is prevented at both the application route and database query level.

---

## 5. SSRF Mitigations & Scan Authorization

### 5.1 Scanning SSRF Protection
- **Target URL Validation (`scanners/base.py` & `core/orchestrator.py`):**
  - Resolves target hostnames via DNS and checks resulting IP addresses against blocked CIDR blocks:
    - Loopback: `127.0.0.0/8`, `::1/128`
    - Private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
    - Link-local: `169.254.0.0/16`, `fe80::/10`
    - Cloud metadata: `169.254.169.254`
  - Re-evaluates IP address before every outbound socket connection to mitigate DNS rebinding attacks.

### 5.2 Asset Scan Authorization Gate
- Active scans require explicit domain authorization recorded in `asset_authorizations`.
- If authorization expires or is revoked, scan requests are rejected with HTTP 403 / status `BLOCKED`.
- Verified in `tests/test_phase2_tenant_asset_auth.py::test_safe_active_scan_blocked_when_authorization_revoked`.

### 5.3 Webhook Egress Controls
- Webhook notification dispatcher (`/api/v1/webhooks/deliver`) re-uses strict SSRF IP filters before dispatching payloads to external endpoints.

---

## 6. Secrets & Cryptographic Hygiene

### 6.1 Secret Storage
- API keys are hashed with SHA-256 before storage; plaintext secret keys are shown exactly once upon creation.
- Webhook signing secrets utilize HMAC-SHA256.
- Database passwords and Redis credentials are read strictly from environment variables (`DATABASE_URL`, `REDIS_URL`, `SECRET_KEY`).

### 6.2 Codebase Secret Scan
- Automated SAST scan (Bandit) showed 0 high-severity security issues.
- Git repository history inspection verified no hardcoded production API tokens, private TLS keys, or cloud credentials.
- Note on Development Config: `.env.example` contains template placeholders only.

---

## 7. Audit Logging & Non-Repudiation

- High-impact events are written to `audit_events`:
  - Authentication success / failure / logout
  - User creation / deletion / role change
  - Asset authorization creation and revocation
  - Risk acceptance request, approval, rejection, expiration
  - Scan creation, cancellation, and manual retry
  - Background outbox recovery and dead-letter actions (added in Sprint 5)
- Audit log records include: `id`, `tenant_id`, `user_id`, `action`, `resource_type`, `resource_id`, `details` (JSON), `ip_address`, `created_at`.
- Immutable design: No application route exists to edit or delete individual audit log records.

---

## 8. Hardening Action Checklist for Production

| Control | Current Status | Production Action Required |
| :--- | :--- | :--- |
| HTTPS Enforcement | Supported via reverse proxy / Flask config | Enable HSTS header (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) |
| Content Security Policy | Basic headers | Add strict CSP header with nonce for scripts |
| Rate Limiting | Implemented on auth/scan endpoints | Tune thresholds for high-concurrency environments |
| Admin Password Rotation | Seed passwords in dev | Force password change on first production login |
| Redis Auth | Supported via `redis://:pass@host:port/0` | Enforce TLS and authentication in production Redis |
| Database Auth | Role-based in PostgreSQL | Restrict DB user permissions (no DDL during runtime) |
