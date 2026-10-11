# SentinelWP — Sprint 7 Security Hardening & Isolation Validation
## Multi-Tenant Security, SSRF Prevention, RBAC Controls, CSRF & Audit Trails

**Sprint:** Sprint 7 — Enterprise QA, Stability & Release Candidate  
**Target Branch:** `feat/sentinelwp-sprint7-release-candidate`  
**Test Suite Coverage:** `tests/test_p0_security.py`, `tests/test_phase2_tenant_asset_auth.py`, `tests/test_phase5_production_readiness.py`, `tests/test_sprint7_qa_hardening.py`  

---

### 1. Multi-Tenant Isolation & Object-Level Authorization

SentinelWP enforces strict logical multi-tenancy. All primary business records (`assets`, `findings`, `scan_jobs`, `scan_results`, `scheduled_scans`, `audit_events`, `integration_outbox`) require a `tenant_id` foreign key.

#### 1.1 Object-Level Access Control (Broken Object Level Authorization - BOLA Defense)
- **Mechanism:** In `app.py`, entity retrieval controllers (`get_asset()`, `get_finding()`, `get_scan()`) explicitly query by `(id, tenant_id)`.
- **Validation Test:** In `tests/test_sprint7_qa_hardening.py::TestSprint7SecurityAndTenantIsolation::test_tenant_cross_access_blocked_returns_404`:
  - An authenticated analyst user belonging to `tenant-s7-b` attempts to read `/asset/<asset_of_tenant_a>`.
  - The application returns **HTTP 404 Not Found** rather than disclosing the asset metadata or returning HTTP 403 (preventing tenant enumeration).
  - Status: **VERIFIED PASS**.

---

### 2. SSRF (Server-Side Request Forgery) Defense

The scanner accepts user-configured target URLs for WordPress sites. To prevent attackers from using the scanner as an intranet proxy or accessing cloud provider instance metadata:

- **Implementation:** `scanners/base.py::is_safe_target_url()`.
- **Blocked Ranges & Prohibitions:**
  1. **Cloud Metadata IP:** Strictly blocks `169.254.169.254` (AWS, GCP, Azure, DigitalOcean metadata endpoints) and link-local range `169.254.0.0/16`.
  2. **Loopback Networks:** Blocks `127.0.0.0/8`, `::1`, and `localhost`.
  3. **RFC 1918 Private Ranges:** Blocks `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
  4. **Dangerous Schemes:** Blocks `file://`, `gopher://`, `ftp://`, `ldap://` (only `http://` and `https://` permitted).
  5. **DNS Rebinding Prevention:** Optional DNS resolution check evaluates the resolved socket IP prior to initiating HTTP probes.
- **Validation Tests:**
  - `test_ssrf_validator_blocks_cloud_metadata_ip` &rarr; **BLOCKED**
  - `test_ssrf_validator_blocks_loopback_and_private_networks` &rarr; **BLOCKED**
  - `test_public_fqdn_accepted_by_ssrf_validator` &rarr; **ALLOWED**

---

### 3. Scan Authorization Gate

To prevent unauthorized or abusive scanning of external third-party web properties:
- **Authorization Enforcement:** Every asset maintains an `authorization_status` (`pending`, `verified`, `revoked`).
- **Pre-Scan Gatekeeper:** The scan orchestrator refuses to dispatch scan jobs against an asset unless its authorization status is `verified` and the authorization has not expired.
- **RBAC Restriction:** Only platform users with the `admin` role are permitted to grant or modify authorization status.

---

### 4. CSRF, Rate Limiting & Session Hardening

#### 4.1 Cross-Site Request Forgery (CSRF)
- **Token Protection:** Flask-WTF CSRF tokens are injected into all forms (`templates/base.html` and modal dialogs).
- **API Token Authentication:** REST API endpoints (`/api/v1/...`) accept signed Bearer API tokens or API key headers, bypassing CSRF only when authenticating via cryptographic API tokens.
- **Failure Mode:** Any unauthenticated or cross-origin POST request lacking a valid CSRF token is rejected with **HTTP 400 Bad Request**.

#### 4.2 Rate Limiting
- **Sensitive Endpoints:** Authentication (`/login`), user registration, password change, and vulnerability intelligence force-sync endpoints are protected by Flask-Limiter.
- **Exceeding Limits:** Returns **HTTP 429 Too Many Requests** with standard `Retry-After` headers.

#### 4.3 Session Cookie Attributes
- **Flags:** `HttpOnly = True`, `SameSite = 'Lax'`, `Secure = True` (in production mode).
- **Session Expiration:** Idle sessions expire after 60 minutes.

---

### 5. Audit Trail & Non-Repudiation

- **Table:** `audit_events` with indexed `(tenant_id, created_at)`.
- **Logged Events:** Authentication attempts, user creation/deletion, role modifications, asset additions/deletions, scan dispatches, vulnerability status changes, risk exception approvals, and outbox event crash recoveries.
- **Integrity:** Audit records are append-only. No application routes or ORM methods permit mutation or deletion of `audit_events`.

---

### 6. Security Validation Verdict

SentinelWP demonstrates enterprise-grade defense-in-depth across multi-tenancy, network perimeter boundaries, role-based authorization, and tamper-evident audit logging.
