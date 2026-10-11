# SENTINELWP — SPRINT 11 SECURITY GAPS & HARDENING AUDIT
## Production Vulnerability Surface & DevSecOps Remediation Plan

**Audit Date:** 2026-10-11  
**Author:** Security Architect & Application Security Engineer  
**Scope:** SentinelWP Core Engine, Network Configuration, Docker Runtime, Secrets Governance  
**Status:** Pre-Implementation Architectural Gap Analysis  

---

## 1. Executive Security Assessment

As SentinelWP transitions into enterprise production deployments on Ubuntu Server LTS, an end-to-end security audit was conducted across the application codebase, container images, network exposure, and operational controls.

While Sprint 10 resolved core data integrity concerns and certified fail-closed PostgreSQL persistence, six critical architectural security gaps were identified in the legacy container and configuration templates that must be remediated in Sprint 11.

---

## 2. Gap Matrix & Severity Classification

| Gap ID | Category | Finding Description | Legacy State | Severity | Target State (Sprint 11) |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **SEC-01** | SSRF Defense | `WSA_TEST_TARGET_ALLOWLIST` can bypass private network blocking | Permitted regardless of `ENVIRONMENT` | **CRITICAL** | Fail-closed: Ignored/rejected in `production` mode |
| **SEC-02** | Ingress Security | Missing Werkzeug `ProxyFix` middleware on Flask WSGI | Not mounted on `app.wsgi_app` | **HIGH** | `ProxyFix(x_for=1, x_proto=1, x_host=1, x_prefix=1)` |
| **SEC-03** | Network Surface | Host port publishing of database & broker (`5433`, `6379`) | Published to `0.0.0.0` on host | **HIGH** | Zero host port publication for internal stores |
| **SEC-04** | Container Isolation | Celery worker healthchecks disabled; potential privilege escalation | Worker healthcheck disabled; default root caps | **MEDIUM** | Non-root `appuser`, `cap_drop: ALL`, `read_only: true` |
| **SEC-05** | Transport Security | Compose file overriding `WSA_SESSION_COOKIE_SECURE` to `false` | Explicitly defaulted to `false` in compose | **HIGH** | Fail-closed: `SESSION_COOKIE_SECURE=True` enforced |
| **SEC-06** | Supply Chain | Unpinned dependencies (`>=`) in `requirements.txt` | Permissive version ranges | **MEDIUM** | Pinned release lockfile with vulnerability audit |

---

## 3. Deep-Dive Gap Analysis & Remediation Specifications

### 3.1 SEC-01: SSRF Protection & Private Target Allowlist Hardening
- **Vulnerability Mechanism:**  
  In `scanners/base.py`, the URL validation routine inspects `WSA_TEST_TARGET_ALLOWLIST` to permit testing against RFC1918 addresses in local development and synthetic laboratory scenarios. If an operator inadvertently retains or configures this variable in an enterprise production `.env` file, an authenticated attacker with scan initiation rights could target internal infrastructure (e.g., internal cloud metadata, internal Kubernetes APIs, or adjacent host services).
- **Remediation Requirement:**  
  When `ENVIRONMENT == "production"`, `WSA_TEST_TARGET_ALLOWLIST` must be strictly disallowed or restricted to explicitly authorized external domain names. Private/loopback IP addresses must be rejected unconditionally regardless of allowlist parameters unless `WSA_ALLOW_PRIVATE_TARGETS` is set to `true` with explicit high-privilege administrative audit logging. Furthermore, in `docker-compose.prod.yml`, `WSA_ALLOW_PRIVATE_TARGETS` must default strictly to `false`.

### 3.2 SEC-02: Reverse Proxy Client IP Trust & Werkzeug ProxyFix
- **Vulnerability Mechanism:**  
  When SentinelWP runs behind an Nginx reverse proxy, incoming TCP connections to Gunicorn originate from Nginx (`172.x.x.x`). Currently, Flask's `app.wsgi_app` is not wrapped with `werkzeug.middleware.proxy_fix.ProxyFix`.  
  This creates two severe security consequences:
  1. **Denial of Service via Rate Limiter Collisions:** `core.rate_limiter` uses `request.remote_addr` as the sliding-window partition key. Without `ProxyFix`, all legitimate users share the reverse proxy's internal IP. If a single bad actor triggers brute-force protection, all enterprise users are locked out.
  2. **Audit Logging Invalidation:** Security audit trails and login failure events record the reverse proxy IP rather than the true client IP provided in `X-Forwarded-For`.
  3. **Broken Redirect Schemes & Secure Cookies:** Gunicorn receives plaintext HTTP from Nginx. Without reading `X-Forwarded-Proto: https`, Flask believes the connection is insecure and may fail to enforce HTTPS redirects or secure session cookies.
- **Remediation Requirement:**  
  In `app.py`, conditionally wrap `app.wsgi_app` with:
  ```python
  from werkzeug.middleware.proxy_fix import ProxyFix
  if os.getenv("WSA_BEHIND_PROXY", "false").lower() in ("true", "1", "yes") or ENVIRONMENT == "production":
      app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
  ```

### 3.3 SEC-03: Network Surface & Database Host Exposure
- **Vulnerability Mechanism:**  
  The legacy `docker-compose.yml` bound PostgreSQL to `${POSTGRES_PORT:-5433}:5432` and Redis to `6379:6379`. On Ubuntu Server LTS with standard UFW or cloud firewall rules, Docker by default manipulates `iptables` directly and bypasses UFW rules unless configured with `DOCKER-USER` chains. This unintentionally exposes the operational database and Redis instance to the host network interface.
- **Remediation Requirement:**  
  In `docker-compose.prod.yml`, omit all `ports` directives from `postgres` and `redis`. Retain only internal network attachments (`networks: [sentinelwp-internal]`).

### 3.4 SEC-04: Non-Root Execution, Capability Dropping & Immutable Filesystem
- **Vulnerability Mechanism:**  
  Containers running with full default capabilities or writable root filesystems provide opportunities for persistence and privilege escalation in the event of Remote Code Execution (RCE) in a third-party dependency.
- **Remediation Requirement:**  
  Across all services in `docker-compose.prod.yml`:
  1. Enforce non-root user `appuser` (UID 1000, GID 1000).
  2. Drop all Linux capabilities: `cap_drop: [ALL]`.
  3. Deny privilege escalation: `security_opt: [no-new-privileges:true]`.
  4. Mount root filesystem as read-only: `read_only: true`.
  5. Provide explicit `tmpfs` mounts for `/tmp` and `/run` with `noexec,nosuid,size=64m`.
  6. Restrict writable paths to explicit named volumes (`/app/data`).

### 3.5 SEC-05: Session Cookie Security & Transport Guarantees
- **Vulnerability Mechanism:**  
  In the legacy compose file, `WSA_SESSION_COOKIE_SECURE` was defaulted to `false` (`${WSA_SESSION_COOKIE_SECURE:-false}`). If deployed in production behind TLS termination, session cookies would lack the `Secure` flag, exposing session tokens to interception over unencrypted HTTP channels.
- **Remediation Requirement:**  
  In `docker-compose.prod.yml`, enforce `WSA_SESSION_COOKIE_SECURE=true`. In `config.py`, fail-fast if `ENVIRONMENT == "production"` and `SESSION_COOKIE_SECURE` is explicitly set to `false`.

### 3.6 SEC-06: Supply Chain Pinning & Vulnerability Audit
- **Vulnerability Mechanism:**  
  Unpinned dependencies allow arbitrary minor/patch updates to be installed at build time, violating deterministic build guarantees and increasing the blast radius of compromised PyPI packages.
- **Remediation Requirement:**  
  1. Generate an explicit, fully pinned `requirements-prod.lock` with exact version constraints.
  2. Implement an automated dependency vulnerability scanning step (`pip-audit` or `safety`) in release pipelines.

---

## 4. Secret Governance & Rotation Architecture

### 4.1 Production Secret Inventory
The following secrets are mandatory in production deployments:
1. `WSA_SECRET_KEY`: High-entropy 32+ character key for Flask session signing and CSRF tokens. Must fail startup if set to default dev values.
2. `POSTGRES_PASSWORD`: Strong password for operational database connection.
3. `REDIS_PASSWORD`: Authentication token for Redis broker and cache.
4. `WSA_ADMIN_PASSWORD`: Initial bootstrap admin password meeting entropy criteria (min 12 chars, upper, lower, digit, special).
5. `WORDFENCE_API_KEY` & `NVD_API_KEY`: External intelligence API keys (optional but protected if configured).

### 4.2 Fail-Safe Startup Validation
Before service initialization, an automated environment validation script (`scripts/validate_prod_env.sh`) will run to ensure:
- None of the production secrets match hardcoded development values (`sentinelwp_dev_password`, `REPLACE_WITH_...`, `admin123`).
- All mandatory keys are defined and exceed minimum entropy lengths.
- File permissions on the production `.env` file are restricted (`chmod 600`).

---

## 5. Security Audit Acceptance Checklist

- [ ] SSRF validation rejects private network ranges fail-closed in production mode.
- [ ] `ProxyFix` correctly forwards real client IP to Flask and rate limiters.
- [ ] No host ports for PostgreSQL (`5432`) or Redis (`6379`) exist in `docker-compose.prod.yml`.
- [ ] All containers run as non-root user UID 1000 with dropped capabilities.
- [ ] Container root filesystems are mounted read-only.
- [ ] Session cookies are strictly configured with `Secure`, `HttpOnly`, and `SameSite=Lax`.
- [ ] Nginx gateway enforces TLS 1.3, modern ciphers, and HSTS headers.
- [ ] Environment secret validation script prevents startup with default credentials.
