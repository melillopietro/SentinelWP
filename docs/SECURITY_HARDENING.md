# SentinelWP — Security Architecture & Hardening Guide
## Defense-in-Depth, Container Isolation, Network Controls & Application Safeguards

This document specifies the security controls, baseline configurations, and architectural safeguards implemented across SentinelWP v4.1.0.

---

## 1. Container & Operating System Hardening

SentinelWP follows a zero-trust containerization architecture designed to minimize host attack surface:

### 1.1 Non-Root Runtime Context
- All application and worker containers run as dedicated unprivileged user `appuser` (UID 1000, GID 1000).
- Root execution is completely disabled across `sentinelwp-web`, `sentinelwp-worker-scan`, `sentinelwp-worker-intel`, `sentinelwp-beat`, and `sentinelwp-migrate`.

### 1.2 Linux Capabilities & Privilege Escalation
- `cap_drop: [ALL]` drops all Linux kernel capabilities.
- `security_opt: [no-new-privileges:true]` strictly prevents processes from gaining additional privileges via `setuid`/`setgid` binaries.

### 1.3 Read-Only Filesystems & Ephemeral Temp Storage
- `read_only: true` mounts container root filesystems as read-only.
- Ephemeral writable storage is explicitly confined to size-limited in-memory `tmpfs` mounts (`/tmp:size=128M,mode=1777`).
- Persistent state is restricted to named Docker volumes mounted under `/app/data`.

### 1.4 Minimal Multi-Stage Build
- Production image (`Dockerfile.prod`) uses a multi-stage build.
- Compilers (`gcc`, `build-essential`) and build-time headers (`libpq-dev`) are isolated in the builder stage and completely absent from the final runtime image.

---

## 2. Network Perimeter & Ingress Security

### 2.1 Private Network Isolation
- **Dual Bridge Networks:**
  - `sentinelwp-internal`: Interconnects datastores (PostgreSQL, Redis), application WSGI, and Celery workers.
  - `sentinelwp-frontend`: Interconnects Nginx gateway and Gunicorn WSGI.
- **Zero Host Port Exposure:** Neither PostgreSQL (`5432`) nor Redis (`6379`) publishes ports to host interfaces (`0.0.0.0` or `127.0.0.1`). They are reachable exclusively over the Docker bridge network.

### 2.2 Ingress Gateway (Nginx) & TLS Termination
- Nginx terminates all external TLS connections using modern cipher suites (`ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`).
- Plaintext HTTP (port 80) unconditionally redirects to HTTPS (port 443) via `HTTP 301 Moved Permanently`.
- Hardened HTTP security headers:
  ```http
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Frame-Options: SAMEORIGIN
  X-Content-Type-Options: nosniff
  X-XSS-Protection: 1; mode=block
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';
  ```

### 2.3 Trusted Proxy Forwarding (ProxyFix)
- Gunicorn WSGI mounts Werkzeug `ProxyFix(x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=0)`.
- Client IP addresses and protocol schemes are accepted exclusively from the trusted Nginx proxy hop. Spoofed or arbitrary upstream `X-Forwarded-*` headers are safely discarded.

---

## 3. Application Security Controls

### 3.1 Session Cookie Hardening
- `WSA_SESSION_COOKIE_SECURE=true`: Session cookies mandate the `Secure` flag. In production mode, application boot fails immediately if this flag is disabled.
- `SESSION_COOKIE_HTTPONLY=true`: Protects session cookies from client-side JavaScript access (mitigating XSS session theft).
- `WSA_SESSION_COOKIE_SAMESITE=Lax`: Mitigates Cross-Site Request Forgery (CSRF).
- Global CSRF token protection is enforced across all state-changing HTTP methods (`POST`, `PUT`, `DELETE`).

### 3.2 Secret Key & Password Entropy Policies
- `WSA_SECRET_KEY` validation rejects values under 32 characters, known weak secrets, and placeholder patterns (`replace_with_`, `change-me`, etc.).
- Admin password validator rejects weak passwords, short lengths ($< 12$ characters), and dictionary terms.

### 3.3 Server-Side Request Forgery (SSRF) Prevention
- Scanner engine validates all scan target URLs via [`scanners/base.py`](file:///Users/piero/Downloads/SentinelWP/scanners/base.py) `is_safe_target_url()`.
- Resolves DNS hostnames and verifies target IPs against disallowed IP blocks:
  - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback addresses (`127.0.0.0/8`)
  - Link-local and AWS/GCP cloud metadata (`169.254.169.254`, `169.254.0.0/16`)
- In production mode, test allowlists (`WSA_TEST_TARGET_ALLOWLIST`) are strictly prohibited and ignored fail-closed.

### 3.4 Runtime DDL Hard-Block
- Dynamic database schema creation via `create_all()` is strictly prohibited in production mode.
- Attempts to invoke `init_db_schema()` against production PostgreSQL abort immediately with a fatal `RuntimeError`. All schema changes must be applied exclusively through versioned Alembic migrations.

---

## 4. Software Supply Chain & Dependency Auditing

- Production dependencies are pinned to specific patched versions in [`requirements-prod.txt`](file:///Users/piero/Downloads/SentinelWP/requirements-prod.txt).
- Dependency vulnerability scans using `pip-audit` verified **0 known vulnerabilities** across all application libraries (Flask 3.1.3, Werkzeug 3.1.9, requests 2.34.2, urllib3 2.8.0, psycopg 3.1.19, Celery 5.4.0).
