# SentinelWP — Production Configuration Reference
## Environment Variables & Service Topology Specification

This document details all environment variables, defaults, validation rules, and configuration contracts for SentinelWP in production mode (`ENVIRONMENT=production`).

---

## 1. Core Application Environment Variables

| Variable Name | Type | Default | Required in Prod? | Description & Security Contract |
| :--- | :---: | :---: | :---: | :--- |
| `ENVIRONMENT` | string | `development` | **YES** | Set to `production`. Activates strict security guards, disables runtime `create_all()`, enforces cookie security, and disables test bypasses. |
| `WSA_SECRET_KEY` | string | *None* | **YES** | Flask session signing secret. Must be $\ge 32$ random characters. Reject known weak secrets and placeholders (`replace_with_`, `change-me`, etc.). |
| `DATABASE_URL` | string | *None* | **YES** | PostgreSQL connection URI. Format: `postgresql+psycopg://<user>:<pass>@<host>:5432/<db>`. Redacted in logs and health probes. |
| `REDIS_URL` | string | *None* | **YES** | Redis connection URI. Format: `redis://:<pass>@<host>:6379/0`. |
| `CELERY_BROKER_URL` | string | *None* | **YES** | Celery broker URI (identical to `REDIS_URL` or queue-specific DB). |
| `CELERY_RESULT_BACKEND` | string | *None* | **YES** | Celery results storage backend (`redis://...`). |
| `SCAN_EXECUTION_BACKEND` | string | `celery` | **YES** | Set to `celery`. Disables eager in-process execution. |
| `WSA_BEHIND_PROXY` | boolean | `false` | **YES** | Set to `true`. Mounts Werkzeug `ProxyFix` middleware behind trusted Nginx gateway. |
| `WSA_PROXY_X_FOR` | integer | `1` | Recommended | Number of upstream trusted reverse proxies for `X-Forwarded-For` header resolution. |
| `WSA_PROXY_X_PROTO` | integer | `1` | Recommended | Number of upstream proxies for `X-Forwarded-Proto` header resolution. |
| `WSA_PROXY_X_HOST` | integer | `1` | Recommended | Number of upstream proxies for `X-Forwarded-Host` header resolution. |
| `WSA_PROXY_X_PORT` | integer | `1` | Recommended | Number of upstream proxies for `X-Forwarded-Port` header resolution. |
| `WSA_PROXY_X_PREFIX` | integer | `0` | Recommended | Number of upstream proxies for `X-Forwarded-Prefix` header resolution. |
| `WSA_SESSION_COOKIE_SECURE` | boolean | `true` | **YES** | Enforces the `Secure` flag on Flask session cookies. Startup fails if set to `false` in production. |
| `WSA_SESSION_COOKIE_SAMESITE`| string | `Lax` | Recommended | SameSite policy for session cookies (`Lax` or `Strict`). |
| `WSA_ALLOW_PRIVATE_TARGETS` | boolean | `false` | **YES** | SSRF prevention guard. In production, must be `false` to block scanning of RFC 1918 addresses, loopback, and cloud metadata (`169.254.169.254`). |
| `WSA_TEST_TARGET_ALLOWLIST` | string | *Empty* | Prohibited | Strictly disabled fail-closed in production mode. |

---

## 2. Worker & Concurrency Configuration

| Variable Name | Default | Service | Description |
| :--- | :---: | :---: | :--- |
| `WORKER_SCAN_CONCURRENCY` | `4` | `worker-scan` | Number of concurrent scan processes. Adjust based on host CPU cores. |
| `WORKER_INTEL_CONCURRENCY` | `2` | `worker-intel` | Concurrency for background intelligence sync and outbox maintenance tasks. |
| `--max-tasks-per-child` | `50` (scan) / `100` (intel) | Workers | Recycles worker processes after $N$ tasks to mitigate Python memory fragmentation. |
| `--max-memory-per-child` | `250000` (KB) | `worker-scan` | Hard memory threshold (~250 MB) after which worker child process restarts gracefully. |

---

## 3. Threat Intelligence API Keys (Optional)

| Variable Name | Default | Purpose |
| :--- | :---: | :--- |
| `WORDFENCE_API_KEY` | *Empty* | Enables live Wordfence vulnerability feed synchronization. |
| `NVD_API_KEY` | *Empty* | Increases National Vulnerability Database (NVD) rate limits. |

---

## 4. Reverse Proxy & Network Isolation Architecture

- **`sentinelwp-internal` Network:** Private bridge network without host port forwarding. Attaches PostgreSQL, Redis, Flask Gunicorn WSGI, Scan Worker, Intel Worker, and Celery Beat.
- **`sentinelwp-frontend` Network:** Connects Nginx Gateway and Gunicorn WSGI.
- **Security Headers injected by Nginx:**
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
  - `X-Frame-Options: SAMEORIGIN`
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';`

---

## 5. Preflight Configuration Validation

Before starting or restarting services, validate `.env.production` using:

```bash
bash scripts/validate_prod_env.sh .env.production
```

Checks performed:
1. File permissions are restricted to `0600` or `0400`.
2. Required variables are present and non-empty.
3. No dummy placeholders (`replace_with_...`, `change-me`, etc.) exist.
4. Passwords and keys exceed minimum entropy thresholds (32 characters for `WSA_SECRET_KEY`, 16 characters for DB and broker passwords).
5. Database and Redis URLs match the credentials defined in the individual variables.
