# SentinelWP Enterprise - Security Operations & Hardening Guide

## 1. Security Architecture & Threat Model

SentinelWP operates as an enterprise security posture management engine. Because it processes asset data, authorization tokens, and vulnerability intelligence, its internal defenses follow strict defense-in-depth:

```
+---------------------------------------------------------------+
|                      Edge Security / WAF                      |
|           DDoS Mitigation, Strict TLS 1.3, Rate Limiting      |
+-------------------------------+-------------------------------+
                                |
                                v
+---------------------------------------------------------------+
|                       Application Layer                       |
|  - CSP, HSTS, X-Content-Type-Options, Permissions-Policy      |
|  - Distributed Sliding-Window Rate Limiter (Redis)            |
|  - Session Hardening (SameSite=Lax, HttpOnly, Secure)         |
|  - Cryptographic State/Nonce OIDC SSO                         |
|  - Granular RBAC (Admin, Analyst, Viewer) & Tenant Isolation  |
+-------------------------------+-------------------------------+
                                |
                                v
+---------------------------------------------------------------+
|                         Data Layer                            |
|  - Least Privilege Database Users (Migration, App, Readonly)  |
|  - Parameterized Queries (Zero Raw SQL Injection)             |
|  - Pluggable Secrets Provider (HashiCorp Vault, File, Env)    |
|  - Tenant Offboarding & GDPR Right-to-be-Forgotten Purge      |
+---------------------------------------------------------------+
```

---

## 2. API Hardening & Distributed Rate Limiting

SentinelWP implements a distributed sliding-window rate limiter powered by Redis (`core/rate_limiter.py`):

- **Algorithm**: Sorted Set (`ZSET`) tracking timestamped hits per client IP and tenant.
- **Failover**: Gracefully degrades to an in-memory sliding window if Redis becomes temporarily unreachable.
- **Headers**: Responses include rate limit telemetry:
  - `Retry-After: <seconds>` on `429 Too Many Requests`.

---

## 3. API Key Lifecycle & Zero-Downtime Key Rotation

SentinelWP provides zero-downtime key rotation via `POST /api/v1/api-keys/rotate` and `POST /api/v1/auth/rotate-key`:

### Rotation Request:
```bash
curl -X POST https://sentinelwp.internal/api/v1/auth/rotate-key \
  -H "Authorization: Bearer <CURRENT_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"grace_period_hours": 24}'
```

### Rotation Mechanics:
1. Generates a new cryptographic API key with matching scopes and tenant association.
2. If `grace_period_hours > 0`, the existing key remains active until the specified expiry, enabling clients and pipelines to update credentials without downtime.
3. If `grace_period_hours == 0`, the old key is revoked immediately.
4. Generates an immutable `api_key_rotated` audit log entry.

---

## 4. Enterprise Secrets Management

SentinelWP abstracts secret retrieval through `core/secrets/provider.py`:

1. **VaultSecretProvider**: Connects to HashiCorp Vault using AppRole authentication over TLS.
2. **FileSecretProvider**: Reads Kubernetes secrets mounted as files (`/run/secrets/`).
3. **EnvSecretProvider**: Standard 12-factor environment variable provider.
4. **CompositeSecretProvider**: Resolves secrets with configurable fallback precedence.

---

## 5. Structured JSON Logging & SIEM Integration

Production logs are formatted as single-line JSON (`core/logging_config.py`) enriched with:
- `timestamp`: UTC ISO 8601 timestamp.
- `request_id`: Correlation ID passed across microservices.
- `tenant_id`: Multi-tenant workspace identifier.
- `user_id`: Authenticated user or API key identity.
- `http`: Request method, route, and remote IP.

Logs can be shipped directly to Datadog, Splunk, or Elastic Logstash via FluentBit.

---

## 6. Tenant Offboarding & Data Purging (GDPR / SOC2)

SentinelWP supports both soft-delete (suspension) and hard-delete (permanent purging) of customer workspaces:

- **Soft Offboarding** (`POST /tenants/<tenant_id>/offboard`):
  - Suspends tenant workspace access.
  - Automatically revokes all active tenant API keys.
  - Disables all recurring scheduled scans.
  - Logs `tenant_offboarded` audit event.

- **Hard Deletion** (`DELETE /api/v1/tenants/<tenant_id>?hard=true`):
  - Requires explicit confirmation header `X-Confirmation: <tenant_id>`.
  - Cascades deletions across assets, scan records, vulnerability findings, scan authorizations, scheduled runs, and audit logs.
  - Guarantees complete data sanitization.
