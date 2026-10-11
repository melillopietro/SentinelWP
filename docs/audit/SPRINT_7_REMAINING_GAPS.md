# SentinelWP — Sprint 7 Remaining Gaps & Future Roadmap
## Non-Blocking Limitations, Residual Operational Risks & Sprint 8 Recommendations

**Sprint:** Sprint 7 — Enterprise QA, Stability & Release Candidate  
**Target Branch:** `feat/sentinelwp-sprint7-release-candidate`  
**Assessment Date:** October 2026  
**Status:** All Critical Pre-Release Blockers Resolved; Minor Post-Pilot Enhancements Cataloged  

---

### 1. Residual Non-Blocking Limitations

| ID | Domain | Description | Current Mitigation | Severity / Impact |
|---|---|---|---|:---:|
| **S7-GAP-001** | **E2E Visual QA** | Headless WSGI and DOM structure tested, but automated browser screenshots remain **NOT VERIFIED** due to absence of Playwright in virtualenv. | Complete DOM, HTTP, and RBAC coverage via Flask test client. | Low (Non-blocking for backend pilot) |
| **S7-GAP-002** | **Observability** | Platform uses structured JSON logging and `/health` route, but lacks a dedicated Prometheus `/metrics` endpoint. | Standard log scrapers (Fluentbit, Datadog) extract metrics from application logs. | Low (Operational convenience) |
| **S7-GAP-003** | **Identity Federation** | Authentication supports local username/password, API tokens, and RBAC, but does not yet package SAML 2.0 or OIDC single sign-on (SSO). | Can be fronted by reverse-proxy OAuth2-Proxy / Cloudflare Access for enterprise SSO. | Low (Enterprise feature roadmap) |
| **S7-GAP-004** | **Data Retention** | High-volume scanning environments lack an automated background retention purge job for scan logs older than 365 days. | Manual admin purge endpoint available (`/admin/purge-db`) with admin authorization. | Low (Storage capacity manageable) |

---

### 2. Residual Operational Risks & Mitigations

#### 2.1 Threat Feed External Rate Limiting
- **Risk:** Without an enterprise NVD API key (`NVD_API_KEY`), NIST rate-limits unauthenticated API calls to 5 requests per 30 seconds.
- **Mitigation:** The NVD synchronizer automatically limits unauthenticated enrichments to 10 records per cycle, queuing remaining records for subsequent ticks.
- **Recommendation:** Production deployments should procure a free NIST NVD API key and configure `NVD_API_KEY`.

#### 2.2 Redis Cluster Partitioning
- **Risk:** If Redis becomes partitioned while `REQUIRE_DISTRIBUTED_LOCK=true`, threat intelligence background sync fails closed.
- **Mitigation:** Highly available Redis Sentinel or AWS ElastiCache cluster configuration prevents single points of failure.

---

### 3. Sprint 8 Strategic Recommendations

Following the controlled enterprise pilot of Release Candidate `v3.7.0-rc1`, the following items are recommended for Sprint 8:

1. **Automated Visual UI Regression Pipeline:**  
   Incorporate Playwright and headless Chromium into the Docker build / CI workflow to enable pixel-diff screenshot comparisons across viewport breakpoints and dark/light themes.
2. **Native Prometheus / OpenTelemetry Exporter:**  
   Implement a `/metrics` route exporting real-time Prometheus gauges for scan duration, queue depth, outbox reclaims, and threat intelligence freshness.
3. **Enterprise SSO & SAML 2.0 Connector:**  
   Introduce SAML/OIDC configuration in Workspace 6 (Administration) for seamless integration with Okta, Azure AD (Entra ID), and Ping Identity.
4. **Automated Audit & Finding Retention Lifecycle:**  
   Provide automated archival policies to compress historical scan runs into cold object storage (S3/GCS) after 90–360 days.
