# SentinelWP — Sprint 8 Remaining Gaps & Pilot Roadmap
## Non-Blocking Limitations, Residual Operational Risks & Post-Pilot Roadmap

**Sprint:** Sprint 8 — End-to-End Pilot Validation & Release Candidate Certification  
**Target Branch:** `test/sentinelwp-sprint8-pilot-validation`  
**Assessment Date:** October 2026  
**Status:** 0 Critical Pre-Pilot Blockers; 5 Post-Pilot Enhancements Cataloged  

---

### 1. Catalog of Remaining Gaps

| Gap ID | Subsystem | Description | Impact & Severity | Proposed Resolution |
|---|---|---|:---:|---|
| **S8-GAP-001** | **E2E Visual QA** | Playwright and Chromium browser binaries are not packaged in the local virtualenv, leaving pixel-level visual screenshots unverified. | **Low**<br>(Headless WSGI verified) | Package Playwright in dedicated CI/CD Docker image with automated screenshot comparisons. |
| **S8-GAP-002** | **Versioning** | Discrepancy between runtime `core/version.py` (`3.7.0`) and high-level docs (`3.8.0-enterprise` / roadmap `4.0.0`). | **Low**<br>(Operational cosmetic) | Execute a synchronized, approved version bump across `core/version.py`, `app.py`, and `README.md`. |
| **S8-GAP-003** | **Observability** | Platform uses JSON structured logs and `/health` probes, but lacks a dedicated Prometheus `/metrics` scrape endpoint. | **Low**<br>(Convenience) | Implement standard Prometheus metric collector exporter route in Workspace 6. |
| **S8-GAP-004** | **Identity Federation** | Platform enforces local RBAC and API tokens, but lacks native SAML 2.0 / OIDC enterprise single sign-on (SSO). | **Low**<br>(Enterprise roadmap) | Add SAML 2.0 / OIDC provider configuration in Workspace 6 (Administration). |
| **S8-GAP-005** | **Data Retention** | High-volume scanning environments require automated background retention policies to purge scan runs older than 365 days. | **Low**<br>(Capacity management) | Add scheduled Celery task to archive/purge scans exceeding tenant retention policies. |

---

### 2. Residual Operational Risks & Production Mitigations

1. **Threat Intelligence NIST API Rate Limiting:**
   - NIST rate-limits unauthenticated API requests to 5 calls per 30 seconds.
   - *Mitigation:* The NVD synchronizer automatically throttles unauthenticated enrichments to 10 records per cycle. Production deployments must configure an enterprise `NVD_API_KEY`.
2. **Distributed Lock Network Partitions:**
   - When `REQUIRE_DISTRIBUTED_LOCK=true`, threat intelligence synchronization fails closed if Redis becomes partitioned.
   - *Mitigation:* Highly available Redis cluster or AWS ElastiCache deployment prevents single-node downtime.
3. **CSV Export Formula Injection Remediation:**
   - Discovered and resolved in Sprint 8 by sanitizing cells in `app.py::export_scans_csv()`.
   - *Mitigation:* Fully covered by automated test regression in `test_sprint8_pilot_validation.py`.

---

### 3. Release Conclusion

SentinelWP possesses zero critical blockers for its controlled enterprise pilot. All remaining gaps are classified as minor post-pilot enhancements suitable for post-release iterations.
