# SentinelWP — Sprint 8 Security Hardening & Data Integrity Validation
## Multi-Tenant Isolation, SSRF Defense, Sensitive Data Redaction & Audit Integrity

**Sprint:** Sprint 8 — End-to-End Pilot Validation & Release Candidate Certification  
**Target Branch:** `test/sentinelwp-sprint8-pilot-validation`  
**Test Suite Coverage:** `tests/test_p0_security.py`, `tests/test_phase2_tenant_asset_auth.py`, `tests/test_phase5_production_readiness.py`, `tests/test_sprint7_qa_hardening.py`, `tests/test_sprint8_pilot_validation.py`  

---

### 1. Multi-Tenant Isolation & BOLA Defense

SentinelWP is architected around logical multi-tenancy where every entity (`assets`, `findings`, `scans`, `scan_jobs`, `audit_events`) is scoped to a `tenant_id`.

#### 1.1 Object-Level Access Verification (OWASP API1:2023 - BOLA)
- **Controller Defense:** `app.py` queries entities explicitly via `(id, tenant_id)`.
- **Enumeration Prevention:** When an authenticated user belonging to Tenant B queries `/asset/<tenant_a_asset_id>`, the server returns **HTTP 404 Not Found** instead of HTTP 403 Forbidden, preventing malicious actors from enumerating resource IDs across tenant boundaries.
- **Verification:** Validated in `tests/test_sprint8_pilot_validation.py::TestSprint8DataIntegrityAndSecurity::test_tenant_bola_protection_returns_404`.

---

### 2. SSRF (Server-Side Request Forgery) Defense Matrix

SentinelWP processes arbitrary user-supplied WordPress URLs for scanning. To guarantee the scanner cannot be abused to pivot against internal infrastructure or cloud hypervisors:

| Prohibited Network Range / Target | RFC Standard / Cloud Provider | Scanner Action | Validation Result |
|---|---|:---:|:---:|
| `169.254.169.254` | AWS / GCP / Azure IMDS Metadata IP | **DROP / BLOCK** | **PASS** |
| `169.254.0.0/16` | RFC 3927 Link-Local Addressing | **DROP / BLOCK** | **PASS** |
| `127.0.0.0/8`, `::1`, `localhost` | Loopback Interface | **DROP / BLOCK** | **PASS** |
| `10.0.0.0/8` | RFC 1918 Private Class A | **DROP / BLOCK** | **PASS** |
| `172.16.0.0/12` | RFC 1918 Private Class B | **DROP / BLOCK** | **PASS** |
| `192.168.0.0/16` | RFC 1918 Private Class C | **DROP / BLOCK** | **PASS** |
| `file://`, `gopher://`, `dict://` | Dangerous URI Schemes | **REJECT** | **PASS** |
| `https://pilot.wordpress.org` | Legitimate Public External FQDN | **PERMIT** | **PASS** |

- **Verification:** Validated in `tests/test_sprint8_pilot_validation.py::TestSprint8DataIntegrityAndSecurity::test_ssrf_blocks_private_and_cloud_metadata`.

---

### 3. Sensitive Data Redaction & Audit Integrity

#### 3.1 Secret Redaction in Scans & Evidence
- **Mechanism:** In `core/evidence/redactor.py`, all HTTP request/response headers, raw configuration snippets, and error traces undergo regex redaction before database persistence:
  - Authorization tokens (`Bearer ...`, `Basic ...`)
  - Cookies (`session=...`, `PHPSESSID=...`, `wordpress_logged_in=...`)
  - Database passwords extracted from misconfigured `wp-config-sample.php`
- **Result:** Stored finding raw data contains only redacted placeholders (`[REDACTED]`), preventing secret exposure in reports and dashboards.

#### 3.2 Append-Only Audit Logging
- **Table:** `audit_events` with indexed `(tenant_id, created_at)`.
- **Logged Events:** Authentication attempts, user management, scan launches, authorization changes, and outbox recoveries.
- **Tamper Evidence:** No application controller exposes update or delete endpoints on `audit_events`.

---

### 4. Database Migration & Backup Safety

1. **Non-Destructive Copy Migration:**  
   `scripts/migrate_sqlite_to_postgres.py` performs pure read-and-copy migration from SQLite to PostgreSQL. The source SQLite database is opened in read-only mode and is never mutated during migration.
2. **Snapshot Safety:**  
   Database snapshot procedures (`data/wsa.db.bak`) run without stopping the web tier by leveraging SQLite WAL (Write-Ahead Logging) checkpoint synchronization.
