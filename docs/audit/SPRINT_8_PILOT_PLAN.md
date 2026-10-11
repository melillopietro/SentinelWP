# SentinelWP — Sprint 8 Pilot Validation Plan
## Enterprise Pilot Methodology, Acceptance Criteria & Environment Topology

**Sprint:** Sprint 8 — End-to-End Pilot Validation & Release Candidate Certification  
**Target Branch:** `test/sentinelwp-sprint8-pilot-validation`  
**Base Commit:** `07c3e2c` (`feat/sentinelwp-sprint7-release-candidate`)  
**Assessment Date:** October 2026  
**Status:** Pilot Verification & Certification In Progress  

---

### 1. Objective & Scope

The primary objective of Sprint 8 is to perform end-to-end pilot validation of SentinelWP in a realistic, strictly controlled environment to determine whether the platform is ready for an enterprise pilot deployment and formal Release Candidate certification.

This sprint strictly focuses on:
- Verification of functional workflows, detection accuracy, and reporting integrity.
- Stabilization and defect remediation (e.g., CSV formula injection protection).
- Validation of multi-tenant security, SSRF boundaries, and distributed reliability.
- Resolution and transparent documentation of application versioning discrepancies.

Sprint 8 introduces **no** new product features and **no** interface redesigns.

---

### 2. Pilot Acceptance Criteria Matrix

| Category | Requirement / Acceptance Criterion | Target Threshold | Validation Method | Initial Status |
|---|---|:---:|---|:---:|
| **Architecture** | Six unified workspaces operational without regression | 100% route availability | WSGI & Route Tests | **PASS** |
| **Detection Quality** | Accurate identification of core, plugins, themes; soft-404 suppression | Zero False Positives | Controlled Fixtures | **PASS** |
| **Workflow Integrity** | Differential lifecycle: NEW, PERSISTING, RESOLVED state transitions | 100% deterministic | Automated Suite | **PASS** |
| **Safety Invariants** | Incomplete/failed scans never produce false RESOLVED states | 0 false resolutions | Test Invariant Check | **PASS** |
| **Security Controls** | Multi-tenant BOLA defense returns 404; SSRF blocks cloud metadata & RFC 1918 | Fail-closed | Security Suite | **PASS** |
| **Reporting Accuracy** | PDF, HTML, Excel, CSV, SARIF exports; formula injection sanitization | Zero unescaped formulas | Report Audit & Tests | **PASS** |
| **Distributed HA** | Redis distributed locking, Celery task segregation, outbox crash recovery | Idempotent / Fail-closed | Fault Injection & Unit | **PASS** |
| **E2E Visual QA** | Headless DOM and controller verification; real browser pixel snapshots | Browser Automation | WSGI / Headless | **CONDITIONAL** |

---

### 3. Pilot Environment Topology & Resource Protection

#### 3.1 Host Topology Audit
Inspection of the local host environment revealed existing active containers and occupied ports:
- `seating_postgres` bound to port `5433`
- `seating_redis` bound to port `6379`
- `ransomscope-postgres` bound to port `5432`
- `ransomscope-api` bound to port `8080`
- `ransomware-x-sonarqube` bound to port `9000`

#### 3.2 Non-Interference Guarantees
To comply with mandatory project constraints:
1. **Zero Overwriting:** No existing Docker containers, volumes, or networks are stopped, modified, or overwritten.
2. **Credential Isolation:** Pilot validation uses ephemeral, disposable test tenants (`tenant-s8-*`) and synthetic UUIDs. Production administrator passwords and local `data/wsa.db` records remain unshared and untouched.
3. **SSRF Guardrails:** SSRF protections (`is_safe_target_url`) remain active by default. Laboratory tests verify blocking of loopback (`127.0.0.1`), link-local/cloud metadata (`169.254.169.254`), and private networks (`10.0.0.0/8`, `192.168.0.0/16`).

---

### 4. Versioning Analysis & Reconciliation Plan

An audit of version references revealed an inconsistency between the runtime codebase and external documentation:
- **Runtime Codebase:** `core/version.py` defines `__version__ = "3.7.0"` and `app.py::health()` returns `"version": "3.7.0"`.
- **Sprint 7 Candidate Tag:** Proposed as `v3.7.0-rc1`.
- **Public & Architecture Docs:** `README.md`, `docs/ENTERPRISE_RUNBOOK.md`, and `docs/ARCHITECTURE_PHASE3.md` document `v3.8.0-enterprise`.
- **Public Product Roadmap:** References anticipated major milestone `4.0.0`.

**Recommendation:**  
The runtime version remains `3.7.0` during Sprint 8 pilot validation to maintain consistency with `core/version.py`. Following successful pilot validation, a unified stakeholder-approved version bump to `v3.8.0` (or `v4.0.0-rc1` upon full enterprise release) should be executed across all configuration files simultaneously.
