# SentinelWP — Sprint 8 End-to-End Operational Workflows
## Full Security Lifecycle, Finding Transitions & Incomplete Scan Safety Invariants

**Sprint:** Sprint 8 — End-to-End Pilot Validation & Release Candidate Certification  
**Target Branch:** `test/sentinelwp-sprint8-pilot-validation`  
**Test Suite Coverage:** `tests/test_sprint3_continuous_monitoring.py`, `tests/test_sprint4_workflow_integration.py`, `tests/test_sprint8_pilot_validation.py`  

---

### 1. 14-Step Operational Security Workflow

The end-to-end security operational workflow was validated across its complete lifecycle:

```
[ 1. Asset Registration ] ───▶ [ 2. Monitoring Config ] ───▶ [ 3. Authorized Scan Execution ]
                                                                             │
                                                                             ▼
[ 6. CVE Correlation ] ◀─── [ 5. Component Identification ] ◀─── [ 4. Evidence Persistence ]
         │
         ▼
[ 7. Risk Posture / Score ] ───▶ [ 8. Report Generation ] ───▶ [ 9. Simulated Remediation ]
                                                                             │
                                                                             ▼
[ 12. Monitoring Dashboard ] ◀─── [ 11. Lifecycle Transitions ] ◀─── [ 10. Subsequent Scan ]
         │
         ▼
[ 13. Alert Deduplication ] ───▶ [ 14. Incomplete Scan Safety Guardrail ]
```

---

### 2. Workflow Step Validation Details

| Step | Operation / Action | Implementation Module | Expected Behavior | Actual Behavior | Status |
|---|---|---|---|---|:---:|
| **1** | Register Asset | `repository.ensure_asset()` | Canonicalizes target URL; sets status `active` | Stored in SQLite/Postgres with UUID | **PASS** |
| **2** | Monitoring Config | `repository.save_asset()` | Sets `monitoring_enabled=True`, sets schedule | Policy persisted with assigned cadence | **PASS** |
| **3** | Execute Scan | `core.tasks.scan_tasks` | Validates `ScanAuthorization`; enqueues to Celery | Re-checks authorization before run | **PASS** |
| **4** | Store Evidence | `repository.save_scan()` | Stores headers, HTML snippets, TLS certificates | Redacts secrets; persists to DB | **PASS** |
| **5** | Component ID | `scanners.wp_detector` | Fingerprints WordPress core, plugins, and themes | Identifies exact slugs & versions | **PASS** |
| **6** | Correlate CVEs | `core.vulnerability_intelligence` | Matches software versions against CISA/NVD feeds | Enriches with CVSS score & vector | **PASS** |
| **7** | Calculate Posture | `core.risk_engine` | Generates 0–100 risk score and A–F letter grade | Deterministic formula based on CVSS | **PASS** |
| **8** | Generate Reports | `reports.generator` | Emits PDF, HTML, Excel, CSV, SARIF v2.1.0 | Correct counts; formula sanitized | **PASS** |
| **9** | Simulate Fix | Local Controlled Fixture | Vulnerable component updated to patched version | Mock response returns patched version | **PASS** |
| **10**| Subsequent Scan | `core.tasks.scan_tasks` | Executes follow-up scan on same asset | Enqueued and executed cleanly | **PASS** |
| **11**| Lifecycle Transitions| `core.differential` | Tracks NEW, PERSISTING, RESOLVED, REOPENED | Fingerprint reconciliation | **PASS** |
| **12**| Dashboard Update | `templates/dashboard.html` | Real-time posture score and active finding count | KPIs update dynamically | **PASS** |
| **13**| Alert Deduplication| `core.intel_monitor` | Outbox prevents spamming alerts for same finding | Unique event key drops duplicates | **PASS** |
| **14**| Failure Safety | `core.differential` | Failed scan never resolves existing findings | `is_complete=False`; 0 false resolutions | **PASS** |

---

### 3. Finding Lifecycle Transitions Validation

Using stable SHA-256 finding fingerprints (`category:slug:vulnerability_id`), the differential engine computes state transitions across consecutive scan cycles:

1. **Cycle 1 (Initial Scan):**  
   New finding detected &rarr; Transition state: **`NEW`** (`new_count = 1`).
2. **Cycle 2 (Unresolved Scan):**  
   Finding remains present in target &rarr; Transition state: **`PERSISTING`** (`persisting_count = 1`).
3. **Cycle 3 (Remediation Scan):**  
   Component upgraded; finding absent in target &rarr; Transition state: **`RESOLVED`** (`resolved_count = 1`).
4. **Cycle 4 (Regression Scan):**  
   Component downgraded or misconfiguration reintroduced &rarr; Transition state: **`REOPENED`** (`reopened_count = 1`).

---

### 4. Critical Safety Invariant: Incomplete Scan Protection

> [!IMPORTANT] Incomplete Scan Safety Invariant  
> A critical failure mode in automated vulnerability monitoring is false resolution: if a subsequent scan crashes, times out, or fails due to network partitions, the raw scan result contains 0 findings. Naive differential systems would falsely mark all previous findings as "RESOLVED".

In SentinelWP:
- `core/differential.py::compute_scan_differential()` checks `new_scan.status == ScanStatus.COMPLETED`.
- If `new_scan.status != ScanStatus.COMPLETED` (e.g., `FAILED`, `CANCELLED`, `TIMEOUT`), the engine forces:
  ```python
  diff.is_complete = False
  diff.incomplete_reason = f"New scan status is {new_scan.status}, not COMPLETED"
  # Zero RESOLVED changes emitted
  ```
- Validated in `tests/test_sprint8_pilot_validation.py::TestSprint8CompleteSecurityWorkflow::test_incomplete_scan_safeguard_prevents_false_resolutions`.
