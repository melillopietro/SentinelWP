# SentinelWP — Sprint 9 Security, Multi-Tenancy & Integrity Verification Report

## 1. Executive Summary

This report assesses the security posture, multi-tenancy boundaries, SSRF defenses, and report integrity protections verified during Sprint 9.

---

## 2. SSRF Protection & Narrow Allowlist Verification

SentinelWP enforces defense-in-depth against Server-Side Request Forgery (SSRF) at both URL parsing and hop-by-hop redirect levels.

### 2.1 Baseline Protection
- **IPv4 Private Ranges**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` blocked.
- **Loopback Ranges**: `127.0.0.0/8`, `::1` blocked.
- **Link-Local & Cloud Metadata**: `169.254.0.0/16`, `metadata.google.internal`, `instance-data` blocked.

### 2.2 Narrow Test Allowlist (`WSA_TEST_TARGET_ALLOWLIST`)
To permit scanning authorized internal laboratory targets without compromising production security:
- `WSA_TEST_TARGET_ALLOWLIST` explicitly checks `target_netloc` (e.g. `127.0.0.1:8099`).
- **Strict Invariant**: Cloud metadata (`169.254.0.0/16` and metadata hostnames) is **never bypassed**, even if erroneously configured in the allowlist.
- **Port Isolation**: Access to non-allowlisted internal ports (e.g. `127.0.0.1:8080`) remains blocked.

---

## 3. Multi-Tenancy & BOLA / IDOR Verification

All data access functions enforce strict `tenant_id` scoping:
- Assets, scans, findings, authorizations, and users are isolated by tenant partition.
- Cross-tenant lookups fail closed and return 404/403.
- Audit event logging records actor user ID, username, and tenant ID on all state-altering operations.

---

## 4. Report Integrity & Formula Injection Defense

### 4.1 Multi-Format Export Artifacts
Generated from the live pilot scan (`2c91f503-6833-46fd-9d41-5d9dd65a4a39`):
1. **Executive HTML**: 63,707 bytes (`pilot_scan_*.html`)
2. **Machine-Readable JSON**: 39,593 bytes (`pilot_scan_*.json`)
3. **Structured Excel**: 13,082 bytes (`pilot_scan_*.xlsx`)
4. **Standard SARIF v2.1.0**: 69,744 bytes (`pilot_scan_*.sarif`)
5. **Printable PDF**: 18,817 bytes (`pilot_scan_*.pdf`)

### 4.2 Formula Injection Defense (CSV & Excel)
All cell values prefixed with dynamic spreadsheet formula characters (`=`, `+`, `-`, `@`) are systematically prepended with a single quote (`'`) to neutralize remote code execution / DDE injection in Microsoft Excel, LibreOffice Calc, and Google Sheets.
