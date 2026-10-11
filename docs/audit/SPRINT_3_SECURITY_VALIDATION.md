# Sprint 3 — Security Validation

## Overview

This document records the security analysis performed during Sprint 3, covering
scanner safety properties, scanning mode isolation, SSRF protection, and
distributed lock correctness.

---

## PHASE 7: Scanning Safety

### DETECT-GAP-001 Subdirectory Probe Gate

**Problem:** The Sprint 2 implementation of subdirectory probing
(`_DEFAULT_WP_SUBDIRS` in `wp_detector.py`) fired unconditionally on every call
to `detect()`, issuing up to 10 additional HTTP requests even in passive mode.
This violated the passive-mode contract (no extra probes beyond the initial root GET).

**Fix:** Added `ENABLE_SUBDIR_PROBE: bool = False` class attribute to
`WordPressDetector`. The orchestrator sets it `True` only for `safe-active`
and `full` scan modes:

```python
if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_SUBDIR_PROBE"):
    scanner.ENABLE_SUBDIR_PROBE = True
```

**Passive mode:** `ENABLE_SUBDIR_PROBE = False` → subdirectory loop is skipped →
only the root URL is probed.

**Scan mode isolation preserved:** The fix follows the exact same per-instance
pattern as `ENABLE_ACTIVE_PROBE` (DETECT-GAP-003/004). Class defaults are
never mutated.

---

### SSRF Protection

SSRF protection in `BaseScanner.validate_target()` applies to every HTTP request
including subdirectory probes. The subdirectory paths are drawn from a bounded
whitelist (`_DEFAULT_WP_SUBDIRS`, max 10 paths). No unbounded URL construction
is possible.

Redirect following is also SSRF-protected in `BaseScanner._get()`: the destination
URL of any redirect is re-validated through `validate_target()` before following.

**Acceptance criterion 8** (Critical scanner safety properties remain intact)
is satisfied. No SSRF protection was weakened or removed.

---

### User-Agent Policy

`WSA_USER_AGENT` env var is respected and applied once at session creation in
`BaseScanner`. No rotation or WAF-evasion logic was added (as per DETECT-OPEN-005
recommendation: honor operator override, do NOT rotate for evasion).

---

### HTTP 403 Handling

`PluginScanner._active_enumerate()` already treats HTTP 403 as confirmed plugin
presence (directory listing denied = plugin confirmed). This is documented behaviour
from Sprint 2 and was reviewed in Sprint 3 — no change required.

---

## PHASE 5: Distributed Lock Security Analysis

### Threat Model

In a multi-worker Celery deployment, two workers could simultaneously call
`sync_all()` causing:
- Duplicate Wordfence/KEV API calls (wasting API budget)
- Redundant DB writes (potential race conditions on upsert)

### Implementation

`_DistributedSyncLock` uses:
1. **Atomic acquisition**: Redis `SET NX EX` — only one process can acquire.
2. **Unique ownership token**: UUID4 stored as lock value. Only the holder can release.
3. **Bounded lease**: 300-second TTL prevents indefinite hold if worker crashes.
4. **Ownership-checked release**: Lua script — only deletes if value matches token.
5. **Graceful fallback**: When Redis is unreachable (timeout 1s), falls back to
   process-local `threading.Lock`. Single-process deployments are unaffected.

### Limitations

- The Redis fallback provides process-level exclusion only. Two separate Python
  processes without Redis access could still race. This is documented in
  `SPRINT_3_REMAINING_GAPS.md`.
- Redis TTL of 300s: if a sync takes > 5 minutes, a second worker could acquire
  the lock while the first is still running. Wordfence sync should complete well
  under 5 minutes in normal operation.

---

## No Secrets in Notifications

`check_intel_triggered_reassessment()` and `get_monitoring_dashboard()` explicitly
exclude all secret/credential fields from their payloads. The outbox event
`payload_json` is verified in `TestPhase8IntelMonitor::test_no_secrets_in_alert_payload`.

---

## Acceptance Criteria Mapping

| Criterion | Mechanism | Status |
|-----------|-----------|--------|
| 1. Stable asset identities | UUID, canonical_url dedup | ✅ |
| 2. Scheduling reliability | DB-level claim, heartbeat recovery | ✅ |
| 3. Duplicate scan prevention | scheduled_runs UNIQUE constraint | ✅ |
| 4. Finding change tracking | ScanDifferential, FindingHistory | ✅ |
| 5. No false resolution on failure | RESOLVED gated to completed scan | ✅ |
| 6. Intel-triggered re-evaluation | check_intel_triggered_reassessment | ✅ |
| 7. Asset authorization enforced | verify_scan_authorization pre-flight | ✅ |
| 8. Scanner safety intact | SSRF, mode isolation, no UA rotation | ✅ |
| 9. Migrations tested | TestMigration006Schema, safe_add_column | ✅ |
| 10. Regression tests pass | 438 passing, 0 failures | ✅ |
