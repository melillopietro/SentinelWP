# Sprint 2 — Security Validation

## Scope

This document records the security-specific review performed during Sprint 2,
covering the changes introduced in commit `42132a5` on branch
`feat/sentinelwp-sprint2-detection-hardening`.

---

## SCAN-GAP-001 — Soft-404 SSRF Analysis

### Change Under Review
`BaseScanner.is_soft_404()` generates and fetches a sentinel URL derived from
`self.target_url`:

```python
sentinel_path = f"/wp-content/plugins/sentinelwp-does-not-exist-{uuid.uuid4().hex[:8]}/"
sentinel_url = baseline_url or (self.target_url.rstrip("/") + sentinel_path)
```

### Threat Model
| Threat | Assessment |
|--------|-----------|
| SSRF via sentinel URL | **Not exploitable.** The sentinel URL is a path appended to the already-validated `target_url`. SSRF validation runs in `BaseScanner.validate_target()` before any scanner runs. The sentinel path is a static prefix with a random 8-hex suffix — no user-controlled input in the URL. |
| External request leakage | **Not present.** `baseline_url` can only be provided by internal scanner code, not via any user-facing API or scan configuration field. |
| UUID predictability | **Not a concern.** The UUID is used purely to construct a non-existent path suffix to avoid caching. There is no secret or auth token in the URL. |
| Request amplification | **Bounded.** `is_soft_404()` is called at most once per `_active_enumerate()` invocation (result cached in `_soft404_checked`), adding a maximum of 2 HTTP requests (probe + sentinel) to the scan budget. |

### Verdict: **PASS** — No new SSRF risk introduced.

---

## DETECT-GAP-001 — Subdirectory Probe Enumeration Scope

### Change Under Review
`detect()` probes up to 10 subdirectory candidates from `_get_subdir_hints()`.

### Threat Model
| Threat | Assessment |
|--------|-----------|
| Unbounded directory enumeration | **Mitigated.** The probe list is capped at 10 entries (`[:10]`). Each probe calls `_detect_multi_signal()` which issues a bounded set of HTTP requests (same as a root probe). |
| User-controlled subdir expansion | `WP_SUBDIR_HINTS` is an environment variable — controlled by the operator deploying SentinelWP, not by end users. No injection risk from scan targets. |
| SSRF via subdirectory paths | **Not exploitable.** All URLs are formed as `target_url.rstrip("/") + subdir`. `target_url` has already passed SSRF validation. Subdirectory values are normalized: only `[a-zA-Z0-9_/-]` patterns, leading `/` enforced. |
| First-match termination bypass | **Not applicable.** The `break` on first match (confidence ≥ 0.15) is a performance optimization and cannot be manipulated by the target server to bypass security checks. |

### Verdict: **PASS** — Enumeration is bounded and operator-controlled.

---

## INTEL-GAP-003 — Concurrency Lock Security

### Change Under Review
`threading.Lock()` used as a non-reentrant mutex for sync operations.

### Analysis
- The lock is module-level (`_sync_lock`), providing process-wide protection.
- `acquire(blocking=False)` prevents deadlock when the lock is already held.
- `_inner()` variants are module-private (underscore prefix); not exposed through
  any API route or Celery task directly.
- Lock is released in a `finally` block in `sync_all()`, preventing permanent
  lock starvation on exception.

### Residual Risk
- **Multi-process deployments (Celery workers on different machines):** The
  `threading.Lock()` is process-local. In a multi-process deployment, two
  separate worker processes could run `sync_all()` simultaneously.
  **Recommendation for Sprint 3:** Replace with a Redis-backed distributed lock
  (e.g., `redis-py` `Lock` or `celery-redbeat` singleton tasks).

### Verdict: **CONDITIONAL PASS** — Sufficient for single-process/single-worker
deployments. Distributed lock required for multi-worker deployments.

---

## INTEL-GAP-004 — CVSS Severity Escalation Prevention

### Change Under Review
Severity assignment in `enrich_findings_with_cves()`.

### Security Impact
The previous code (`f.severity = Severity.HIGH` unconditionally) created a
finding inflation vulnerability: an attacker who controls a CVE entry in OSV
(e.g., by filing a low-severity advisory) could not exploit this to suppress
findings — but conversely, legitimate low-CVSS advisories were being reported
as HIGH, potentially causing alert fatigue and response miscalibration.

The fix normalises downward as well as upward:
- CVSS 9.8 → CRITICAL ✓
- CVSS 4.0 → MEDIUM (not inflated to HIGH) ✓
- No CVSS data → existing severity preserved ✓

### Verdict: **PASS** — Eliminates severity inflation, improves alert fidelity.

---

## SCAN-GAP-004 — TLS Deprecation

### Change Under Review
Removal of `ssl.PROTOCOL_TLSv1` and `ssl.PROTOCOL_TLSv1_1` from `_check_protocols()`.

### Security Assessment
The new implementation uses `ssl.TLSVersion` enum constraints with
`PROTOCOL_TLS_CLIENT` as the base context. This is the correct, modern approach:
- `PROTOCOL_TLS_CLIENT` enforces hostname checking by default (disabled here via
  `ctx.check_hostname = False` because we're probing a third-party target, not
  authenticating to it).
- Setting `minimum_version = maximum_version = tls_version` forces the handshake
  to use exactly that TLS version, giving an accurate detection of deprecated
  protocol support.
- The legacy fallback is wrapped in `warnings.catch_warnings()` to prevent
  DeprecationWarning noise from polluting logs on older Python builds.

### Verdict: **PASS** — Modernization reduces runtime warnings and ensures
compatibility with Python 3.12+ without losing detection capability.

---

## No New Attack Surface

The Sprint 2 changes were reviewed for:

| Attack surface category | Assessment |
|------------------------|-----------|
| New HTTP endpoints introduced | None |
| New authenticated routes | None |
| New DB schema changes | None |
| New file writes | None |
| New subprocess execution | None |
| New deserialization paths | None |
| New external network calls | `_enrich_with_nvd_inner()` calls NVD API (existing `nvd_client.py`; no new domain) |
| New environment variable parsing | `WP_SUBDIR_HINTS` (operator-controlled, comma-separated string of paths, no eval) |

---

## Summary

| ID | Security Finding | Severity | Status |
|----|-----------------|----------|--------|
| SCAN-GAP-001 | Soft-404 sentinel URL — no SSRF risk | N/A | PASS |
| DETECT-GAP-001 | Subdirectory probes bounded and operator-controlled | N/A | PASS |
| INTEL-GAP-003 | Thread-local lock (process-local only) | LOW | CONDITIONAL PASS |
| INTEL-GAP-004 | CVSS severity inflation eliminated | N/A | PASS |
| SCAN-GAP-004 | TLS API modernisation | N/A | PASS |

**Open security recommendation for Sprint 3:** Distributed lock for
`sync_all()` in multi-worker deployments (Redis-backed).
