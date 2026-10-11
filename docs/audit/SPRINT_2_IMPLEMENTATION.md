# Sprint 2 — Implementation Record
**Branch:** `feat/sentinelwp-sprint2-detection-hardening`  
**Commit:** `42132a5`  
**Date:** 2025  
**Test baseline entering sprint:** 352 passing  
**Test baseline exiting sprint:** 394 passing (+42 new, 0 regressions)

---

## Gaps Closed

| ID | Category | File(s) Changed | Summary |
|----|----------|-----------------|---------|
| DETECT-GAP-003 | Scanner accuracy | `scanners/theme_scanner.py`, `scanners/orchestrator.py` | ThemeScanner passive gate + orchestrator active-probe flag |
| DETECT-GAP-004 | Scanner accuracy | `scanners/orchestrator.py` | Orchestrator sets `ENABLE_ACTIVE_PROBE` generically for any scanner with that attribute |
| SCAN-GAP-001 | False-positive reduction | `scanners/base.py`, `scanners/plugin_scanner.py` | `is_soft_404()` added to BaseScanner; PluginScanner uses it |
| DETECT-GAP-001 | Detection coverage | `scanners/wp_detector.py` | Subdirectory fallback probing when root confidence < 0.15 |
| INTEL-GAP-003 | Concurrency safety | `core/vulnerability_intelligence/service.py` | Non-blocking lock on all public sync functions; `_inner` variants for reentrant calls |
| INTEL-GAP-004 | Intelligence accuracy | `scanners/vuln_intel.py` | `_cvss_to_severity()` replaces unconditional HIGH assignment |
| INTEL-GAP-001 | Intelligence coverage | `core/vulnerability_intelligence/service.py` | `_enrich_with_nvd_inner()` wired into `sync_all()` with failure isolation |
| SCAN-GAP-004 | Compatibility / security | `scanners/tls_scanner.py` | `ssl.TLSVersion` min/max constraints replace deprecated `ssl.PROTOCOL_*` constants |
| EVI-GAP-002 | Evidence quality | `scanners/theme_scanner.py` | `version_confidence` added to theme findings `raw_data` |

---

## Detailed Change Log

### DETECT-GAP-003 — ThemeScanner Passive Mode Gate

**Problem:** `ThemeScanner._probe_default_themes()` was called unconditionally,
issuing HEAD requests for 13 default theme paths during every passive scan. This
violated the passive-mode contract (no extra probes beyond a single GET).

**Fix:** Added `ENABLE_ACTIVE_PROBE: bool = False` class attribute. `scan()` now
only calls `_probe_default_themes()` when the flag is `True`.

**Orchestrator wiring (DETECT-GAP-004):**
```python
if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_ACTIVE_PROBE"):
    scanner.ENABLE_ACTIVE_PROBE = True
```
This sets the flag per-instance so the class default is never mutated globally.

---

### SCAN-GAP-001 — Soft-404 Suppression in PluginScanner

**Problem:** Sites using WordPress' custom 404 template return HTTP 200 for any
unknown URL. `_active_enumerate()` was treating every HTTP 200 as plugin confirmed,
producing large batches of false-positive findings.

**Fix:** `BaseScanner.is_soft_404(probe_url, baseline_url=None)` added:
1. Fetches probe URL; returns `False` immediately for non-HTML content types.
2. Generates a sentinel URL (`sentinelwp-does-not-exist-<hex8>/`) and fetches it.
3. If sentinel returns a real 404 → not a soft-404 site → `False`.
4. Compares body length ratio; ratio ≥ 0.85 → `True` (soft-404).
5. Secondary check: chunk-based content similarity for template-rendered pages.
6. Fail-open: if sentinel request fails, returns `False` to avoid false negatives.

`PluginScanner._active_enumerate()` calls `is_soft_404()` on the first HTTP-200
hit and caches the result (`_soft404_checked` / `_is_soft404_site`). HTTP-403
responses bypass the check entirely (directory listing denied = confirmed presence).

---

### DETECT-GAP-001 — WordPress Subdirectory Detection

**Problem:** WordPress installed at `/blog`, `/wordpress`, `/wp`, or similar
subdirectories was not detected because all signals were probed only at the root.

**Fix:**
- Added `_DEFAULT_WP_SUBDIRS` list (7 common paths).
- Added `_get_subdir_hints()` which merges defaults with any additional paths from
  `WP_SUBDIR_HINTS` env var (comma-separated).
- `detect()` tries each candidate if root confidence < 0.15.
- `_detect_multi_signal()` accepts optional `override_url` parameter.
- First matching subdir wins; loop breaks immediately.
- Subdir evidence is appended: `"Detected in subdirectory: /blog"`.

---

### INTEL-GAP-003 — Concurrent Sync Prevention

**Problem:** If two Celery workers triggered `sync_all()` simultaneously, both
would execute fully — duplicating DB writes and wasting external API budget.
Additionally, calling `sync_all()` which already held `_sync_lock` and then
delegating to `sync_wordfence()` (which also tries to acquire the same
non-reentrant lock) would deadlock.

**Fix:**
- Each public sync function (`sync_wordfence`, `sync_kev`, `sync_plugin_metadata`)
  acquires `_sync_lock` with `blocking=False`; returns `{'status': 'skipped'}` if
  already locked.
- Each has a corresponding `_<name>_inner()` variant that performs the actual work
  without touching the lock.
- `sync_all()` calls the `_inner` variants directly (it already holds the lock).

---

### INTEL-GAP-004 — CVSS-Based Severity Normalisation

**Problem:** `enrich_findings_with_cves()` unconditionally set
`f.severity = Severity.HIGH` for any finding that matched a CVE, regardless of
the actual CVSS score. A CVSS 2.0 informational advisory would inflate a finding
to HIGH.

**Fix:**
- Added `_cvss_to_severity(cvss_score: Optional[float]) -> Optional[Severity]`
  using the standard CVSS v3 banding (9.0+ CRITICAL, 7.0-8.9 HIGH, 4.0-6.9
  MEDIUM, 0.1-3.9 LOW, 0.0 INFO).
- `enrich_findings_with_cves()` derives severity from the best available CVSS
  score across all matched CVEs.
- If no CVSS data is present in the OSV response, the existing finding severity
  is preserved (no inflation).

---

### INTEL-GAP-001 — NVD Enrichment Pipeline

**Problem:** `nvd_client.py` existed but was never called. Vulnerability records
matched via Wordfence or KEV that had no CVSS score could not be enriched.

**Fix:**
- Added `_enrich_with_nvd_inner()` to `service.py`:
  - Queries `vulnerability_records` for rows with `cve_id IS NOT NULL` and
    `cvss_score IS NULL`.
  - Calls `nvd_client.enrich_cve(cve_id)` per record.
  - Bounded: 10 records/sync without NVD API key, 40 with key.
  - Per-record errors logged but not propagated.
- Wired into `sync_all()` after plugin metadata sync.
- Wrapped in `try/except` inside `sync_all()` for complete failure isolation.

---

### SCAN-GAP-004 — TLS Protocol Deprecation

**Problem:** `_check_protocols()` created `ssl.SSLContext(ssl.PROTOCOL_TLSv1)` and
`ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)`. These constants were deprecated in
Python 3.10 and removed in Python 3.12+, causing `AttributeError` on modern
Python and `DeprecationWarning` on older versions.

**Fix:**
- Modern path: `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with
  `ctx.minimum_version = tls_version` and `ctx.maximum_version = tls_version`
  using `ssl.TLSVersion.TLSv1` / `ssl.TLSVersion.TLSv1_1`.
- Legacy fallback: when `ssl.TLSVersion` enum value is `None` (enum member
  removed from Python build), falls back to `ssl.PROTOCOL_*` constant wrapped
  in `warnings.catch_warnings(simplefilter("ignore", DeprecationWarning))`.
- Extracted `_emit_deprecated_protocol_finding(name)` helper to avoid duplication.

---

### EVI-GAP-002 — Theme Finding version_confidence

**Problem:** Theme findings from `_detect_active_theme()` had no `version_confidence`
field in `raw_data`, making evidence records inconsistent with plugin findings which
always carry this field.

**Fix:** `version_confidence = "high" if version else "none"` computed and included
in every `_add_finding()` call from `_detect_active_theme()`.

---

## Test Regression Fix

**Root cause:** `test_service.py::test_sync_all_valid_data` and
`test_sync_all_empty_api_key_skips_wf` patched `service.sync_wordfence` and
`service.sync_kev` (the public wrappers). Post INTEL-GAP-003, `sync_all()` calls
`_sync_wordfence_inner()` / `_sync_kev_inner()` directly, so the patches were
never triggered.

**Fix:** Updated both tests to patch `_sync_wordfence_inner`,
`_sync_kev_inner`, `_sync_plugin_metadata_inner`, and `_enrich_with_nvd_inner`.

**NVD isolation bug discovered by test:** `test_nvd_failure_does_not_break_sync_all`
revealed that `_enrich_with_nvd_inner()` exceptions were not caught inside
`sync_all()`. Fixed by wrapping the call in `try/except Exception`.
