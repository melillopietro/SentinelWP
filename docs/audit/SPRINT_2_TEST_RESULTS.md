# Sprint 2 — Test Results

## Summary

| Metric | Value |
|--------|-------|
| Sprint 2 branch | `feat/sentinelwp-sprint2-detection-hardening` |
| Sprint 2 commit | `42132a5` |
| Tests passing at Sprint 1 baseline | **352** |
| Tests passing at Sprint 2 completion | **394** |
| New Sprint 2 tests added | **42** |
| Test regressions introduced | **0** |
| Pre-existing test failures fixed | **2** |
| Production bugs found by tests | **1** |

---

## Test File Inventory

| File | Tests | Sprint | Focus |
|------|-------|--------|-------|
| `tests/test_sprint2_detection_hardening.py` | 42 | Sprint 2 | All Sprint 2 gaps (new) |
| `tests/test_sprint1_detection_accuracy.py` | 49 | Sprint 1 | Detection accuracy (unchanged) |
| `tests/test_sprint0_remediation.py` | 39 | Sprint 0 | Security remediations (unchanged) |
| `tests/vulnerability_intelligence/test_service.py` | 11 | Sprint 0/1/2 | Service layer (2 tests updated) |
| `tests/test_p0_security.py` | varies | Phase 0 | Core security (unchanged) |
| `tests/test_phase*.py` | varies | Phase 1–5 | Phase-level integration (unchanged) |
| `tests/test_wordpress_version_regression.py` | varies | Sprint 1 | WP version detection (unchanged) |

---

## Sprint 2 Test Classes and Results

### `TestThemeScannerPassiveGate` — 5 tests
| Test | Result |
|------|--------|
| `test_passive_mode_no_active_probe_called` | ✅ PASS |
| `test_passive_mode_head_not_called_for_default_themes` | ✅ PASS |
| `test_active_mode_probes_default_themes` | ✅ PASS |
| `test_active_mode_head_called_for_each_default_theme` | ✅ PASS |
| `test_active_probe_finding_emitted_when_theme_exists` | ✅ PASS |

### `TestOrchestratorActiveProbeGate` — 2 tests
| Test | Result |
|------|--------|
| `test_passive_mode_does_not_enable_active_probe` | ✅ PASS |
| `test_safe_active_mode_enables_active_probe` | ✅ PASS |

### `TestPluginScannerSoft404` — 4 tests
| Test | Result |
|------|--------|
| `test_soft404_site_suppresses_200_responses` | ✅ PASS |
| `test_genuine_content_200_accepted` | ✅ PASS |
| `test_http_403_bypasses_soft404_check` | ✅ PASS |
| `test_is_soft404_called_only_once` | ✅ PASS |

### `TestIsSoft404` — 4 tests
| Test | Result |
|------|--------|
| `test_returns_false_when_probe_returns_nonhtml` | ✅ PASS |
| `test_returns_false_when_sentinel_returns_real_404` | ✅ PASS |
| `test_returns_true_when_bodies_are_identical` | ✅ PASS |
| `test_returns_false_when_probe_returns_non_200` | ✅ PASS |

### `TestWordPressDetectorSubdirectory` — 3 tests
| Test | Result |
|------|--------|
| `test_subdir_detection_used_when_root_misses` | ✅ PASS |
| `test_root_detection_wins_if_confident_enough` | ✅ PASS |
| `test_no_detection_if_all_subdirs_miss` | ✅ PASS |

### `TestVulnIntelConcurrencyGate` — 5 tests
| Test | Result |
|------|--------|
| `test_sync_all_skipped_when_lock_held` | ✅ PASS |
| `test_sync_wordfence_skipped_when_lock_held` | ✅ PASS |
| `test_sync_kev_skipped_when_lock_held` | ✅ PASS |
| `test_sync_plugin_metadata_skipped_when_lock_held` | ✅ PASS |
| `test_concurrent_sync_all_second_call_skips` | ✅ PASS |

### `TestCvssSeverityNormalisation` — 11 tests
| Test | Result |
|------|--------|
| `test_none_cvss_returns_none` | ✅ PASS |
| `test_critical_score` | ✅ PASS |
| `test_high_score` | ✅ PASS |
| `test_medium_score` | ✅ PASS |
| `test_low_score` | ✅ PASS |
| `test_zero_score_is_info` | ✅ PASS |
| `test_string_cvss_score_parsed` | ✅ PASS |
| `test_invalid_cvss_returns_none` | ✅ PASS |
| `test_enrich_no_cvss_preserves_existing_severity` | ✅ PASS |
| `test_enrich_cvss_4_maps_to_medium` | ✅ PASS |
| `test_enrich_cvss_9_8_maps_to_critical` | ✅ PASS |

### `TestNvdEnrichmentInner` — 3 tests
| Test | Result | Notes |
|------|--------|-------|
| `test_sync_all_calls_enrich_nvd_inner` | ✅ PASS | |
| `test_nvd_failure_does_not_break_sync_all` | ✅ PASS (after fix) | Found real bug: NVD exceptions not caught; fixed in `service.py` |
| `test_enrich_with_nvd_inner_available` | ✅ PASS | |

### `TestTLSScannerModernAPI` — 2 tests
| Test | Result |
|------|--------|
| `test_check_protocols_does_not_use_deprecated_protocol_constants` | ✅ PASS |
| `test_tls_version_enum_used_when_available` | ✅ PASS |

### `TestThemeScannerVersionConfidence` — 3 tests
| Test | Result |
|------|--------|
| `test_theme_with_version_has_high_confidence` | ✅ PASS |
| `test_theme_without_version_has_none_confidence` | ✅ PASS |
| `test_theme_raw_data_has_method_passive` | ✅ PASS |

---

## Pre-existing Tests Fixed During Sprint 2

### `tests/vulnerability_intelligence/test_service.py`

**`test_sync_all_valid_data`** and **`test_sync_all_empty_api_key_skips_wf`** were
failing (2 failures on the Sprint 2 baseline before new test development).

**Root cause:** Both tests patched `service.sync_wordfence` and `service.sync_kev`
(the public wrappers). After INTEL-GAP-003, `sync_all()` calls the `_inner` variants
directly to avoid deadlock. The public wrappers were never called, so the patches
had no effect and assertions on call counts failed.

**Fix:** Updated both tests to patch `_sync_wordfence_inner`, `_sync_kev_inner`,
`_sync_plugin_metadata_inner`, and `_enrich_with_nvd_inner`.

---

## Production Bug Found by Testing

**Bug:** `_enrich_with_nvd_inner()` exceptions were not caught inside `sync_all()`.
Any unhandled exception from the NVD enrichment step would propagate to the Celery
task caller, causing the entire `sync_all` task to be marked as FAILED and leaving
`_sync_lock` in the released state (protected by `finally`), but returning no results.

**Discovered by:** `test_nvd_failure_does_not_break_sync_all` (initial run: FAILED).

**Fix applied:** Wrapped `_enrich_with_nvd_inner()` call in `try/except Exception`:
```python
try:
    nvd_res = _enrich_with_nvd_inner()
except Exception as exc:
    logger.error("NVD enrichment failed during sync_all: %s", exc)
    nvd_res = {'status': 'error', 'reason': str(exc)}
```

**Status:** Fixed in commit `42132a5`. Test now passes.

---

## Full Suite Run (Final)

```
python3 -m pytest tests/ -q --tb=short
394 passed, 41 warnings in 23.91s
```

Environment: Python 3.14.8, pytest 9.1.1, macOS arm64.

All 41 warnings are pre-existing:
- 28 × `ssl.TLSVersion.TLSv1[_1] is deprecated` (from TLS scanner probing test URLs)
- 9 × `InsecureRequestWarning` (from test fixtures using real HTTPS targets)
- 4 × SQLAlchemy / Flask deprecation notices

None are new warnings introduced by Sprint 2 changes.
