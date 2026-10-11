# Sprint 3 — Test Results

**Branch:** `feat/sentinelwp-sprint3-continuous-monitoring`  
**Commit:** `8e2e0a5`  
**Python version:** 3.14.8 (local test runner)  
**Test runner:** pytest 9.1.1  

---

## Final Test Run

```
438 passed, 39 warnings in 26.53s
```

**Baseline (Sprint 2 exit):** 394 passing, 0 failures  
**Sprint 3 additions:** +44 new tests  
**Regressions introduced:** 0  
**New failures:** 0  

---

## New Test File

### `tests/test_sprint3_continuous_monitoring.py`

44 tests covering all Sprint 3 phases:

| Test Class | Tests | Phase |
|------------|-------|-------|
| `TestPhase1AssetInventory` | 4 | Asset Inventory |
| `TestPhase2ContinuousMonitoring` | 5 | Continuous Monitoring |
| `TestPhase3Differential` | 6 | Security Posture Differential |
| `TestPhase4VulnerabilityLifecycle` | 4 | Vulnerability Lifecycle |
| `TestPhase5DistributedLock` | 6 | Distributed Synchronization |
| `TestPhase6PerThemeFindings` | 4 | Per-Theme Correlation |
| `TestPhase7ScanSafety` | 4 | Scanning Safety |
| `TestPhase8IntelMonitor` | 4 | Intelligence-Driven Monitoring |
| `TestPhase9MonitoringDashboard` | 6 | Dashboard and Alerting |
| `TestMigration006Schema` | 2 | DB Migration Validation |

---

## Updated Existing Tests

### `tests/test_sprint2_detection_hardening.py`

Two tests updated to match Sprint 3 changes:

1. `TestThemeScannerPassiveGate::test_active_probe_finding_emitted_when_theme_exists`  
   Updated to check for `"Default Theme Present"` title (per-theme format) and  
   `raw_data["slug"]` instead of the old aggregated `raw_data["default_themes"]`.

2. `TestWordPressDetectorSubdirectory::test_subdir_detection_used_when_root_misses`  
   Updated to set `detector.ENABLE_SUBDIR_PROBE = True` before calling `detect()`,  
   mirroring what the orchestrator does for `safe-active` mode.

---

## Test Coverage Notes

- All HTTP interactions are mocked using `unittest.mock.patch`.
- No external HTTP requests are made during test execution.
- Redis is not required — the distributed lock tests use the thread-lock fallback path.
- DB tests use `init_db(force=True)` for isolation.

---

## Warnings (not failures)

- `DeprecationWarning: ssl.TLSVersion.TLSv1_1 is deprecated` — pre-existing, from `tls_scanner.py`
- `InsecureRequestWarning` from `urllib3` for HTTPS to `example.com` / `dns.google` — pre-existing, from integration-style tests that make real requests
- These warnings existed before Sprint 3 and are not new.
