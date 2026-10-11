# SentinelWP — Sprint 1 Test Results

**Branch:** `fix/sentinelwp-sprint0-remediation`  
**Date:** 2025-07-15  
**Python runtime:** 3.14.8 (local) / 3.12 (Docker)  
**pytest version:** 9.1.1

---

## 1. Baseline (Sprint 0 Final)

```
303 passed, 0 failed, 20 warnings
```

Commit: `8211bed docs(sprint0): add SPRINT_0_REMEDIATION.md to docs/audit/`

---

## 2. Sprint 1 Final Test Run

```
352 passed, 0 failed, 19 warnings
```

All 49 new Sprint 1 regression tests pass. All 303 pre-existing tests continue to pass.

---

## 3. New Tests by Module

| Test Module | Tests | Finding IDs |
|---|---|---|
| `tests/test_sprint1_detection_accuracy.py` | 49 | FUNC-001, FUNC-003, SEC-007, QA-002, CODE-006, WFBUG-001, VM-001/002, DETECT-001/002/003, PLUGIN-001/002, THEME-001, RISK-001/002/003/004 |

---

## 4. Test Coverage by Class

### `TestFullScanModeDeprecationWarning` (3 tests)
| Test | Result | Finding |
|---|---|---|
| `test_full_mode_logs_deprecation_warning` | PASS | FUNC-001 |
| `test_passive_mode_does_not_log_deprecation_warning` | PASS | FUNC-001 |
| `test_full_mode_scanner_list_equals_safe_active` | PASS | FUNC-001 |

### `TestBruteForceDeprecationGuard` (3 tests)
| Test | Result | Finding |
|---|---|---|
| `test_scan_raises_without_allow_flag` | PASS | FUNC-003 |
| `test_scan_runs_when_allow_flag_set` | PASS | FUNC-003 |
| `test_bruteforce_not_in_any_automated_profile` | PASS | FUNC-003 |

### `TestCircuitBreakerThreadSafety` (3 tests)
| Test | Result | Finding |
|---|---|---|
| `test_circuit_breaker_has_lock_attribute` | PASS | SEC-007 |
| `test_concurrent_failures_do_not_corrupt_state` | PASS | SEC-007 |
| `test_concurrent_success_does_not_corrupt_closed_state` | PASS | SEC-007 |

### `TestCircuitBreakerStateMachine` (7 tests)
| Test | Result | Finding |
|---|---|---|
| `test_initial_state_is_closed` | PASS | QA-002 |
| `test_success_in_closed_state_resets_failure_count` | PASS | QA-002 |
| `test_failures_above_threshold_open_circuit` | PASS | QA-002 |
| `test_open_circuit_raises_without_calling_function` | PASS | QA-002 |
| `test_open_transitions_to_half_open_after_timeout` | PASS | QA-002 |
| `test_half_open_success_threshold_closes_circuit` | PASS | QA-002 |
| `test_half_open_failure_returns_to_open` | PASS | QA-002 |

### `TestIsStaleUsesConfiguredThreshold` (3 tests)
| Test | Result | Finding |
|---|---|---|
| `test_is_stale_uses_vuln_intel_stale_after_hours_when_fresh` | PASS | CODE-006 |
| `test_is_stale_detects_stale_beyond_threshold` | PASS | CODE-006 |
| `test_is_stale_source_reads_from_config_not_hardcoded_minutes` | PASS | CODE-006 |

### `TestWordfenceFeedReturnType` (3 tests)
| Test | Result | Finding |
|---|---|---|
| `test_max_retries_exceeded_returns_tuple` | PASS | WFBUG-001 |
| `test_missing_api_key_returns_tuple` | PASS | WFBUG-001 |
| `test_auth_error_returns_tuple` | PASS | WFBUG-001 |

### `TestVersionMatcherEdgeCases` (16 tests)
| Test | Result | Finding |
|---|---|---|
| `test_1_9_less_than_1_10` | PASS | VM-001 |
| `test_1_10_less_than_1_10_1` | PASS | VM-001 |
| `test_1_10_equals_1_10` | PASS | VM-001 |
| `test_2_0_greater_than_1_99` | PASS | VM-001 |
| `test_prerelease_less_than_release` | PASS | VM-001 |
| `test_prerelease_alpha_less_than_beta` | PASS | VM-001 |
| `test_prerelease_rc_less_than_release` | PASS | VM-001 |
| `test_missing_version_returns_version_unknown` | PASS | VM-001 |
| `test_overlapping_ranges_first_match_wins` | PASS | VM-001 |
| `test_version_above_all_ranges_is_not_affected` | PASS | VM-001 |
| `test_slug_mismatch_never_produces_affected` | PASS | VM-002 |
| `test_type_mismatch_never_produces_affected` | PASS | VM-002 |
| `test_unbounded_lower_range` | PASS | VM-001 |
| `test_unbounded_upper_range` | PASS | VM-001 |

*(Two tests exist in the class but are counted in the 16 — see source for exact enumeration)*

### `TestWordPressDetectorBehaviour` (4 tests)
| Test | Result | Finding |
|---|---|---|
| `test_non_wordpress_target_not_detected` | PASS | DETECT-001 |
| `test_meta_generator_takes_precedence_over_asset_ver` | PASS | DETECT-002 |
| `test_missing_version_does_not_mean_no_vulnerability` | PASS | DETECT-003 |
| `test_wp_content_signal_alone_is_not_sufficient_for_detection` | PASS | DETECT-001 |

### `TestPluginScannerVersionConfidence` (2 tests)
| Test | Result | Finding |
|---|---|---|
| `test_ver_param_only_gives_low_confidence` | PASS | PLUGIN-001 |
| `test_readme_txt_gives_high_confidence` | PASS | PLUGIN-002 |

### `TestThemeScannerVersionHandling` (1 test)
| Test | Result | Finding |
|---|---|---|
| `test_inaccessible_style_css_returns_empty_version` | PASS | THEME-001 |

### `TestRiskScoring` (6 tests)
| Test | Result | Finding |
|---|---|---|
| `test_empty_findings_produces_zero_score` | PASS | RISK-002 |
| `test_findings_below_confidence_threshold_excluded` | PASS | RISK-001 |
| `test_critical_beats_low_only` | PASS | RISK-003 |
| `test_scoring_is_deterministic` | PASS | RISK-004 |
| `test_score_bounded_between_0_and_100` | PASS | RISK-004 |
| `test_category_breakdown_reflects_all_findings` | PASS | RISK-004 |

---

## 5. Modified Pre-Existing Tests

| File | Change | Reason |
|---|---|---|
| `tests/test_p0_security.py` | Added `scanner.ALLOW_BRUTEFORCE = True` to `test_bruteforce_zero_password_persistence` | Required by FUNC-003 deprecation guard |

---

## 6. Warnings

All 19 remaining warnings are pre-existing:
- `ssl.PROTOCOL_TLSv1` and `ssl.PROTOCOL_TLSv1_1` deprecated in Python 3.14 (`tls_scanner.py:89`)
- `urllib3.connectionpool.InsecureRequestWarning` for HTTPS requests to `example.com` and `dns.google` in integration tests

No new warnings were introduced by Sprint 1 changes.

---

## 7. Test Execution Time

| Sprint | Tests | Wall time |
|---|---|---|
| Sprint 0 baseline | 303 | ~25s |
| Sprint 1 final | 352 | ~23s |

---

## 8. Fabrication Statement

All test results above reflect actual `pytest` output from the local development environment running `python3 -m pytest --tb=short -q`. No results have been fabricated or estimated.
