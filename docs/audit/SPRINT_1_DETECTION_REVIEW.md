# SentinelWP — Sprint 1 Detection Review

**Branch:** `fix/sentinelwp-sprint0-remediation`  
**Baseline commit:** `8211bed` (Sprint 0 final)  
**Sprint 1 changes:** see Git log from `8211bed` onwards  
**Date:** 2025-07-15  
**Prepared by:** Principal Application Security Engineer / WordPress Security Researcher

---

## 1. Scope

Sprint 1 reviewed and improved:

- WordPress detection and version fingerprinting (`scanners/wp_detector.py`)
- Plugin identification and version confidence (`scanners/plugin_scanner.py`)
- Theme identification and version extraction (`scanners/theme_scanner.py`)
- Scanner mode enforcement and deprecation (`scanners/orchestrator.py`, `scanners/bruteforce_scanner.py`)
- Vulnerability intelligence pipeline (`core/vulnerability_intelligence/`)
- Risk scoring correctness (`core/risk_engine.py`)
- CircuitBreaker thread-safety (`core/integrations/circuit_breaker.py`)

---

## 2. WordPress Detection — Multi-Signal Analysis

### 2.1 Signal Inventory

| Signal | Weight | Source |
|---|---|---|
| `meta_generator` | 0.35 | Homepage `<meta name="generator">` |
| `wp_content` | 0.15 | `/wp-content/` in HTML |
| `wp_includes` | 0.15 | `/wp-includes/` in HTML |
| `rest_api_link` | 0.15 | `<link rel="https://api.w.org/">` in HTML or `Link:` header |
| `wp_json_ns` | 0.15 | `/wp-json/` returns `namespaces`/`name`/`routes` |
| `core_assets` | 0.15 | Known WP core assets with `?ver=` |
| `wp_cookie` | 0.10 | `wordpress_*` or `wp-settings` cookie |
| `wp_login` | 0.10 | `wp-login.php` returns HTTP 200 |
| `rss_generator` | 0.10 | RSS feed contains WordPress generator tag |

Maximum possible score: 1.40 (capped at 1.0). Detection threshold: 0.15.

### 2.2 Version Source Precedence

```
meta_generator (5) > rss_feed (4) > asset_ver_param (3) > readme_html (2) > rest_api (1)
```

Within same precedence level, `high` reliability beats `medium`.

Regression tests in `TestWordPressDetectorBehaviour` verify:
- `test_meta_generator_takes_precedence_over_asset_ver` — 6.5.2 wins over 6.3.0 from asset
- `test_non_wordpress_target_not_detected` — empty HTML body → detected=False, confidence < 0.15
- `test_missing_version_does_not_mean_no_vulnerability` — WP detected with no version still reports finding

### 2.3 Detection Accuracy Assessment

| Scenario | Expected | Verified |
|---|---|---|
| Standard WP with meta generator | detected=True, version from meta | ✅ |
| WP without meta generator (assets only) | detected=True, version from asset | ✅ |
| WP without any version signal | detected=True, version=None | ✅ |
| Non-WordPress HTML page | detected=False | ✅ |
| WP behind redirect (canonical URL update) | base_url updated | ✅ |
| Reversed attribute order in meta tag | Handled by two-branch regex | ✅ |
| Prerelease version in meta generator | Parsed correctly | ✅ |
| Version conflict across signals | Precedence policy applied, logged | ✅ |

### 2.4 Confirmed Detection Weakness — Not Fixed in Sprint 1

- **Subdirectory installations:** No probe for `/blog/`, `/wp/`, `/cms/`, etc. The detector only follows HTTP redirects from the initial request; it does not enumerate common subdirectory paths. Documented as remaining gap.
- **Reverse proxy stripping headers:** If the proxy strips `Link:` headers and the homepage contains no WP assets, signal count may be low. Handled by multiple signal sources; no single source is mandatory.

### 2.5 Evidence Traceability

Every detection result carries:
- `evidence: List[str]` — human-readable list of signals observed
- `version_source` — which probe produced the version
- `version_confidence` — `high` / `medium` / `low`
- `confidence_score` — aggregate 0.0–1.0

Missing evidence does not imply a secure configuration. The `test_missing_version_does_not_mean_no_vulnerability` regression test enforces this.

---

## 3. Plugin Scanner Review

### 3.1 Passive Detection

Plugin slugs are extracted from `/wp-content/plugins/<slug>/` references in homepage HTML. Version detection follows a two-step hierarchy:

1. `?ver=<version>` from asset URLs → `version_confidence = "low"`
2. `readme.txt` Stable tag → `version_confidence = "high"` (overrides step 1)

The `version_confidence` field is present in all plugin findings' `raw_data`.

### 3.2 Active Probing

Active probing issues a HEAD request to the plugin directory URL. If the directory returns 200 or 403, the plugin is recorded. Version is fetched from `readme.txt` (Stable tag).

Active probe is gated by `ENABLE_ACTIVE_PROBE = True`. The orchestrator does not currently set this to `False` for passive mode — a known limitation (passive mode scanner receives full plugin scanner which still fetches the homepage for passive signals).

### 3.3 False-Positive Prevention

- Slug matching uses exact regex: `/wp-content/plugins/([a-zA-Z0-9_-]+)/`
- Version overriding: readme.txt always wins over `?ver=` parameter
- Confidence rating surfaced explicitly — callers can filter by `version_confidence`

### 3.4 Regression Tests

`TestPluginScannerVersionConfidence`:
- `test_ver_param_only_gives_low_confidence` — confirms `version_confidence = 'low'` without readme
- `test_readme_txt_gives_high_confidence` — confirms `version_confidence = 'high'` and version override

---

## 4. Theme Scanner Review

- Active detection from homepage HTML (passive)
- Active probing of 13 default WordPress themes via `style.css` HEAD
- Version extracted from `style.css` `Version:` header if accessible; empty string otherwise

Regression: `TestThemeScannerVersionHandling::test_inaccessible_style_css_returns_empty_version`

### 4.1 Known Gaps

- No `version_confidence` field in theme findings (raw_data has `version` but no `version_confidence` key). Low priority — theme versions are less security-critical than plugin versions.
- `_probe_default_themes()` is always called even in passive mode (same issue as PluginScanner active probe). Documented as remaining gap.

---

## 5. Scan Mode Enforcement

### 5.1 FUNC-001 — 'full' Mode Deprecation Warning

**Before:** `run_scan(mode="full")` silently ran the `safe-active` profile without any notice.

**After:** A `WARNING` log entry is emitted:
```
Scan mode 'full' is deprecated and treated as 'safe-active'. BruteForceScanner is
excluded from all automated profiles. No additional probing beyond safe-active
will be performed.
```

Regression: `TestFullScanModeDeprecationWarning` (3 tests).

### 5.2 FUNC-003 — BruteForceScanner Disabled Guard

**Before:** `BruteForceScanner.scan()` would execute against any target.

**After:** `scan()` raises `RuntimeError` unless `ALLOW_BRUTEFORCE = True` is explicitly set by the caller. Default is `False`.

Regression: `TestBruteForceDeprecationGuard` (3 tests including `test_bruteforce_not_in_any_automated_profile`).

---

## 6. Summary

| Area | Status | Tests Added |
|---|---|---|
| WP multi-signal detection | Reviewed — no code changes required | 4 |
| Version precedence | Verified correct | 1 |
| Missing-version handling | Verified does not imply secure | 1 |
| Plugin version confidence | Verified correct | 2 |
| Theme version (inaccessible) | Verified returns empty string | 1 |
| FUNC-001 full mode warning | Fixed | 3 |
| FUNC-003 bruteforce guard | Fixed | 3 |

Total new detection tests: **15** (within `test_sprint1_detection_accuracy.py`).
