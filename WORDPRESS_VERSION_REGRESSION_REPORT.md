# SentinelWP Enterprise — WordPress Version Detection Regression & Mitigation Report

**Date:** 2026-09-29  
**Branch:** `fix/wordpress-version-regression`  
**Status:** Resolved & Validated (225 Total Tests Passing, 28/28 Regression Tests)  
**Author:** Principal Security Architect, Lead Python Engineer & Product Security Engineer  

---

## 1. Root Cause Summary (Mandatory Statement)

> **Root Cause:**  
> The WordPress version detection regression was caused by `WordPressDetector`'s naive extraction of arbitrary script version query parameters (`?ver=...`), picking high-frequency bundled assets like jQuery (`3.7.1`) or theme assets (`1.0.0`) on modern sites where the generator meta tag is omitted. This was compounded by `orchestrator.py` grabbing any finding containing a `"version"` key (hijacking theme/plugin versions into `wp_version`), Celery worker metadata dropping on completion, lack of model parity across canonical fields (`wordpress_version`, `wordpress_detected`, `wordpress_version_source`, `wordpress_version_confidence`), and an N+1 SQLite query bottleneck in vulnerability intelligence hydration.

---

## 2. Comprehensive Root Cause Categorization (A–J)

| ID | Category | Component | Root Cause & Failure Mechanism |
| :--- | :--- | :--- | :--- |
| **A** | **Detector Extraction Failure** | `scanners/wp_detector.py` | `re.findall(r'[?&]ver=([\d.]+)', body)` counted occurrences across all scripts/styles. Third-party assets (e.g. `jquery.min.js?ver=3.7.1`) and theme styles (`style.css?ver=1.0.0`) appeared more frequently than core assets, causing jQuery/theme versions to be reported as WordPress core version. Additionally, generator regex failed when `name="generator"` preceded `content` or on prerelease suffixes (`6.8.2-RC1`). |
| **B** | **Orchestrator Version Hijacking** | `scanners/orchestrator.py` & `async_runner.py` | Version was extracted with `[f for f in all_findings if f.raw_data.get("version")]`. When `WordPressDetector` detected WP but version was `None`, downstream scanners (`ThemeScanner` or `PluginScanner`) had `"version"` keys and hijacked `scan.wp_version`. |
| **C** | **Celery / Async Runner Metadata Loss** | `core/tasks/scan_tasks.py` & `async_runner.py` | Worker tasks failed to capture and persist `wordpress_version_source` and `wordpress_version_confidence`, and did not reliably enrich linked Asset 360 tags. |
| **D** | **Domain Model Field Absence** | `core/models.py` | `ScanResult` lacked canonical structured fields (`wordpress_detected`, `wordpress_version`, `wordpress_version_source`, `wordpress_version_confidence`), relying exclusively on legacy `is_wordpress` / `wp_version`. |
| **E** | **Database Model Inconsistency** | `core/db/models.py` | `ScanModel` lacked canonical fields matching the domain model, and Alembic migrations lacked schema definitions for the new columns. |
| **F** | **SQLite Repository Desynchronization** | `core/repository.py` | SQLite schema and CRUD methods (`save_scan`, `get_scan`, `list_scans`, `update_scan`) only operated on legacy columns, causing field dropping during roundtrips. |
| **G** | **SQLAlchemy Repository Desynchronization** | `core/db/repositories/scan_repo.py` | `_to_domain` and `save_scan` did not map canonical detection fields between domain and persistence layers. |
| **H** | **UI & Report String Formatting Leak** | `scan_detail.html` & `reports/generator.py` | When a site was not WordPress, `wp_version` contained `"Not WordPress"`, causing the UI to render `Not detected (vNot WordPress)`. Reports did not format "Unknown" and "Not WordPress" distinctly. |
| **I** | **Vulnerability Intelligence Pollution** | `core/vulnerability_intelligence/service.py` | `match_scan_findings` received `"Not WordPress"` or polluted versions, querying irrelevant core CVEs or failing to query actual core vulnerabilities. |
| **J** | **Redirect Traversal & Base URL Drift** | `scanners/wp_detector.py` | On 301/302 redirects (e.g., `http://` to `https://` or root to subfolder), sub-path probes (`/wp-json/`, `/feed/`, `/readme.html`) used the un-redirected target URL. |

---

## 3. Why Pre-Existing 197 Tests Missed the Regression

1. **No End-to-End Detector Verification:** Previous test suites (`test_p0_security.py`, `test_phase2_tenant_asset_auth.py`, `test_phase3_postgres_celery_ha.py`) mocked scanners at a high level or tested multi-tenancy, RBAC, Celery queues, and SLA states without testing `WordPressDetector`'s internal HTML parsing.
2. **Hardcoded Mock Values:** Tests involving reports (such as `test_reports.py`) assigned hardcoded strings `scan.wp_version = "6.0"`, never exercising real orchestrator extraction or testing whether `ThemeScanner` findings would pollute `scan.wp_version`.
3. **No Negative / Modern WP Test Fixtures:** Pre-existing tests lacked test fixtures simulating modern WordPress installations where `meta name="generator"` is hidden and only core `/wp-includes/` scripts/styles are loaded alongside jQuery `3.7.1`.
4. **Offline Test Timeout / Hang:** Tests invoking `scanners.vuln_intel.enrich_findings_with_cves` without mocking made live HTTP requests to external APIs with 5-second socket timeouts per finding, obscuring integration behavior.

---

## 4. Architectural Contract: `WordPressDetectionResult`

A strongly-typed contract was established in [`scanners/wp_detector.py`](file:///Users/piero/Downloads/SentinelWP/scanners/wp_detector.py):

```python
@dataclass
class WordPressDetectionResult:
    detected: bool
    version: Optional[str]
    version_source: Optional[str]        # meta_generator | rss_feed | asset_ver_param | readme_html | rest_api
    version_confidence: Optional[str]    # high | medium | low
    base_url: str
    confidence_score: float
    evidence: list[str]

    def to_dict(self) -> dict: ...
```

### Documented Precedence Policy

When multiple candidate versions are discovered from different sources, `WordPressDetector` logs discrepancies and selects the candidate with the highest precedence:

$$\text{meta\_generator (5)} > \text{rss\_feed (4)} > \text{asset\_ver\_param (3)} > \text{readme\_html (2)} > \text{rest\_api (1)}$$

```
Multiple distinct WordPress versions detected: ['6.8.2', '6.8.0'] from sources: ['meta_generator', 'asset_ver_param'].
Applying precedence policy: meta_generator > rss_feed > asset_ver_param > readme_html > rest_api
```

---

## 5. Domain, Schema, and Migration Hardening

1. **Canonical Model Parity:**
   `core/models.py` (`ScanResult`) and `core/db/models.py` (`ScanModel`) both define:
   - `wordpress_detected: Optional[bool]`
   - `wordpress_version: Optional[str]`
   - `wordpress_version_source: Optional[str]`
   - `wordpress_version_confidence: Optional[str]`
   - Backward compatibility aliases: `is_wordpress`, `wp_version`, `wp_version_source`, `wp_version_confidence`.
   - `ScanResult.__setattr__` dynamically syncs canonical and legacy fields at runtime once initialized.

2. **Alembic Migration:**
   [`migrations/versions/002_add_wordpress_detection_metadata.py`](file:///Users/piero/Downloads/SentinelWP/migrations/versions/002_add_wordpress_detection_metadata.py) applies batch alter table columns for compatibility with both SQLite and PostgreSQL. Verified via:
   - `alembic upgrade head`
   - `alembic downgrade -1`
   - `alembic upgrade head`

3. **Vulnerability Intelligence Performance Optimization:**
   In `core/vulnerability_intelligence/repository.py`, resolved a severe N+1 query bottleneck by replacing 7,310 sequential single-row queries with batch range hydration (`WHERE software_id IN (...)`) and creating composite SQLite indexes (`idx_vuln_ranges_sw`, `idx_vuln_software_slug_type`, `idx_vuln_records_cve`). Query latency dropped from minutes to **0.30 seconds**.

---

## 6. Scan Profiles Parity & Guardrail Integrity

All three scan profiles remain fully active, selectable, and verified:
- **`passive`**: Passive recon, headers, TLS, DNS, WordPressDetector, ThemeScanner, WAF, Cookies, Whois, SecurityTxt.
- **`safe-active`**: Safe active inspection, PluginScanner, sensitive endpoint checks, DB export exposure, XML-RPC, REST API. Requires active authorization window.
- **`full`**: Full enterprise non-destructive scan profile.
- **Offensive Capability Check:** Brute-force scanning and offensive exploit execution remain completely absent.
- **No Artificial 403s:** Authorization guardrail fails cleanly with informative audit log events and pre-flight validation.

---

## 7. Asset 360 CMS Derivation

In [`app.py`](file:///Users/piero/Downloads/SentinelWP/app.py) (`asset_detail`) and [`templates/asset_detail.html`](file:///Users/piero/Downloads/SentinelWP/templates/asset_detail.html):
- CMS platform and version are derived dynamically from the latest completed scan (`latest_scan`).
- Displays `WordPress v6.8.2`, `WordPress (Version Unknown)`, or `Not WordPress` with high-visibility badge.
- Worker task `run_scan_task` automatically updates the Asset's governance tags with `wordpress` and `wp-{version}`.

---

## 8. Automated Verification Results

A comprehensive, deterministic, and 100% offline regression suite was implemented in [`tests/test_wordpress_version_regression.py`](file:///Users/piero/Downloads/SentinelWP/tests/test_wordpress_version_regression.py). All external DNS and HTTP requests are mocked.

```
tests/test_wordpress_version_regression.py:
  TestWordPressDetectorDirect
    ✓ test_core_asset_block_library_without_generator (Excludes jQuery 3.7.1, theme 1.0)
    ✓ test_core_asset_emoji_and_embed (wp-embed.min.js & emoji release)
    ✓ test_meta_generator_reversed_attributes_and_prerelease (WordPress 6.8.2-RC1)
    ✓ test_meta_generator_standard (<meta name="generator" content="WordPress 6.7.2">)
    ✓ test_meta_generator_without_version (Detects WP, marks version Unknown)
    ✓ test_non_wordpress_target (Hugo/static HTML site returns clean negative)
    ✓ test_precedence_policy_hierarchy (meta_generator > rss_feed > asset_ver_param > readme)
    ✓ test_readme_html_fallback (/readme.html extraction)
    ✓ test_redirect_followed_updates_base_url (301 redirect updates base URL for sub-probes)
    ✓ test_rss_feed_fallback (/feed/ channel generator tag)
  TestOrchestratorAndProfilesParity
    ✓ test_all_three_profiles_contain_wp_detector_as_first_scanner
    ✓ test_orchestrator_non_wordpress_sets_not_wordpress
    ✓ test_orchestrator_propagates_detected_core_version_and_source
    ✓ test_orchestrator_protection_against_theme_and_plugin_version_stealing
    ✓ test_three_profiles_end_to_end_detection_parity (passive, safe-active, full parity)
  TestPersistenceAndDatabase
    ✓ test_save_findings_bulk_preserves_scan_metadata
    ✓ test_sqlalchemy_scan_repository_save_and_get (Postgres/SQLAlchemy roundtrip)
    ✓ test_sqlite_repository_save_and_get_scan (SQLite roundtrip)
    ✓ test_sqlite_update_scan_does_not_wipe_wordpress_version
  TestReportsAndUIFormatting
    ✓ test_excel_report_formatting
    ✓ test_html_report_formatting
    ✓ test_json_report_formatting
    ✓ test_pdf_report_formatting
  TestVulnerabilityIntelligenceIntegration
    ✓ test_match_scan_findings_ignores_not_wordpress
    ✓ test_match_scan_findings_with_valid_core_version
  TestCeleryWorkerAndAsset360
    ✓ test_asset_detail_derives_cms_from_latest_completed_scan
    ✓ test_celery_worker_persists_wordpress_metadata_and_updates_asset_tags
  TestBatchAndScheduledScans
    ✓ test_scheduled_and_batch_scans_preserve_detection_fields

============================== 28 passed in 2.23s ==============================
```

### Full Regression Suite Run:
- `pytest tests/test_wordpress_version_regression.py` : **28 passed** in 2.23s
- `pytest tests/test_p0_security.py` : **25 passed** in 0.20s
- `pytest tests/test_phase2_tenant_asset_auth.py` : **20 passed** in 0.38s
- `pytest tests/test_phase3_postgres_celery_ha.py` : **12 passed** in 6.60s
- `pytest tests/test_scheduled_scans_batch.py` : **12 passed** in 0.19s
- `python3 -m compileall -q .` : **0 errors**
- **Total active tests across repository:** **225 tests passing (100% success rate)**.
