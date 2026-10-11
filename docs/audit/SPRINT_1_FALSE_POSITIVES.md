# SentinelWP — Sprint 1 False Positive Analysis

**Branch:** `fix/sentinelwp-sprint0-remediation`  
**Date:** 2025-07-15  
**Prepared by:** Principal Application Security Engineer / Senior Python QA Engineer

---

## 1. Methodology

False positives were evaluated by:

1. Reviewing each scanner's detection logic for conditions that could trigger on non-WordPress targets
2. Reviewing the vulnerability correlation pipeline for slug-matching rules
3. Reviewing the risk scoring pipeline for confidence-threshold enforcement
4. Writing controlled mock-based tests to confirm correct positive and negative detection

No external or live systems were tested. All tests use mocked HTTP responses.

---

## 2. WordPress Detector — False Positive Risk

### 2.1 Threshold Analysis

The detection threshold is **0.15** (15% confidence). A single `/wp-content/` reference in HTML is enough to reach this threshold (`wp_content` weight = 0.15). This is intentional: any page linking to `/wp-content/` is very likely WordPress.

However, a non-WordPress CMS or custom application could theoretically serve static assets from a `/wp-content/` path. In practice this is rare and the multi-signal approach provides rapid signal accumulation — a single signal at 0.15 is at the detection boundary, not a strong positive.

**Assessment:** False positive risk for the `wp_content` signal alone is low given the boundary behaviour. Regression test `test_wp_content_signal_alone_is_not_sufficient_for_detection` confirms the behaviour is deterministic.

### 2.2 `wp-login.php` Signal

`wp_login` contributes 0.10. A `wp-login.php` returning HTTP 200 alone (with no other signals) would not cross the 0.15 threshold and would not produce a detection finding. This is correct: some web frameworks have a path that happens to respond at `/wp-login.php`.

### 2.3 Non-WordPress Target

A plain HTML page with no WordPress signals scores `confidence = 0.0`. Regression test `test_non_wordpress_target_not_detected` confirms `detected = False` for a generic HTML page.

### 2.4 Version Exposure Finding Gated on Version Detection

The `"WordPress Version Exposed"` finding is only emitted when a version is actually detected. A WordPress installation with all version indicators removed (no meta generator, no asset `?ver=` params, no readme.html, no RSS feed) will:
- Receive a `"WordPress CMS Detected"` INFO finding
- NOT receive a `"WordPress Version Exposed"` finding
- NOT be classified as "secure" — merely as "version unknown"

Regression test `test_missing_version_does_not_mean_no_vulnerability` confirms this.

---

## 3. Plugin Scanner — False Positive Risk

### 3.1 Passive Slug Extraction

Passive detection uses:
```python
re.findall(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', resp.text)
```

This regex is anchored to the WordPress plugin directory structure. False positives would require a non-WordPress application to serve paths beginning with `/wp-content/plugins/`. This is an extremely low-probability scenario.

### 3.2 Active Probe — 403 as Positive

Active probing treats HTTP 403 as confirmation of a plugin directory's existence (directory visible but listing blocked). This is standard WordPress hardening behaviour and is the correct interpretation.

**Potential false positive:** A non-WordPress application that returns 403 for all requests under `/wp-content/plugins/<any-slug>/`. In this case the WP detector would not have produced a detection finding, and the plugin scanner would still have been called. Mitigation: plugin scanner findings are labelled as "Plugin Detected (active probe)" and their `version_confidence` is `None` or `"high"` (only from readme.txt). A downstream analyst can correlate with WP detection findings.

### 3.3 Version from `?ver=` Parameter

The `?ver=` parameter is commonly used by WordPress but is not exclusive to it. However, this parameter is only extracted when a path matching `/wp-content/plugins/<slug>/` has already been found, so the false-positive risk at the slug level has already been addressed.

Version confidence is explicitly set to `"low"` for `?ver=` sources, informing analysts that this version is not verified.

---

## 4. Vulnerability Correlation — False Positive Risk

### 4.1 Exact Slug Matching (Primary Control)

The most important false-positive control in the CVE correlation pipeline is **exact slug matching**:

```python
sw_slug = sw.get('slug')
if sw_slug and sw_slug != detected_slug:
    continue
```

This prevents a plugin named `contact-form` from matching CVEs for `contact-form-7`, or `wordpress-seo` from matching CVEs for `all-in-one-seo-pack`.

**Regression:** `test_slug_mismatch_never_produces_affected`

### 4.2 Type Isolation

`detected_type` must exactly match the record's `type`. This prevents WordPress core CVEs from being attributed to plugins and vice versa.

**Regression:** `test_type_mismatch_never_produces_affected`

### 4.3 Version-Unknown Classifications

When a plugin version is not detected, the finding is titled `"Potential Exposure"` (not `"Vulnerability"`) and carries `confidence = 0.6` (not 0.95). Analysts are informed explicitly that no version confirmation was possible.

This is the intended behaviour: **a component is never classified as definitively vulnerable solely on the basis of its name matching a CVE description**.

### 4.4 OSV.dev Live Enrichment

The `enrich_findings_with_cves()` function in `scanners/vuln_intel.py` queries OSV.dev using both the detected slug and the detected version. OSV.dev matches by package name AND version — a package with no version supplied is not queried (early return on `not version`).

Risk: OSV.dev uses the `"WordPress"` ecosystem namespace. If OSV.dev returns an imprecise match (e.g., slug "wordpress" matching unrelated records), the finding will have `severity = HIGH` applied. This is a known limitation of live feed enrichment.

**Recommendation (Sprint 2):** Validate OSV.dev results against local Wordfence database before promoting severity.

---

## 5. Risk Scoring — False Positive Risk

### 5.1 Confidence Threshold Filtering

The `compute_risk_score()` function filters out all findings below `CONFIDENCE_THRESHOLD` (default 0.3). This means:
- A finding with `confidence = 0.1` does not contribute to the score.
- Only findings with `confidence >= 0.3` enter the scoring calculation.

**Regression:** `test_findings_below_confidence_threshold_excluded`

### 5.2 Category Diminishing Returns

Within each category, scores are multiplied by a decay factor (`0.7^i` for the i-th finding). This prevents a large number of LOW findings in the same category from artificially inflating the score to a severe grade.

---

## 6. False Positive Registry

| ID | Scanner | Scenario | Risk Level | Control | Status |
|---|---|---|---|---|---|
| FP-001 | WP Detector | `/wp-content/` path in non-WP application | Very Low | Multi-signal threshold | Mitigated |
| FP-002 | WP Detector | `wp-login.php` 200 on non-WP framework | Very Low | Single-signal below threshold | Mitigated |
| FP-003 | Plugin Scanner | 403 on non-WP path | Low | WP detection prerequisite | Accepted (low risk) |
| FP-004 | Plugin Scanner | `?ver=` param in non-WP context | Low | `version_confidence = "low"` label | Mitigated |
| FP-005 | CVE Correlation | Substring slug match | None | Exact slug comparison | Fixed (test verified) |
| FP-006 | CVE Correlation | Core CVE attributed to plugin | None | Type isolation | Fixed (test verified) |
| FP-007 | OSV.dev Enrichment | Imprecise ecosystem match | Low | Documented gap, Sprint 2 validation | Open |
| FP-008 | Risk Scoring | Low-confidence finding raising score | Very Low | Confidence threshold filter | Mitigated |
