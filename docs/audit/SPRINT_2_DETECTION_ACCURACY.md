# Sprint 2 — Detection Accuracy

## Summary of Improvements

| Gap ID | Scanner | Detection Type | Before | After |
|--------|---------|---------------|--------|-------|
| DETECT-GAP-003 | ThemeScanner | Default themes | Always probed (even passive) | Passive: HTML only; Active: HEAD probes |
| DETECT-GAP-001 | WordPressDetector | WordPress at subdirectory | Not detected | Detected via bounded subdir probes |
| SCAN-GAP-001 | PluginScanner | Plugin enumeration | Soft-404 false positives | Sentinel-based soft-404 suppression |
| EVI-GAP-002 | ThemeScanner | Theme evidence quality | No version_confidence | `version_confidence` in raw_data |

---

## DETECT-GAP-003 — ThemeScanner Mode Gating

### Problem
`ThemeScanner.scan()` called `_probe_default_themes()` unconditionally. This issued
13 HEAD requests (one per default WordPress theme) during every scan — including
`passive` mode where no additional requests beyond the homepage GET should be made.

**Impact:**
- **False positives in passive mode:** Any HTTP 200 from a CDN or caching layer
  could be misinterpreted as a default theme being present.
- **Passive contract violated:** Operators selecting passive mode for non-intrusive
  reconnaissance received active probing without consent.
- **Unnecessary request budget:** 13 extra HEAD requests per scan added latency
  and risk of rate-limiting or IP flagging.

### Solution
Added `ENABLE_ACTIVE_PROBE: bool = False` class attribute. `scan()` now:

```python
def scan(self) -> list:
    self._detect_active_theme()          # Always: passive HTML parsing
    if self.ENABLE_ACTIVE_PROBE:         # DETECT-GAP-003: only in active modes
        self._probe_default_themes()
    return self.findings
```

The orchestrator sets the flag per-instance for `safe-active` and `full` modes:

```python
if scan_mode in ("safe-active", "full") and hasattr(scanner, "ENABLE_ACTIVE_PROBE"):
    scanner.ENABLE_ACTIVE_PROBE = True
```

### Detection Behaviour After Fix

| Scan Mode | `_detect_active_theme()` | `_probe_default_themes()` |
|-----------|--------------------------|--------------------------|
| passive | ✓ (1 GET, HTML parsing) | ✗ |
| safe-active | ✓ | ✓ (13 HEAD requests) |
| full | ✓ | ✓ (13 HEAD requests) |

---

## DETECT-GAP-001 — WordPress Subdirectory Installation Support

### Problem
WordPress is frequently installed in subdirectories:
- `example.com/blog` — blog subdirectory
- `example.com/wordpress` — default Docker/dev subdirectory
- `example.com/wp` — abbreviated path
- `example.com/cms` — generic CMS path

The detector only probed signals at the root domain. If root confidence < 0.15,
the site was reported as non-WordPress — even if it had a fully operational
WordPress installation at a subdirectory path.

**Estimated false-negative rate:** ~15% of WordPress installations use a
non-root path (based on WordPress.com data and hosting provider defaults).

### Solution
`detect()` now tries a bounded list of subdirectory candidates when root
confidence is insufficient:

```python
_DEFAULT_WP_SUBDIRS = ["/blog", "/wordpress", "/wp", "/cms", "/site", "/web", "/news"]

def _get_subdir_hints() -> List[str]:
    extra = os.getenv("WP_SUBDIR_HINTS", "")
    normalized = [f"/{s.strip().lstrip('/')}" for s in extra.split(",") if s.strip()]
    return list(dict.fromkeys(_DEFAULT_WP_SUBDIRS + normalized))[:10]
```

```python
if confidence < 0.15:
    for subdir in _get_subdir_hints():
        candidate_url = self.target_url.rstrip("/") + subdir
        sub_detection = self._detect_multi_signal(override_url=candidate_url)
        if sub_detection["confidence"] >= 0.15:
            # Use this subdir's results
            evidence.append(f"Detected in subdirectory: {subdir}")
            break
```

The `_detect_multi_signal()` method was extended with an `override_url` parameter
to probe a different base URL without mutating `self.target_url`.

### Detection Coverage by Scenario

| Scenario | Before | After |
|----------|--------|-------|
| WordPress at root | ✓ | ✓ |
| WordPress at `/blog` | ✗ | ✓ |
| WordPress at `/wordpress` | ✗ | ✓ |
| WordPress at custom path via WP_SUBDIR_HINTS | ✗ | ✓ |
| Non-WordPress site | ✓ (not detected) | ✓ (not detected) |

### Performance Impact
- Best case (root hit): 0 additional requests.
- Worst case (root miss, 7 subdirs tried, none match): ~7 × (signals per subdir probe) extra requests.
- Loop terminates on first match — average case for subdirectory installations is 1–2 additional probes.

---

## SCAN-GAP-001 — Soft-404 False Positive Suppression

### Problem
Many WordPress installations configure a custom "404 not found" page that:
1. Uses a full WordPress template (same header, footer, nav as a real page).
2. Returns HTTP status **200** instead of 404.
3. Returns the same body for **every** non-existent path.

When `PluginScanner._active_enumerate()` probed
`/wp-content/plugins/<slug>/`, these sites returned HTTP 200 for *every* plugin
slug — whether it was installed or not. The scanner was reporting the entire
`_ACTIVE_PROBE_PLUGINS` list as confirmed findings.

**Severity of false positives:** HIGH
- 100+ false-positive plugin findings per scan on affected sites.
- Inflated risk scores, misleading vulnerability correlation.
- Operator time wasted triaging non-existent plugins.

### Solution
`BaseScanner.is_soft_404(probe_url)` implements a sentinel-based comparison:

```
1. Fetch probe URL
   → Non-HTML content-type? Return False (real content)
   → Non-200 status? Return False

2. Fetch sentinel URL: /wp-content/plugins/sentinelwp-does-not-exist-<random8hex>/
   → Sentinel returns 404 / connection error? Return False (normal 404 site)
   → Sentinel returns 200? Proceed to comparison

3. Length ratio = min(len_probe, len_sentinel) / max(len_probe, len_sentinel)
   → ratio ≥ 0.85? Return True (soft-404 — bodies are nearly identical)

4. Chunk similarity: sample first 500 chars of sentinel in 50-char windows
   → ≥ 80% of windows found in probe body? Return True

5. Default: Return False (fail-open to avoid false negatives)
```

`PluginScanner._active_enumerate()` caches the result:
```python
_soft404_checked = False
_is_soft404_site = False

if resp.status_code == 200:
    if not _soft404_checked:
        _is_soft404_site = self.is_soft_404(url)
        _soft404_checked = True
    if _is_soft404_site:
        continue  # Skip — soft-404 site
```

**HTTP 403 bypasses the check:** Directory listing denied is unambiguous evidence
of plugin presence. The sentinel comparison would also incorrectly classify 403
as non-soft-404 since the condition `probe_resp.status_code != 200` would return
False early.

### Effectiveness

| Site Type | Before | After |
|-----------|--------|-------|
| Standard 404 (returns HTTP 404) | Correct | Correct |
| Soft-404 (returns HTTP 200 for all paths) | False positives | Suppressed |
| Plugin truly present (HTTP 200, different body) | Correct | Correct |
| Plugin truly present (HTTP 403) | Correct | Correct (bypass) |

---

## EVI-GAP-002 — Theme Finding Evidence Quality

### Problem
Plugin scanner findings have always included `version_confidence` in `raw_data`:
```python
raw_data={"type": "plugin", "slug": plugin, "version": version, "version_confidence": ...}
```

Theme scanner findings were missing this field, creating inconsistency in evidence
records and preventing downstream code from reliably assessing how trustworthy
version information is.

### Solution
`_detect_active_theme()` now computes and includes `version_confidence`:

```python
version_confidence = "high" if version else "none"
raw_data={
    "theme": theme,
    "version": version,
    "version_confidence": version_confidence,
    "method": "passive",
}
```

Values:
- `"high"` — version extracted from `style.css` `Version:` header (reliable).
- `"none"` — theme name detected from HTML path but no version found.

The `method: "passive"` field distinguishes passive HTML detections from future
active probe results.

---

## Known Remaining Gaps (Detection)

| ID | Scanner | Description | Priority |
|----|---------|-------------|----------|
| DETECT-OPEN-001 | PluginScanner | Soft-404 threshold (0.85) may miss sites with partial template variation. Consider adding a Levenshtein-ratio secondary check. | LOW |
| DETECT-OPEN-002 | WordPressDetector | `WP_SUBDIR_HINTS` is not documented in `.env.example`. | LOW |
| DETECT-OPEN-003 | ThemeScanner | `_probe_default_themes()` returns a single aggregated finding. Individual theme findings with per-theme version data would improve correlation accuracy. | MEDIUM |
| DETECT-OPEN-004 | PluginScanner | readme.txt version extraction used as "high" confidence but WordPress.org CDN may serve stale cached versions. Consider a `?v=<timestamp>` cache-bust parameter. | LOW |
