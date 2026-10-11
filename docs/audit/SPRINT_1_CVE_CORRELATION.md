# SentinelWP — Sprint 1 CVE Correlation Review

**Branch:** `fix/sentinelwp-sprint0-remediation`  
**Date:** 2025-07-15  
**Prepared by:** Cyber Threat Intelligence Architect / Principal Application Security Engineer

---

## 1. CVE Pipeline Architecture

```
Wordfence Intelligence v3 Feed
         │
         ▼
   normalize_wordfence_record()   ← field normalization, date parsing
         │
         ▼
   upsert_vulnerability_record()  ← SQLite upsert (id = Wordfence UUID)
         │
         ▼
   match_scan_findings()          ← slug + type + version range match
         │
         ├── CISA KEV lookup (get_kev_status)
         ├── Plugin metadata (active_installs)
         └── MatchResult (affected / not_affected / version_unknown / range_unknown)

OSV.dev (scanners/vuln_intel.py)  ← live enrichment (secondary, per-finding)
CISA KEV Feed                     ← direct ingestion via cisa_kev_client.py
WordPress.org Plugin API          ← metadata cache (active_installs, current_version)
NVD                               ← API key available via NVD_API_KEY; no active client
```

---

## 2. Feed Ingestion Verification

### 2.1 Wordfence Client

**WFBUG-001 (Fixed in Sprint 1):**  
`fetch_production_feed_with_reason()` had a code path that `return None` instead of `return None, msg` after max retries, breaking the documented return type `tuple[Optional[dict], str]`. Any caller that unpacked the return value (`data, reason = ...`) would have raised `TypeError: cannot unpack non-iterable NoneType object`.

**Remediation:** Changed `return None` to `return None, msg` on line 115 of `wordfence_client.py`.

**Regression:** `TestWordfenceFeedReturnType` — 3 tests covering:
- Max-retry exhaustion returns `(None, str)`
- Missing API key returns `(None, str)`
- HTTP 401 returns `(None, str)`

**Retry logic verified:**
- HTTP 429: respects `Retry-After` header, exponential backoff
- HTTP 5xx: exponential backoff with jitter, max 3 retries
- Network errors: retry up to `max_retries`

**Authentication:** Bearer token via `WORDFENCE_API_KEY` (configurable from DB settings table or env var; DB setting takes precedence).

### 2.2 CISA KEV Client

The `sync_kev()` function in `service.py` accepts both the CISA KEV JSON `{"vulnerabilities": [...]}` wrapper and bare list format. Field aliasing handles both the API format (`cveID`, `dateAdded`, `vendorProject`) and normalized internal format (`cve`, `date_added`, `vendor`).

No issues found.

### 2.3 WordPress.org Plugin Metadata

Plugin metadata is cached per-slug for `PLUGIN_METADATA_CACHE_HOURS` hours (default 168h = 7 days). Cache is checked before fetching. Errors on individual slugs are counted but do not abort the batch.

No issues found.

### 2.4 NVD Enrichment

`NVD_API_KEY` is configurable but no active NVD client exists. The `nvd_client.py` file is present but `service.py` does not call it. This is a known gap (not a regression).

---

## 3. Data Normalization

### 3.1 Version Range Schema

Wordfence affected version ranges map to:

```python
{
    "from_version": str,  # "" or "*" = unbounded
    "from_inclusive": bool,
    "to_version": str,    # "" or "*" = unbounded
    "to_inclusive": bool
}
```

### 3.2 Deterministic Version Comparison

`version_matcher.py` uses a tuple-based numeric comparator:

- `"1.9"` → `(1, 9)` < `"1.10"` → `(1, 10)` ✅ (not lexicographic)
- `"1.2.3-beta"` < `"1.2.3"` ✅ (prerelease weight: alpha=-3, beta=-2, rc=-1)
- Wildcards (`"*"`) → `None` → treated as unbounded ✅

**Regression tests:** `TestVersionMatcherEdgeCases` — 16 tests covering:
- `1.9 < 1.10` (numeric comparison)
- `1.10 < 1.10.1`
- `2.0 > 1.99`
- Prerelease: alpha < beta < rc < release
- Missing/empty/wildcard detected version → `version_unknown`
- Overlapping ranges: first match wins
- Version above all ranges → `not_affected`
- Unbounded lower/upper bounds

### 3.3 Duplicate CVE Handling

`deduplicate_by_cve()` removes Wordfence records whose CVE already appears in the OSV dataset. Records without CVE are always kept. Verified by `test_deduplicate_by_cve` in `tests/vulnerability_intelligence/test_normalizer.py`.

Orchestrator-level deduplication: `existing_cves` set prevents the same CVE from being reported twice across the live OSV enrichment and the local Wordfence database match.

### 3.4 Source Provenance

All vulnerability records carry `source = 'wordfence'`. The `updated` field (ISO-8601 UTC) tracks freshness.

---

## 4. False-Positive Prevention (CVE Correlation)

### 4.1 Exact Slug Matching

`match_software()` requires **exact** slug equality:
```python
if sw_slug and sw_slug != detected_slug:
    continue
```

A plugin named `contact-form` will **not** match a CVE record for `contact-form-7`. Substring or fuzzy matching is never performed.

**Regression:** `test_slug_mismatch_never_produces_affected` confirms this.

### 4.2 Type Isolation

A `core` record never matches a `plugin` query and vice versa. The `detected_type` parameter must match `sw.get('type')` exactly.

**Regression:** `test_type_mismatch_never_produces_affected` confirms this.

### 4.3 Version-Unknown Handling

When a plugin version is not detected (`None` or `""`):
- `match_software()` returns `status='version_unknown'`
- The orchestrator classifies this as "Potential Exposure" at `Severity.MEDIUM` with `confidence=0.6`
- Title is prefixed with "Potential Exposure" to distinguish from confirmed vulnerabilities

**Regression:** `test_missing_version_returns_version_unknown` confirms `version_unknown` is returned correctly.

### 4.4 Malformed Range Handling

`is_version_affected()` wraps all comparison logic in `try/except Exception`, returning `status='range_unknown'` on any error. Callers treat `range_unknown` the same as `affected` (conservative). This is the correct security posture.

---

## 5. Stale Data Threshold — CODE-006 (Fixed)

**Before:** `is_stale()` used `timedelta(minutes=30)` — ignoring the documented configuration variable `VULN_INTEL_STALE_AFTER_HOURS` (default `0.5`h = 30 min, but independently configurable).

**After:** `is_stale()` uses `timedelta(hours=VULN_INTEL_STALE_AFTER_HOURS)`. The default value `0.5` produces the same behaviour as the old hardcoded 30 minutes, so no operational change occurs at default configuration. However, operators who have set `VULN_INTEL_STALE_AFTER_HOURS` to a different value (e.g., `24` for daily sync) now get correct behaviour.

**Regression:** `TestIsStaleUsesConfiguredThreshold` — 3 tests including a source inspection test that asserts `timedelta(minutes=30)` does not appear in the source.

---

## 6. Feed Freshness Monitoring

| Source | Freshness threshold | Staleness indicator |
|---|---|---|
| Wordfence | `VULN_INTEL_STALE_AFTER_HOURS` | `is_stale()` → True |
| CISA KEV | Same threshold (shared check) | `is_stale()` → True |
| Plugin metadata | `PLUGIN_METADATA_CACHE_HOURS` = 168h | Per-slug cache expiry |

`get_status()` exposes `is_stale`, `last_success_at`, and per-source sync state for the `/api/vuln-intel/status` endpoint.

---

## 7. OPS-001 — Sync Concurrency

`sync_all()` acquires `_sync_lock` (non-blocking) before running. If a sync is already running, it returns `{'status': 'skipped', 'reason': 'Sync in progress'}`.

`sync_wordfence()`, `sync_kev()`, and `sync_plugin_metadata()` can still be called individually without the lock. This is acceptable if called directly (e.g., via admin UI), but could allow concurrent duplicate runs in a Celery-scheduled scenario. This remains an open gap for Sprint 2.

---

## 8. Remaining Gaps

| ID | Description | Priority |
|---|---|---|
| NVD-001 | NVD client is present but not integrated in `service.py` | Low |
| OPS-001 | `sync_wordfence/kev/metadata` callable without `_sync_lock` from external callers | Medium |
| WFBUG-002 | No response-size guard on Wordfence feed download (large payloads accepted) | Low |
| FEED-001 | No feed signature/hash verification for Wordfence payload | Low |
