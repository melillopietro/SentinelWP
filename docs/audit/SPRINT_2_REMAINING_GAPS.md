# Sprint 2 — Remaining Gaps

This document catalogs all known gaps that were **not addressed** in Sprint 2,
either because they were out of scope, lower priority, or depend on infrastructure
changes beyond the current sprint.

---

## Detection Gaps (Open)

### DETECT-OPEN-001 — Soft-404 Threshold Tuning
**Severity:** LOW  
**Scanner:** PluginScanner, BaseScanner  
**Description:** The soft-404 similarity threshold defaults to 0.85 (configurable
via `SOFT_404_SIMILARITY_THRESHOLD` env var). Sites with partial template variation
(e.g., different navigation counts or random session tokens in the body) may produce
body length ratios below 0.85, causing false negatives — i.e., soft-404 sites that
are not detected as such.  
**Recommendation:** Add Levenshtein-ratio or difflib.SequenceMatcher comparison as
an additional signal. Consider tuning the default threshold to 0.80 after empirical
testing.

### DETECT-OPEN-002 — WP_SUBDIR_HINTS Not Documented
**Severity:** LOW  
**File:** `.env.example`  
**Description:** The `WP_SUBDIR_HINTS` environment variable (added in DETECT-GAP-001)
controls additional subdirectory paths for WordPress detection. It is not currently
documented in `.env.example` or `README.md`.  
**Recommendation:** Add entry to `.env.example`:
```
# Comma-separated additional subdirectory paths to probe for WordPress installations.
# Default paths (/blog, /wordpress, /wp, /cms, /site, /web, /news) are always tried.
# WP_SUBDIR_HINTS=/myapp,/website,/blog2
```

### DETECT-OPEN-003 — ThemeScanner Aggregated Default Theme Finding
**Severity:** MEDIUM  
**Scanner:** ThemeScanner  
**Description:** `_probe_default_themes()` emits a single aggregated finding
("Default Themes Present: N") rather than one finding per confirmed theme. This
prevents per-theme CVE correlation (e.g., a specific version of `twentytwentytwo`
may have a known vulnerability).  
**Recommendation:** Refactor to emit one finding per confirmed default theme with
its own `raw_data` carrying slug, version, and confidence — consistent with
PluginScanner's per-plugin findings.

### DETECT-OPEN-004 — Plugin Version Cache-Busting
**Severity:** LOW  
**Scanner:** PluginScanner  
**Description:** `_get_plugin_version_from_readme()` fetches `readme.txt` from the
WordPress.org CDN. WordPress.org CDN may serve stale cached versions. This could
result in an older version number being reported as the installed version.  
**Recommendation:** Add a `?v=<timestamp>` or `Cache-Control: no-cache` header to
the readme.txt request to reduce CDN cache staleness.

### DETECT-OPEN-005 — UserAgent Fingerprinting Evasion
**Severity:** MEDIUM  
**All scanners**  
**Description:** All scanner requests use `USER_AGENT` from config. A sufficiently
sophisticated WAF or CDN could fingerprint SentinelWP's scanner by its User-Agent
string and serve different content (e.g., blank theme directory listings, or 200-OK
for all paths).  
**Recommendation:** Consider randomizing User-Agent from a pool of legitimate browser
strings in active scan modes, or honor the operator's `USER_AGENT` override.

---

## Intelligence Gaps (Open)

### INTEL-OPEN-001 — Distributed Sync Lock
**Severity:** MEDIUM  
**File:** `core/vulnerability_intelligence/service.py`  
**Description:** `_sync_lock = threading.Lock()` is process-local. In a horizontally-
scaled Celery deployment (multiple workers across multiple machines), two workers
can run `sync_all()` simultaneously, causing duplicate API calls and redundant DB
writes.  
**Recommendation:** Replace with a Redis-backed distributed lock:
```python
from redis import Redis
from redis.lock import Lock

redis_client = Redis.from_url(os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"))
_distributed_lock = redis_client.lock("sentinelwp:vuln_intel_sync", timeout=300)
```

### INTEL-OPEN-002 — Historical NVD Enrichment Backfill
**Severity:** LOW  
**File:** `core/vulnerability_intelligence/service.py`  
**Description:** `_enrich_with_nvd_inner()` processes up to 10 (or 40) records per
sync cycle. If there are hundreds of records missing CVSS scores, full backfill will
take many sync cycles. There is no one-time bulk backfill mechanism.  
**Recommendation:** Add a management command or one-off Celery task
`backfill_nvd_enrichment()` that processes all missing records in batches with
configurable sleep between API calls.

### INTEL-OPEN-003 — KEV Exploitation Evidence Fields
**Severity:** LOW  
**File:** `core/vulnerability_intelligence/service.py`  
**Description:** The CISA KEV feed includes `dateAdded`, `knownRansomwareCampaignUse`,
and `notes` fields. These are not currently stored or surfaced in findings.  
**Recommendation:** Extend the vulnerability record schema to include KEV-specific
fields. Surface `knownRansomwareCampaignUse = true` in findings as a HIGH or
CRITICAL severity escalation factor.

### INTEL-OPEN-004 — OSV Ecosystem Taxonomy Verification
**Severity:** LOW  
**File:** `scanners/vuln_intel.py`  
**Description:** `lookup_osv_vulnerabilities()` uses `ecosystem: "WordPress"`.
OSV.dev's taxonomy may use `"WordPress"`, `"wordpress"`, or a plugin-specific
ecosystem. This needs empirical verification against OSV's actual data.  
**Recommendation:** Test against known vulnerable plugins (e.g., `contact-form-7`
5.5.3) and verify that OSV returns results with the current ecosystem value.

---

## Concurrency and Infrastructure Gaps (Open)

### INFRA-OPEN-001 — Redis Unavailability During Sync
**Severity:** LOW  
**Description:** If Redis is unavailable when `sync_all()` is called, Celery tasks
will fail to enqueue but the sync itself (running in a worker) is unaffected. However,
the circuit breaker in `siem.py` depends on Redis for state. No smoke test exists
for Redis connectivity on startup.  
**Recommendation:** Add a startup health check that verifies Redis connectivity and
logs a WARNING (not ERROR) if unavailable.

### INFRA-OPEN-002 — NVD API Key Management
**Severity:** LOW  
**Description:** `NVD_API_KEY` is fetched via `_get_nvd_api_key()` in `nvd_client.py`.
It is not currently documented in `.env.example` or validated on startup.  
**Recommendation:** Add to `.env.example`:
```
# Optional: NVD REST API key for higher rate limits (50 req/30s vs 5 req/30s).
# Register at https://nvd.nist.gov/developers/request-an-api-key
# NVD_API_KEY=your-api-key-here
```

---

## Evidence and Reporting Gaps (Open)

### EVI-OPEN-001 — Finding Reference Field Population
**Severity:** LOW  
**Multiple scanners**  
**Description:** Many scanner findings leave `f.reference = None`. This means
finding detail views show no external reference link. Several scanners have CVE
or advisory information available but do not populate the `reference` field.  
**Recommendation:** Audit all scanner `_add_finding()` calls and populate
`reference` with a relevant URL where one is available.

### EVI-OPEN-002 — Remediation Text Consistency
**Severity:** LOW  
**Multiple scanners**  
**Description:** Remediation text quality varies significantly across scanners.
Some provide actionable, specific guidance; others use generic placeholder text.  
**Recommendation:** Establish a remediation text template and review all scanner
findings in Sprint 3 for consistency.

---

## Summary Table

| ID | Area | Severity | Recommended Sprint |
|----|------|----------|-------------------|
| DETECT-OPEN-001 | Detection | LOW | Sprint 3 |
| DETECT-OPEN-002 | Documentation | LOW | Sprint 3 (quick win) |
| DETECT-OPEN-003 | Detection | MEDIUM | Sprint 3 |
| DETECT-OPEN-004 | Detection | LOW | Sprint 4 |
| DETECT-OPEN-005 | Detection | MEDIUM | Sprint 3 |
| INTEL-OPEN-001 | Infrastructure | MEDIUM | Sprint 3 |
| INTEL-OPEN-002 | Intelligence | LOW | Sprint 4 |
| INTEL-OPEN-003 | Intelligence | LOW | Sprint 4 |
| INTEL-OPEN-004 | Intelligence | LOW | Sprint 3 |
| INFRA-OPEN-001 | Infrastructure | LOW | Sprint 3 |
| INFRA-OPEN-002 | Documentation | LOW | Sprint 3 (quick win) |
| EVI-OPEN-001 | Evidence | LOW | Sprint 4 |
| EVI-OPEN-002 | Evidence | LOW | Sprint 4 |

**MEDIUM priority open items for Sprint 3:**
1. DETECT-OPEN-003 — Per-theme findings in `_probe_default_themes()`
2. DETECT-OPEN-005 — User-Agent fingerprinting evasion
3. INTEL-OPEN-001 — Distributed lock for multi-worker deployments
