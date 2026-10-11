# SentinelWP — Sprint 1 Remaining Gaps

**Branch:** `fix/sentinelwp-sprint0-remediation`  
**Date:** 2025-07-15  
**Prepared by:** Principal Application Security Engineer

This document records all detection limitations, architectural weaknesses, and open findings not addressed in Sprint 1. Items are prioritised for Sprint 2.

---

## 1. Detection Gaps

### DETECT-GAP-001 — Subdirectory WordPress Installations
**Description:** `WordPressDetector` does not probe common subdirectory paths such as `/blog/`, `/wp/`, `/cms/`, `/wordpress/`. If WordPress is installed at `https://example.com/blog/` and the canonical root returns a non-WordPress landing page, the scanner will report "Not WordPress".  
**Impact:** False negative for subdirectory installs.  
**Recommended fix:** Probe a configurable list of common subdirectory prefixes and check for WP signals at each. Use `base_url` from the best-confidence probe.  
**Sprint:** 2

### DETECT-GAP-002 — Reverse Proxy Stripping WP Headers
**Description:** Some reverse proxy configurations strip the `Link: <...api.w.org...>` header before it reaches the scanner. If the homepage also has no `/wp-content/` or `/wp-includes/` references, the signal count may fall below the detection threshold.  
**Impact:** Low false-negative risk; mitigated by multi-signal approach (multiple independent signals).  
**Recommended fix:** Document as expected limitation in operator guide.  
**Sprint:** 3

### DETECT-GAP-003 — Theme Scanner Active Probe in Passive Mode
**Description:** `ThemeScanner._probe_default_themes()` issues HEAD requests for 13 default themes regardless of scan mode. The orchestrator's passive profile includes `ThemeScanner`, meaning these 13 HEAD requests are made even in "passive" mode.  
**Impact:** Minor violation of passive-mode semantics (no active probing).  
**Recommended fix:** Add `ENABLE_ACTIVE_PROBE` flag to `ThemeScanner`, parallel to `PluginScanner.ENABLE_ACTIVE_PROBE`. Set `False` in passive profile.  
**Sprint:** 2

### DETECT-GAP-004 — Plugin Scanner Active Probe in Passive Mode
**Description:** Same issue as DETECT-GAP-003 for `PluginScanner.ENABLE_ACTIVE_PROBE`. The orchestrator passive profile does not include `PluginScanner`, so this is only a concern if the orchestrator profile is changed.  
**Assessment:** Currently contained — `PluginScanner` is not in passive profile.  
**Sprint:** 2 (preemptive hardening)

---

## 2. Vulnerability Intelligence Gaps

### INTEL-GAP-001 — No Active NVD Enrichment
**Description:** `core/vulnerability_intelligence/nvd_client.py` exists but `service.py` never calls it. NVD CVSS scores and CWE data are not retrieved or cross-referenced.  
**Impact:** CVE records lacking CVSS data in Wordfence feed will have `cvss_score = None`.  
**Recommended fix:** Integrate `nvd_client.py` into `sync_all()` for CVSS enrichment of records missing scores.  
**Sprint:** 2

### INTEL-GAP-002 — No Response-Size Guard on Wordfence Feed
**Description:** The Wordfence feed download in `wordfence_client.py` uses `requests.get()` with no `stream=True` or maximum-size guard. A very large feed payload would be held entirely in memory.  
**Impact:** Low in practice (Wordfence feed is ~50MB); potential OOM in constrained environments.  
**Recommended fix:** Add `stream=True` + incremental JSON reading, or a content-length check before parsing.  
**Sprint:** 2

### INTEL-GAP-003 — OPS-001: Individual Sync Functions Bypass Lock
**Description:** `sync_wordfence()`, `sync_kev()`, and `sync_plugin_metadata()` can be called directly (e.g., from admin UI routes) without acquiring `_sync_lock`. This could allow concurrent duplicate runs.  
**Impact:** Duplicate DB upserts (safe due to UPSERT semantics), but wasted CPU/network on concurrent calls.  
**Recommended fix:** Add lock acquisition inside each individual sync function (check-and-skip pattern).  
**Sprint:** 2

### INTEL-GAP-004 — OSV.dev Enrichment Overrides Severity
**Description:** `enrich_findings_with_cves()` unconditionally sets `severity = Severity.HIGH` on any finding that gets an OSV.dev match, regardless of the original finding's severity or the CVE's CVSS score. A CVSS 4.0 vulnerability would be promoted to HIGH.  
**Impact:** Possible inflation of finding severity.  
**Recommended fix:** Map CVSS score to severity using the same mapping used by the Wordfence pipeline (≥9.0 → CRITICAL, ≥7.0 → HIGH, ≥4.0 → MEDIUM, else LOW).  
**Sprint:** 2

### INTEL-GAP-005 — Backported Patch Detection Not Implemented
**Description:** WordPress distributions (e.g., some Linux distros) backport security patches to older version numbers. A version `5.9.3-patched` might receive a CVE fix that was officially released as `6.0.1`. The version matcher has no concept of backported patches.  
**Impact:** False positive (reporting a backported-patched version as vulnerable).  
**Recommended fix:** Document limitation; add advisory note to findings; add vendor-specific patch override configuration.  
**Sprint:** 3

---

## 3. Scanner Reliability Gaps

### SCAN-GAP-001 — No Soft-404 Detection
**Description:** WordPress installations with custom 404 templates return HTTP 200 for all URLs. The plugin scanner's active probe treats HTTP 200 as plugin-confirmed, but a soft-404 could produce false positives.  
**Impact:** Active probe may falsely detect plugins on sites with universal soft-404 responses.  
**Recommended fix:** Add a `_is_soft_404()` helper that probes a clearly non-existent URL and checks if the response matches the probe URL. If sizes match within tolerance or response body matches the 404 body, classify as soft-404.  
**Sprint:** 2

### SCAN-GAP-002 — No Rate Limiting Between Requests
**Description:** Scanners do not insert delays between HTTP requests. On shared hosting, aggressive scanning may trigger rate-limiting at the target.  
**Impact:** Requests return 429; `BaseScanner` treats any non-200/403 as miss → findings may be missed.  
**Recommended fix:** Add configurable `SCAN_REQUEST_DELAY_MS` with default 0 (off by default; opt-in for considerate scanning).  
**Sprint:** 2

### SCAN-GAP-003 — No Response Size Limit in BaseScanner
**Description:** `_safe_request()` does not cap response body size. A server returning a very large HTML page could be read entirely into memory.  
**Impact:** OOM risk for very large responses.  
**Recommended fix:** Add `stream=True` + `iter_content()` limited to `MAX_EVIDENCE_SIZE_BYTES`.  
**Sprint:** 2

### SCAN-GAP-004 — TLS Scanner Deprecation Warnings
**Description:** `scanners/tls_scanner.py:89` uses `ssl.PROTOCOL_TLSv1` and `ssl.PROTOCOL_TLSv1_1` which are deprecated in Python 3.14. The tests generate deprecation warnings.  
**Impact:** Will become errors in a future Python version.  
**Recommended fix:** Replace with `ssl.TLSVersion` enum or use `ssl.SSLContext.set_ciphers()` approach.  
**Sprint:** 2

---

## 4. Architecture Gaps (from Sprint 0)

These were documented in Sprint 0 and remain open:

| ID | Description | Sprint |
|---|---|---|
| ARCH-001 | Dual persistence paths (raw SQLite + SQLAlchemy ORM) | 2 |
| ARCH-002 | Circuit breaker is process-local (not Redis-backed) | 2 |
| SEC-008 | `list_assets(limit=500)` silently truncates — callers unaware | 2 |
| FUNC-002 | SLA default retention values hardcoded | 2 |
| OPS-003 | Purge task uses SQLite internal functions — may behave differently in PostgreSQL | 2 |
| PROD-001 | Changelog version stamp not injected from `core.version` | 2 |
| PROD-002 | Asset list UI has no pagination indicator for >500 assets | 2 |
| CODE-005 | `intel_queue_depth` metric is approximate (stale DB flag) | 2 |

---

## 5. Evidence Model Gaps

### EVI-GAP-001 — No `scanner` Field in Finding Model
**Description:** `Finding` dataclass does not have a `scanner` field identifying which scanner produced it. The `category` field partially serves this purpose but is not a scanner name.  
**Impact:** Difficult to filter findings by scanner in post-processing.  
**Recommended fix:** Add `scanner_id: Optional[str]` to `Finding` and populate it in each scanner's `_add_finding()` calls.  
**Sprint:** 2

### EVI-GAP-002 — Theme Scanner Lacks `version_confidence`
**Description:** Theme findings in `raw_data` contain `version` but no `version_confidence` key. This is inconsistent with plugin findings.  
**Impact:** Minor inconsistency; theme version is lower-priority than plugin version.  
**Recommended fix:** Add `version_confidence: "high"` (from `style.css Version:`) or `"none"` (if version not found) to theme `raw_data`.  
**Sprint:** 2

---

## 6. Recommended Sprint 2 Priority Order

1. **SCAN-GAP-001** — Soft-404 detection (prevents active-probe false positives)
2. **INTEL-GAP-004** — OSV.dev severity mapping (prevents severity inflation)
3. **DETECT-GAP-003** — Theme scanner passive-mode gate
4. **INTEL-GAP-003** — OPS-001 individual sync lock enforcement
5. **INTEL-GAP-001** — NVD enrichment integration
6. **DETECT-GAP-001** — Subdirectory WordPress detection
7. **SCAN-GAP-004** — TLS scanner Python 3.14 deprecation warnings
8. **EVI-GAP-001** — `scanner_id` field in Finding model
9. All Sprint 0 carry-forwards (ARCH-001, ARCH-002, etc.)
