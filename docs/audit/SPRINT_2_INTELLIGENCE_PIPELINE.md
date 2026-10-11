# Sprint 2 — Intelligence Pipeline

## Architecture Overview (Post Sprint 2)

```
Celery periodic task (maintenance_tasks.py)
    └── sync_all()          [acquires _sync_lock; calls _inner variants]
         ├── _sync_wordfence_inner()     [Wordfence Production Feed API]
         ├── _sync_kev_inner()           [CISA KEV JSON catalog]
         ├── _sync_plugin_metadata_inner(slugs)  [WordPress.org Plugin API]
         └── _enrich_with_nvd_inner()   [NVD REST API v2.0]  ← NEW (INTEL-GAP-001)

Runtime scan path
    └── enrich_findings_with_cves(findings)  [OSV.dev REST API]
         └── _cvss_to_severity(score)   ← NEW (INTEL-GAP-004)
```

---

## Data Sources

| Source | Endpoint | Auth Required | Rate Limit | Sync Frequency |
|--------|----------|--------------|------------|----------------|
| Wordfence Production Feed | `api.wordfence.com/v2/...` | API key (WORDFENCE_API_KEY) | Per key | Periodic (configurable) |
| CISA KEV | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | Public | Periodic |
| WordPress Plugin API | `api.wordpress.org/plugins/info/1.2/` | None | Polite | Periodic, batched by slug |
| NVD REST API v2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | Optional (NVD_API_KEY) | 5 req/30s (no key) / 50 req/30s (key) | Per sync, bounded |
| OSV.dev | `api.osv.dev/v1/query` | None | Public | Per scan finding |

---

## Sync Flow — sync_all()

```
sync_all()
│
├── Acquire _sync_lock (non-blocking)
│   └── If locked → return {'status': 'skipped', 'reason': 'Sync in progress'}
│
├── vuln_repo.init_vuln_intel_db()
│
├── _sync_wordfence_inner()
│   ├── Check WORDFENCE_API_KEY configured
│   ├── wordfence_client.fetch_production_feed_with_reason()
│   ├── normalizer.normalize_wordfence_feed()
│   ├── normalizer.deduplicate_by_cve()
│   └── vuln_repo.upsert_vulnerability_record() × N
│
├── _sync_kev_inner()
│   ├── Fetch CISA KEV JSON
│   ├── Cross-reference with existing vulnerability records
│   └── vuln_repo.mark_as_kev() × N
│
├── _sync_plugin_metadata_inner(slugs)
│   ├── Batch fetch WordPress Plugin API for each slug
│   └── vuln_repo.update_plugin_metadata() × N
│
├── _enrich_with_nvd_inner()   ← INTEL-GAP-001
│   ├── Query: SELECT cve_id FROM vulnerability_records WHERE cvss_score IS NULL LIMIT N
│   ├── nvd_client.enrich_cve(cve_id) × min(N, max_enrichments)
│   │   ├── GET NVD /rest/json/cves/2.0?cveId={cve_id}
│   │   └── vuln_repo.update_cvss(cve_id, score, vector, rating)
│   └── Returns {status, enriched, skipped, errors}
│       [Exception caught; does not abort sync_all]
│
└── Release _sync_lock (finally)
```

---

## INTEL-GAP-001 — NVD Enrichment Details

### Problem Statement
Vulnerability records ingested from Wordfence often lack CVSS scores when the
CVE is newly disclosed or when the Wordfence feed entry was created before NIST
published the final CVSS assessment. Without a CVSS score:
- Severity normalisation (`_cvss_to_severity`) cannot operate.
- Risk scoring in downstream pipelines defaults to fallback values.

### Implementation
```python
def _enrich_with_nvd_inner() -> Dict[str, Any]:
    api_key = _get_nvd_api_key()
    max_enrichments = 40 if api_key else 10

    rows = conn.execute(
        "SELECT id, cve_id FROM vulnerability_records "
        "WHERE cve_id IS NOT NULL AND (cvss_score IS NULL OR cvss_score = 0) "
        "LIMIT ?", (max_enrichments,)
    )
    for row in rows:
        try:
            nvd_data = enrich_cve(row['cve_id'])
            if nvd_data and nvd_data.get('cvss_score'):
                vuln_repo.update_cvss(row['id'], nvd_data)
                enriched += 1
        except Exception as exc:
            errors += 1
            logger.warning("NVD enrichment failed for %s: %s", row['cve_id'], exc)
```

### Rate Limiting Behaviour
| NVD_API_KEY configured | Max enrichments per sync | Effective request rate |
|------------------------|--------------------------|----------------------|
| No | 10 | ~1 req per 6s (safe for 5 req/30s limit) |
| Yes | 40 | ~1 req per 0.75s (safe for 50 req/30s limit) |

### Failure Isolation
`_enrich_with_nvd_inner()` is wrapped in a `try/except Exception` block inside
`sync_all()`. Any failure (network timeout, NVD API error, DB error) results in:
- Error logged at `ERROR` level with exception detail.
- `nvd_enrichment` key in `sync_all()` return value contains
  `{'status': 'error', 'reason': <exception message>}`.
- `wordfence`, `cisa_kev`, and `plugin_metadata` results are unaffected.

---

## INTEL-GAP-003 — Concurrency Control

### Lock Architecture

```
_sync_lock = threading.Lock()   # module-level, process-local

Public functions (sync_wordfence, sync_kev, sync_plugin_metadata):
    _sync_lock.acquire(blocking=False)
    └── Success → run _inner() → release in finally
    └── Failure → return {'status': 'skipped'}

sync_all():
    _sync_lock.acquire(blocking=False)
    └── Success → call _inner variants directly → release in finally
    └── Failure → return {'status': 'skipped', 'reason': 'Sync in progress'}
```

### Why `_inner` Variants
`threading.Lock` is **not reentrant**. If `sync_all()` called `sync_wordfence()`,
the inner call would attempt `_sync_lock.acquire(blocking=False)` on a lock
already held by `sync_all()` in the same thread. Because `blocking=False` is used,
this would return `False` immediately — effectively silently skipping Wordfence sync
inside `sync_all()`.

The `_inner` variants perform the actual sync work without touching the lock.
This is the standard pattern for mutex-guarded functions in Python.

### Limitation (for Sprint 3)
`threading.Lock()` is **process-local**. In a horizontally-scaled Celery
deployment (multiple worker processes on separate machines), two workers can
run `sync_all()` simultaneously. This results in duplicated API calls and
redundant DB writes — not data corruption, but wasteful.

**Recommended Sprint 3 action:** Implement a Redis-backed distributed lock
using `redis-py`'s `Lock` with a TTL, or use `celery-redbeat` to schedule
sync as a singleton task.

---

## INTEL-GAP-004 — CVSS Severity Normalisation

### Mapping Table

| CVSS v3 Score Range | Severity |
|--------------------|----------|
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0.1 – 3.9 | LOW |
| 0.0 | INFO |
| None / invalid | `None` → preserve existing severity |

### Behaviour When No CVSS Data
If the OSV.dev response contains CVE matches but none of them carry a
`cvss_score` key, `best_cvss` remains `None`. `_cvss_to_severity(None)` returns
`None`. The `if derived_severity is not None:` guard means `f.severity` is
never touched — preserving the scanner's original assessment.

---

## Open Items for Sprint 3

| Item | Priority | Description |
|------|----------|-------------|
| INTEL-OPEN-001 | MEDIUM | Distributed lock for sync_all() in multi-worker deployments |
| INTEL-OPEN-002 | LOW | NVD enrichment backfill — run a one-time job to enrich all historical records |
| INTEL-OPEN-003 | LOW | KEV exploitation evidence: attach KEV date-added and ransomware-group fields to findings |
| INTEL-OPEN-004 | LOW | OSV.dev ecosystem: currently uses "WordPress" ecosystem; verify this matches OSV's taxonomy for WP plugins/themes |
