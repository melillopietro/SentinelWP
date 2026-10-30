# Enterprise detection integrity (v4.1.0+)

SentinelWP separates **evidence** from **verdict** so operators can trust findings in production. This document is the product contract for false positives, vulnerability correlation, misconfiguration checks, and PHP webshell indicators.

## Vulnerability intelligence (truthful layering)

| Layer | Source | When it runs | Enterprise rule |
|-------|--------|--------------|-----------------|
| **Authoritative** | Local Wordfence/CISA corpus (`match_scan_findings`) | Every scan via `core/scan_pipeline.py` | Exact slug + type match. With version → **Vulnerability** (confidence 0.95). Without version → **Potential Exposure** (confidence 0.6), never “confirmed vulnerable by name alone”. |
| **Advisory** | OSV.dev (`enrich_findings_with_cves`) | Only if `OSV_LIVE_ENRICHMENT_ENABLED=true` | OSV hits **not** in local corpus are labeled *Not corroborated* and confidence capped at **0.75**. |

Default: OSV live enrichment is **off** (`OSV_LIVE_ENRICHMENT_ENABLED=false` in `config.py`). Sync freshness of the local corpus determines whether “new” CVEs appear — enable Wordfence key / periodic sync for production.

Sync and async scan paths share the same pipeline (`finalize_and_score_scan`).

## False positive controls (exposure / plugins)

- **Plugin active probe**: site-wide soft-404 canary before accepting HTTP 200 (`PluginScanner`, SCAN-GAP-001).
- **Exposure checks**: shared HTML soft-404 markers (`scanners/soft404.py`) before git/env/debug/backup findings; payload shape checks (e.g. `DB_NAME`, git `ref:`).
- **Risk score**: findings below confidence threshold excluded (`CONFIDENCE_THRESHOLD`).
- **Non-WordPress**: multi-signal detector; non-WP targets labeled `Not WordPress` and skipped for core CVE matching.

## Misconfiguration coverage (honest scope)

Safe-active / full modes assess common WordPress posture issues (examples):

- Public `wp-admin` / `xmlrpc.php` / REST user enumeration vectors
- Exposed `debug.log`, `.env`, `.git`, `wp-config` backups, Adminer/phpinfo
- Missing security headers / TLS posture (dedicated scanners)

These are **configuration/exposure findings**, not CVE matches. Severity reflects reachability and evidence strength, not exploit success.

## PHP webshell / backdoor indicators

Scanner: `PhpArtifactScanner` (safe-active / full only — not passive).

| Control | Behavior |
|---------|----------|
| Probe budget | Bounded path list (`default_probe_paths`, ≤24), year-aware uploads |
| Soft-404 abort | Site-wide canary → no probes (avoids mass FP) |
| Response soft-404 | Per-URL themed 404 markers suppress findings |
| Signatures | Conservative heuristics in `php_artifact_signatures.py` |
| Category | `compromise_indicator` |
| Wording | *Likely* / *Suspicious* — **never** “confirmed compromise” from HTTP content alone |
| Evidence | `verification_required: true`, `content_redacted: true`, signature hit names |

**Out of scope (truthful limitations):** recursive upload-tree crawling, authenticated file listing, binary/encoded packers without strong markers, memory-only malware, and definitive attribution. Pair with host EDR / backup diff / WAF logs for incident response.

## Validation

```bash
python scripts/enterprise_detection_validation.py
```

Report: `reports/detection_integrity.json` (suite pass/fail + policy flags).
