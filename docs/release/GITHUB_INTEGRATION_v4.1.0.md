# SentinelWP v4.1.0 — Safe GitHub Integration Report

**Date:** 2026-10-11  
**Public `origin/main` (preserved):** `ad1de5ec8dc10df1648e946663405e88c642ac09`  
**Release candidate source:** `3bb5b96188e8077ca5e466d859ba9386b19fbe47`  
**Integration branch HEAD:** `69c590b95c8ad8e6d5eed441078538407dfd6a3d`

## Strategy

1. Branch **from** `origin/main` (single public v4.0.0 commit — history unchanged).
2. Import the full tested **v4.1.0 enterprise tree** from `3bb5b96`.
3. **Reconcile** the fifteen paths that existed only on public main (no silent drops).
4. Run regression gates; push branch; open PR to `main` (**no merge, tag, or release**).

## Reconciliation — 15 GitHub-only paths

| Path | Decision | v4.1.0 handling |
|------|----------|-----------------|
| `CHANGELOG_v3.7.1.md` | **Retain** | Restored from main (historical changelog). |
| `core/auth.py` | **Obsolete** | Superseded by `core/auth/` package (`passwords.py`, OIDC, session roles). Not restored. |
| `core/scan_pipeline.py` | **Port + integrate** | Restored; orchestrator/async_runner call `add_core_maintenance_findings`; tests in `tests/test_scan_pipeline.py`. |
| `core/wordpress_version.py` | **Port** | Restored; used by scan pipeline, `CoreSecurityScanner`, `tests/test_wordpress_version.py`. |
| `core/vulnerability_intelligence/curated_advisories.py` | **Port** | Restored; seeded in tests / lab via `seed_curated_advisories()`. |
| `scanners/core_security_scanner.py` | **Port + wire** | Restored; added to all scan profiles after `WordPressDetector`. |
| `docs/RISK_SCORING_MODEL.md` | **Retain (annotated)** | Restored with v4.1.0 note: authoritative scoring is `core/risk_engine.py`. |
| `scripts/benchmark_risk_scores.py` | **Retain** | Restored from main (offline calibration tooling). |
| `scripts/sensitivity_analysis.py` | **Retain** | Restored from main. |
| `tests/conftest.py` | **Port** | Restored (SQLite/vuln intel connection reset for isolated pytest). |
| `tests/test_risk_engine_deterministic.py` | **Port** | Restored; passes against v4.1.0 engine (+ `vulnerability_intelligence` multiplier). |
| `tests/test_risk_engine_edge_cases.py` | **Not ported** | Targets public 4.0.0-only calibration (decay 0.9, weight set). Conflicts with enterprise engine validated by 640+ Sprint tests. Documented here; use `test_risk_engine_deterministic` + Sprint suites. |
| `tests/test_scan_pipeline.py` | **Port** | Restored; requires `OSV_LIVE_ENRICHMENT_ENABLED` in `config.py` (added, default off). |
| `tests/test_wordpress_version.py` | **Port** | Restored; complements `tests/test_wordpress_version_regression.py` (28 tests). |
| `tests/vulnerability_intelligence/test_version_matcher_edge_cases.py` | **Not ported** | Targets main-only `version_matcher` parsing; enterprise matcher covered by Sprint 1/7 tests. |

### Functionality preserved from public 4.0.0

- WordPress core version helpers and **core update available** findings (`add_core_maintenance_findings`).
- **CoreSecurityScanner** (CVE-2026-87902 theme precondition signals).
- **Curated advisories** seed path for lab/tests.
- Risk documentation and offline benchmark scripts.
- Additional pytest coverage (+9 net vs 640 baseline).

### Enterprise-only behavior retained

- Six UI workspaces unchanged.
- No `BruteForceScanner` in automated profiles.
- Canonical `wordpress_version_*` fields and Sprint 11 security remediation (SSRF preflight, RBAC, Celery claims).
- Enterprise `core/risk_engine.py` decay (`0.7`) and Sprint-validated scoring.

## Test and security gates (integration tree)

| Gate | Result |
|------|--------|
| `pytest tests/` | **649 passed** |
| `pip-audit -r requirements-prod.txt` (Py 3.12) | Run in CI / lab with 3.12 venv (local default Python may be 3.14) |
| Secrets in commit | No `.env` secrets, dumps, or private keys staged; test passwords are fixture-only |

## Remaining blockers before merge/tag

- Maintainer review of PR diff (especially deleted-vs-main paths).
- Production `pip-audit` on Python **3.12** in CI.
- Lab Docker E2E re-run on integration SHA (recommended; prior E2E on `3bb5b96` + patch delta).
- Explicit approval to **merge**, tag `v4.1.0`, publish images, and GitHub Release.
