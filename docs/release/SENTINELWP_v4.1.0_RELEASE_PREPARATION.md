# SentinelWP v4.1.0 — Official Release Preparation Report

**Date (UTC):** 2026-10-11  
**Local branch:** `release/sentinelwp-v4.1.0`  
**Prior checkpoint:** `bbbc7221ea92213f04c209accfdffc3a8f65be52` (reliability patch)  
**GitHub remote:** https://github.com/melillopietro/SentinelWP  

---

## 1. Repository integrity

| Item | Value |
|------|--------|
| **Local HEAD (pre-release commit)** | `bbbc7221ea92213f04c209accfdffc3a8f65be52` |
| **Public `origin/main` HEAD** | `ad1de5ec8dc10df1648e946663405e88c642ac09` |
| **Merge-base** | **None** (`git merge-base` exit 1) |
| **Common history?** | **No** — unrelated histories |

### Divergence analysis
- **`origin/main`:** Single commit *“Initial commit: SentinelWP v4.0.0”* (**97 files**). Forced update observed on fetch (`ffb7b67...ad1de5e`).
- **Local enterprise line:** **388 files** at reliability patch; deep Sprint 8–11 history from `07c3e2c` through `bbbc722`.
- **Path overlap:** **82** paths share names; **306** paths exist only locally; **15** paths exist only on `origin/main`.

### Files only on GitHub `main` (review before integration)
`CHANGELOG_v3.7.1.md`, `core/auth.py`, `core/scan_pipeline.py`, `core/vulnerability_intelligence/curated_advisories.py`, `core/wordpress_version.py`, `docs/RISK_SCORING_MODEL.md`, `scanners/core_security_scanner.py`, `scripts/benchmark_risk_scores.py`, `scripts/sensitivity_analysis.py`, `tests/conftest.py`, `tests/test_risk_engine_*`, `tests/test_scan_pipeline.py`, `tests/test_wordpress_version.py`, `tests/vulnerability_intelligence/test_version_matcher_edge_cases.py`

### Functional parity assessment (4.0.0 README vs local)
Local tree **includes** documented 4.0.0 scanner capabilities (e.g. `.git/HEAD`, `.env`, `wp-config-sample.php` in `scanners/exposure_scanner.py`), setup wizard routes, SSRF controls, async/Celery scanning, scheduled audits, and six-workspace UI. Enterprise line is a **superset** for production features; the 15 GitHub-only files may contain refactors (e.g. `core/scan_pipeline.py`) that should be **manually diffed** and ported if missing equivalent logic.

### Safe integration plan (no force push)
1. **Do not** `git push --force` to `main`.
2. Publish branch `release/sentinelwp-v4.1.0` to GitHub (after approval).
3. Open PR to `main` with maintainer note: **unrelated histories**.
4. Merge option A: `git merge --allow-unrelated-histories` on GitHub/consensus — resolve conflicts keeping enterprise deployment + remediated auth/scan paths; manually import any unique 4.0.0 modules still needed.
5. Merge option B (maintainer): **Replace** `main` content with `release/sentinelwp-v4.1.0` after sign-off that 4.0.0-only files are obsolete or cherry-picked.
6. Tag **`v4.1.0`** only after merge approval and CI.

---

## 2. Version alignment (4.1.0)

| Area | Updated |
|------|---------|
| `core/version.py` | `4.1.0`, codename `Enterprise` |
| `/health` JSON | `__version__` |
| UI sidebar / changelog | `app_version` context |
| Reports (HTML/PDF/SARIF) | `SENTINELWP_VERSION` |
| `core/update_checker.py` | `v4.1.0` |
| Docker tags | `sentinelwp:4.1.0` in prod + validation compose |
| `CHANGELOG.md` | New authoritative entry |
| `README.md` | v4.1.0 header + summary |
| `docs/SECURITY_HARDENING.md`, `docs/UPGRADE_ROLLBACK.md` | Current release refs |

**Not renamed:** API route prefix `/api/v1`, Alembic revision IDs, historical `docs/audit/*` sprint reports.

---

## 3. Functional & security compatibility (validated)

| Capability | Status |
|------------|--------|
| Auth + tenant slug login | E2E + unit tests |
| REST/session RBAC | Remediation tests + HTTPS probes |
| Tenant isolation | Existing test suite |
| Atomic scan job claim | Postgres/SQLite + dual-worker lab |
| SSRF submission + worker | REL-001/002 E2E + unit |
| WordPress scanning / intel / assets / findings | Regression suite |
| Celery Beat scheduling | E2E PASS |
| Reports PDF/HTML/JSON/XLSX/SARIF | E2E PASS |
| Six workspaces + Playwright | E2E PASS |

No unapproved UI redesign in version alignment commit.

---

## 4. Enterprise deployment validation

| Item | Result |
|------|--------|
| Image | `sentinelwp:4.1.0` |
| Digest | `sha256:4a1f08a45d00c61d0a993cf3b01acb1422397b62042c7191b20dd73b3b2ef0e0` |
| `/health` via gateway | `"version":"4.1.0"` |
| Phase 4 E2E | **PASS** (`tests/e2e/logs/v4.1.0_e2e_run.log`) |
| Volumes | Preserved (no delete) |

Fresh install vs upgrade: migration head `009_sprint11_schema_parity` verified in E2E migration section; full greenfield install on empty volume not re-run in this session (same compose as prior Sprint 11 validation).

---

## 5. Release testing summary

| Gate | Result |
|------|--------|
| Pytest `tests/` | **640 passed**, 11 warnings |
| pip-audit (Py 3.12, `requirements-prod.txt`) | Exit **0**, no known vulnerabilities |
| Playwright (6 workspaces) | **PASS** (E2E Section 7) |
| Container config | Non-root UID 1000, loopback ingress, internal DB/Redis (validation stack) |

**Disclaimer:** Laboratory PASS does not alone certify production; operator runbooks and secrets governance still required.

---

## 6. Release artifacts (prepared, not published)

| Document | Path |
|----------|------|
| Release notes | `docs/release/RELEASE_NOTES_v4.1.0.md` |
| PR template | `docs/release/GITHUB_PR_v4.1.0.md` |
| Changelog | `CHANGELOG.md` |
| Upgrade / rollback | `docs/UPGRADE_ROLLBACK.md` |

---

## 7. Release candidate commit

Created after version alignment and docs (see `git log -1` on `release/sentinelwp-v4.1.0`).

---

## 8. Recommended GitHub procedure (after approval)

1. Push `release/sentinelwp-v4.1.0` to `origin` (no force).
2. Open PR per `docs/release/GITHUB_PR_v4.1.0.md`; label **history-rewrite / unrelated-histories**.
3. Run GitHub Actions / local CI on PR head.
4. Merge with chosen integration strategy (Section 1).
5. Tag `v4.1.0`, create GitHub Release attaching `RELEASE_NOTES_v4.1.0.md`.
6. Publish container image to registry (optional, separate approval).

---

## 9. Decision

### **CONDITIONAL GO**

**Ready:** Version 4.1.0 aligned, tested enterprise candidate on branch `release/sentinelwp-v4.1.0`, Docker/E2E/security gates passed in lab.

**Blockers before public GitHub release:**
1. **Explicit integration decision** for unrelated `main` vs enterprise history.
2. Manual review of **15 files** unique to GitHub `main` for any missing 4.0.0 logic.
3. Authorized **push, PR, merge, tag** (not executed in this task).

---

## 10. Authorization request

No push, PR, merge, tag, image publish, or GitHub Release was performed.

Please authorize GitHub publication when integration strategy is chosen.
