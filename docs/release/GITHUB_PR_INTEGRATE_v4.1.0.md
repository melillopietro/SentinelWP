# Pull Request — Integrate SentinelWP v4.1.0 onto public main

## Title
**Release: SentinelWP v4.1.0 (enterprise line integrated on preserved public history)**

## Base / head
- **Base:** `main` @ `ad1de5ec8dc10df1648e946663405e88c642ac09` (Initial commit: SentinelWP v4.0.0)
- **Head:** `release/integrate-sentinelwp-v4.1.0`

## Why this branch exists
Public `main` is a **single-commit** v4.0.0 snapshot. The enterprise Sprint 8–11 line was developed on a **separate history** with no merge-base. To **preserve public Git history** (no force-push, no replacement of `main`), this PR:

1. Starts from **`origin/main`** unchanged.
2. Adds the full **v4.1.0** enterprise codebase as a follow-on commit series.
3. **Reconciles** fifteen files that existed only on public main (scan pipeline, WordPress version helpers, core security scanner, curated advisories, docs, tests) — see `docs/release/GITHUB_INTEGRATION_v4.1.0.md`.

This is **not** a fast-forward; it is an intentional integration PR for review.

## Summary
- **Version:** 4.1.0 (`core/version.py`, Docker tags, UI, `/health`)
- **Enterprise:** PostgreSQL, Celery/Beat, Alembic through Sprint 11, Docker/Nginx production stack
- **Security:** Session RBAC, SSRF preflight + worker enforcement, atomic scan job claims (SWP-REL-001/002/003)
- **4.0.0 parity:** Core maintenance findings, `CoreSecurityScanner`, curated advisories, WordPress version module restored and wired

## Test evidence
- **649** pytest tests passed on integration branch (640 Sprint baseline + ported public tests)
- Prior lab: Phase 4 E2E PASS on release candidate `3bb5b96` (re-run recommended on integration SHA before merge)

## Upgrade / migration
- `CHANGELOG.md` — v4.1.0 entry
- `docs/UPGRADE_ROLLBACK.md`, `docs/DEPLOYMENT_UBUNTU.md`
- Alembic: upgrade through `009_sprint11_schema_parity`

## Known limitations
- Unrelated histories: first merge establishes unified tree; no force push used
- Risk doc `docs/RISK_SCORING_MODEL.md` describes 4.0.0 narrative; runtime scoring is `core/risk_engine.py` (see doc note)
- Laboratory validation ≠ full production certification

## Rollback
- Revert merge commit on `main` or reset deployment to previous image/volume backup per `docs/UPGRADE_ROLLBACK.md`

## Checklist (reviewer)
- [ ] Review fifteen-file reconciliation table in `GITHUB_INTEGRATION_v4.1.0.md`
- [ ] Confirm no secrets/credentials in diff
- [ ] CI: pytest + pip-audit (Python 3.12)
- [ ] Optional: Docker Compose sprint11 validation E2E

**Do not merge until release manager approval.** Tag `v4.1.0` and GitHub Release are out of scope for this PR until post-merge authorization.
